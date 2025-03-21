"""
This module implements a FastAPI supervisor plugin that fetches release information
for the Edge Node Launcher from a GitHub repository, compiles it, and regenerates
an HTML page with the latest releases and download links.

Classes
-------
NaeuralReleaseAppPlugin
  Subclass of the SupervisorFastApiWebApp, providing overrides for release fetching
  and HTML generation functionality.
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, TypedDict
from dataclasses import dataclass, field
from functools import wraps
from enum import Enum

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.4.1'

RELEASES_CACHE_FILE = 'releases_history.pkl'

_CONFIG = {
  **BasePlugin.CONFIG,
  'ASSETS': 'plugins/business/fastapi/launcher_download',
  'JINJA_ARGS': {
    'html_files': [
      {
        'name': 'releases.html',
        'route': '/',
        'method': 'get'
      }
    ]
  },
  'NR_PREVIOUS_RELEASES': 5, # The number of previous releases that has to be fetched
  'RELEASES_TO_FETCH': 50, # The amount of releases to check from GitHub
  'REGENERATION_INTERVAL': 10 * 60,
  "RELEASES_REPO_URL": "https://api.github.com/repos/Ratio1/edge_node_launcher",
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
  'DEBUG_MODE': False,  # or True if you want more logs
  'SHOW_ALL_RELEASES_BY_DEFAULT': False,
  'GITHUB_API_TIMEOUT': 30,
  'MAX_RETRIES': 3
}


def handle_errors(func_name=None, fallback_value=None):
    """Decorator for handling errors in methods.
    Args:
      func_name: The name to use in error messages. If None, uses the method name.
      fallback_value: The value to return if an exception occurs.
    """
    def decorator(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            nonlocal func_name
            if func_name is None:
                func_name = method.__name__
            try:
                return method(self, *args, **kwargs)
            except Exception as e:
                error_msg = f"{func_name}: Error: {str(e)}"
                self.log_error(func_name, error_msg, e)
                return fallback_value
        return wrapper
    return decorator


class NaeuralReleaseAppPlugin(BasePlugin):
  CONFIG = _CONFIG

  def on_init(self, **kwargs):
    super(NaeuralReleaseAppPlugin, self).on_init(**kwargs)
    self._last_day_regenerated = (self.datetime.now() - self.timedelta(days=1)).day
    self.__last_generation_time = 0
    self.html_generator = HtmlGenerator(self.CONFIG, self)
    self.release_fetcher = ReleaseDataFetcher(self.CONFIG, self, self.cfg_releases_repo_url, self.cfg_max_retries,
                                              self.cfg_github_api_timeout, self.cfg_debug_mode)
    self._cached_releases = self._load_cached_releases()
    return

  @handle_errors(fallback_value=[])
  def _load_cached_releases(self) -> List[Dict[str, Any]]:
    """Load cached releases from pickle, or return an empty list on failure."""
    data = self.diskapi_load_pickle_from_data(RELEASES_CACHE_FILE)
    if data:
      self.P(f"_load_cached_releases: Loaded {len(data)} from cache.")
      return data
    return []

  @handle_errors(fallback_value=False)
  def _save_cached_releases(self, releases: List[Dict[str, Any]]) -> bool:
    """Save the entire release list back to pickle cache."""
    self.diskapi_save_pickle_to_data(releases, RELEASES_CACHE_FILE)
    self.P(f"_save_cached_releases: Saved {len(releases)} release(s) to cache.")
    return True

  def log_error(self, func_name: str, error_msg: str, exc_info: Optional[Exception] = None) -> str:
    details = [f"ERROR in {func_name}:", error_msg]
    if exc_info and self.cfg_debug_mode:
      import traceback
      details.append("Traceback:")
      details.append(''.join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__)))
    msg = "\n".join(details)
    self.P(msg)
    return msg

  def get_latest_releases(self) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    1. Check GitHub releases until we find NR_PREVIOUS_RELEASES valid ones
    2. Check which of those valid ones are already in our cache
    3. Download complete details for valid ones not in cache
    4. Add these to cache
    5. Return the NR_PREVIOUS_RELEASES valid releases

    A valid release has all required assets: Ubuntu 22.04, Windows MSI, Windows ZIP, macOS ARM.
    """
    func_name = "get_latest_releases"
    try:
      # 1) Load current cache
      cached_tags = {c['tag_name'] for c in self._cached_releases}
      self.P(f"{func_name}: Loaded {len(self._cached_releases)} releases from cache")

      # 2) Get releases from GitHub (basic info)
      github_releases = self.release_fetcher.get_top_n_releases(self.cfg_releases_to_fetch)

      if not github_releases:
        # If GitHub returned nothing, use what's in cache
        if self._cached_releases:
          self.P(f"{func_name}: GitHub returned 0 releases, using {len(self._cached_releases)} cached releases")
          return self._cached_releases, {'message': "Using cached data - unable to fetch updates from GitHub", 'rate_limited': False}
        else:
          return [], {'message': "No releases found from GitHub & no cache available", 'rate_limited': False}

      self.P(f"{func_name}: GitHub returned {len(github_releases)} basic releases")

      # 3) Find NR_PREVIOUS_RELEASES valid releases from GitHub
      valid_github_releases = []
      for release in github_releases:
        assets = release.get('assets', [])
        asset_names = [a.get('name', '') for a in assets]

        # Check for all required assets
        has_ubuntu_22_04 = any('LINUX_Ubuntu-22.04.AppImage' in name for name in asset_names)
        has_windows_zip = any('Windows_msi.zip' in name for name in asset_names)
        has_windows_msi = any(name.endswith('Windows.msi') for name in asset_names)
        has_macos_arm = any('OSX-arm64.zip' in name for name in asset_names)

        if has_ubuntu_22_04 and has_windows_zip and has_windows_msi and has_macos_arm:
          valid_github_releases.append(release)
          self.P(f"{func_name}: Found valid release {release['tag_name']} with all required assets")

          # Stop once we've found enough valid releases
          if len(valid_github_releases) >= self.cfg_nr_previous_releases:
            self.P(f"{func_name}: Found {self.cfg_nr_previous_releases} valid releases, stopping search")
            break
        else:
          missing = []
          if not has_ubuntu_22_04: missing.append("Ubuntu 22.04")
          if not has_windows_zip: missing.append("Windows ZIP")
          if not has_windows_msi: missing.append("Windows MSI")
          if not has_macos_arm: missing.append("macOS ARM")
          self.P(f"{func_name}: Skipping invalid release {release['tag_name']} - missing assets: {', '.join(missing)}")

      if not valid_github_releases:
        # If no valid releases found on GitHub, use what's in cache
        if self._cached_releases:
          self.P(f"{func_name}: No valid releases from GitHub, using {len(self._cached_releases)} cached releases")
          return self._cached_releases, None
        else:
          return [], {'message': "No valid releases found with all required assets", 'rate_limited': False}

      self.P(f"{func_name}: Found {len(valid_github_releases)} valid releases from GitHub")

      # 4) Check which valid releases are already in cache
      new_valid_releases = []
      cached_valid_releases = []

      for release in valid_github_releases:
        if release['tag_name'] in cached_tags:
          cached_release = next(c for c in self._cached_releases if c['tag_name'] == release['tag_name'])
          cached_valid_releases.append(cached_release)
          self.P(f"{func_name}: Cache hit for release {release['tag_name']}")
        else:
          new_valid_releases.append(release)

      if new_valid_releases:
        self.P(
          f"{func_name}: Found {len(cached_valid_releases)} releases in cache, fetching {len(new_valid_releases)} missing releases")

        # 5) Download complete details for new valid releases
        new_full_releases = []

        for r in new_valid_releases:
          tag = r['tag_name']
          try:
            details = self.release_fetcher.get_release_details(tag)
            new_release = {
              'tag_name': details.tag_name,
              'published_at': details.published_at,
              'body': details.body,
              'assets': details.assets,
              'commit_sha': details.commit_sha,
              'commit_info': details.commit_info,
              'tag_info': details.tag_info
            }
            new_full_releases.append(new_release)
          except GitHubApiError as e:
            if e.is_rate_limit:
              raise
            self.log_error(func_name, f"Failed to fetch release details for {tag}: {str(e)}")

        # 6) Add new valid releases to cache
        if new_full_releases:
          updated_cache = [r for r in self._cached_releases if r['tag_name'] not in {nf['tag_name'] for nf in new_full_releases}]
          updated_cache.extend(new_full_releases)
          updated_cache.sort(key=lambda x: x['published_at'], reverse=True)
          self._cached_releases = updated_cache
          self._save_cached_releases(updated_cache)
          self.P(f"{func_name}: Added {len(new_full_releases)} new releases to cache")
      else:
        self.P(f"{func_name}: All releases already in cache, no downloads needed")
        new_full_releases = []

      # 7) Combine cached valid releases with new full releases and return
      result = cached_valid_releases + new_full_releases

      self.P(f"{func_name}: Returning {len(result)} valid releases")
      return result, None

    except GitHubApiError as gh_e:
      msg = f"{func_name}: GitHubApiError {gh_e}"
      self.log_error(func_name, msg)
      # fallback to cached releases
      if self._cached_releases:
        fallback = sorted(self._cached_releases, key=lambda x: x['published_at'], reverse=True)
        result = fallback[:self.cfg_nr_previous_releases]
        self.P(f"{func_name}: GitHub API error, using {len(result)} cached releases")
        return result, {'message': f"Using cached data - GitHub API error: {str(gh_e)}", 'rate_limited': gh_e.is_rate_limit, 'error_type': gh_e.error_type.value}

      return [], {'message': msg, 'rate_limited': gh_e.is_rate_limit, 'error_type': gh_e.error_type.value}

    except Exception as e:
      msg = f"{func_name}: Unexpected error: {str(e)}"
      self.log_error(func_name, msg, e)
      # fallback to cached releases
      if self._cached_releases:
        fallback = sorted(self._cached_releases, key=lambda x: x['published_at'], reverse=True)
        result = fallback[:self.cfg_nr_previous_releases]
        self.P(f"{func_name}: Unexpected error, using {len(result)} cached releases")
        return result, {'message': f"Using cached data - Failed to fetch updates: {str(e)}", 'rate_limited': False}

      return [], {'message': msg, 'rate_limited': False}

  @handle_errors(fallback_value=True)
  def _regenerate_index_html(self) -> bool:
    """
    Fetch/compile the full set of releases from cache+GitHub, then
    generate the final releases.html for display.
    Returns True if successful.
    """
    func_name = "_regenerate_index_html"
    self.P(f"{func_name}: Starting HTML regeneration...")

    # 1) Retrieve the full set of releases
    try:
      raw_releases, release_error = self.get_latest_releases()
      if not raw_releases:
        # Use the error info from get_latest_releases if present
        if release_error:
          error_message = release_error.get('message', "Failed to get any releases")
        else:
          error_message = "Failed to get any releases"
        self.log_error(func_name, error_message)
        return False
    except Exception as e:
      error_message = f"{func_name}: Exception while fetching releases: {str(e)}"
      self.log_error(func_name, error_message, e)
      return False

    # 2) Process the releases into the shape the HTML generator expects
    try:
      # Convert raw_releases directly to ReleaseInfo objects using list comprehension
      releases_for_html = [
        ReleaseInfo(
          tag_name=release_data['tag_name'],
          published_at=release_data['published_at'],
          body=release_data.get('body', '') or '',
          assets=[
            ReleaseAsset(asset['name'], asset['size'], asset['browser_download_url']) 
            for asset in release_data.get('assets', [])
          ]
        )
        for release_data in raw_releases
      ]
      
      self.P(f"{func_name}: Successfully processed {len(releases_for_html)} releases for HTML generation")

    except Exception as e:
      error_msg = f"{func_name}: Error processing release data: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

    # 3) Generate and write the HTML
    try:
      # Pass the error_info to the HTML generator if it exists
      using_cached_data = release_error is not None
      html_content = self.html_generator.generate_complete_html(
        releases=releases_for_html,
        ee_id=self.ee_id,
        ee_addr=self.ee_addr,
        last_update=self.datetime_to_str(),
        using_cached_data=using_cached_data,
        error_message=release_error.get('message', '') if release_error else ''
      )

      # Where we will write the HTML
      web_server_path = self.get_web_server_path()
      output_path = self.os_path.join(web_server_path, 'assets/releases.html')

      with open(output_path, 'w') as fd:
        fd.write(html_content)

      self.P(f"{func_name}: releases.html generated successfully at {output_path}")
      self.P(
        f"{func_name}: HTML generation complete with {len(releases_for_html)} releases, size: {len(html_content)} bytes")
      return True

    except Exception as e:
      error_msg = f"{func_name}: Error writing HTML file: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

  @handle_errors(fallback_value=True)
  def _maybe_regenerate_index_html(self) -> bool:
    """
    Check if enough time has passed since last regeneration. If so, regenerate.
    """
    func_name = "_maybe_regenerate_index_html"
    current_time = self.time()
    if (current_time - self.__last_generation_time) > self.cfg_regeneration_interval:
      self.P(f"{func_name}: Regeneration interval elapsed, regenerating releases.html...")
      result = self._regenerate_index_html()
      current_day = self.datetime.now().day

      # Whether success or failure, update the generation time to avoid repeated attempts
      self.__last_generation_time = current_time

      if result:
        self._last_day_regenerated = current_day
        self.P(f"{func_name}: HTML regeneration successful.")
      else:
        self.P(f"{func_name}: HTML regeneration failed (see logs).")
    return True

  def process(self):
    """Called periodically. Triggers the conditional regeneration of the HTML."""
    try:
      self._maybe_regenerate_index_html()
    except Exception as e:
      self.log_error("process", f"Unhandled error in process(): {str(e)}", e)
    return


@dataclass(frozen=True)
class GitHubReleaseData:
  """Holds all fetched data about one GitHub release."""
  tag_name: str
  published_at: str
  body: str
  assets: List[Dict[str, Any]] = field(default_factory=list)
  commit_sha: Optional[str] = None
  commit_info: Optional[Dict[str, Any]] = None
  tag_info: Optional[Dict[str, Any]] = None

  def __post_init__(self):
    """Validate the data after initialization."""
    if not self.tag_name:
      raise ValueError("tag_name cannot be empty")
    if not self.published_at:
      raise ValueError("published_at cannot be empty")


class GitHubApiErrorType(Enum):
  RATE_LIMIT = "rate_limit"
  NOT_FOUND = "not_found"
  NETWORK = "network"
  UNKNOWN = "unknown"


class GitHubApiError(Exception):
  def __init__(self, message: str, error_type: GitHubApiErrorType, status_code: Optional[int] = None,
               response_text: Optional[str] = None):
    self.error_type = error_type
    self.status_code = status_code
    self.response_text = response_text
    super().__init__(message)

  @property
  def is_rate_limit(self) -> bool:
    return self.error_type == GitHubApiErrorType.RATE_LIMIT

  @classmethod
  def from_response(cls, response, message: Optional[str] = None) -> 'GitHubApiError':
    if response.status_code == 403 and 'rate limit' in response.text.lower():
      return cls(message or f"GitHub API rate limit: {response.text}",
                 error_type=GitHubApiErrorType.RATE_LIMIT,
                 status_code=response.status_code,
                 response_text=response.text)
    elif response.status_code == 404:
      return cls(message or f"Not found: {response.text}",
                 error_type=GitHubApiErrorType.NOT_FOUND,
                 status_code=response.status_code,
                 response_text=response.text)
    else:
      return cls(message or f"GitHub API error: {response.text}",
                 error_type=GitHubApiErrorType.UNKNOWN,
                 status_code=response.status_code,
                 response_text=response.text)


class ReleaseDataFetcher:
  """
  Fetches release data from GitHub.
  Only calls get_top_n_releases(...) to limit the fetch to the last N releases.
  """

  def __init__(self, config: Dict[str, Any], logger: Any, releases_repo_url: str, max_retries: int,
               github_api_timeout: int, debug_mode: bool):
    self.logger = logger
    self.requests = logger.requests
    self._releases_repo_url = releases_repo_url
    self._max_retries = max_retries
    self._debug_mode = debug_mode
    self._github_api_timeout = github_api_timeout

  def _log(self, msg: str):
    if self._debug_mode:
      self.logger.P(f"[ReleaseDataFetcher] {msg}")

  def _make_request(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
    retries = 0
    last_exc = None
    while retries < self._max_retries:
      try:
        self._log(f"GET {url} with {params}")
        response = self.requests.get(url, params=params, timeout=self._github_api_timeout)
        if response.status_code == 200:
          self.logger.P(f"[ReleaseDataFetcher] API request successful: {url} (status: 200)")
          return response.json()
        else:
          self.logger.P(f"[ReleaseDataFetcher] API request failed: {url} (status: {response.status_code})")
          raise GitHubApiError.from_response(response)
      except GitHubApiError as github_error:
        if github_error.is_rate_limit or retries >= (self._max_retries - 1):
          raise
        last_exc = github_error
      except Exception as e:
        if retries >= (self._max_retries - 1):
          raise GitHubApiError(str(e), GitHubApiErrorType.NETWORK)
        last_exc = e
      retries += 1
      self.logger.P(f"[ReleaseDataFetcher] Retry {retries}/{self._max_retries} for {url}")
    # If we reach here, re-raise last error
    raise last_exc

  def get_top_n_releases(self, n: int) -> List[Dict[str, Any]]:
    """
    Fetch from GitHub the last n release objects (basic info only).
    """
    url = f"{self._releases_repo_url}/releases"
    # param per_page=n will limit to the top n (most recent) releases
    return self._make_request(url, params={"per_page": n}) or []

  def get_release_details(self, tag_name: str) -> 'GitHubReleaseData':
    # 1) fetch the release by its tag
    release_url = f"{self._releases_repo_url}/releases/tags/{tag_name}"
    release_data = self._make_request(release_url)

    # 2) fetch tag info to get commit sha
    tag_url = f"{self._releases_repo_url}/git/refs/tags/{tag_name}"
    try:
      tag_data = self._make_request(tag_url)
    except GitHubApiError as e:
      self._log(f"Failed to fetch tag refs for {tag_name}: {e}")
      tag_data = None

    commit_sha = None
    commit_info = None
    if tag_data:
      if tag_data['object']['type'] == 'tag':
        # We have an annotated tag that points to another object
        tag_obj = self._make_request(tag_data['object']['url'])
        commit_sha = tag_obj['object']['sha']
      else:
        commit_sha = tag_data['object']['sha']

      if commit_sha:
        commit_info = self._get_commit_info(commit_sha)

    body_text = release_data.get('body', '') or ""
    if not body_text.strip() and commit_info and 'commit' in commit_info and 'message' in commit_info['commit']:
      # fallback to commit message, using already fetched commit_info
      body_text = commit_info['commit']['message']

    return GitHubReleaseData(
      tag_name=release_data['tag_name'],
      published_at=release_data['published_at'],
      body=body_text,
      assets=release_data.get('assets', []),
      commit_sha=commit_sha,
      commit_info=commit_info,
      tag_info=tag_data,
    )

  def _get_commit_info(self, commit_sha: str) -> Optional[Dict[str, Any]]:
    curl = f"{self._releases_repo_url}/commits/{commit_sha}"
    return self._make_request(curl)


@dataclass
class ReleaseAsset:
  """Data class for release assets."""
  name: str
  size: int
  browser_download_url: str

  @property
  def size_mb(self) -> float:
    """Return size in megabytes."""
    return self.size / (1024 * 1024)


@dataclass
class ReleaseInfo:
  """Data class for release information suitable for HTML rendering."""
  tag_name: str
  published_at: str
  body: str
  assets: List[ReleaseAsset]

  @property
  def safe_tag_name(self) -> str:
    """Return sanitized tag name for use in HTML IDs."""
    return self.tag_name.replace("'", "").replace('.', '-')

  @property
  def formatted_date(self) -> str:
    """Return formatted publication date."""
    dt = datetime.strptime(self.published_at, '%Y-%m-%dT%H:%M:%SZ')
    return dt.strftime('%B %d, %Y')


class HtmlGenerator:
  """Class responsible for generating HTML content for the releases page."""

  def __init__(self, config: Dict[str, Any], plugin: 'NaeuralReleaseAppPlugin'):
    self.config = config
    self.plugin = plugin

  def generate_html_head(self) -> str:
    """Generate the HTML head section with styles."""
    return """
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Edge Node Launcher Releases</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
          }
          .jumbo {
            background: linear-gradient(135deg, #4b6cb7 0%, #182848 100%);
            color: white;
            padding: 3em 2em;
            text-align: center;
            border-radius: 8px;
            margin-top: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .jumbo h1 {
            margin-top: 0;
            font-size: 2.5em;
          }
          .jumbo button {
            background-color: #ff7e5f;
            color: white;
            border: none;
            padding: 12px 24px;
            font-size: 1.1em;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
            margin-top: 15px;
          }
          .jumbo button:hover {
            background-color: #ff6347;
          }
          .cached-data-warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 10px 15px;
            border-radius: 5px;
            margin-top: 15px;
            font-size: 0.9em;
            text-align: center;
            border-left: 4px solid #ffeeba;
            display: flex;
            align-items: center;
            justify-content: center;
          }
          .cached-data-warning span {
            margin-left: 10px;
          }
          .latest-release, .previous-releases {
            margin: 2em 0;
            background-color: white;
            padding: 2em;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
          }
          .latest-release h2, .previous-releases h2 {
              color: #4b6cb7;
              border-bottom: 2px solid #f0f0f0;
              padding-bottom: 10px;
          }
          .release-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 1em;
          }
          .release-date {
            color: #666;
            font-style: italic;
          }
          .release-content {
            display: flex;
            flex-wrap: wrap;
            gap: 2em;
          }
          .release-details {
            flex: 1;
            min-width: 300px;
          }
          .download-options {
            flex: 1;
            min-width: 300px;
          }
          .release-notes-container {
            position: relative;
          }
          .release-notes {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            white-space: pre-wrap;
            font-size: 0.95em;
            max-height: 200px;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            margin: 0;
          }
          .commit-info {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.9em;
            max-height: 100px;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
          }
          .expanded {
            max-height: 1000px !important;
          }
          .commit-title {
            font-weight: bold;
            margin-bottom: 5px;
          }
          .see-more-btn {
            background-color: #f0f0f0;
            border: none;
            padding: 5px 10px;
            font-size: 0.8em;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 5px;
            color: #666;
            display: none;
            position: relative;
          }
          .see-more-btn:hover {
            background-color: #e0e0e0;
          }
          .see-more-btn .see-less-text {
            display: none;
          }
          .see-more-btn.expanded .see-more-text {
            display: none;
          }
          .see-more-btn.expanded .see-less-text {
            display: inline;
          }
          .download-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 1em;
          }
          .download-item {
            display: flex;
            align-items: center;
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 10px 15px;
            transition: transform 0.2s, box-shadow 0.2s;
          }
          .download-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
          }
          .linux {
            border-left: 4px solid #f0ad4e;
          }
          .windows {
            border-left: 4px solid #5bc0de;
          }
          .macos {
            border-left: 4px solid #5cb85c;
          }
          .os-icon {
            font-size: 1.8em;
            margin-right: 15px;
          }
          .download-details {
            flex: 1;
            display: flex;
            flex-direction: column;
          }
          .os-name {
            font-weight: bold;
            margin-bottom: 3px;
          }
          .file-size {
            color: #777;
            font-size: 0.8em;
            margin-bottom: 5px;
          }
          .download-btn {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            padding: 6px 12px;
            border-radius: 4px;
            text-decoration: none;
            font-size: 0.9em;
            align-self: flex-start;
          }
          .download-btn:hover {
            background-color: #45a049;
            text-decoration: none;
          }
          .release-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
            transition: transform 0.2s;
            display: none;
          }
          .release-card.visible {
            display: block;
          }
          .release-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
          }
          .release-card-header {
              display: flex;
              justify-content: space-between;
              align-items: center;
              padding: 15px 20px;
              background-color: #f8f9fa;
              border-bottom: 1px solid #e0e0e0;
          }
          .release-card-header h3 {
              margin: 0;
              color: #4b6cb7;
              font-size: 1.2em;
          }
          .release-card-content {
              padding: 20px;
              display: flex;
              flex-wrap: wrap;
              gap: 20px;
          }
          .release-info {
              flex: 1;
              min-width: 250px;
          }
          .release-downloads {
              flex: 2;
              min-width: 300px;
              display: flex;
              flex-wrap: wrap;
              gap: 15px;
          }
          .download-section {
              flex: 1;
              min-width: 150px;
          }
          .download-section h4 {
              margin-top: 0;
              margin-bottom: 10px;
              color: #555;
              font-size: 1em;
              border-bottom: 1px solid #eee;
              padding-bottom: 5px;
          }
          .download-list {
              display: flex;
              flex-direction: column;
              gap: 8px;
          }
          .download-item-small {
              display: flex;
              flex-direction: column;
              padding: 8px 10px;
              border-radius: 6px;
              background-color: #f9f9f9;
              transition: background-color 0.2s;
          }
          .download-item-small:hover {
              background-color: #f0f0f0;
          }
          .download-item-small.linux {
              border-left: 3px solid #f0ad4e;
          }
          .download-item-small.windows {
              border-left: 3px solid #5bc0de;
          }
          .download-item-small.macos {
              border-left: 3px solid #5cb85c;
          }
          .download-btn-small {
              display: inline-block;
              background-color: #4CAF50;
              color: white;
              padding: 4px 8px;
              border-radius: 4px;
              text-decoration: none;
              font-size: 0.8em;
              margin-top: 5px;
              align-self: flex-start;
          }
          .download-btn-small:hover {
              background-color: #45a049;
              text-decoration: none;
          }
          .releases-container {
              margin-top: 20px;
          }
          .show-all-btn {
              display: block;
              margin: 20px auto;
              background-color: #4b6cb7;
              color: white;
              border: none;
              padding: 10px 20px;
              font-size: 1em;
              border-radius: 4px;
              cursor: pointer;
              transition: background-color 0.3s;
          }
          .show-all-btn:hover {
              background-color: #3a5795;
          }
        </style>
      </head>
        """

  def generate_jumbo_section(self, ee_id: str, ee_addr: str, last_update: str, using_cached_data: bool = False, error_message: str = "") -> str:
    """Generate the jumbo header section."""
    cached_data_warning = ""
    if using_cached_data:
      cached_data_warning = f"""
        <div class="cached-data-warning">
          <strong>⚠️</strong><span>You are viewing cached data. {error_message}</span>
        </div>
      """
      
    return f"""
        <body>
            <div class="jumbo">
                <h1>Edge Node Launcher Releases</h1>
                <p>Download the latest version of Edge Node Launcher to stay up-to-date with new features.</p>
                <p>This page was generated by Edge Node <code>{ee_id}:{ee_addr}</code> at {last_update}.</p>
                {cached_data_warning}
                <button onclick="document.getElementById('latest-release').scrollIntoView({{behavior: 'smooth'}});" class="download-btn">
                    Download Edge Node Launcher
                </button>
            </div>
        """

  def _generate_download_item(self, asset: ReleaseAsset, os_type: str, os_name: str, icon: str) -> str:
    """Generate HTML for a download item."""
    return f"""
            <div class="download-item {os_type}">
                <div class="os-icon">{icon}</div>
                <div class="download-details">
                    <span class="os-name">{os_name}</span>
                    <span class="file-size">{asset.size_mb:.2f} MB</span>
                    <a href="{asset.browser_download_url}" class="download-btn">Download</a>
                </div>
            </div>
        """

  def _format_release_info(self, release: ReleaseInfo) -> str:
    """Format release body text for display."""
    if not release.body.strip():
      return "No release information available"

    lines = release.body.strip().split('\n')
    if len(lines) == 1:
      return lines[0]

    formatted = f"<div class='commit-title'>{lines[0]}</div>"
    if len(lines) > 1:
      formatted += "<ul class='commit-message'>"
      for i, line in enumerate(lines[1:]):
        css_class = "visible" if i < 2 else "hidden"
        if line.strip().startswith('*'):
          formatted += f"<li class='{css_class}'>{line.strip()[1:].strip()}</li>"
        elif line.strip():
          formatted += f"<li class='{css_class}'>{line.strip()}</li>"
      formatted += "</ul>"
    return formatted

  def _generate_download_section(self, assets: List[ReleaseAsset], is_latest: bool = False) -> str:
    """Generate the download section HTML for a release."""
    # Define all asset patterns and their properties
    asset_configs = [
      # (regex pattern, os_type, display_name, icon)
      (r'Windows_msi\.zip', 'windows', 'Windows (ZIP)', '🪟'),
      (r'Windows\.msi$', 'windows', 'Windows (MSI)', '🪟'),
      (r'OSX-arm64\.zip', 'macos', 'macOS (Apple Silicon)', '🍎'),
      (r'LINUX_Ubuntu-22\.04\.AppImage', 'linux', 'Linux Ubuntu 22.04', '🐧'),
    ]
    
    # Create a lookup dictionary of assets by pattern
    found_assets = {}
    for pattern, _, _, _ in asset_configs:
      found_assets[pattern] = next((a for a in assets if self.plugin.re.search(pattern, a.name)), None)
    
    if is_latest:
      # Generate HTML for the latest release (all assets in a grid)
      download_items = [
        self._generate_download_item(found_assets[pattern], os_type, display_name, icon)
        for pattern, os_type, display_name, icon in asset_configs
        if found_assets[pattern]  # Only include if asset exists
      ]
      
      return f"""
        <div class="download-options">
          <h3>Download Options:</h3>
          <div class="download-grid">
            {''.join(download_items)}
          </div>
        </div>
      """
    else:
      # Generate HTML for previous releases (grouped by OS type)
      os_groups = {
        "Windows": [(r'Windows_msi\.zip', 'Windows ZIP'), (r'Windows\.msi$', 'Windows MSI')],
        "macOS": [(r'OSX-arm64\.zip', 'Apple Silicon')],
        "Linux": [(r'LINUX_Ubuntu-22\.04\.AppImage', 'Ubuntu 22.04')],
      }

      download_sections = []
      for os_name, pattern_variants in os_groups.items():
        # Create HTML items for each asset in this OS category
        items = [
          f"""
          <div class="download-item-small {os_name.lower()}">
            <span class="os-name">{variant}</span>
            <span class="file-size">{found_assets[pattern].size_mb:.2f} MB</span>
            <a href="{found_assets[pattern].browser_download_url}" class="download-btn-small">Download</a>
          </div>
          """
          for pattern, variant in pattern_variants
          if found_assets[pattern]  # Only include if asset exists
        ]
        
        # Only add this OS section if it has items
        if items:
          download_sections.append(f"""
            <div class="download-section">
              <h4>{os_name}</h4>
              <div class="download-list">
                {''.join(items)}
              </div>
            </div>
          """)
      
      return f"""
        <div class="release-downloads">
          {''.join(download_sections)}
        </div>
      """

  def generate_latest_release_section(self, release: ReleaseInfo) -> str:
    release_info = self._format_release_info(release)
    download_section = self._generate_download_section(release.assets, is_latest=True)

    return f"""
      <div class="latest-release" id="latest-release">
        <div class="release-header">
          <h2>Latest Release: {release.tag_name}</h2>
          <span class="release-date">Released on {release.formatted_date}</span>
        </div>
        <div class="release-content">
          <div class="release-details">
            <h3>Release Details:</h3>
            <div class="release-notes-container">
              <pre id="latest-release-info" class="release-notes">{release_info}</pre>
              <button id="latest-release-btn" class="see-more-btn" onclick="toggleContent('latest-release-info')" style="display: none;">
                <span class="see-more-text">See More</span>
                <span class="see-less-text">See Less</span>
              </button>
            </div>
          </div>
          {download_section}
        </div>
      </div>
    """

  def generate_previous_releases_section(self, releases: List[ReleaseInfo]) -> str:
    """
    Generate the previous releases section.
    We now show *all* older releases (though the user can still click 'Show All' to expand).
    """
    release_cards = []
    # releases[0] is the "latest"; so we skip that for "previous"
    for i, release in enumerate(releases[1:], start=1):
      visible_class = "visible" if (i <= 2 or self.config.get('SHOW_ALL_RELEASES_BY_DEFAULT', False)) else ""
      release_info = self._format_release_info(release)
      download_section = self._generate_download_section(release.assets, is_latest=False)
      release_cards.append(f"""
        <div class="release-card {visible_class}" id="release-row-{i}">
          <div class="release-card-header">
            <h3>{release.tag_name}</h3>
            <span class="release-date">{release.formatted_date}</span>
          </div>
          <div class="release-card-content">
            <div class="release-info">
              <div id="release-info-{release.safe_tag_name}" class="commit-info">
                {release_info}
              </div>
              <button id="btn-{release.safe_tag_name}" class="see-more-btn" onclick="toggleContent('release-info-{release.safe_tag_name}')" style="display: none;">
                <span class="see-more-text">See More</span>
                <span class="see-less-text">See Less</span>
              </button>
            </div>
            {download_section}
          </div>
        </div>
      """)

    show_all_button_text = "Show Less" if self.config.get('SHOW_ALL_RELEASES_BY_DEFAULT',
                                                          False) else "Show All Releases"

    return f"""
      <div class="previous-releases">
        <h2>Previous Releases</h2>
        <div class="releases-container">
          {''.join(release_cards)}
        </div>
        <button id="show-all-btn" class="show-all-btn" onclick="toggleAllReleases()">
          {show_all_button_text}
        </button>
      </div>
    """

  def generate_javascript(self) -> str:
    """Same JS as before, unmodified."""
    return """
      <script>
        function checkContentOverflow(contentId, buttonId) {
          const content = document.getElementById(contentId);
          const button = document.getElementById(buttonId);
          if (!content || !button) return;

          if (content.tagName === 'PRE') {
            if (content.scrollHeight > content.clientHeight || content.textContent.split('\\n').length > 4) {
              button.style.display = 'block';
            }
          } else {
            const hasHiddenItems = content.querySelectorAll('li.hidden').length > 0;
            const isOverflowing = content.scrollHeight > content.clientHeight;
            const hasManyParagraphs = content.textContent.split('\\n').length > 3;
            if (hasHiddenItems || isOverflowing || hasManyParagraphs) {
              button.style.display = 'block';
            }
          }
        }
        function toggleContent(id) {
          const element = document.getElementById(id);
          const buttonId = id === 'latest-release-info' ? 'latest-release-btn' : 'btn-' + id.replace('release-info-', '');
          const button = document.getElementById(buttonId);

          element.classList.toggle('expanded');
          if (button) button.classList.toggle('expanded');

          if (element.classList.contains('expanded')) {
            const listItems = element.querySelectorAll('li');
            listItems.forEach(item => {
              item.classList.add('visible');
              item.classList.remove('hidden');
            });
          } else {
            const listItems = element.querySelectorAll('li');
            listItems.forEach((item, index) => {
              if (index >= 2) {
                item.classList.add('hidden');
                item.classList.remove('visible');
              }
            });
          }
        }
        function toggleAllReleases() {
          const button = document.getElementById('show-all-btn');
          const rows = document.querySelectorAll('.release-card');
          const hiddenRows = document.querySelectorAll('.release-card:not(.visible)');
          if (hiddenRows.length > 0) {
            rows.forEach(row => row.classList.add('visible'));
            button.textContent = 'Show Less';
          } else {
            rows.forEach((row, index) => {
              if (index >= 2) {
                row.classList.remove('visible');
              }
            });
            button.textContent = 'Show All Releases';
          }
        }
        document.addEventListener('DOMContentLoaded', function() {
          checkContentOverflow('latest-release-info', 'latest-release-btn');
          const commitInfos = document.querySelectorAll('.commit-info');
          commitInfos.forEach(info => {
            const listItems = info.querySelectorAll('li');
            listItems.forEach((item, index) => {
              if (index >= 2) {
                item.classList.add('hidden');
              } else {
                item.classList.add('visible');
              }
            });
            const infoId = info.id;
            const btnId = 'btn-' + infoId.replace('release-info-', '');
            checkContentOverflow(infoId, btnId);
          });
        });
      </script>
    """

  def generate_complete_html(self, releases: List[ReleaseInfo], ee_id: str, ee_addr: str, last_update: str, 
                            using_cached_data: bool = False, error_message: str = "") -> str:
    """
    Generate the complete HTML page from the list of ReleaseInfo objects.
    The first release is the "latest," and everything else is in "previous" section.
    """
    if not releases:
      return "<html><body><h1>No releases available</h1></body></html>"

    return (
        self.generate_html_head() +
        self.generate_jumbo_section(ee_id, ee_addr, last_update, using_cached_data, error_message) +
        self.generate_latest_release_section(releases[0]) +
        self.generate_previous_releases_section(releases) +
        self.generate_javascript() +
        "</body></html>"
    )