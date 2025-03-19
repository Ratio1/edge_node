import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, TypedDict
from dataclasses import dataclass, field
from functools import lru_cache
from enum import Enum

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.4.0'

RELEASES_CACHE_FILE = 'releases_history.pkl'

_CONFIG = {
    **BasePlugin.CONFIG,
    'ASSETS' : 'plugins/business/fastapi/launcher_download',
    'JINJA_ARGS': {
        'html_files': [
            {
                'name'  : 'releases.html',
                'route' : '/',
                'method': 'get'
            }
        ]
    },
    'NR_PREVIOUS_RELEASES': 5,            # We only fetch these many from GitHub
    'REGENERATION_INTERVAL': 10*60,
    "RELEASES_REPO_URL": "https://api.github.com/repos/Ratio1/edge_node_launcher",
    'VALIDATION_RULES': {
        **BasePlugin.CONFIG['VALIDATION_RULES'],
    },
    'DEBUG_MODE': False,  # or True if you want more logs
    'SHOW_ALL_RELEASES_BY_DEFAULT': False,
    'GITHUB_API_TIMEOUT': 30,
    'MAX_RETRIES': 3
}

class NaeuralReleaseAppPlugin(BasePlugin):
  CONFIG = _CONFIG

  def on_init(self, **kwargs):
      super(NaeuralReleaseAppPlugin, self).on_init(**kwargs)
      self._last_day_regenerated = (self.datetime.now() - self.timedelta(days=1)).day
      self.__last_generation_time = 0
      self.html_generator = HtmlGenerator(self.CONFIG, self)
      self.data_processor = ReleaseDataProcessor(self)
      self.release_fetcher = ReleaseDataFetcher(self.CONFIG, self, self.cfg_releases_repo_url, self.cfg_max_retries, self.cfg_github_api_timeout, self.cfg_debug_mode)
      self._cached_releases = self._load_cached_releases()
      return


  def _load_cached_releases(self) -> List[Dict[str, Any]]:
      """Load cached releases from pickle, or return an empty list on failure."""
      try:
          data = self.diskapi_load_pickle_from_data(RELEASES_CACHE_FILE)
          if data:
              self.P(f"_load_cached_releases: Loaded {len(data)} from cache.")
              return data
      except Exception as e:
          self.log_error("_load_cached_releases", f"Failed to load cache: {str(e)}")
      return []

  def _save_cached_releases(self, releases: List[Dict[str, Any]]) -> bool:
      """Save the entire release list back to pickle cache."""
      try:
          self.diskapi_save_pickle_to_data(releases, RELEASES_CACHE_FILE)
          self.P(f"_save_cached_releases: Saved {len(releases)} release(s) to cache.")
          return True
      except Exception as e:
          self.log_error("_save_cached_releases", f"Failed to save cache: {str(e)}")
          return False

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
      Fetch from GitHub only the last `cfg_nr_previous_releases` basic releases.
      For each of those that are not yet cached, fetch full details and add them to the cache.
      Keep old releases in the cache (never remove them).
      Return the *entire* cached release list (including older ones), sorted desc by date.
      """
      func_name = "get_latest_releases"
      try:
          # 1) Load current cache
          cached = self._cached_releases
          cached_tags = {c['tag_name'] for c in cached}

          # 2) Get the *latest N* from GitHub (just basic info)
          n = self.cfg_nr_previous_releases
          top_n_basic = self.release_fetcher.get_top_n_releases(n)
          if not top_n_basic:
              # If GitHub returned nothing, fallback to cache if we have any
              if cached:
                  self.P(f"{func_name}: GitHub returned 0, using cached = {len(cached)}.")
                  # Sort cache by date desc for consistency
                  cached.sort(key=lambda x: x['published_at'], reverse=True)
                  return cached, None
              else:
                  return [], {'message': "No releases found & no cache available", 'rate_limited': False}

          # 3) For each of those top N, if not in cache, fetch details
          new_full = []
          for r in top_n_basic:
              tag = r['tag_name']
              if tag not in cached_tags:
                  # fetch and store
                  try:
                      details = self.release_fetcher.get_release_details(tag)
                      new_full.append({
                          'tag_name': details.tag_name,
                          'published_at': details.published_at,
                          'body': details.body,
                          'assets': details.assets,
                          'commit_sha': details.commit_sha,
                          'commit_info': details.commit_info,
                          'tag_info': details.tag_info
                      })
                      self.P(f"{func_name}: Downloaded new release: {tag}")
                  except GitHubApiError as e:
                      if e.is_rate_limit:
                          raise
                      # else log and skip
                      self.log_error(func_name, f"Failed to fetch release details for {tag}: {str(e)}")

          # 4) Add newly fetched items to the cache, never removing older items
          if new_full:
              extended_cache = cached + new_full
              extended_cache.sort(key=lambda x: x['published_at'], reverse=True)
              self._save_cached_releases(extended_cache)
              return extended_cache, None
          else:
              # No new releases discovered => just return the existing cache sorted
              cached.sort(key=lambda x: x['published_at'], reverse=True)
              return cached, None

      except GitHubApiError as gh_e:
          msg = f"{func_name}: GitHubApiError {gh_e}"
          self.log_error(func_name, msg)
          # fallback to cache if possible
          fallback = self._cached_releases
          if fallback:
              fallback.sort(key=lambda x: x['published_at'], reverse=True)
              self.P(f"{func_name}: returning fallback from cache: {len(fallback)} items.")
              return fallback, None
          return [], {'message': msg, 'rate_limited': gh_e.is_rate_limit, 'error_type': gh_e.error_type.value}

      except Exception as e:
          msg = f"{func_name}: Unexpected error: {str(e)}"
          self.log_error(func_name, msg, e)
          fallback = self._cached_releases
          if fallback:
              fallback.sort(key=lambda x: x['published_at'], reverse=True)
              self.P(f"{func_name}: returning fallback from cache: {len(fallback)} items.")
              return fallback, None
          return [], {'message': msg, 'rate_limited': False}

  def compile_release_info(self, releases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
      """
      Turn the raw release dicts (already fully fetched) into the final shape needed for HTML.
      We do not re-fetch from GitHub here. We simply trust what's in the cache.
      """
      if not releases:
          self.log_error("compile_release_info", "No releases provided.")
          return []

      # Sort descending by published date
      sorted_releases = sorted(releases, key=lambda x: x['published_at'], reverse=True)
      # Optionally, you can slice them *here* if you only want to SHOW the last N, but
      # the user said "all from cache are displayed," so we skip slicing.
      # sorted_releases = sorted_releases[:self.cfg_nr_previous_releases]  # <--- if you wanted
      return sorted_releases

  def _regenerate_index_html(self) -> bool:
    """
    Fetch/compile the full set of releases from cache+GitHub, then
    generate the final releases.html for display.
    Returns True if successful.
    """
    func_name = "_regenerate_index_html"
    self.P(f"{func_name}: Starting HTML regeneration...")

    # Where we will write the HTML
    web_server_path = self.get_web_server_path()
    output_path = self.os_path.join(web_server_path, 'assets/releases.html')

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

    # 2) Compile them (no re-fetch) and transform them into the shape the HTML generator expects
    try:
      compiled_releases = self.compile_release_info(raw_releases)
      if not compiled_releases:
        self.log_error(func_name, "No compiled releases available, skipping HTML generation")
        return False

      # Convert compiled data into our ReleaseInfo objects for HTML
      releases_for_html = self.data_processor.process_releases(compiled_releases)
      self.P(f"{func_name}: Successfully processed {len(releases_for_html)} releases for HTML generation")

    except Exception as e:
      error_msg = f"{func_name}: Error in compile_release_info or data_processor: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

    # 3) Generate and write the HTML
    try:
      html_content = self.html_generator.generate_complete_html(
        releases=releases_for_html,
        ee_id=self.ee_id,
        ee_addr=self.ee_addr,
        last_update=self.datetime_to_str()
      )
      with open(output_path, 'w') as fd:
        fd.write(html_content)

      self.P(f"{func_name}: releases.html generated successfully at {output_path}")
      self.P(f"{func_name}: HTML generation complete with {len(releases_for_html)} releases, size: {len(html_content)} bytes")
      return True

    except Exception as e:
      error_msg = f"{func_name}: Error writing HTML file: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

  def _maybe_regenerate_index_html(self) -> bool:
    """
    Check if enough time has passed since last regeneration. If so, regenerate.
    """
    func_name = "_maybe_regenerate_index_html"
    try:
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
    except Exception as e:
      error_msg = f"{func_name}: Unhandled error: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

  def process(self):
    """Called periodically. Triggers the conditional regeneration of the HTML."""
    try:
      self._maybe_regenerate_index_html()
    except Exception as e:
      self.log_error("process", f"Unhandled error in process(): {str(e)}", e)
    return


class ReleaseAssetType(Enum):
    """Types of release assets we support."""
    LINUX_20_04 = "LINUX_Ubuntu-20.04.AppImage"
    LINUX_22_04 = "LINUX_Ubuntu-22.04.AppImage"
    LINUX_24_04 = "LINUX_Ubuntu-24.04.AppImage"
    WINDOWS_ZIP = "Windows_msi.zip"
    WINDOWS_MSI = "Windows.msi"
    MACOS_ARM = "OSX-arm64.zip"

class AssetInfo(TypedDict):
    """Type definition for asset information."""
    name: str
    size: int
    browser_download_url: str

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

    @property
    def formatted_date(self) -> str:
        """Return formatted publication date."""
        dt = datetime.strptime(self.published_at, '%Y-%m-%dT%H:%M:%SZ')
        return dt.strftime('%B %d, %Y')

    @property
    def has_valid_body(self) -> bool:
        """Check if the release has a valid body."""
        return bool(self.body and self.body.strip())

    def get_asset_by_type(self, asset_type: ReleaseAssetType) -> Optional[AssetInfo]:
        """Get asset information by type."""
        return next(
            (a for a in self.assets if asset_type.value in a['name']),
            None
        )


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

  def __init__(self, config: Dict[str, Any], logger: Any, releases_repo_url: str, max_retries: int, github_api_timeout: int, debug_mode: bool):
    self.config = config
    self.logger = logger
    self.requests = logger.requests
    self._cache_timeout = timedelta(minutes=10)
    self._last_cache_clear = datetime.now()
    self._releases_repo_url = releases_repo_url
    self._max_retries = max_retries
    self._debug_mode = debug_mode
    self._github_api_timeout = github_api_timeout

  def _log(self, msg: str):
    if self._debug_mode:
      self.logger.P(f"[ReleaseDataFetcher] {msg}")

  def _check_and_clear_cache(self):
    now = datetime.now()
    if now - self._last_cache_clear > self._cache_timeout:
      self.get_release_details.cache_clear()
      self.get_commit_message.cache_clear()
      self._last_cache_clear = now
      self._log("Cleared internal lru_cache")

  def _make_request(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
    retries = 0
    last_exc = None
    while retries < self._max_retries:
      try:
        self._log(f"GET {url} with {params}")
        resp = self.requests.get(url, params=params, timeout=self._github_api_timeout)
        if resp.status_code == 200:
          self.logger.P(f"[ReleaseDataFetcher] API request successful: {url} (status: 200)")
          return resp.json()
        else:
          self.logger.P(f"[ReleaseDataFetcher] API request failed: {url} (status: {resp.status_code})")
          raise GitHubApiError.from_response(resp)
      except GitHubApiError as ghe:
        if ghe.is_rate_limit or retries >= (self._max_retries - 1):
          raise
        last_exc = ghe
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
    self._check_and_clear_cache()
    url = f"{self._releases_repo_url}/releases"
    # param per_page=n will limit to the top n (most recent) releases
    return self._make_request(url, params={"per_page": n}) or []

  @lru_cache(maxsize=50)
  def get_release_details(self, tag_name: str) -> 'GitHubReleaseData':
    self._check_and_clear_cache()
    # 1) fetch the release by its tag
    rurl = f"{self._releases_repo_url}/releases/tags/{tag_name}"
    release_data = self._make_request(rurl)

    # 2) fetch tag info to get commit sha
    turl = f"{self._releases_repo_url}/git/refs/tags/{tag_name}"
    try:
      tag_data = self._make_request(turl)
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
    if not body_text.strip() and commit_sha:
      # fallback to commit message
      msg = self.get_commit_message(commit_sha)
      if msg:
        body_text = msg

    return GitHubReleaseData(
      tag_name=release_data['tag_name'],
      published_at=release_data['published_at'],
      body=body_text,
      assets=release_data.get('assets', []),
      commit_sha=commit_sha,
      commit_info=commit_info,
      tag_info=tag_data,
    )

  @lru_cache(maxsize=100)
  def _get_commit_info(self, commit_sha: str) -> Optional[Dict[str, Any]]:
    curl = f"{self._releases_repo_url}/commits/{commit_sha}"
    return self._make_request(curl)

  @lru_cache(maxsize=100)
  def get_commit_message(self, commit_sha: str) -> Optional[str]:
    ci = self._get_commit_info(commit_sha)
    if ci and 'commit' in ci and 'message' in ci['commit']:
      return ci['commit']['message']
    return None

class ReleaseAsset:
  """Data class for release assets."""
  def __init__(self, name: str, size: int, browser_download_url: str):
    self.name = name
    self.size = size
    self.browser_download_url = browser_download_url

  @property
  def size_mb(self) -> float:
    """Return size in megabytes."""
    return self.size / (1024 * 1024)


class ReleaseInfo:
  """Data class for release information suitable for HTML rendering."""
  def __init__(self, tag_name: str, published_at: str, body: str, assets: List[ReleaseAsset]):
    self.tag_name = tag_name
    self.published_at = published_at
    self.body = body
    self.assets = assets

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

  def generate_jumbo_section(self, ee_id: str, ee_addr: str, last_update: str) -> str:
    """Generate the jumbo header section."""
    return f"""
        <body>
            <div class="jumbo">
                <h1>Edge Node Launcher Releases</h1>
                <p>Download the latest version of Edge Node Launcher to stay up-to-date with new features.</p>
                <p>This page was generated by Edge Node <code>{ee_id}:{ee_addr}</code> at {last_update}.</p>
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
    """
    Generate the download section HTML for a release.
    (Same as your previous logic, except no changes required here.)
    """
    download_items = []
    # Helper to match by name
    def find_asset(pattern: str) -> Optional[ReleaseAsset]:
      return next((a for a in assets if self.plugin.re.search(pattern, a.name)), None)

    # Linux assets
    linux_20_04 = find_asset(r'LINUX_Ubuntu-20\.04\.AppImage')
    linux_22_04 = find_asset(r'LINUX_Ubuntu-22\.04\.AppImage')
    linux_24_04 = find_asset(r'LINUX_Ubuntu-24\.04\.AppImage')

    # Windows assets
    win_zip = find_asset(r'Windows_msi\.zip')
    win_msi = find_asset(r'Windows\.msi$')

    # macOS assets
    macos_arm = find_asset(r'OSX-arm64\.zip')

    if is_latest:
      if linux_20_04:
        download_items.append(self._generate_download_item(linux_20_04, "linux", "Linux Ubuntu 20.04", "🐧"))
      if linux_22_04:
        download_items.append(self._generate_download_item(linux_22_04, "linux", "Linux Ubuntu 22.04", "🐧"))
      if linux_24_04:
        download_items.append(self._generate_download_item(linux_24_04, "linux", "Linux Ubuntu 24.04", "🐧"))
      if macos_arm:
        download_items.append(self._generate_download_item(macos_arm, "macos", "macOS (Apple Silicon)", "🍎"))
      if win_zip:
        download_items.append(self._generate_download_item(win_zip, "windows", "Windows (ZIP)", "🪟"))
      if win_msi:
        download_items.append(self._generate_download_item(win_msi, "windows", "Windows (MSI)", "🪟"))

      return f"""
        <div class="download-options">
          <h3>Download Options:</h3>
          <div class="download-grid">
            {''.join(download_items)}
          </div>
        </div>
      """
    else:
      # group for previous releases
      sections = {
        "Linux": [
          (linux_20_04, "Ubuntu 20.04"),
          (linux_22_04, "Ubuntu 22.04"),
          (linux_24_04, "Ubuntu 24.04"),
        ],
        "Windows": [
          (win_zip, "Windows ZIP"),
          (win_msi, "Windows MSI"),
        ],
        "macOS": [
          (macos_arm, "Apple Silicon"),
        ],
      }
      for os_name, asset_pairs in sections.items():
        items = []
        for asset_obj, variant in asset_pairs:
          if asset_obj:
            items.append(f"""
              <div class="download-item-small {os_name.lower()}">
                <span class="os-name">{variant}</span>
                <span class="file-size">{asset_obj.size_mb:.2f} MB</span>
                <a href="{asset_obj.browser_download_url}" class="download-btn-small">Download</a>
              </div>
            """)
        if items:
          download_items.append(f"""
            <div class="download-section">
              <h4>{os_name}</h4>
              <div class="download-list">
                {''.join(items)}
              </div>
            </div>
          """)

      return f"""
        <div class="release-downloads">
          {''.join(download_items)}
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

    show_all_button_text = "Show Less" if self.config.get('SHOW_ALL_RELEASES_BY_DEFAULT', False) else "Show All Releases"

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

  def generate_complete_html(self, releases: List[ReleaseInfo], ee_id: str, ee_addr: str, last_update: str) -> str:
    """
    Generate the complete HTML page from the list of ReleaseInfo objects.
    The first release is the "latest," and everything else is in "previous" section.
    """
    if not releases:
      return "<html><body><h1>No releases available</h1></body></html>"

    return (
      self.generate_html_head() +
      self.generate_jumbo_section(ee_id, ee_addr, last_update) +
      self.generate_latest_release_section(releases[0]) +
      self.generate_previous_releases_section(releases) +
      self.generate_javascript() +
      "</body></html>"
    )


class ReleaseDataProcessor:
  def __init__(self, logger):
    self.logger = logger

  def convert_to_release_info(self, release_data: Dict[str, Any]) -> 'ReleaseInfo':
    # same as before
    assets = []
    for a in release_data.get('assets', []):
      assets.append(ReleaseAsset(a['name'], a['size'], a['browser_download_url']))
    return ReleaseInfo(
      tag_name=release_data['tag_name'],
      published_at=release_data['published_at'],
      body=release_data.get('body', '') or '',
      assets=assets
    )

  def process_releases(self, raw_releases: List[Dict[str, Any]]) -> List['ReleaseInfo']:
    """Turn the fully-fetched release dicts into a list of ReleaseInfo."""
    releases = []
    for r in raw_releases:
      ri = self.convert_to_release_info(r)
      releases.append(ri)
    return releases
