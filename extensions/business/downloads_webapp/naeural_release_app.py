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
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, NamedTuple, TypedDict, Literal
from dataclasses import dataclass, field
from functools import lru_cache
from enum import Enum

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.3.5'

_CONFIG = {
  **BasePlugin.CONFIG,

  'ASSETS' : 'plugins/business/fastapi/launcher_download',
  'JINJA_ARGS': {
    'html_files' : [
      {
        'name'  : 'releases.html',
        'route' : '/',
        'method' : 'get'
      }
    ]
  },
  'NR_PREVIOUS_RELEASES': 5,
  'REGENERATION_INTERVAL': 10*60,
  "RELEASES_REPO_URL": "https://api.github.com/repos/Ratio1/edge_node_launcher",
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
  'DEBUG_MODE': False,  # Enable detailed error reporting
  'SHOW_ALL_RELEASES_BY_DEFAULT': False,
  'GITHUB_API_TIMEOUT': 30,  # Timeout for GitHub API requests in seconds
  'MAX_RETRIES': 3,  # Maximum number of retries for failed API requests
}


class NaeuralReleaseAppPlugin(BasePlugin):
  """
  A plugin to fetch and display release information for Edge Node Launcher.

  Attributes
  ----------
  CONFIG : dict
    The configuration dictionary for this plugin.

  Methods
  -------
  on_init(**kwargs)
    Initializes the plugin and sets up state.
  get_latest_releases()
    Fetches and processes the latest releases from GitHub.
  compile_release_info(releases)
    Processes releases into the format expected by the UI.
  _regenerate_index_html()
    Regenerates the releases.html file with updated release info.
  _maybe_regenerate_index_html()
    Conditionally regenerates the HTML if enough time has passed.
  process()
    Periodically checks whether to regenerate the HTML.
  """

  CONFIG = _CONFIG

  def on_init(self, **kwargs):
    """Initialize the plugin with improved state management."""
    super(NaeuralReleaseAppPlugin, self).on_init(**kwargs)
    self._last_day_regenerated = (self.datetime.now() - self.timedelta(days=1)).day
    self.__last_generation_time = 0
    self.html_generator = HtmlGenerator(self.CONFIG, self)
    self.data_processor = ReleaseDataProcessor(self)
    self.release_fetcher = ReleaseDataFetcher(self.CONFIG, self)
    return

  def log_error(self, func_name: str, error_msg: str, exc_info: Optional[Exception] = None) -> str:
    """Log an error with improved formatting and context."""
    error_details = [f"ERROR in {func_name}:"]
    error_details.append(error_msg)

    if exc_info and self.cfg_debug_mode:
      tb_str = ''.join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))
      error_details.append("Traceback:")
      error_details.append(tb_str)

    error_message = "\n".join(error_details)
    self.P(error_message)
    return error_message

  def get_latest_releases(self) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Fetch and process release information with improved error handling."""
    func_name = "get_latest_releases"
    try:
      all_releases = self.release_fetcher.get_all_releases()
      if not all_releases:
        return [], {'message': "No releases found", 'rate_limited': False}

      processed_releases = self.compile_release_info(all_releases)
      return processed_releases, None

    except GitHubApiError as e:
      error_msg = f"Failed to fetch releases: {str(e)}"
      self.log_error(func_name, error_msg)
      return [], {
        'message': error_msg,
        'rate_limited': e.is_rate_limit,
        'error_type': e.error_type.value
      }

    except Exception as e:
      error_msg = f"Unexpected error while fetching releases: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return [], {'message': error_msg, 'rate_limited': False}

  def compile_release_info(self, releases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process releases with improved error recovery and validation."""
    func_name = "compile_release_info"
    if not releases:
      self.log_error(func_name, "No releases provided")
      return []

    try:
      # Sort and filter releases
      releases.sort(key=lambda x: x['published_at'], reverse=True)
      releases = releases[:self.cfg_nr_previous_releases]

      processed_releases = []
      for release in releases:
        try:
          # Get release details
          release_data = self.release_fetcher.get_release_details(release['tag_name'])

          # Try to get commit message if needed
          if not release_data.has_valid_body and release_data.commit_sha:
            commit_message = self.release_fetcher.get_commit_message(release_data.commit_sha)
            if commit_message:
              # Create new instance with updated body due to frozen=True
              release_data = GitHubReleaseData(
                tag_name=release_data.tag_name,
                published_at=release_data.published_at,
                body=commit_message,
                assets=release_data.assets,
                commit_sha=release_data.commit_sha,
                commit_info=release_data.commit_info,
                tag_info=release_data.tag_info
              )

          # Convert to UI format
          processed_release = {
            'tag_name': release_data.tag_name,
            'published_at': release_data.published_at,
            'body': release_data.body,
            'assets': release_data.assets,
            'commit_info': release_data.commit_info
          }

          processed_releases.append(processed_release)
          self.P(f"{func_name}: Processed release {release_data.tag_name}")

        except GitHubApiError as e:
          self.log_error(
            func_name,
            f"Failed to process release {release.get('tag_name', 'unknown')}: {str(e)}"
          )
          if e.is_rate_limit:
            return processed_releases
          continue

      return processed_releases

    except Exception as e:
      error_msg = f"Failed to compile release info: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return processed_releases[:1] if processed_releases else []

  def _regenerate_index_html(self):
    """
    Regenerate the index.html file listing the latest releases and metadata.
    """
    func_name = "_regenerate_index_html"
    self.P(f"{func_name}: Starting HTML regeneration...")

    # Check if HTML file already exists
    web_server_path = self.get_web_server_path()
    output_path = self.os_path.join(web_server_path, 'assets/releases.html')
    file_exists = self.os_path.isfile(output_path)

    # Step 1: Fetch releases
    try:
      raw_releases, release_error = self.get_latest_releases()
      if not raw_releases:
        # Use the error information returned from get_latest_releases
        if release_error:
          error_message = release_error.get('message', "Failed to get any releases")
        else:
          error_message = "Failed to get any releases"

        self.log_error(func_name, error_message)
        return False
    except Exception as e:
      error_message = f"Failed during release fetching: {str(e)}"
      self.log_error(func_name, error_message, e)
      return False

    # Step 2: Compile release information
    try:
      raw_releases_with_commits = self.compile_release_info(raw_releases)
      if not raw_releases_with_commits:
        error_message = "Failed to compile any release information"
        self.log_error(func_name, error_message)
        return False

      # Convert raw releases to ReleaseInfo objects
      releases = self.data_processor.process_releases(raw_releases_with_commits, [])

    except Exception as e:
      error_msg = f"Failed during release compilation: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

    # Step 3: Generate HTML
    try:
      html_content = self.html_generator.generate_complete_html(
        releases=releases,
        ee_id=self.ee_id,
        ee_addr=self.ee_addr,
        last_update=self.datetime_to_str()
      )

      with open(output_path, 'w') as fd:
        fd.write(html_content)

      self.P(f"{func_name}: releases.html has been generated successfully.")
      return True
    except Exception as e:
      error_msg = f"Failed to generate or write HTML: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

  def _maybe_regenerate_index_html(self):
    """
    Regenerate the html files if the last regeneration was more than
    cfg_regeneration_interval seconds ago.
    If regeneration fails and an HTML file already exists, keep the existing file
    instead of replacing it with a fallback page.
    """
    func_name = "_maybe_regenerate_index_html"
    try:
      current_time = self.time()

      # Only regenerate if enough time has passed since last generation
      if (current_time - self.__last_generation_time) > self.cfg_regeneration_interval:
        self.P(f"{func_name}: Regeneration interval elapsed, regenerating releases.html...")

        # Attempt to regenerate the HTML
        result = self._regenerate_index_html()
        current_day = self.datetime.now().day

        if result:
          # Successful regeneration
          self._last_day_regenerated = current_day
          self.__last_generation_time = current_time
          self.P(f"{func_name}: HTML regeneration successful")
        else:
          # Failed regeneration - _regenerate_index_html already handles the file_exists check
          self.P(f"{func_name}: HTML regeneration failed, but _regenerate_index_html handled fallback")

          # Update the generation time anyway to avoid constant retries when failing
          self.__last_generation_time = current_time
      return True
    except Exception as e:
      error_msg = f"Failed to check regeneration condition: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False

  def process(self):
    """
    Called periodically. Triggers the conditional regeneration of the HTML.
    """
    try:
      self._maybe_regenerate_index_html()
    except Exception as e:
      self.log_error("process", f"Unhandled error in process method: {str(e)}", e)
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
    """Data class for GitHub release information with validation and helper methods."""
    tag_name: str
    published_at: str
    body: str
    assets: List[AssetInfo] = field(default_factory=list)
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
    """Types of GitHub API errors."""
    RATE_LIMIT = "rate_limit"
    NOT_FOUND = "not_found"
    NETWORK = "network"
    UNKNOWN = "unknown"

class GitHubApiError(Exception):
    """Exception raised for GitHub API errors with improved error categorization."""
    def __init__(
        self,
        message: str,
        error_type: GitHubApiErrorType,
        status_code: Optional[int] = None,
        response_text: Optional[str] = None
    ):
        self.error_type = error_type
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(message)

    @property
    def is_rate_limit(self) -> bool:
        """Check if this is a rate limit error."""
        return self.error_type == GitHubApiErrorType.RATE_LIMIT

    @classmethod
    def from_response(cls, response: Any, message: Optional[str] = None) -> 'GitHubApiError':
        """Create an error instance from a response object."""
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            error_type = GitHubApiErrorType.RATE_LIMIT
        elif response.status_code == 404:
            error_type = GitHubApiErrorType.NOT_FOUND
        else:
            error_type = GitHubApiErrorType.UNKNOWN
            
        return cls(
            message or f"GitHub API error: {response.text}",
            error_type=error_type,
            status_code=response.status_code,
            response_text=response.text
        )

class ReleaseDataFetcher:
    """Class responsible for fetching release data from GitHub with improved caching."""
    
    def __init__(self, config: Dict[str, Any], logger: Any):
        self.config = config
        self.logger = logger
        self.requests = logger.requests
        self._cache_timeout = timedelta(minutes=10)
        self._last_cache_clear = datetime.now()
        
    def _log(self, message: str, level: Literal["info", "error", "debug"] = "info") -> None:
        """Enhanced logging with levels."""
        prefix = "ReleaseDataFetcher"
        if level == "error":
            self.logger.P(f"{prefix} ERROR: {message}")
        elif level == "debug" and self.config.get('DEBUG_MODE'):
            self.logger.P(f"{prefix} DEBUG: {message}")
        else:
            self.logger.P(f"{prefix}: {message}")
            
    def _check_and_clear_cache(self) -> None:
        """Clear caches if they're too old."""
        now = datetime.now()
        if now - self._last_cache_clear > self._cache_timeout:
            self.get_commit_message.cache_clear()
            self.get_release_details.cache_clear()
            self._last_cache_clear = now
            self._log("Cache cleared", level="debug")
            
    def _make_request(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Make a request to GitHub API with improved error handling."""
        retries = 0
        last_error = None
        
        while retries < self.config['MAX_RETRIES']:
            try:
                self._log(f"Request to: {url}", level="debug")
                response = self.requests.get(
                    url,
                    params=params,
                    timeout=self.config['GITHUB_API_TIMEOUT']
                )
                
                if response.status_code == 200:
                    return response.json()
                    
                raise GitHubApiError.from_response(response)
                
            except GitHubApiError as e:
                if e.is_rate_limit or retries >= self.config['MAX_RETRIES'] - 1:
                    raise
                last_error = e
                
            except Exception as e:
                if retries >= self.config['MAX_RETRIES'] - 1:
                    raise GitHubApiError(
                        f"Network error: {str(e)}",
                        error_type=GitHubApiErrorType.NETWORK
                    )
                last_error = e
                
            retries += 1
            self._log(
                f"Request failed ({retries}/{self.config['MAX_RETRIES']}): {str(last_error)}",
                level="error"
            )
            
    def get_all_releases(self) -> List[Dict[str, Any]]:
        """Fetch all releases from GitHub."""
        self._check_and_clear_cache()
        url = f"{self.config['RELEASES_REPO_URL']}/releases"
        return self._make_request(url, params={"per_page": 100})
        
    @lru_cache(maxsize=50)
    def get_release_details(self, release_id: str) -> GitHubReleaseData:
        """Fetch detailed information for a specific release with caching."""
        # Fetch release information
        release_url = f"{self.config['RELEASES_REPO_URL']}/releases/tags/{release_id}"
        release_data = self._make_request(release_url)
        
        # Fetch tag information
        tag_url = f"{self.config['RELEASES_REPO_URL']}/git/refs/tags/{release_id}"
        try:
            tag_data = self._make_request(tag_url)
        except GitHubApiError as e:
            self._log(f"Failed to fetch tag data: {str(e)}", level="error")
            tag_data = None
            
        # Get commit SHA and info
        commit_sha = None
        commit_info = None
        
        if tag_data:
            try:
                if tag_data['object']['type'] == 'tag':
                    tag_object = self._make_request(tag_data['object']['url'])
                    commit_sha = tag_object['object']['sha']
                else:
                    commit_sha = tag_data['object']['sha']
                    
                if commit_sha:
                    commit_info = self._get_commit_info(commit_sha)
            except GitHubApiError as e:
                self._log(f"Failed to fetch commit data: {str(e)}", level="error")
                
        return GitHubReleaseData(
            tag_name=release_data['tag_name'],
            published_at=release_data['published_at'],
            body=release_data.get('body', ''),
            assets=release_data.get('assets', []),
            commit_sha=commit_sha,
            commit_info=commit_info,
            tag_info=tag_data
        )
        
    @lru_cache(maxsize=100)
    def _get_commit_info(self, commit_sha: str) -> Optional[Dict[str, Any]]:
        """Internal method to fetch commit information with caching."""
        try:
            commit_url = f"{self.config['RELEASES_REPO_URL']}/commits/{commit_sha}"
            return self._make_request(commit_url)
        except GitHubApiError as e:
            self._log(f"Failed to fetch commit info: {str(e)}", level="error")
            return None
            
    @lru_cache(maxsize=100)
    def get_commit_message(self, commit_sha: str) -> Optional[str]:
        """Fetch commit message with caching."""
        commit_info = self._get_commit_info(commit_sha)
        return commit_info['commit']['message'] if commit_info else None


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
  """Data class for release information."""

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
    """
    Initialize the HTML generator.

    Parameters
    ----------
    config : Dict[str, Any]
        Configuration dictionary
    plugin : NaeuralReleaseAppPlugin
        Plugin instance that implements P() method for logging and provides re module
    """
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
                <p>Download the latest version of Edge Node Launcher to stay up-to-date with new features and improvements.</p>
                <p>This page was proudly generated by Edge Node <code>{ee_id}:{ee_addr}</code> at {last_update}.</p>
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
    """Format release information for display."""
    if not release.body or not release.body.strip():
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

    Parameters
    ----------
    assets : List[ReleaseAsset]
        List of release assets
    is_latest : bool
        Whether this is for the latest release section

    Returns
    -------
    str
        HTML for the download section
    """
    download_items = []

    # Helper function to find assets by pattern
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

    # Generate download items based on whether it's latest or previous release
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
    else:
      # For previous releases, organize by OS type
      sections = {
        "Linux": [(linux_20_04, "Ubuntu 20.04"), (linux_22_04, "Ubuntu 22.04"), (linux_24_04, "Ubuntu 24.04")],
        "Windows": [(win_zip, "ZIP"), (win_msi, "MSI")],
        "macOS": [(macos_arm, "Apple Silicon")]
      }

      for os_name, assets in sections.items():
        items = []
        for asset, variant in assets:
          if asset:
            items.append(f"""
                            <div class="download-item-small {os_name.lower()}">
                                <span class="os-name">{variant}</span>
                                <span class="file-size">{asset.size_mb:.2f} MB</span>
                                <a href="{asset.browser_download_url}" class="download-btn-small">Download</a>
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

    if is_latest:
      return f"""
                <div class="download-options">
                    <h3>Download Options:</h3>
                    <div class="download-grid">
                        {''.join(download_items)}
                    </div>
                </div>
            """
    else:
      return f"""
                <div class="release-downloads">
                    {''.join(download_items)}
                </div>
            """

  def generate_latest_release_section(self, release: ReleaseInfo) -> str:
    """
    Generate the latest release section HTML.

    Parameters
    ----------
    release : ReleaseInfo
        The latest release information

    Returns
    -------
    str
        HTML for the latest release section
    """
    release_info = self._format_release_info(release)
    download_section = self._generate_download_section(release.assets, is_latest=True)

    return f"""
            <div class="latest-release" id="latest-release">
                <div class="release-header">
                    <h2>Latest Release: {release.tag_name.replace("'", "")}</h2>
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
    Generate the previous releases section HTML.

    Parameters
    ----------
    releases : List[ReleaseInfo]
        List of previous releases

    Returns
    -------
    str
        HTML for the previous releases section
    """
    release_cards = []
    for i, release in enumerate(releases[1:]):  # Skip the latest release
      visible_class = "visible" if (i < 2 or self.config.get('SHOW_ALL_RELEASES_BY_DEFAULT', False)) else ""
      release_info = self._format_release_info(release)
      download_section = self._generate_download_section(release.assets, is_latest=False)

      release_cards.append(f"""
                <div class="release-card {visible_class}" id="release-row-{i}">
                    <div class="release-card-header">
                        <h3>{release.tag_name.replace("'", "")}</h3>
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
                <button id="show-all-btn" class="show-all-btn" onclick="toggleAllReleases()">{show_all_button_text}</button>
            </div>
        """

  def generate_javascript(self) -> str:
    """Generate the JavaScript code for the page."""
    return """
            <script>
                // Check if content needs expansion and show button only if needed
                function checkContentOverflow(contentId, buttonId) {
                    const content = document.getElementById(contentId);
                    const button = document.getElementById(buttonId);

                    if (!content || !button) return;

                    // For pre elements (latest release)
                    if (content.tagName === 'PRE') {
                        // Only show button if content is taller than default height or has multiple paragraphs
                        if (content.scrollHeight > content.clientHeight || content.textContent.split('\\n').length > 4) {
                            button.style.display = 'block';
                        }
                    }
                    // For div elements with commit info (previous releases)
                    else {
                        // Check if there are hidden list items or if content is overflowing
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

                    // Show all list items when expanded
                    if (element.classList.contains('expanded')) {
                        const listItems = element.querySelectorAll('li');
                        listItems.forEach(item => {
                            item.classList.add('visible');
                            item.classList.remove('hidden');
                        });
                    } else {
                        // Hide items beyond the first 2 when collapsed
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

                // Initialize on page load
                document.addEventListener('DOMContentLoaded', function() {
                    // Initialize latest release
                    checkContentOverflow('latest-release-info', 'latest-release-btn');

                    // Initialize previous releases
                    const commitInfos = document.querySelectorAll('.commit-info');
                    commitInfos.forEach(info => {
                        // Process list items
                        const listItems = info.querySelectorAll('li');
                        listItems.forEach((item, index) => {
                            if (index >= 2) {
                                item.classList.add('hidden');
                            } else {
                                item.classList.add('visible');
                            }
                        });

                        // Check if button should be shown
                        const infoId = info.id;
                        const btnId = 'btn-' + infoId.replace('release-info-', '');
                        checkContentOverflow(infoId, btnId);
                    });
                });
            </script>
        """

  def generate_complete_html(self, releases: List[ReleaseInfo], ee_id: str, ee_addr: str, last_update: str) -> str:
    """
    Generate the complete HTML page.

    Parameters
    ----------
    releases : List[ReleaseInfo]
        List of all releases
    ee_id : str
        Edge Node ID
    ee_addr : str
        Edge Node address
    last_update : str
        Last update timestamp

    Returns
    -------
    str
        Complete HTML page
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
  """Class responsible for processing and converting release data."""

  def __init__(self, logger):
    """
    Initialize the processor.

    Parameters
    ----------
    logger : Any
        Logger object that implements P() method
    """
    self.logger = logger

  def convert_to_release_info(self, release_data: dict, commit_info: Optional[dict] = None) -> ReleaseInfo:
    """
    Convert raw release data to a ReleaseInfo object.

    Parameters
    ----------
    release_data : dict
        Raw release data from GitHub API
    commit_info : Optional[dict]
        Optional commit information

    Returns
    -------
    ReleaseInfo
        Structured release information
    """
    assets = []
    for asset_data in release_data.get('assets', []):
      assets.append(ReleaseAsset(
        name=asset_data['name'],
        size=asset_data['size'],
        browser_download_url=asset_data['browser_download_url']
      ))

    # Get release body, falling back to commit message if needed
    body = release_data.get('body', '').strip()
    if not body and commit_info and commit_info.get('commit'):
      body = commit_info['commit'].get('message', '')

    return ReleaseInfo(
      tag_name=release_data['tag_name'],
      published_at=release_data['published_at'],
      body=body,
      assets=assets
    )

  def process_releases(self, raw_releases: List[dict], raw_tags: List[dict]) -> List[ReleaseInfo]:
    """
    Process raw releases and tags into ReleaseInfo objects.

    Parameters
    ----------
    raw_releases : List[dict]
        List of raw release data from GitHub API
    raw_tags : List[dict]
        List of raw tag data from GitHub API

    Returns
    -------
    List[ReleaseInfo]
        List of processed release information
    """
    releases = []
    for release in raw_releases:
      # Find matching tag
      tag = next((t for t in raw_tags if t['name'] == release['tag_name']), None)
      commit_info = None
      if tag:
        commit_info = release.get('commit_info')

      releases.append(self.convert_to_release_info(release, commit_info))
    return releases
