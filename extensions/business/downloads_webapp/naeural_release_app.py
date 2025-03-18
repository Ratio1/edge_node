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
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

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
  'NR_PREVIOUS_RELEASES': 10,
  'REGENERATION_INTERVAL': 10*60,
  "RELEASES_REPO_URL": "https://api.github.com/repos/Ratio1/edge_node_launcher",
  "GITHUB_REPO_URL": "https://github.com/Ratio1/edge_node_launcher/releases",
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
  'DEBUG_MODE': False,  # Enable detailed error reporting
  'SHOW_ALL_RELEASES_BY_DEFAULT': False,
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
    Fetches the latest releases from the GitHub repository.
  get_latest_tags()
    Fetches the latest tags from the GitHub repository.
  get_commit_info(commit_sha)
    Fetches commit information for a given commit SHA.
  get_release_by_tag(tag_name)
    Fetches information for a specific release by its tag name.
  compile_release_info(releases, tags)
    Associates commit information with each release record.
  check_for_rate_limit(response, raise_exception=True)
    Checks API responses for GitHub rate limit warnings.
  _generate_fallback_html(error_message)
    Generates a fallback HTML page when GitHub API issues occur.
  _generate_fallback_html_and_save(error_message)
    Generates and saves a fallback HTML page.
  _regenerate_index_html()
    Regenerates the releases.html file with updated release info.
  _maybe_regenerate_index_html()
    Conditionally regenerates the HTML if enough time has passed.
  process()
    Periodically checks whether to regenerate the HTML.
  """

  CONFIG = _CONFIG

  def on_init(self, **kwargs):
    """
    Initialize the plugin, setting last regeneration times and creating helpers.
    """
    super(NaeuralReleaseAppPlugin, self).on_init(**kwargs)
    self._last_day_regenerated = (self.datetime.now() - self.timedelta(days=1)).day
    self.__last_generation_time = 0
    self.html_generator = HtmlGenerator(self.CONFIG, self)
    self.data_processor = ReleaseDataProcessor(self)
    return

  def log_error(self, func_name, error_msg, exc_info=None):
    """
    Log an error with contextual information and optional traceback.
    
    Parameters
    ----------
    func_name : str
      The name of the function where the error occurred.
    error_msg : str
      The error message to log.
    exc_info : Exception, optional
      The exception object if available.
    """
    error_details = f"ERROR in {func_name}: {error_msg}"
    if exc_info and self.cfg_debug_mode:
      tb_str = ''.join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))
      error_details += f"\nTraceback:\n{tb_str}"
    self.P(error_details)
    return error_details

  def get_latest_releases(self):
    """
    Fetch the latest releases from GitHub, up to NR_PREVIOUS_RELEASES + 1.

    Returns
    -------
    tuple
      A tuple containing (releases_list, error_data) where:
      - releases_list is a list of JSON objects corresponding to recent GitHub releases
      - error_data is a dict with 'message' and 'rate_limited' keys or None if no error
    """
    func_name = "get_latest_releases"
    try:
      releases_url = f"{self.cfg_releases_repo_url}/releases"
      self.P(f"{func_name}: Requesting releases from: {releases_url}")
      
      # Use a higher per_page value to ensure we get all the releases we need
      response = self.requests.get(releases_url,
                                   params={"per_page": 100})
      
      if response.status_code != 200:
        error_msg = f"Failed to fetch releases. Status code: {response.status_code}, Response: {response.text}"
        self.log_error(func_name, error_msg)
        # Return error data with information about rate limiting
        is_rate_limited = response.status_code == 403 and 'rate limit' in response.text.lower()
        return [], {'message': error_msg, 'rate_limited': is_rate_limited, 'response': response}
        
      releases = response.json()
      self.check_for_rate_limit(releases)
      self.P(f"{func_name}: Successfully fetched {len(releases)} releases")
      
      # Debug: Print full release data for inspection
      for i, release in enumerate(releases):
        self.P(f"{func_name}: Release {i} - Tag: {release.get('tag_name', 'Unknown')}")
        self.P(f"{func_name}: Release {i} - Has body: {bool(release.get('body'))}")
        if release.get('body'):
          self.P(f"{func_name}: Release {i} - Body preview: {release.get('body')[:100]}...")
        self.P(f"{func_name}: Release {i} - Keys: {sorted(release.keys())}")
      
      return releases, None
    except Exception as e:
      error_msg = f"Failed to fetch releases: {str(e)}"
      self.log_error(func_name, error_msg, e)
      # Check if the exception indicates rate limiting
      if "rate limit" in str(e).lower():
        error_msg = f"GitHub API rate limit exceeded during release fetching: {str(e)}"
        return [], {'message': error_msg, 'rate_limited': True}
      return [], {'message': error_msg, 'rate_limited': False}

  def get_latest_tags(self):
    """
    Fetch the latest tags from GitHub, up to NR_PREVIOUS_RELEASES + 1.

    Returns
    -------
    tuple
      A tuple containing (tags_list, error_data) where:
      - tags_list is a list of JSON objects corresponding to recent GitHub tags
      - error_data is a dict with 'message' and 'rate_limited' keys or None if no error
    """
    func_name = "get_latest_tags"
    try:
      tags_url = f"{self.cfg_releases_repo_url}/tags"
      self.P(f"{func_name}: Requesting tags from: {tags_url}")
      response = self.requests.get(tags_url,
                                   params={"per_page": self.cfg_nr_previous_releases + 1})
      
      if response.status_code != 200:
        error_msg = f"Failed to fetch tags. Status code: {response.status_code}, Response: {response.text}"
        self.log_error(func_name, error_msg)
        # Return error data with information about rate limiting
        is_rate_limited = response.status_code == 403 and 'rate limit' in response.text.lower()
        return [], {'message': error_msg, 'rate_limited': is_rate_limited, 'response': response}
        
      tags = response.json()
      self.check_for_rate_limit(tags)
      self.P(f"{func_name}: Successfully fetched {len(tags)} tags")
      return tags, None
    except Exception as e:
      error_msg = f"Failed to fetch tags: {str(e)}"
      self.log_error(func_name, error_msg, e)
      # Check if the exception indicates rate limiting
      if "rate limit" in str(e).lower():
        error_msg = f"GitHub API rate limit exceeded during tag fetching: {str(e)}"
        return [], {'message': error_msg, 'rate_limited': True}
      return [], {'message': error_msg, 'rate_limited': False}

  def get_commit_info(self, commit_sha):
    """
    Fetch commit information for a given commit SHA from GitHub.

    Parameters
    ----------
    commit_sha : str
      The commit SHA for which to fetch information.

    Returns
    -------
    dict
      JSON object with information about the specified commit.
    """
    func_name = f"get_commit_info({commit_sha})"
    try:
      commit_url = f"{self.cfg_releases_repo_url}/commits/{commit_sha}"
      self.P(f"{func_name}: Requesting commit info from: {commit_url}")
      response = self.requests.get(commit_url)
      
      if response.status_code != 200:
        error_msg = f"Failed to fetch commit info. Status code: {response.status_code}, Response: {response.text}"
        self.log_error(func_name, error_msg)
        return None
        
      commit_info = response.json()
      self.check_for_rate_limit(commit_info)
      return commit_info
    except Exception as e:
      error_msg = f"Failed to fetch commit info: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return None

  def get_release_by_tag(self, tag_name):
    """
    Fetch information for a specific release by its tag name.
    
    Parameters
    ----------
    tag_name : str
      The tag name of the release to fetch.
      
    Returns
    -------
    dict
      JSON object with information about the specified release, or None if not found.
    """
    func_name = f"get_release_by_tag({tag_name})"
    try:
      release_url = f"{self.cfg_releases_repo_url}/releases/tags/{tag_name}"
      self.P(f"{func_name}: Requesting specific release from: {release_url}")
      response = self.requests.get(release_url)
      
      if response.status_code != 200:
        error_msg = f"Failed to fetch release. Status code: {response.status_code}, Response: {response.text}"
        self.log_error(func_name, error_msg)
        return None
        
      release_info = response.json()
      self.check_for_rate_limit(release_info)
      self.P(f"{func_name}: Successfully fetched release for tag {tag_name}")
      return release_info
    except Exception as e:
      error_msg = f"Failed to fetch release: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return None

  def get_commit_message_for_tag(self, tag_name):
    """
    Fetch the commit message for a specific tag.
    
    Parameters
    ----------
    tag_name : str
      The tag name to fetch the commit message for.
      
    Returns
    -------
    str
      The commit message for the tag, or None if not found.
    """
    func_name = f"get_commit_message_for_tag({tag_name})"
    try:
      # First get the tag to find the commit SHA
      tag_url = f"{self.cfg_releases_repo_url}/git/refs/tags/{tag_name}"
      self.P(f"{func_name}: Requesting tag reference from: {tag_url}")
      tag_response = self.requests.get(tag_url)
      
      if tag_response.status_code != 200:
        error_msg = f"Failed to fetch tag reference. Status code: {tag_response.status_code}, Response: {tag_response.text}"
        self.log_error(func_name, error_msg)
        return None
        
      tag_data = tag_response.json()
      self.check_for_rate_limit(tag_data)
      
      # Get the object type and SHA
      if tag_data.get('object', {}).get('type') == 'tag':
        # This is an annotated tag, we need to get the tag object first
        tag_object_url = tag_data['object']['url']
        self.P(f"{func_name}: Requesting annotated tag object from: {tag_object_url}")
        tag_object_response = self.requests.get(tag_object_url)
        
        if tag_object_response.status_code != 200:
          error_msg = f"Failed to fetch tag object. Status code: {tag_object_response.status_code}, Response: {tag_object_response.text}"
          self.log_error(func_name, error_msg)
          return None
          
        tag_object_data = tag_object_response.json()
        self.check_for_rate_limit(tag_object_data)
        
        # Get the commit SHA from the tag object
        commit_sha = tag_object_data.get('object', {}).get('sha')
      else:
        # This is a lightweight tag, we can use the SHA directly
        commit_sha = tag_data.get('object', {}).get('sha')
      
      if not commit_sha:
        error_msg = f"Could not find commit SHA for tag {tag_name}"
        self.log_error(func_name, error_msg)
        return None
      
      # Now get the commit information
      commit_url = f"{self.cfg_releases_repo_url}/commits/{commit_sha}"
      self.P(f"{func_name}: Requesting commit information from: {commit_url}")
      commit_response = self.requests.get(commit_url)
      
      if commit_response.status_code != 200:
        error_msg = f"Failed to fetch commit information. Status code: {commit_response.status_code}, Response: {commit_response.text}"
        self.log_error(func_name, error_msg)
        return None
        
      commit_data = commit_response.json()
      self.check_for_rate_limit(commit_data)
      
      # Extract the commit message
      commit_message = commit_data.get('commit', {}).get('message')
      if commit_message:
        self.P(f"{func_name}: Successfully retrieved commit message for tag {tag_name}")
        return commit_message
      else:
        error_msg = f"No commit message found for tag {tag_name}"
        self.log_error(func_name, error_msg)
        return None
    except Exception as e:
      error_msg = f"Failed to fetch commit message for tag {tag_name}: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return None

  def check_for_rate_limit(self, response, raise_exception=True):
    """
    Checks the response body for GitHub rate limit messages.

    Parameters
    ----------
    response : dict
      The response JSON to check.
    raise_exception : bool, optional
      Whether to raise an exception if the rate limit is reached.

    Returns
    -------
    bool
      True if rate limit is reached, otherwise False.
    """
    func_name = "check_for_rate_limit"
    result = False
    if isinstance(response, dict) and 'message' in response:
      if 'rate limit' in response['message']:
        msg = f"GitHub API rate limit reached! Details: {response.get('message')}"
        if raise_exception:
          self.log_error(func_name, msg)
          raise Exception(msg)
        self.P(msg)
        result = True
    return result

  def compile_release_info(self, releases, tags):
    """
    Sorts releases by publish date, trims to NR_PREVIOUS_RELEASES,
    and augments each with commit info if available.

    Parameters
    ----------
    releases : list
      A list of release JSON objects.
    tags : list
      A list of tag JSON objects.

    Returns
    -------
    list
      The updated list of release objects, each including a 'commit_info' key.
    """
    func_name = "compile_release_info"
    if not releases:
      self.log_error(func_name, "No releases provided")
      return []
    
    try:
      # Create a dictionary of tags for faster lookup
      tags_dict = {tag['name'].strip("'"): tag for tag in tags} if tags else {}
      
      releases.sort(key=lambda x: x['published_at'], reverse=True)
      releases = releases[:self.cfg_nr_previous_releases]
      
      for i, release in enumerate(releases):
        try:
          release_tag = release['tag_name'].strip("'")
          self.P(f"{func_name}: Processing release {i} - Tag: {release_tag}")
          
          # If the release doesn't have a body, try to fetch it directly
          if not release.get('body') or not release['body'].strip():
            self.P(f"{func_name}: Release {release_tag} has no body, trying to fetch directly")
            specific_release = self.get_release_by_tag(release_tag)
            if specific_release and specific_release.get('body') and specific_release['body'].strip():
              release['body'] = specific_release['body']
              self.P(f"{func_name}: Successfully fetched body for release {release_tag}")
            else:
              # If still no body, try to get the commit message for the tag
              self.P(f"{func_name}: No body found for release {release_tag}, trying to get commit message")
              commit_message = self.get_commit_message_for_tag(release_tag)
              if commit_message:
                release['body'] = commit_message
                self.P(f"{func_name}: Successfully fetched commit message for release {release_tag}")
          
          # Get tag from dictionary instead of searching through the list
          tag = tags_dict.get(release_tag)
          if tag:
            try:
              commit_info = self.get_commit_info(tag['commit']['sha'])
              self.check_for_rate_limit(commit_info)
              release['commit_info'] = commit_info
              self.P(f"{func_name}: Added commit info for release {release_tag}")
            except Exception as e:
              error_msg = f"Failed to get commit info for release {release_tag}, index {i}: {str(e)}"
              self.log_error(func_name, error_msg, e)
              if i > 1:
                return releases
              release['commit_info'] = None
          else:
            self.P(f"{func_name}: Warning - No matching tag found for release {release_tag}")
            release['commit_info'] = None
            
          # Debug: Print release information after processing
          self.P(f"{func_name}: Release {i} after processing - Tag: {release_tag}")
          self.P(f"{func_name}: Release {i} - Has body: {bool(release.get('body'))}")
          if release.get('body'):
            self.P(f"{func_name}: Release {i} - Body preview: {release.get('body')[:100]}...")
          self.P(f"{func_name}: Release {i} - Has commit_info: {bool(release.get('commit_info'))}")
        except Exception as e:
          error_msg = f"Failed to process release at index {i}: {str(e)}"
          self.log_error(func_name, error_msg, e)
          release['commit_info'] = None
      return releases
    except Exception as e:
      error_msg = f"Failed to compile release info: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return releases[:1] if releases else []

  def _regenerate_index_html(self):
    """
    Regenerate the index.html file listing the latest releases and metadata.
    If releases cannot be fetched due to GitHub API rate limits, it generates a fallback page,
    but only if no HTML file already exists.
    """
    func_name = "_regenerate_index_html"
    self.P(f"{func_name}: Starting HTML regeneration...")
    
    error_message = ""
    
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
        
        # Generate fallback page instead of returning False only if no file exists
        if "rate limit" in error_message.lower():
          if file_exists:
            self.P(f"{func_name}: Rate limit exceeded, but existing HTML file was preserved")
            return False
          else:
            return self._generate_fallback_html_and_save(error_message)
        return False
    except Exception as e:
      error_message = f"Failed during release fetching: {str(e)}"
      self.log_error(func_name, error_message, e)
      
      # Check if it's a rate limit exception
      if "rate limit" in str(e).lower():
        if file_exists:
          self.P(f"{func_name}: Rate limit exception encountered, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
      return False
    
    # Step 2: Fetch tags
    raw_tags = []
    try:
      raw_tags, tag_error = self.get_latest_tags()
      if not raw_tags and tag_error and tag_error.get('rate_limited', False):
        error_message = tag_error.get('message', "Failed to get any tags")
        self.log_error(func_name, error_message)
        if file_exists:
          self.P(f"{func_name}: Rate limit exceeded during tag fetching, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
    except Exception as e:
      error_message = f"Failed during tag fetching: {str(e)}"
      self.log_error(func_name, error_message, e)
      
      if "rate limit" in str(e).lower():
        if file_exists:
          self.P(f"{func_name}: Rate limit exception during tag fetching, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
    
    # Step 3: Compile release information
    try:
      raw_releases_with_commits = self.compile_release_info(raw_releases, raw_tags)
      if not raw_releases_with_commits:
        error_message = "Failed to compile any release information"
        self.log_error(func_name, error_message)
        if file_exists:
          self.P(f"{func_name}: Failed to compile release information, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
          
      # Convert raw releases to ReleaseInfo objects
      releases = self.data_processor.process_releases(raw_releases_with_commits, raw_tags)
        
    except Exception as e:
      error_msg = f"Failed during release compilation: {str(e)}"
      self.log_error(func_name, error_msg, e)
      
      if "rate limit" in str(e).lower():
        if file_exists:
          self.P(f"{func_name}: Rate limit exception during compilation, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
      return False
    
    # Step 4: Generate HTML
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

  def _generate_fallback_html_and_save(self, error_message):
    """
    Generate a fallback HTML page and save it to the web server path.
    
    Parameters
    ----------
    error_message : str
      The error message to display on the fallback page.
      
    Returns
    -------
    bool
      True if the fallback page was generated and saved successfully.
    """
    func_name = "_generate_fallback_html_and_save"
    try:
      html_content = self.html_generator._generate_fallback_html(error_message)
      
      web_server_path = self.get_web_server_path()
      self.P(f"{func_name}: Writing fallback page to web server path: {web_server_path}")
      output_path = self.os_path.join(web_server_path, 'assets/releases.html')
      
      with open(output_path, 'w') as fd:
        fd.write(html_content)

      self.P(f"{func_name}: Fallback releases.html has been generated successfully.")
      return True
    except Exception as e:
      error_msg = f"Failed to write fallback HTML to file: {str(e)}"
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
                        const btnId = 'btn-' + infoId.rre.eplace('release-info-', '');
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
      return self._generate_fallback_html("No releases available")

    return (
        self.generate_html_head() +
        self.generate_jumbo_section(ee_id, ee_addr, last_update) +
        self.generate_latest_release_section(releases[0]) +
        self.generate_previous_releases_section(releases) +
        self.generate_javascript() +
        "</body></html>"
    )

  def _generate_fallback_html(self, error_message: str) -> str:
    """
    Generate a fallback HTML page when the GitHub API rate limit is exceeded or releases cannot be fetched.

    Parameters
    ----------
    error_message : str
        The error message to display

    Returns
    -------
    str
        HTML content for the fallback page
    """
    return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Edge Node Launcher Releases</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 20px;
                    text-align: center;
                }}
                .error-container {{
                    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                    border-radius: 8px;
                    padding: 40px 20px;
                    margin: 40px auto;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    color: #3a5795;
                    margin-bottom: 20px;
                }}
                p {{
                    margin-bottom: 20px;
                    font-size: 1.1em;
                }}
                .error-message {{
                    background-color: #ffecec;
                    color: #d8000c;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-family: monospace;
                    text-align: left;
                    max-width: 100%;
                    overflow-x: auto;
                }}
                .redirect-button {{
                    display: inline-block;
                    background-color: #4b6cb7;
                    color: white;
                    text-decoration: none;
                    padding: 12px 24px;
                    border-radius: 4px;
                    font-weight: bold;
                    margin-top: 20px;
                    transition: background-color 0.3s;
                }}
                .redirect-button:hover {{
                    background-color: #3a5795;
                }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>Edge Node Launcher Releases</h1>
                {"<p>⚠️ We're currently experiencing limitations with GitHub's API service.</p>" if "rate limit" in error_message.lower() else "<p>⚠️ We're currently experiencing difficulties retrieving release information.</p>"}
                <div class="error-message">{error_message}</div>
                <p>Please visit the official GitHub releases page to download the Edge Node Launcher:</p>
                <a href="{self.config['GITHUB_REPO_URL']}" class="redirect-button">Go to GitHub Releases</a>
            </div>
        </body>
        </html>
        """


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
