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

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.3.4'

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
    Initialize the plugin, setting last regeneration times.
    """
    super(NaeuralReleaseAppPlugin, self).on_init(**kwargs)
    self._last_day_regenerated = (self.datetime.now() - self.timedelta(days=1)).day
    self.__last_generation_time = 0
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
    list
      A list of JSON objects corresponding to recent GitHub releases.
    """
    func_name = "get_latest_releases"
    try:
      releases_url = f"{self.cfg_releases_repo_url}/releases"
      self.P(f"{func_name}: Requesting releases from: {releases_url}")
      response = self.requests.get(releases_url,
                                   params={"per_page": self.cfg_nr_previous_releases + 1})
      
      if response.status_code != 200:
        error_msg = f"Failed to fetch releases. Status code: {response.status_code}, Response: {response.text}"
        self.log_error(func_name, error_msg)
        return []
        
      releases = response.json()
      self.check_for_rate_limit(releases)
      self.P(f"{func_name}: Successfully fetched {len(releases)} releases")
      return releases
    except Exception as e:
      error_msg = f"Failed to fetch releases: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return []

  def get_latest_tags(self):
    """
    Fetch the latest tags from GitHub, up to NR_PREVIOUS_RELEASES + 1.

    Returns
    -------
    list
      A list of JSON objects corresponding to recent GitHub tags.
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
        return []
        
      tags = response.json()
      self.check_for_rate_limit(tags)
      self.P(f"{func_name}: Successfully fetched {len(tags)} tags")
      return tags
    except Exception as e:
      error_msg = f"Failed to fetch tags: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return []

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
      releases.sort(key=lambda x: x['published_at'], reverse=True)
      releases = releases[:self.cfg_nr_previous_releases]
      for i, release in enumerate(releases):
        try:
          release_tag = release['tag_name'].strip("'")
          tag = next((tag for tag in tags if tag['name'].strip("'") == release_tag), None)
          if tag:
            try:
              commit_info = self.get_commit_info(tag['commit']['sha'])
              self.check_for_rate_limit(commit_info)
              release['commit_info'] = commit_info
            except Exception as e:
              error_msg = f"Failed to get commit info for release {release_tag}, index {i}: {str(e)}"
              self.log_error(func_name, error_msg, e)
              if i > 1:
                return releases
              release['commit_info'] = None
          else:
            self.P(f"{func_name}: Warning - No matching tag found for release {release_tag}")
            release['commit_info'] = None
        except Exception as e:
          error_msg = f"Failed to process release at index {i}: {str(e)}"
          self.log_error(func_name, error_msg, e)
          release['commit_info'] = None
      return releases
    except Exception as e:
      error_msg = f"Failed to compile release info: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return releases[:1] if releases else []

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

  def _generate_fallback_html(self, error_message=""):
    """
    Generate a fallback HTML page when the GitHub API rate limit is exceeded or releases cannot be fetched.
    This provides users with a direct link to the GitHub releases page.

    Parameters
    ----------
    error_message : str, optional
      The error message to display, defaults to an empty string.

    Returns
    -------
    str
      HTML content for the fallback page.
    """
    func_name = "_generate_fallback_html"
    self.P(f"{func_name}: Generating fallback HTML page")
    
    github_repo_url = self.cfg_github_repo_url
    last_update = self.datetime_to_str()
    
    html_content = """
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
                max-width: 1000px;
                margin: 0 auto;
                padding: 20px;
                text-align: center;
            }
            .error-container {
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                border-radius: 8px;
                padding: 40px 20px;
                margin: 40px auto;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            h1 {
                color: #3a5795;
                margin-bottom: 20px;
            }
            p {
                margin-bottom: 20px;
                font-size: 1.1em;
            }
            .error-message {
                background-color: #ffecec;
                color: #d8000c;
                padding: 15px;
                border-radius: 4px;
                margin: 20px 0;
                font-family: monospace;
                text-align: left;
                max-width: 100%;
                overflow-x: auto;
            }
            .redirect-button {
                display: inline-block;
                background-color: #4b6cb7;
                color: white;
                text-decoration: none;
                padding: 12px 24px;
                border-radius: 4px;
                font-weight: bold;
                margin-top: 20px;
                transition: background-color 0.3s;
            }
            .redirect-button:hover {
                background-color: #3a5795;
            }
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1>Edge Node Launcher Releases</h1>
    """
    
    # Add error-specific content
    if "rate limit" in error_message.lower():
        html_content += f"""
            <p>⚠️ We're currently experiencing limitations with GitHub's API service.</p>
            <p>The Edge Node Launcher download page could not be generated because GitHub's API rate limit has been exceeded.</p>
            <div class="error-message">{error_message}</div>
        """
    else:
        html_content += f"""
            <p>⚠️ We're currently experiencing difficulties retrieving release information.</p>
            <p>The Edge Node Launcher download page could not be generated due to the following issue:</p>
            <div class="error-message">{error_message}</div>
        """
    
    # Add GitHub redirect
    html_content += f"""
            <p>Please visit the official GitHub releases page to download the Edge Node Launcher:</p>
            <a href="{github_repo_url}" class="redirect-button">Go to GitHub Releases</a>
            <p style="font-size: 0.8em; margin-top: 40px;">This page was generated by Edge Node <code>{self.ee_id}:{self.ee_addr}</code> at {last_update}.</p>
        </div>
    </body>
    </html>
    """
    
    return html_content

  def _regenerate_index_html(self):
    """
    Regenerate the index.html file listing the latest releases and metadata.
    If releases cannot be fetched due to GitHub API rate limits, it generates a fallback page,
    but only if no HTML file already exists.
    """
    func_name = "_regenerate_index_html"
    self.P(f"{func_name}: Starting HTML regeneration...")
    
    rate_limited = False
    error_message = ""
    
    # Check if HTML file already exists
    web_server_path = self.get_web_server_path()
    output_path = self.os_path.join(web_server_path, 'assets/releases.html')
    file_exists = self.os_path.isfile(output_path)
    
    # Step 1: Fetch releases
    try:
      raw_releases = self.get_latest_releases()
      if not raw_releases:
        error_response = self.requests.get(f"{self.cfg_releases_repo_url}/releases")
        if error_response.status_code == 403 and 'rate limit' in error_response.text.lower():
          error_message = f"GitHub API rate limit exceeded. Response: {error_response.text}"
          rate_limited = True
        else:
          error_message = "Failed to get any releases"
        self.log_error(func_name, error_message)
        
        # Generate fallback page instead of returning False only if no file exists
        if rate_limited or error_response.status_code != 200:
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
        rate_limited = True
        if file_exists:
          self.P(f"{func_name}: Rate limit exception encountered, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
      return False
    
    # Step 2: Fetch tags
    try:
      raw_tags = self.get_latest_tags()
      if not raw_tags:
        error_response = self.requests.get(f"{self.cfg_releases_repo_url}/tags")
        if error_response.status_code == 403 and 'rate limit' in error_response.text.lower():
          error_message = f"GitHub API rate limit exceeded. Response: {error_response.text}"
          rate_limited = True
          if file_exists:
            self.P(f"{func_name}: Rate limit exceeded during tag fetching, but existing HTML file was preserved")
            return False
          else:
            return self._generate_fallback_html_and_save(error_message)
        else:
          error_msg = "Failed to get any tags, proceeding with limited information"
          self.log_error(func_name, error_msg)
          # We continue anyway, as we can still generate some HTML with just releases
    except Exception as e:
      error_msg = f"Failed during tag fetching: {str(e)}"
      self.log_error(func_name, error_msg, e)
      
      # Check if it's a rate limit exception
      if "rate limit" in str(e).lower():
        rate_limited = True
        error_message = f"GitHub API rate limit exceeded during tag fetching: {str(e)}"
        if file_exists:
          self.P(f"{func_name}: Rate limit exception during tag fetching, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
      
      raw_tags = []
    
    # Step 3: Compile release information
    try:
      releases = self.compile_release_info(raw_releases, raw_tags)
      if not releases:
        error_message = "Failed to compile any release information, aborting HTML generation"
        self.log_error(func_name, error_message)
        if file_exists:
          self.P(f"{func_name}: Failed to compile release information, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
    except Exception as e:
      error_message = f"Failed during release compilation: {str(e)}"
      self.log_error(func_name, error_message, e)
      
      # Check if it's a rate limit exception
      if "rate limit" in str(e).lower():
        rate_limited = True
        if file_exists:
          self.P(f"{func_name}: Rate limit exception during compilation, but existing HTML file was preserved")
          return False
        else:
          return self._generate_fallback_html_and_save(error_message)
        
      return False
    
    # Step 4: Generate HTML header
    try:
      html_content = """
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
              table {
                  width: 100%;
                  border-collapse: collapse;
                  margin-top: 20px;
              }
              table, th, td {
                  border: 1px solid #e0e0e0;
              }
              th {
                  background-color: #f8f9fa;
                  font-weight: 600;
              }
              th, td {
                  padding: 12px 15px;
                  text-align: left;
              }
              tr:nth-child(even) {
                  background-color: #f9f9f9;
              }
              a {
                  color: #4b6cb7;
                  text-decoration: none;
              }
              a:hover {
                  text-decoration: underline;
              }
              .download-btn {
                  display: inline-block;
                  background-color: #4CAF50;
                  color: white;
                  padding: 6px 12px;
                  border-radius: 4px;
                  text-decoration: none;
                  margin-top: 5px;
              }
              .download-btn:hover {
                  background-color: #45a049;
                  text-decoration: none;
              }
              pre {
                  background-color: #f8f9fa;
                  padding: 10px;
                  border-radius: 4px;
                  white-space: pre-wrap;
                  font-size: 0.9em;
                  max-height: 100px;
                  overflow: hidden;
                  transition: max-height 0.3s ease-out;
              }
              .commit-info {
                  background-color: #f8f9fa;
                  padding: 10px;
                  border-radius: 4px;
                  font-size: 0.9em;
                  max-height: 80px;
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
              }
              .see-more-btn:hover {
                  background-color: #e0e0e0;
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
              .release-row {
                  display: none;
              }
              .release-row.visible {
                  display: table-row;
              }
              .commit-message {
                  list-style-type: disc;
                  padding-left: 20px;
                  margin: 5px 0;
              }
              .commit-message li {
                  margin-bottom: 3px;
              }
              .commit-message li.hidden {
                  display: none;
              }
              .commit-message li.visible {
                  display: list-item;
              }
          </style>
      </head>
      """
    except Exception as e:
      error_msg = f"Failed during HTML header generation: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False
    
    # Step 5: Generate HTML body with latest update info
    try:
      last_update = self.datetime_to_str()
      # NOTE: We must escape curly braces in f-strings for literal JS object usage.
      html_content += f"""
      <body>
          <div class="jumbo">
              <h1>Edge Node Launcher Releases</h1>
              <p>Download the latest version of Edge Node Launcher to stay up-to-date with new features and improvements.</p>
              <p>This page was proudly generated by Edge Node <code>{self.ee_id}:{self.ee_addr}</code> at {last_update}.</p>
              <button onclick="document.getElementById('latest-release').scrollIntoView({{behavior: 'smooth'}});" class="download-btn">Download Edge Node Launcher</button>
          </div>
      """
    except Exception as e:
      error_msg = f"Failed during HTML body generation: {str(e)}"
      self.log_error(func_name, error_msg, e)
      return False
    
    # Step 6: Generate latest release section
    try:
      latest_release = releases[0]
      dct_info = {
        k : v for k, v in latest_release.items()
        if k in ['tag_name', 'published_at', 'tarball_url', 'zipball_url', 'created_at']
      }
      self.P(f"{func_name}: latest_release:\n{self.json_dumps(dct_info, indent=2)}")
      
      # Safely get commit message
      commit_message = "No commit information available"
      if latest_release.get('commit_info') and latest_release['commit_info'].get('commit'):
        commit_message = latest_release['commit_info']['commit'].get('message', commit_message)
      
      latest_release_section = f"""
          <div class="latest-release" id="latest-release">
              <h2>Latest Release: {latest_release['tag_name'].replace("'","")}</h2>
              <h3>Details:</h3>
              <div style="margin-left: 2em;">
                <pre id="latest-release-info">{commit_message}</pre>
                <button class="see-more-btn" onclick="toggleContent('latest-release-info')">See More</button>
              </div>
              <p>Date Published: {self.datetime.strptime(latest_release['published_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%B %d, %Y')}</p>
              <ul>
      """

      assets = latest_release.get('assets', [])
      for asset in assets:
        if self.re.search(r'LINUX_Ubuntu-20\.04\.AppImage', asset['name']):
          latest_release_section += f'<li>Linux Ubuntu 20.04: {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'
        if self.re.search(r'LINUX_Ubuntu-22\.04\.AppImage', asset['name']):
          latest_release_section += f'<li>Linux Ubuntu 22.04: {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'
        if self.re.search(r'LINUX_Ubuntu-24\.04\.AppImage', asset['name']):
          latest_release_section += f'<li>Linux Ubuntu 24.04: {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'
        if self.re.search(r'OSX-arm64\.zip', asset['name']):
          latest_release_section += f'<li>macOS (Apple Silicon): {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'
        if self.re.search(r'WIN32\.zip', asset['name']):
          latest_release_section += f'<li>Windows (ZIP): {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'
        if self.re.search(r'Windows\.msi$', asset['name']):
          latest_release_section += f'<li>Windows (MSI): {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'

      latest_release_section += f"""
              </ul>
          </div>
      """

      html_content += latest_release_section
    except Exception as e:
      error_msg = f"Failed during latest release section generation: {str(e)}"
      self.log_error(func_name, error_msg, e)
      # Continue anyway, we can still show previous releases
    
    # Step 7: Generate previous releases section
    try:
      previous_releases_section = """
          <div class="previous-releases">
              <h2>Previous Releases</h2>
              <table id="previous-releases-table">
                  <thead>
                      <tr>
                          <th>Release Info</th>
                          <th>Date</th>
                          <th>Linux</th>
                          <th>Windows</th>
                          <th>macOS</th>
                      </tr>
                  </thead>
                  <tbody>
      """

      for i, release in enumerate(releases[1:]):
        if release is None:
          continue
        try:
          # Safely get commit message
          commit_message = "No commit information available"
          formatted_message = commit_message
          
          if release.get('commit_info') and release['commit_info'].get('commit'):
            commit_message = release['commit_info']['commit'].get('message', commit_message)
            
            if '\n' in commit_message:
              lines = commit_message.strip().split('\n')
              formatted_message = f"<div class='commit-title'>{lines[0]}</div>"
              if len(lines) > 1:
                formatted_message += "<ul class='commit-message'>"
                for j, line in enumerate(lines[1:]):
                  css_class = "visible" if j < 2 else "hidden"
                  if line.strip().startswith('*'):
                    formatted_message += f"<li class='{css_class}'>{line.strip()[1:].strip()}</li>"
                  elif line.strip():
                    formatted_message += f"<li class='{css_class}'>{line.strip()}</li>"
                formatted_message += "</ul>"
            else:
              formatted_message = commit_message

          # Make all releases visible by default if configured to do so
          visible_class = "visible" if (i < 2 or self.cfg_show_all_releases_by_default) else ""
          safe_tag_name = release['tag_name'].replace("'", "").replace('.', '-')

          release_row = f"""
                      <tr class="release-row {visible_class}" id="release-row-{i}">
                          <td>
                            {release['tag_name'].replace("'","")}
                            <div style="margin-left: 1em;">
                              <div id="release-info-{safe_tag_name}" class="commit-info">
                                {formatted_message}
                              </div>
                              <button class="see-more-btn" onclick="toggleContent('release-info-{safe_tag_name}')">See More</button>
                            </div>
                          </td>

                          <td>
                            {self.datetime.strptime(release['published_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%B %d, %Y')}
                          </td>

                          <td>
          """
          linux_20_04 = next((asset for asset in release.get('assets', []) if self.re.search(r'LINUX_Ubuntu-20\.04\.AppImage', asset['name'])), None)
          linux_22_04 = next((asset for asset in release.get('assets', []) if self.re.search(r'LINUX_Ubuntu-22\.04\.AppImage', asset['name'])), None)
          linux_24_04 = next((asset for asset in release.get('assets', []) if self.re.search(r'LINUX_Ubuntu-24\.04\.AppImage', asset['name'])), None)
          win_zip = next((asset for asset in release.get('assets', []) if self.re.search(r'WIN32\.zip', asset['name'])), None)
          win_exe = next((asset for asset in release.get('assets', []) if self.re.search(r'Windows\.exe$', asset['name'])), None)
          win_msi = next((asset for asset in release.get('assets', []) if self.re.search(r'Windows\.msi$', asset['name'])), None)
          macos_arm = next((asset for asset in release.get('assets', []) if self.re.search(r'OSX-arm64\.zip', asset['name'])), None)

          if linux_20_04:
            release_row += f'Ubuntu 20.04: {linux_20_04["size"] / (1024 * 1024):.2f} MB - <a href="{linux_20_04["browser_download_url"]}" class="download-btn">Download</a><br>'
          if linux_22_04:
            release_row += f'Ubuntu 22.04: {linux_22_04["size"] / (1024 * 1024):.2f} MB - <a href="{linux_22_04["browser_download_url"]}" class="download-btn">Download</a><br>'
          if linux_24_04:
            release_row += f'Ubuntu 24.04: {linux_24_04["size"] / (1024 * 1024):.2f} MB - <a href="{linux_24_04["browser_download_url"]}" class="download-btn">Download</a>'

          release_row += '</td><td>'

          if win_zip:
            release_row += f'ZIP: {win_zip["size"] / (1024 * 1024):.2f} MB - <a href="{win_zip["browser_download_url"]}" class="download-btn">Download</a><br>'
          if win_exe:
            release_row += f'EXE: {win_exe["size"] / (1024 * 1024):.2f} MB - <a href="{win_exe["browser_download_url"]}" class="download-btn">Download</a><br>'
          if win_msi:
            release_row += f'MSI: {win_msi["size"] / (1024 * 1024):.2f} MB - <a href="{win_msi["browser_download_url"]}" class="download-btn">Download</a>'
            
          release_row += '</td><td>'
          
          if macos_arm:
            release_row += f'Apple Silicon: {macos_arm["size"] / (1024 * 1024):.2f} MB - <a href="{macos_arm["browser_download_url"]}" class="download-btn">Download</a>'

          release_row += '</td></tr>'

          previous_releases_section += release_row
        except Exception as e:
          error_msg = f"Failed to process release at index {i}: {str(e)}"
          self.log_error(func_name, error_msg, e)
          continue

      # Update the Show/Hide button text based on default visibility setting
      show_all_button_text = "Show Less" if self.cfg_show_all_releases_by_default else "Show All Releases"
      
      previous_releases_section += f"""
                  </tbody>
              </table>
              <button id="show-all-btn" class="show-all-btn" onclick="toggleAllReleases()">{show_all_button_text}</button>
          </div>
      </body>
      <script>
          function toggleContent(id) {{
              const element = document.getElementById(id);
              element.classList.toggle('expanded');

              const button = element.nextElementSibling;
              if (element.classList.contains('expanded')) {{
                  button.textContent = 'See Less';
                  // Show all list items when expanded
                  const listItems = element.querySelectorAll('li');
                  listItems.forEach(item => {{
                      item.classList.add('visible');
                      item.classList.remove('hidden');
                  }});
              }} else {{
                  button.textContent = 'See More';
                  // Hide items beyond the first 2 when collapsed
                  const listItems = element.querySelectorAll('li');
                  listItems.forEach((item, index) => {{
                      if (index >= 2) {{
                          item.classList.add('hidden');
                          item.classList.remove('visible');
                      }}
                  }});
              }}
          }}

          function toggleAllReleases() {{
              const button = document.getElementById('show-all-btn');
              const rows = document.querySelectorAll('.release-row');
              const hiddenRows = document.querySelectorAll('.release-row:not(.visible)');

              if (hiddenRows.length > 0) {{
                  rows.forEach(row => row.classList.add('visible'));
                  button.textContent = 'Show Less';
              }} else {{
                  rows.forEach((row, index) => {{
                      if (index >= 2) {{
                          row.classList.remove('visible');
                      }}
                  }});
                  button.textContent = 'Show All Releases';
              }}
          }}

          // Initialize to hide list items beyond the first 2 on page load
          document.addEventListener('DOMContentLoaded', function() {{
              const commitInfos = document.querySelectorAll('.commit-info');
              commitInfos.forEach(info => {{
                  const listItems = info.querySelectorAll('li');
                  listItems.forEach((item, index) => {{
                      if (index >= 2) {{
                          item.classList.add('hidden');
                      }} else {{
                          item.classList.add('visible');
                      }}
                  }});
              }});
          }});
      </script>
      </html>
      """

      html_content += previous_releases_section
    except Exception as e:
      error_msg = f"Failed during previous releases section generation: {str(e)}"
      self.log_error(func_name, error_msg, e)
      # If we can't generate previous releases section, at least try to close the HTML properly
      html_content += "</body></html>"
    
    # Step 8: Write the HTML to file
    try:
      web_server_path = self.get_web_server_path()
      self.P(f"{func_name}: Writing to web server path: {web_server_path}")
      output_path = self.os_path.join(web_server_path, 'assets/releases.html')
      
      with open(output_path, 'w') as fd:
        fd.write(html_content)

      self.P(f"{func_name}: releases.html has been generated successfully.")
      return True
    except Exception as e:
      error_msg = f"Failed to write HTML to file: {str(e)}"
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
      html_content = self._generate_fallback_html(error_message)
      
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
      current_day = self.datetime.now().day
      if (self.time() - self.__last_generation_time) > self.cfg_regeneration_interval:
        self.P(f"{func_name}: Regeneration interval elapsed, regenerating releases.html...")
        
        # Check if an HTML file already exists before attempting regeneration
        web_server_path = self.get_web_server_path()
        output_path = self.os_path.join(web_server_path, 'assets/releases.html')
        file_exists = self.os_path.isfile(output_path)
        
        # Attempt to regenerate the HTML
        result = self._regenerate_index_html()
        
        if result:
          # Successful regeneration
          self._last_day_regenerated = current_day
          self.__last_generation_time = self.time()
          self.P(f"{func_name}: HTML regeneration successful")
        else:
          # Failed regeneration
          if file_exists:
            # If file already exists, keep it and don't overwrite with fallback
            self.P(f"{func_name}: HTML regeneration failed but existing file was preserved")
          else:
            # If no file exists, the fallback page was likely generated in _regenerate_index_html
            self.P(f"{func_name}: HTML regeneration failed and fallback page was generated")
          
          # Update the generation time anyway to avoid constant retries when failing
          self.__last_generation_time = self.time()
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
