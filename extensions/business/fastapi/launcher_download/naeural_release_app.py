from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.3.1'

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
  
  "RELEASES_REPO_URL": "https://api.github.com/repos/NaeuralEdgeProtocol/edge_node_launcher",
  'VALIDATION_RULES': {

    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}

class NaeuralReleaseAppPlugin(BasePlugin):

  CONFIG = _CONFIG

  def on_init(self, **kwargs):
    super(NaeuralReleaseAppPlugin, self).on_init(**kwargs)
    self._last_day_regenerated = (self.datetime.now() - self.timedelta(days=1)).day
    self.__last_generation_time = 0
    return

  # Fetch the latest 10 releases
  def get_latest_releases(self):
    releases_url = f"{self.cfg_releases_repo_url}/releases"
    self.P("Requesting releases from: {}".format(releases_url))
    response = self.requests.get(releases_url, params={"per_page": self.cfg_nr_previous_releases + 1})
    releases = response.json()
    self.check_for_rate_limit(releases)
    return releases


  # Fetch the last 10 tags
  def get_latest_tags(self):
    tags_url = f"{self.cfg_releases_repo_url}/tags"
    self.P("Requesting tags from: {}".format(tags_url))
    response = self.requests.get(tags_url, params={"per_page": self.cfg_nr_previous_releases + 1})
    tags = response.json()
    self.check_for_rate_limit(tags)
    return tags


  def get_commit_info(self, commit_sha):    
    commit_url = f"{self.cfg_releases_repo_url}/commits/{commit_sha}"
    self.P("Requesting commit info from: {}".format(commit_url))
    response = self.requests.get(commit_url)
    commit_info = response.json()
    self.check_for_rate_limit(commit_info)
    return commit_info


  def compile_release_info(self, releases, tags):
    releases.sort(key=lambda x: x['published_at'], reverse=True)
    releases = releases[:self.cfg_nr_previous_releases]
    for i, release in enumerate(releases):
      release_tag = release['tag_name'].strip("'")
      tag = next((tag for tag in tags if tag['name'].strip("'") == release_tag), None)
      if tag:
        try:
          commit_info = self.get_commit_info(tag['commit']['sha'])
          self.check_for_rate_limit(commit_info)
        except Exception as e:
          if i > 1:
            return releases
        release['commit_info'] = commit_info
      else:
        release['commit_info'] = None
      # end if
    return releases
  
  
  def check_for_rate_limit(self, response, raise_exception=True):
    result = False
    if 'message' in response:
      if 'rate limit' in response['message']:
        msg = "Rate limit reached!"
        if raise_exception:
          raise Exception(msg)
        self.P(msg)
        result = True
    return result


  def _regenerate_index_html(self):
    """
    Regenerate the index.html file.
    """
    try:
      raw_releases = self.get_latest_releases()
      raw_tags = self.get_latest_tags()

      releases = self.compile_release_info(raw_releases, raw_tags)

      # Define the HTML structure
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
              .expanded {
                  max-height: 1000px;
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
          </style>
      </head>
      """ 
      last_update = self.datetime_to_str()
      html_content += f"""
      <body>
          <div class="jumbo">
              <h1>Edge Node Launcher Releases</h1>
              <p>Download the latest version of Edge Node Launcher to stay up-to-date with new features and improvements.</p>
              <p>This page was proudly generated by Edge Node <code>{self.ee_id}:{self.ee_addr}</code> at {last_update}.</p>
              <button onclick="document.getElementById('latest-release').scrollIntoView({behavior: 'smooth'});" class="download-btn">Download Edge Node Launcher</button>
          </div>
      """

      # Add the latest release section
      latest_release = releases[0]
      dct_info = {
        k : v for k, v in latest_release.items() 
        if k in ['tag_name', 'published_at', 'tarball_url', 'zipball_url', 'created_at']
      }
      self.P("latest_release:\n{} ".format(self.json_dumps(dct_info, indent=2)))
      latest_release_section = f"""
          <div class="latest-release" id="latest-release">
              <h2>Latest Release: {latest_release['tag_name'].replace("'","")}</h2>
              <h3>Details:</h3>
              <div style="margin-left: 2em;">            
                <pre id="latest-release-info">{latest_release['commit_info']['commit']['message']}</pre>
                <button class="see-more-btn" onclick="toggleContent('latest-release-info')">See More</button>
              </div>
              <p>Date Published: {self.datetime.strptime(latest_release['published_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%B %d, %Y')}</p>
              <ul>
      """

      assets = latest_release['assets']
      for asset in assets:
        if self.re.search(r'LINUX_Ubuntu-20\.04\.zip', asset['name']):
          latest_release_section += f'<li>Linux Ubuntu 20.04: {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'
        if self.re.search(r'LINUX_Ubuntu-22\.04\.zip', asset['name']):
          latest_release_section += f'<li>Linux Ubuntu 22.04: {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'
        if self.re.search(r'WIN32\.zip', asset['name']):
          latest_release_section += f'<li>Windows: {asset["size"] / (1024 * 1024):.2f} MB - <a href="{asset["browser_download_url"]}" class="download-btn">Download</a></li>'

      latest_release_section += f"""
                  <li>Source Code: <a href="{latest_release['tarball_url']}" class="download-btn">.tar</a>, <a href="{latest_release['zipball_url']}" class="download-btn">.zip</a></li>
              </ul>
          </div>
      """

      html_content += latest_release_section

      # Add the previous releases section
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
                          <th>Source Code</th>
                      </tr>
                  </thead>
                  <tbody>
      """

      for i, release in enumerate(releases[1:]):
        if release is None:
          continue
        try:
          # Format the commit message to be more readable with bullet points
          commit_message = release['commit_info']['commit']['message']
          formatted_message = ""
          
          # Process the commit message to format it with bullet points if it contains line breaks
          if '\n' in commit_message:
            lines = commit_message.strip().split('\n')
            formatted_message = f"<div class='commit-title'>{lines[0]}</div>"
            if len(lines) > 1:
              formatted_message += "<ul class='commit-message'>"
              for line in lines[1:]:
                if line.strip().startswith('*'):
                  formatted_message += f"<li>{line.strip()[1:].strip()}</li>"
                elif line.strip():
                  formatted_message += f"<li>{line.strip()}</li>"
              formatted_message += "</ul>"
          else:
            formatted_message = commit_message
          
          # Determine if this row should be visible initially (first 2 rows)
          visible_class = "visible" if i < 2 else ""
          
          release_row = f"""
                      <tr class="release-row {visible_class}" id="release-row-{i}">
                          <td>
                            {release['tag_name'].replace("'","")}
                            <div style="margin-left: 1em;">            
                              <div id="release-info-{release['tag_name'].replace('.', '-')}" class="commit-info">
                                {formatted_message}
                              </div>
                              <button class="see-more-btn" onclick="toggleContent('release-info-{release['tag_name'].replace('.', '-')}')">See More</button>
                            </div>
                          </td>
                          
                          <td>
                            {self.datetime.strptime(release['published_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%B %d, %Y')}
                          </td>
                          
                          <td>
          """
          linux_20_04 = next((asset for asset in release['assets'] if self.re.search(r'LINUX_Ubuntu-20\.04\.zip', asset['name'])), None)
          linux_22_04 = next((asset for asset in release['assets'] if self.re.search(r'LINUX_Ubuntu-22\.04\.zip', asset['name'])), None)
          windows = next((asset for asset in release['assets'] if self.re.search(r'WIN32\.zip', asset['name'])), None)

          if linux_20_04:
            release_row += f'Ubuntu 20.04: {linux_20_04["size"] / (1024 * 1024):.2f} MB - <a href="{linux_20_04["browser_download_url"]}" class="download-btn">Download</a><br>'
          if linux_22_04:
            release_row += f'Ubuntu 22.04: {linux_22_04["size"] / (1024 * 1024):.2f} MB - <a href="{linux_22_04["browser_download_url"]}" class="download-btn">Download</a>'

          release_row += '</td><td>'

          if windows:
            release_row += f'{windows["size"] / (1024 * 1024):.2f} MB - <a href="{windows["browser_download_url"]}" class="download-btn">Download</a>'

          release_row += f'</td><td><a href="{release["tarball_url"]}" class="download-btn">.tar</a>, <a href="{release["zipball_url"]}" class="download-btn">.zip</a></td></tr>'

          previous_releases_section += release_row
        except:
          continue
      # end for all releases

      # Add a "Show All Releases" button
      previous_releases_section += """
                  </tbody>
              </table>
              <button id="show-all-btn" class="show-all-btn" onclick="toggleAllReleases()">Show All Releases</button>
          </div>
      </body>
      <script>
          function toggleContent(id) {
              const element = document.getElementById(id);
              element.classList.toggle('expanded');
              
              const button = element.nextElementSibling;
              if (element.classList.contains('expanded')) {
                  button.textContent = 'See Less';
              } else {
                  button.textContent = 'See More';
              }
          }
          
          function toggleAllReleases() {
              const button = document.getElementById('show-all-btn');
              const rows = document.querySelectorAll('.release-row');
              const hiddenRows = document.querySelectorAll('.release-row:not(.visible)');
              
              if (hiddenRows.length > 0) {
                  // Show all rows
                  rows.forEach(row => row.classList.add('visible'));
                  button.textContent = 'Show Less';
              } else {
                  // Hide all except first two rows
                  rows.forEach((row, index) => {
                      if (index >= 2) {
                          row.classList.remove('visible');
                      }
                  });
                  button.textContent = 'Show All Releases';
              }
          }
      </script>
      </html>
      """

      html_content += previous_releases_section

      # Write the HTML content to a file
      self.P(self.get_web_server_path())
      with open(self.os_path.join(self.get_web_server_path(), 'assets/releases.html'), 'w') as fd:
        fd.write(html_content)

      self.P("releases.html has been generated successfully.")
    except Exception as e:
      self.P("ERROR: {}".format(e))
      return      
    return


  def _maybe_regenerate_index_html(self):
    """
    Regenerate the html files if the last regeneration was more than X seconds ago
    ago.
    """
    current_day = self.datetime.now().day
    # if current_day != self._last_day_regenerated:
    if (self.time() - self.__last_generation_time) > self.cfg_regeneration_interval:
      self.P("Regenerating releases.html ...")
      self._regenerate_index_html()
      self._last_day_regenerated = current_day
      self.__last_generation_time = self.time()
    # end if
    return


  def process(self):
    self._maybe_regenerate_index_html()
    return
    