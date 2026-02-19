import requests


class _WebApiExposureMixin:
  """
  Detect GraphQL introspection leaks, cloud metadata endpoints,
  and API auth bypass (OWASP WSTG-APIT).
  """

  def _web_test_graphql_introspection(self, target, port):
    """
    Check if GraphQL introspection is exposed in production endpoints.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings on GraphQL introspection exposure.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    graphql_url = base_url.rstrip("/") + "/graphql"
    try:
      payload = {"query": "{__schema{types{name}}}"}
      resp = requests.post(graphql_url, json=payload, timeout=5, verify=False)
      if resp.status_code == 200 and "__schema" in resp.text:
        finding = f"VULNERABILITY: GraphQL introspection enabled at {graphql_url}."
        self.P(finding)
        findings.append(finding)
      else:
        findings.append(f"OK: GraphQL introspection disabled or unreachable at {graphql_url}.")
    except Exception as e:
      message = f"ERROR: GraphQL probe failed on {graphql_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: GraphQL introspection probe reported no issues at {graphql_url}.")
    return "\n".join(findings)


  def _web_test_metadata_endpoints(self, target, port):
    """
    Probe cloud metadata paths to detect SSRF-style exposure.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings on metadata endpoint exposure.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    metadata_paths = [
      "/latest/meta-data/",
      "/metadata/computeMetadata/v1/",
      "/computeMetadata/v1/",
    ]
    try:
      for path in metadata_paths:
        url = base_url.rstrip("/") + path
        resp = requests.get(url, timeout=3, verify=False, headers={"Metadata-Flavor": "Google"})
        if resp.status_code == 200:
          finding = f"VULNERABILITY: Cloud metadata endpoint exposed at {url}."
          self.P(finding)
          findings.append(finding)
    except Exception as e:
      message = f"ERROR: Metadata endpoint probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: Metadata endpoint probe did not detect exposure on {base_url}.")
    return "\n".join(findings)


  def _web_test_api_auth_bypass(self, target, port):
    """
    Detect APIs that succeed despite invalid Authorization headers.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings related to auth bypass behavior.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    candidate_paths = ["/api/", "/api/health", "/api/status"]
    try:
      for path in candidate_paths:
        url = base_url.rstrip("/") + path
        resp = requests.get(
          url,
          timeout=3,
          verify=False,
          headers={"Authorization": "Bearer invalid-token"},
        )
        if resp.status_code in (200, 204):
          finding = f"VULNERABILITY: API endpoint {url} accepts invalid Authorization header."
          self.P(finding)
          findings.append(finding)
        else:
          findings.append(f"OK: API endpoint {url} rejected invalid Authorization header (status {resp.status_code}).")
    except Exception as e:
      message = f"ERROR: API auth bypass probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: API auth bypass not detected on {base_url}.")
    return "\n".join(findings)
