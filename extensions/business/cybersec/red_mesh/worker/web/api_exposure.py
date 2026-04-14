import requests

from ...findings import Finding, Severity, probe_result, probe_error


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
    dict
      Structured findings on GraphQL introspection exposure.
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    graphql_url = base_url.rstrip("/") + "/graphql"
    try:
      payload = {"query": "{__schema{types{name}}}"}
      resp = requests.post(graphql_url, json=payload, timeout=5, verify=False)
      if resp.status_code == 200 and "__schema" in resp.text:
        findings_list.append(Finding(
          severity=Severity.MEDIUM,
          title="GraphQL introspection enabled",
          description=f"GraphQL endpoint at {graphql_url} exposes the full schema "
                      "via introspection, revealing all types, queries, and mutations.",
          evidence=f"POST {graphql_url} with __schema query returned 200 with schema data.",
          remediation="Disable introspection in production (e.g. introspection: false in Apollo Server).",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))
    except Exception as e:
      self.P(f"GraphQL probe failed on {graphql_url}: {e}", color='y')
      return probe_error(target, port, "graphql", e)

    return probe_result(findings=findings_list)


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
    dict
      Structured findings on metadata endpoint exposure.
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"

    # (path, provider, extra_headers)
    metadata_paths = [
      ("/latest/meta-data/", "AWS EC2", {}),
      ("/metadata/computeMetadata/v1/", "GCP", {"Metadata-Flavor": "Google"}),
      ("/computeMetadata/v1/", "GCP (alt)", {"Metadata-Flavor": "Google"}),
      ("/metadata/instance?api-version=2021-02-01", "Azure IMDS", {"Metadata": "true"}),
      ("/metadata/v1/", "DigitalOcean", {}),
      ("/latest/meta-data", "Alibaba Cloud ECS", {}),
      ("/opc/v2/instance/", "Oracle Cloud", {}),
    ]
    try:
      for path, provider, extra_headers in metadata_paths:
        url = base_url.rstrip("/") + path
        resp = requests.get(url, timeout=3, verify=False, headers=extra_headers)
        if resp.status_code == 200:
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Cloud metadata endpoint exposed ({provider})",
            description=f"Metadata endpoint at {url} is accessible, potentially leaking "
                        "IAM credentials, instance identity tokens, and cloud configuration.",
            evidence=f"GET {url} returned 200 OK.",
            remediation="Block metadata endpoint access from application layer; use IMDSv2 (AWS) or metadata concealment.",
            owasp_id="A10:2021",
            cwe_id="CWE-918",
            confidence="certain",
          ))
    except Exception as e:
      self.P(f"Metadata endpoint probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "metadata", e)

    return probe_result(findings=findings_list)


  # SSRF-prone parameter names commonly seen in web applications
  _SSRF_PARAMS = ("url", "redirect", "proxy", "callback", "dest", "uri",
                  "src", "href", "link", "fetch")
  # Markers that indicate internal/metadata content was returned
  _SSRF_MARKERS = ("ami-id", "instance-id", "iam/security-credentials",
                   "meta-data", "computeMetadata", "hostname", "local-ipv4")

  def _web_test_ssrf_basic(self, target, port):
    """
    Low-confidence SSRF check: inject metadata URL into common parameters.

    Real SSRF typically lives in backend webhook/PDF/image endpoints that
    require deeper crawling to discover.  This probe catches low-hanging fruit
    only — URL-accepting parameters on well-known paths.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    dict
      Structured findings.
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    ssrf_payload = "http://169.254.169.254/latest/meta-data/"
    candidate_paths = ["/", "/api/", "/webhook"]

    try:
      for path in candidate_paths:
        if len(findings_list) >= 2:
          break
        for param in self._SSRF_PARAMS:
          if len(findings_list) >= 2:
            break
          try:
            url = f"{base_url.rstrip('/')}{path}?{param}={ssrf_payload}"
            resp = requests.get(url, timeout=4, verify=False)
            body_lower = resp.text.lower()
            if resp.status_code == 200 and any(m in body_lower for m in self._SSRF_MARKERS):
              findings_list.append(Finding(
                severity=Severity.CRITICAL,
                title=f"SSRF: parameter '{param}' fetches internal resources",
                description=f"Injecting a metadata URL into the '{param}' parameter at "
                            f"{path} returned cloud metadata content, indicating SSRF.",
                evidence=f"GET {url} returned metadata markers.",
                remediation="Validate and restrict URLs accepted by server-side parameters; "
                            "block requests to internal/metadata IPs.",
                owasp_id="A10:2021",
                cwe_id="CWE-918",
                confidence="certain",
              ))
              break  # one finding per path is enough
          except Exception:
            pass
    except Exception as e:
      self.P(f"SSRF basic probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "ssrf_basic", e)

    return probe_result(findings=findings_list)


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
    dict
      Structured findings related to auth bypass behavior.
    """
    findings_list = []
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
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title=f"API auth bypass: {path} accepts invalid token",
            description=f"API endpoint {url} returned success with a fabricated Bearer token, "
                        "indicating missing or broken authentication middleware.",
            evidence=f"GET {url} with 'Bearer invalid-token' returned {resp.status_code}.",
            remediation="Validate Bearer tokens in authentication middleware for all API endpoints.",
            owasp_id="A07:2021",
            cwe_id="CWE-287",
            confidence="certain",
          ))
    except Exception as e:
      self.P(f"API auth bypass probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "api_auth", e)

    return probe_result(findings=findings_list)
