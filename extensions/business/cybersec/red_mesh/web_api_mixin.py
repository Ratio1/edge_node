import requests

from .findings import Finding, Severity, probe_result, probe_error


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

    if not findings_list:
      findings_list.append(Finding(
        severity=Severity.INFO,
        title="GraphQL introspection disabled or unreachable",
        description=f"Introspection query at {graphql_url} did not return schema data.",
        confidence="firm",
      ))
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

    metadata_paths = [
      ("/latest/meta-data/", "AWS EC2"),
      ("/metadata/computeMetadata/v1/", "GCP"),
      ("/computeMetadata/v1/", "GCP (alt)"),
    ]
    try:
      for path, provider in metadata_paths:
        url = base_url.rstrip("/") + path
        resp = requests.get(url, timeout=3, verify=False, headers={"Metadata-Flavor": "Google"})
        if resp.status_code == 200:
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Cloud metadata endpoint exposed ({provider})",
            description=f"Metadata endpoint at {url} is accessible, potentially leaking "
                        "IAM credentials, instance identity tokens, and cloud configuration.",
            evidence=f"GET {url} returned 200 OK.",
            remediation="Block metadata endpoint access from application layer; use IMDSv2 (AWS) or metadata concealment.",
            owasp_id="A05:2021",
            cwe_id="CWE-918",
            confidence="certain",
          ))
    except Exception as e:
      self.P(f"Metadata endpoint probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "metadata", e)

    if not findings_list:
      findings_list.append(Finding(
        severity=Severity.INFO,
        title="No cloud metadata endpoints detected",
        description=f"Checked AWS, GCP metadata paths on {base_url}.",
        confidence="firm",
      ))
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

    if not findings_list:
      findings_list.append(Finding(
        severity=Severity.INFO,
        title="API endpoints rejected invalid authorization",
        description=f"Checked {', '.join(candidate_paths)} on {base_url} — all rejected invalid tokens.",
        confidence="firm",
      ))
    return probe_result(findings=findings_list)
