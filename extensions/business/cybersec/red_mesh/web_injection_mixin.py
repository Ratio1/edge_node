import requests
from urllib.parse import quote


class _WebInjectionMixin:
  """
  Non-destructive probes for path traversal, reflected XSS,
  and SQL injection (OWASP WSTG-INPV).
  """

  def _web_test_path_traversal(self, target, port):
    """
    Attempt basic path traversal payload against the target.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings about traversal attempts.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      # Path traversal test
      trav_url = base_url.rstrip("/") + "/../../../../etc/passwd"
      resp_trav = requests.get(trav_url, timeout=2, verify=False)
      if "root:x:" in resp_trav.text:
        finding = f"VULNERABILITY: Path traversal at {trav_url}."
        self.P(finding)
        findings.append(finding)
    except Exception as e:
      message = f"ERROR: Path traversal probe failed on {base_url}: {e}"
      self.P(message, color='r')
      findings.append(message)
    if not findings:
      findings.append(f"OK: Path traversal payload not successful on {base_url}.")
    return "\n".join(findings)


  def _web_test_xss(self, target, port):
    """
    Probe reflected XSS by injecting a harmless script tag.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings related to reflected XSS.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      # Basic XSS reflection test
      payload = "<script>alert(1)</script>"
      test_url = base_url.rstrip("/") + f"/{payload}"
      resp_test = requests.get(test_url, timeout=3, verify=False)
      if payload in resp_test.text:
        finding = f"VULNERABILITY: Reflected XSS at {test_url}."
        self.P(finding)
        findings.append(finding)
    except Exception as e:
      message = f"ERROR: XSS probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: Reflected XSS not observed at {base_url}.")
    return "\n".join(findings)


  def _web_test_sql_injection(self, target, port):
    """
    Send boolean SQLi payload and look for database error leakage.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings related to SQL injection.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      # Simple SQL injection probe
      inj_payload = quote("'1' OR '1'='1'")
      inj_url = base_url + f"?id={inj_payload}"
      resp_inj = requests.get(inj_url, timeout=3, verify=False)
      errors = ["sql", "syntax", "mysql", "psql", "postgres", "sqlite", "ora-"]
      body = resp_inj.text.lower()
      if any(err in body for err in errors):
        finding = f"VULNERABILITY: Potential SQL injection at {inj_url}."
        self.P(finding)
        findings.append(finding)
    except Exception as e:
      message = f"ERROR: SQL injection probe failed on {base_url}: {e}"
      self.P(message, color='r')
      findings.append(message)
    if not findings:
      findings.append(f"OK: SQL injection probe did not reveal errors on {base_url}.")
    return "\n".join(findings)
