import requests


class _WebDiscoveryMixin:
  """
  Enumerate exposed files, admin panels, and homepage secrets (OWASP WSTG-INFO).
  """

  def _web_test_common(self, target, port):
    """
    Look for exposed common endpoints and weak access controls.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings from endpoint checks.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      # Check common sensitive endpoints
      for path in ["/robots.txt", "/.env", "/.git/", "/admin", "/login"]:
        url = base_url + path
        resp = requests.get(url, timeout=2, verify=False)
        if resp.status_code == 200:
          finding = f"VULNERABILITY: Accessible resource at {url} (200 OK)."
          self.P(finding)
          findings.append(finding)
        elif resp.status_code in (401, 403):
          self.P(f"Protected resource {url} (status {resp.status_code}).")
          findings.append(
            f"INFO: Access control enforced at {url} (status {resp.status_code})."
          )
    except Exception as e:
      message = f"ERROR: Common endpoint probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: No common endpoint exposures detected on {base_url}.")
    return "\n".join(findings)


  def _web_test_homepage(self, target, port):
    """
    Scan landing pages for clear-text secrets or database dumps.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings from homepage inspection.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      # Check homepage for leaked info
      resp_main = requests.get(base_url, timeout=3, verify=False)
      text = resp_main.text[:10000]
      for marker in ["API_KEY", "PASSWORD", "SECRET", "BEGIN RSA PRIVATE KEY"]:
        if marker in text:
          finding = (
            f"VULNERABILITY: sensitive '{marker}' found on {base_url}."
          )
          findings.append(finding)
          self.P(finding)
      # Check for other potential leaks
      if "database" in text.lower():
        finding = f"VULNERABILITY: potential database leak at {base_url}."
        findings.append(finding)
        self.P(finding)
    except Exception as e:
      message = f"ERROR: Homepage probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: No sensitive markers detected on {base_url} homepage.")
    return "\n".join(findings)
