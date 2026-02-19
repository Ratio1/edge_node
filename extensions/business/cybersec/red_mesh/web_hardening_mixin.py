import requests
from urllib.parse import quote


class _WebHardeningMixin:
  """
  Audit cookie flags, security headers, CORS policy, redirect handling,
  and HTTP methods (OWASP WSTG-CONF).
  """

  def _web_test_flags(self, target, port):
    """
    Check cookies for Secure/HttpOnly/SameSite and directory listing.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings on cookie flags and directory listing.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"

    try:
      resp_main = requests.get(base_url, timeout=3, verify=False)
      # Check cookies for Secure/HttpOnly flags
      cookies_hdr = resp_main.headers.get("Set-Cookie", "")
      if cookies_hdr:
        for cookie in cookies_hdr.split(","):
          if "Secure" not in cookie:
            finding = f"VULNERABILITY: Cookie missing Secure flag: {cookie.strip()} on {base_url}."
            findings.append(finding)
            self.P(finding)
          if "HttpOnly" not in cookie:
            finding = f"VULNERABILITY: Cookie missing HttpOnly flag: {cookie.strip()} on {base_url}."
            findings.append(finding)
            self.P(finding)
          if "SameSite" not in cookie:
            finding = f"VULNERABILITY: Cookie missing SameSite flag: {cookie.strip()} on {base_url}."
            findings.append(finding)
            self.P(finding)
      # Detect directory listing
      if "Index of /" in resp_main.text:
        finding = f"VULNERABILITY: Directory listing exposed at {base_url}."
        findings.append(finding)
        self.P(finding)
    except Exception as e:
      message = f"ERROR: Cookie/flags probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: Cookie flags and directory listing checks passed for {base_url}.")
    return "\n".join(findings)


  def _web_test_security_headers(self, target, port):
    """
    Flag missing HTTP security headers.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings about security headers presence.
    """
    findings = []
    try:
      scheme = "https" if port in (443, 8443) else "http"
      base_url = f"{scheme}://{target}"
      if port not in (80, 443):
        base_url = f"{scheme}://{target}:{port}"
      resp_main = requests.get(base_url, timeout=3, verify=False)
      # Check for missing security headers
      security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
      ]
      for header in security_headers:
        if header not in resp_main.headers:
          finding = f"VULNERABILITY: Missing security header {header} on {base_url}."
          self.P(finding)
          findings.append(finding)
        else:
          findings.append(f"OK: Security header {header} present on {base_url}.")
    except Exception as e:
      message = f"ERROR: Security header probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: Security header check found no issues on {base_url}.")
    return "\n".join(findings)


  def _web_test_cors_misconfiguration(self, target, port):
    """
    Detect overly permissive CORS policies.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings related to CORS policy.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      malicious_origin = "https://attacker.example"
      resp = requests.get(
        base_url,
        timeout=3,
        verify=False,
        headers={"Origin": malicious_origin}
      )
      acao = resp.headers.get("Access-Control-Allow-Origin", "")
      acac = resp.headers.get("Access-Control-Allow-Credentials", "")
      if acao in ("*", malicious_origin):
        finding = f"VULNERABILITY: CORS misconfiguration: {acao} allowed on {base_url}."
        self.P(finding)
        findings.append(finding)
        if acao == "*" and acac.lower() == "true":
          finding = f"VULNERABILITY: CORS allows credentials for wildcard origin on {base_url}."
          self.P(finding, color='r')
          findings.append(finding)
      elif acao:
        info = f"OK: CORS allow origin {acao} on {base_url}."
        self.P(info)
        findings.append(info)
      else:
        findings.append(f"OK: No permissive CORS headers detected on {base_url}.")
    except Exception as e:
      message = f"ERROR: CORS probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: CORS probe did not detect misconfiguration on {base_url}.")
    return "\n".join(findings)


  def _web_test_open_redirect(self, target, port):
    """
    Check common redirect parameters for open redirect abuse.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings about open redirects.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      payload = "https://attacker.example"
      redirect_url = base_url.rstrip("/") + f"/login?next={quote(payload, safe=':/')}"
      resp = requests.get(
        redirect_url,
        timeout=3,
        verify=False,
        allow_redirects=False
      )
      if 300 <= resp.status_code < 400:
        location = resp.headers.get("Location", "")
        if payload in location:
          finding = f"VULNERABILITY: Open redirect via next parameter at {redirect_url}."
          self.P(finding)
          findings.append(finding)
      else:
        findings.append(
          f"OK: Redirect endpoint at {redirect_url} did not expose open redirect behavior."
        )
    except Exception as e:
      message = f"ERROR: Open redirect probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: Open redirect not detected at {base_url}.")
    return "\n".join(findings)


  def _web_test_http_methods(self, target, port):
    """
    Surface risky HTTP verbs enabled on the root resource.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings related to allowed HTTP methods.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      resp = requests.options(base_url, timeout=3, verify=False)
      allow = resp.headers.get("Allow", "")
      if allow:
        risky = [method for method in ("PUT", "DELETE", "TRACE", "CONNECT") if method in allow.upper()]
        if risky:
          finding = f"VULNERABILITY: Risky HTTP methods {', '.join(risky)} enabled on {base_url}."
          self.P(finding)
          findings.append(finding)
        else:
          findings.append(f"OK: Only safe HTTP methods exposed on {base_url} ({allow}).")
      else:
        findings.append(f"OK: OPTIONS response missing Allow header on {base_url}.")
    except Exception as e:
      message = f"ERROR: HTTP methods probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: HTTP methods probe did not detect risky verbs on {base_url}.")
    return "\n".join(findings)
