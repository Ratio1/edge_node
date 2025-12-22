import requests
from urllib.parse import quote

class _WebTestsMixin:
  """
  HTTP-centric probes that emulate manual red-team playbooks.

  Methods perform lightweight checks for common web vulnerabilities across
  discovered web services.
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
