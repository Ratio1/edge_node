import requests
from urllib.parse import quote

class _WebTestsMixin:
  """HTTP-centric probes that emulate manual red-team playbooks."""

  def _web_test_common(self, target, port):
    """Look for exposed common endpoints and weak access controls."""
    result = ""
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
          result += finding + "\n"
        elif resp.status_code in (401, 403):
          self.P(f"Protected resource {url} (status {resp.status_code}).")
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result

  
  def _web_test_homepage(self, target, port):
    """Scan landing pages for clear-text secrets or database dumps."""
    result = ""
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
          result += finding + "\n"
          self.P(finding)
      # Check for other potential leaks
      if "database" in text.lower():
        finding = f"VULNERABILITY: potential database leak at {base_url}."
        result += finding + "\n"
        self.P(finding)
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_security_headers(self, target, port):
    """Flag missing HTTP security headers (OWASP A05/A06)."""
    result = ""
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
          result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_flags(self, target, port):
    """Check cookies for Secure/HttpOnly/SameSite and directory listing."""
    result = ""
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
            result += finding + "\n"
            self.P(finding)
          if "HttpOnly" not in cookie:
            finding = f"VULNERABILITY: Cookie missing HttpOnly flag: {cookie.strip()} on {base_url}."
            result += finding + "\n"
            self.P(finding)
          if "SameSite" not in cookie:
            finding = f"VULNERABILITY: Cookie missing SameSite flag: {cookie.strip()} on {base_url}."
            result += finding + "\n"
            self.P(finding)
      # Detect directory listing
      if "Index of /" in resp_main.text:
        finding = f"VULNERABILITY: Directory listing exposed at {base_url}."
        result += finding + "\n"
        self.P(finding)
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_xss(self, target, port):
    """Probe reflected XSS by injecting a harmless script tag."""
    result = ""
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
        result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result     


  def _web_test_path_traversal(self, target, port):
    """Attempt basic path traversal payload against the target."""
    result = ""
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
        result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}", color='r')
    return result     
  
  
  def _web_test_sql_injection(self, target, port):
    """Send boolean SQLi payload and look for database error leakage."""
    result = ""
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
        result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}", color='r')
    return result


  def _web_test_cors_misconfiguration(self, target, port):
    """Detect overly permissive CORS policies (OWASP A01/A05)."""
    result = ""
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
        result += finding + "\n"
        if acao == "*" and acac.lower() == "true":
          finding = f"VULNERABILITY: CORS allows credentials for wildcard origin on {base_url}."
          self.P(finding, color='r')
          result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_open_redirect(self, target, port):
    """Check common redirect parameters for open redirect abuse."""
    result = ""
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
          result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_http_methods(self, target, port):
    """Surface risky HTTP verbs enabled on the root resource."""
    result = ""
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
          result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_graphql_introspection(self, target, port):
    """Check if GraphQL introspection is exposed in production endpoints."""
    result = ""
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
        result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_metadata_endpoints(self, target, port):
    """Probe cloud metadata paths to detect SSRF-style exposure."""
    result = ""
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
          result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result


  def _web_test_api_auth_bypass(self, target, port):
    """Detect APIs that succeed despite invalid Authorization headers."""
    result = ""
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
          result += finding + "\n"
    except Exception as e:
      self.P(f"Web test error on port {port}: {e}")
    return result
