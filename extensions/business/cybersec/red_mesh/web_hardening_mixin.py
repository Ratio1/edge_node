import re as _re
import time as _time
import secrets as _secrets
import requests
from urllib.parse import quote

from .findings import Finding, Severity, probe_result, probe_error


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
    dict
      Structured findings on cookie flags and directory listing.
    """
    findings_list = []
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
          cookie_name = cookie.strip().split("=")[0] if "=" in cookie else cookie.strip()[:30]
          if "Secure" not in cookie:
            findings_list.append(Finding(
              severity=Severity.MEDIUM,
              title=f"Cookie missing Secure flag: {cookie_name}",
              description=f"Cookie will be sent over unencrypted HTTP connections.",
              evidence=f"Set-Cookie: {cookie.strip()[:80]} on {base_url}",
              remediation="Add the Secure attribute to this cookie.",
              owasp_id="A05:2021",
              cwe_id="CWE-614",
              confidence="certain",
            ))
          if "HttpOnly" not in cookie:
            findings_list.append(Finding(
              severity=Severity.MEDIUM,
              title=f"Cookie missing HttpOnly flag: {cookie_name}",
              description=f"Cookie is accessible to JavaScript, enabling theft via XSS.",
              evidence=f"Set-Cookie: {cookie.strip()[:80]} on {base_url}",
              remediation="Add the HttpOnly attribute to this cookie.",
              owasp_id="A05:2021",
              cwe_id="CWE-1004",
              confidence="certain",
            ))
          if "SameSite" not in cookie:
            findings_list.append(Finding(
              severity=Severity.MEDIUM,
              title=f"Cookie missing SameSite flag: {cookie_name}",
              description=f"Cookie may be sent with cross-site requests, enabling CSRF.",
              evidence=f"Set-Cookie: {cookie.strip()[:80]} on {base_url}",
              remediation="Add SameSite=Lax or SameSite=Strict to this cookie.",
              owasp_id="A01:2021",
              cwe_id="CWE-1275",
              confidence="certain",
            ))
      # Detect directory listing
      if "Index of /" in resp_main.text:
        findings_list.append(Finding(
          severity=Severity.MEDIUM,
          title="Directory listing exposed",
          description=f"Directory listing is enabled at {base_url}, revealing file structure.",
          evidence=f"'Index of /' found in response body.",
          remediation="Disable directory listing in the web server configuration.",
          owasp_id="A01:2021",
          cwe_id="CWE-548",
          confidence="certain",
        ))
    except Exception as e:
      self.P(f"Cookie/flags probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "flags", e)

    return probe_result(findings=findings_list)


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
    dict
      Structured findings about security headers presence.
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"

    _HEADER_META = {
      "Content-Security-Policy": (Severity.MEDIUM, "CWE-693", "A05:2021",
        "Prevents XSS and data injection by controlling resource loading."),
      "X-Frame-Options": (Severity.MEDIUM, "CWE-1021", "A05:2021",
        "Prevents clickjacking by controlling iframe embedding."),
      "X-Content-Type-Options": (Severity.LOW, "CWE-693", "A05:2021",
        "Prevents MIME-type sniffing attacks."),
      "Strict-Transport-Security": (Severity.MEDIUM, "CWE-319", "A02:2021",
        "Enforces HTTPS and prevents protocol downgrade attacks."),
      "Referrer-Policy": (Severity.LOW, "CWE-200", "A05:2021",
        "Controls how much referrer information is included with requests."),
    }

    try:
      resp_main = requests.get(base_url, timeout=3, verify=False)
      for header, (severity, cwe, owasp, desc) in _HEADER_META.items():
        if header not in resp_main.headers:
          findings_list.append(Finding(
            severity=severity,
            title=f"Missing security header: {header}",
            description=desc,
            evidence=f"Header {header} absent from {base_url} response.",
            remediation=f"Add the {header} header to server responses.",
            owasp_id=owasp,
            cwe_id=cwe,
            confidence="certain",
          ))
    except Exception as e:
      self.P(f"Security header probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "security_headers", e)

    return probe_result(findings=findings_list)


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
    dict
      Structured findings related to CORS policy.
    """
    findings_list = []
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
      if acao == "*" and acac.lower() == "true":
        findings_list.append(Finding(
          severity=Severity.CRITICAL,
          title="CORS allows credentials with wildcard origin",
          description="Any origin can make credentialed cross-site requests, enabling full account takeover.",
          evidence=f"Access-Control-Allow-Origin: *, Allow-Credentials: true on {base_url}",
          remediation="Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.",
          owasp_id="A05:2021",
          cwe_id="CWE-942",
          confidence="certain",
        ))
      elif acao in ("*", malicious_origin):
        findings_list.append(Finding(
          severity=Severity.HIGH,
          title=f"CORS misconfiguration: {acao} allowed",
          description=f"CORS policy reflects attacker-controlled origins, enabling cross-site data theft.",
          evidence=f"Access-Control-Allow-Origin: {acao} on {base_url}",
          remediation="Restrict Access-Control-Allow-Origin to trusted domains only.",
          owasp_id="A05:2021",
          cwe_id="CWE-942",
          confidence="certain",
        ))
    except Exception as e:
      self.P(f"CORS probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "cors", e)

    return probe_result(findings=findings_list)


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
    dict
      Structured findings about open redirects.
    """
    findings_list = []
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
          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title="Open redirect via next parameter",
            description="The login endpoint redirects to attacker-controlled URLs via the next parameter.",
            evidence=f"Location: {location} at {redirect_url}",
            remediation="Validate redirect targets against an allowlist of trusted domains.",
            owasp_id="A01:2021",
            cwe_id="CWE-601",
            confidence="certain",
          ))
    except Exception as e:
      self.P(f"Open redirect probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "open_redirect", e)

    return probe_result(findings=findings_list)


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
    dict
      Structured findings related to allowed HTTP methods.
    """
    findings_list = []
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
          risky_str = ", ".join(risky)
          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Risky HTTP methods enabled: {risky_str}",
            description=f"OPTIONS response lists dangerous methods on {base_url}.",
            evidence=f"Allow: {allow}",
            remediation="Disable risky HTTP methods in the web server configuration.",
            owasp_id="A05:2021",
            cwe_id="CWE-749",
            confidence="certain",
          ))
    except Exception as e:
      self.P(f"HTTP methods probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "http_methods", e)

    return probe_result(findings=findings_list)


  # Regex for POST forms and hidden inputs (CSRF detection)
  _FORM_RE = _re.compile(
    r'<form[^>]*method\s*=\s*["\']?post["\']?[^>]*>(.*?)</form>',
    _re.IGNORECASE | _re.DOTALL,
  )
  _HIDDEN_INPUT_RE = _re.compile(
    r'<input[^>]*type\s*=\s*["\']?hidden["\']?[^>]*name\s*=\s*["\']?([^"\'>\s]+)',
    _re.IGNORECASE,
  )
  _CSRF_FIELD_NAMES = frozenset({
    "csrf_token", "_token", "csrfmiddlewaretoken",
    "authenticity_token", "__requestverificationtoken",
    "_csrf", "csrf", "xsrf_token", "_xsrf",
    "anti-forgery-token", "__antiforgerytoken",
  })

  def _web_test_csrf(self, target, port):
    """
    Detect POST forms missing CSRF protection tokens.

    Checks the landing page, /login, /contact, and /register for
    <form method="POST"> tags without a CSRF-like hidden field.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    dict
      Structured findings about missing CSRF protection.
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"

    for path in ("/", "/login", "/contact", "/register"):
      try:
        resp = requests.get(base_url + path, timeout=3, verify=False)
        if resp.status_code != 200:
          continue

        # Check response headers for SPA-style CSRF tokens
        has_header_token = any(
          h.lower() in resp.headers
          for h in ("x-csrf-token", "x-xsrf-token")
        )
        if has_header_token:
          continue

        for form_match in self._FORM_RE.finditer(resp.text):
          form_html = form_match.group(1)
          hidden_names = {
            name.lower()
            for name in self._HIDDEN_INPUT_RE.findall(form_html)
          }
          if hidden_names & self._CSRF_FIELD_NAMES:
            continue  # has CSRF token — OK

          # Extract form action for evidence
          action_match = _re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', form_match.group(0), _re.IGNORECASE)
          action = action_match.group(1) if action_match else path

          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title=f"POST form at {path} missing CSRF token",
            description="A form submitting via POST has no hidden CSRF token field, "
                        "making it vulnerable to cross-site request forgery.",
            evidence=f"Form action={action}, hidden fields={sorted(hidden_names) if hidden_names else 'none'}",
            remediation="Add a CSRF token to all state-changing forms.",
            owasp_id="A01:2021",
            cwe_id="CWE-352",
            confidence="firm",
          ))
      except Exception:
        continue

    return probe_result(findings=findings_list)


  # ── A04:2021 — Insecure Design probes ──────────────────────────────

  _ENUM_MESSAGE_VARIANTS = frozenset({
    "user not found", "no such user", "unknown user", "account not found",
    "invalid username", "email not found", "does not exist",
  })

  def _web_test_account_enumeration(self, target, port):
    """
    Detect account enumeration via login response differences.

    Compares responses for a definitely-invalid username vs plausibly-real
    usernames.  Differences in status code, body length, or error message
    indicate the server reveals account existence.

    Parameters
    ----------
    target : str
    port : int

    Returns
    -------
    dict
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    login_paths = ["/login", "/api/login", "/auth/login"]
    fake_user = f"nonexistent_user_{_secrets.token_hex(6)}"
    real_candidates = ["admin", "root", "test"]
    password = "WrongPassword123!"

    for path in login_paths:
      url = base_url.rstrip("/") + path
      try:
        resp_fake = requests.post(
          url, data={"username": fake_user, "password": password},
          timeout=3, verify=False, allow_redirects=False,
        )
        if resp_fake.status_code == 404:
          continue

        for real_user in real_candidates:
          resp_real = requests.post(
            url, data={"username": real_user, "password": password},
            timeout=3, verify=False, allow_redirects=False,
          )
          fake_lower = resp_fake.text.lower()
          real_lower = resp_real.text.lower()
          fake_has_enum = any(m in fake_lower for m in self._ENUM_MESSAGE_VARIANTS)
          real_has_enum = any(m in real_lower for m in self._ENUM_MESSAGE_VARIANTS)
          if fake_has_enum and not real_has_enum:
            findings_list.append(Finding(
              severity=Severity.MEDIUM,
              title="Account enumeration via login: different error messages",
              description=f"Login at {path} returns different error messages for "
                          "valid vs invalid usernames, revealing account existence.",
              evidence="Invalid user response mentions 'not found'; valid user response does not.",
              remediation="Use generic error messages: 'Invalid credentials' for all failures.",
              owasp_id="A04:2021",
              cwe_id="CWE-204",
              confidence="firm",
            ))
            return probe_result(findings=findings_list)

          # Check response length difference (>20%)
          len_fake = len(resp_fake.text)
          len_real = len(resp_real.text)
          if len_fake > 0 and abs(len_real - len_fake) / max(len_fake, 1) > 0.2:
            if resp_fake.status_code == resp_real.status_code:
              findings_list.append(Finding(
                severity=Severity.MEDIUM,
                title="Account enumeration via login: response size differs",
                description=f"Login at {path} returns different-sized responses for "
                            "valid vs invalid usernames.",
                evidence=f"Invalid user: {len_fake} bytes, '{real_user}': {len_real} bytes "
                         f"(delta {abs(len_real - len_fake)} bytes).",
                remediation="Ensure login responses are identical regardless of username validity.",
                owasp_id="A04:2021",
                cwe_id="CWE-204",
                confidence="firm",
              ))
              return probe_result(findings=findings_list)
      except Exception:
        continue

    return probe_result(findings=findings_list)


  _CAPTCHA_KEYWORDS = frozenset({"captcha", "recaptcha", "hcaptcha", "g-recaptcha"})

  def _web_test_rate_limiting(self, target, port):
    """
    Detect missing rate limiting on authentication endpoints.

    Sends 5 login attempts with 500ms spacing and checks for 429 responses,
    rate-limit headers, or CAPTCHA challenges.

    Parameters
    ----------
    target : str
    port : int

    Returns
    -------
    dict
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    login_paths = ["/login", "/api/login", "/auth/login"]
    password = "WrongPassword123!"
    attempt_count = 5

    for path in login_paths:
      url = base_url.rstrip("/") + path
      try:
        probe_resp = requests.get(url, timeout=3, verify=False, allow_redirects=False)
        if probe_resp.status_code == 404:
          continue

        rate_limited = False
        for i in range(attempt_count):
          resp = requests.post(
            url,
            data={"username": f"test_user_{i}", "password": password},
            timeout=3, verify=False, allow_redirects=False,
          )
          if resp.status_code == 429:
            rate_limited = True
            break
          if resp.headers.get("Retry-After") or resp.headers.get("X-RateLimit-Remaining"):
            rate_limited = True
            break
          body_lower = resp.text.lower()
          if any(kw in body_lower for kw in self._CAPTCHA_KEYWORDS):
            rate_limited = True
            break
          if i < attempt_count - 1:
            _time.sleep(0.5)

        if not rate_limited:
          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title=f"No rate limiting on login endpoint ({path})",
            description=f"{attempt_count} rapid login attempts accepted without "
                        "429 response, rate-limit headers, or CAPTCHA challenge.",
            evidence=f"POST {url} x{attempt_count} with 500ms spacing — all accepted.",
            remediation="Implement rate limiting on authentication endpoints.",
            owasp_id="A04:2021",
            cwe_id="CWE-307",
            confidence="firm",
          ))
          return probe_result(findings=findings_list)
      except Exception:
        continue

    return probe_result(findings=findings_list)


  # ── A08:2021 — Subresource integrity & mixed content ────────────────

  _SCRIPT_SRC_RE = _re.compile(
    r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>',
    _re.IGNORECASE,
  )
  _LINK_HREF_RE = _re.compile(
    r'<link[^>]*\brel\s*=\s*["\']stylesheet["\'][^>]*\bhref\s*=\s*["\']([^"\']+)["\']',
    _re.IGNORECASE,
  )
  _INTEGRITY_RE = _re.compile(r'\bintegrity\s*=\s*["\']', _re.IGNORECASE)
  _IMG_SRC_RE = _re.compile(
    r'<img[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', _re.IGNORECASE,
  )
  _IFRAME_SRC_RE = _re.compile(
    r'<iframe[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', _re.IGNORECASE,
  )

  def _web_test_subresource_integrity(self, target, port):
    """
    Detect external scripts/stylesheets loaded without SRI attributes.

    Parameters
    ----------
    target : str
    port : int

    Returns
    -------
    dict
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    try:
      resp = requests.get(base_url, timeout=4, verify=False)
      if resp.status_code != 200:
        return probe_result(findings=findings_list)
      html = resp.text

      for match in self._SCRIPT_SRC_RE.finditer(html):
        src = match.group(1)
        if not src.startswith(("http://", "https://")) or target in src:
          continue
        tag_start = match.start()
        tag_end = html.find(">", match.end()) + 1
        tag_html = html[tag_start:tag_end]
        if self._INTEGRITY_RE.search(tag_html):
          continue
        findings_list.append(Finding(
          severity=Severity.MEDIUM,
          title="External script loaded without SRI",
          description=f"Script from {src[:80]} has no integrity attribute. "
                      "A compromised CDN could serve malicious code.",
          evidence=f'<script src="{src[:80]}" ...> without integrity=',
          remediation="Add integrity= and crossorigin= attributes to external scripts.",
          owasp_id="A08:2021",
          cwe_id="CWE-829",
          confidence="certain",
        ))
        if len(findings_list) >= 5:
          break

      if len(findings_list) < 5:
        for match in self._LINK_HREF_RE.finditer(html):
          href = match.group(1)
          if not href.startswith(("http://", "https://")) or target in href:
            continue
          tag_start = match.start()
          tag_end = html.find(">", match.end()) + 1
          tag_html = html[tag_start:tag_end]
          if self._INTEGRITY_RE.search(tag_html):
            continue
          findings_list.append(Finding(
            severity=Severity.LOW,
            title="External stylesheet loaded without SRI",
            description=f"Stylesheet from {href[:80]} has no integrity attribute.",
            evidence=f'<link href="{href[:80]}" ...> without integrity=',
            remediation="Add integrity= and crossorigin= attributes to external stylesheets.",
            owasp_id="A08:2021",
            cwe_id="CWE-829",
            confidence="certain",
          ))
          if len(findings_list) >= 5:
            break

    except Exception as e:
      self.P(f"SRI probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "sri", e)

    return probe_result(findings=findings_list)


  def _web_test_mixed_content(self, target, port):
    """
    Detect HTTPS pages loading resources over plain HTTP.

    Only runs on HTTPS ports (443, 8443). Active mixed content (scripts) is
    HIGH; passive (images, stylesheets, iframes) is MEDIUM.

    Parameters
    ----------
    target : str
    port : int

    Returns
    -------
    dict
    """
    findings_list = []
    if port not in (443, 8443):
      return probe_result(findings=findings_list)

    base_url = f"https://{target}" if port == 443 else f"https://{target}:{port}"

    try:
      resp = requests.get(base_url, timeout=4, verify=False)
      if resp.status_code != 200:
        return probe_result(findings=findings_list)
      html = resp.text

      for match in self._SCRIPT_SRC_RE.finditer(html):
        src = match.group(1)
        if src.startswith("http://"):
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title="Active mixed content: script loaded over HTTP",
            description=f"HTTPS page loads script from {src[:80]} over plain HTTP. "
                        "An attacker can modify the script in transit.",
            evidence=f'<script src="{src[:80]}"> on HTTPS page',
            remediation="Load all scripts over HTTPS.",
            owasp_id="A08:2021",
            cwe_id="CWE-319",
            confidence="certain",
          ))
          if len(findings_list) >= 5:
            break

      if len(findings_list) < 5:
        passive_patterns = [
          (self._LINK_HREF_RE, "stylesheet"),
          (self._IMG_SRC_RE, "image"),
          (self._IFRAME_SRC_RE, "iframe"),
        ]
        for regex, resource_type in passive_patterns:
          for match in regex.finditer(html):
            url = match.group(1)
            if url.startswith("http://"):
              findings_list.append(Finding(
                severity=Severity.MEDIUM,
                title=f"Passive mixed content: {resource_type} loaded over HTTP",
                description=f"HTTPS page loads {resource_type} from {url[:80]} over plain HTTP.",
                evidence=f'{resource_type} src/href="{url[:80]}" on HTTPS page',
                remediation=f"Load all {resource_type}s over HTTPS.",
                owasp_id="A08:2021",
                cwe_id="CWE-319",
                confidence="certain",
              ))
              if len(findings_list) >= 5:
                break
          if len(findings_list) >= 5:
            break

    except Exception as e:
      self.P(f"Mixed content probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "mixed_content", e)

    return probe_result(findings=findings_list)
