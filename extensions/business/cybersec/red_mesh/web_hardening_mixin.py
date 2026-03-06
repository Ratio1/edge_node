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
