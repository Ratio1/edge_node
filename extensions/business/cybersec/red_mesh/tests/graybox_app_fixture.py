"""In-memory graybox target for worker-level tests (RM-219).

`FakeApp` answers requests by URL and method; `FakeSession` stands in for
`requests.Session` (patch `requests.Session` with `app.session_factory`). The app
knows one account, a regular user `alice`: there is no admin, so every admin
route denies her the way the graybox app does (403 or 404).
"""

import json
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlparse, urljoin

from requests.structures import CaseInsensitiveDict

BASE = "http://testapp.local:8000"
LOGIN = "/auth/login/"
SECRET = "secret"  # weak JWT signing secret: PT-OAPI2-02 finds it


def _b64(raw: bytes) -> str:
  import base64
  return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(payload: dict, secret: str = SECRET) -> str:
  import hashlib
  import hmac
  head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
  body = _b64(json.dumps(payload).encode())
  sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
  return f"{head}.{body}.{_b64(sig)}"


class FakeResponse:

  def __init__(self, status=200, body="", json_body=None, headers=None,
               url="", history=None, method="GET"):
    self.status_code = status
    self._json = json_body
    self.text = json.dumps(json_body) if json_body is not None else body
    self.content = self.text.encode()
    self.headers = CaseInsensitiveDict({
      "content-type": "application/json" if json_body is not None else "text/html",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
    })
    self.headers.update(headers or {})
    self.url = url
    self.history = history or []
    self.cookies = {}
    self.elapsed = timedelta(milliseconds=5)
    self.request = SimpleNamespace(method=method, url=url, headers={}, body=None)

  def json(self):
    if self._json is not None:
      return self._json
    return json.loads(self.text)

  @property
  def ok(self):
    return self.status_code < 400


class FakeCookie:

  def __init__(self, name, value):
    self.name = name
    self.value = value
    self.secure = True

  def has_nonstandard_attr(self, name):
    return True

  def get_nonstandard_attr(self, name, default=None):
    return "Lax" if name == "SameSite" else ""


class FakeJar:

  def __init__(self):
    self._cookies = {}

  def get_dict(self):
    return dict(self._cookies)

  def get(self, name, default=None):
    return self._cookies.get(name, default)

  def set(self, name, value, **kwargs):
    self._cookies[name] = value

  def clear(self, *args, **kwargs):
    self._cookies.clear()

  def __iter__(self):
    return iter([FakeCookie(n, v) for n, v in self._cookies.items()])


class FakeSession:

  def __init__(self, app):
    self.app = app
    self.cookies = FakeJar()
    self.headers = CaseInsensitiveDict()
    self.verify = True
    self.closed = 0
    self.id = len(app.sessions)
    app.sessions.append(self)

  def request(self, method, url, params=None, data=None, json=None,
              headers=None, allow_redirects=True, timeout=None, **kwargs):
    history = []
    for _ in range(6):
      resp = self.app.handle(self, method.upper(), url, params, data, json,
                             CaseInsensitiveDict({**self.headers, **(headers or {})}))
      location = resp.headers.get("Location")
      if not (allow_redirects and 300 <= resp.status_code < 400 and location):
        resp.history = history
        return resp
      history.append(resp)
      url = urljoin(url, location)
      method, params, data, json = "GET", None, None, None
    return resp

  def get(self, url, **kw):
    return self.request("GET", url, **kw)

  def post(self, url, **kw):
    return self.request("POST", url, **kw)

  def put(self, url, **kw):
    return self.request("PUT", url, **kw)

  def patch(self, url, **kw):
    return self.request("PATCH", url, **kw)

  def delete(self, url, **kw):
    return self.request("DELETE", url, **kw)

  def head(self, url, **kw):
    return self.request("HEAD", url, **kw)

  def options(self, url, **kw):
    return self.request("OPTIONS", url, **kw)

  def close(self):
    self.closed += 1


def _redirect(location, headers=None):
  return FakeResponse(302, "", headers={"Location": location, **(headers or {})})


class FakeApp:
  """The target. `log` records (session id, method, path) for every request."""

  def __init__(self, username="alice", password="pw"):
    self.username = username
    self.password = password
    # A second account with a guessable password: the weak-auth phase finds it.
    self.users = {username: password, "guest": "guest"}
    self.reset_count = 0
    self.sessions = []
    self.log = []
    self.login_attempts = []
    self.token = make_jwt({"sub": username})

  def session_factory(self):
    return FakeSession(self)

  # ── helpers ────────────────────────────────────────────────────────────

  def _authed(self, session, headers):
    if session.cookies.get("sessionid") == "valid":
      return True
    return headers.get("Authorization", "") == f"Bearer {self.token}"

  def _page(self, url, body, status=200, headers=None):
    return FakeResponse(status, body, url=url, headers=headers)

  def _json(self, url, body, status=200, headers=None):
    return FakeResponse(status, json_body=body, url=url, headers=headers)

  def handle(self, session, method, url, params, data, json_body, headers):
    parsed = urlparse(url)
    path = parsed.path
    query = dict(parse_qsl(parsed.query))
    query.update(params or {})
    self.log.append((session.id, method, path))
    full = BASE + path
    authed = self._authed(session, headers)

    if path == LOGIN:
      return self._login(session, method, full, data)
    if path == "/auth/password-reset/":
      return self._reset(full, method)
    if path == "/auth/logout/":
      if method != "POST":
        return self._page(full, "", 405)
      session.cookies.clear()
      return _redirect(LOGIN)
    if path == "/manage/users/":
      # A privileged page the regular user can open: PT-A01-02 reports it.
      return self._page(full, "User management: all users, is_admin flags", status=200)
    if path.startswith("/admin") or path.startswith("/api/admin"):
      # The graybox app denies the regular user with 404 on some admin routes.
      return self._page(full, "denied", 404 if "export" in path else 403)

    if path in ("/debug/", "/debug/config", "/.env"):
      return self._page(full, "DEBUG = True " + "x" * 80)
    if path in ("/api/openapi.json", "/openapi.json"):
      return self._json(full, {"openapi": "3.0.0", "paths": {}})
    if path.startswith("/api/v1/") or path.startswith("/api/v0/"):
      return self._json(full, {"ok": True, "version": path.split("/")[2]})
    if path == "/api/token/":
      if method != "POST":
        return self._page(full, "", 405)
      return self._json(full, {"token": self.token})
    if path == "/api/auth/logout/":
      return self._json(full, {"ok": True})

    if not authed:
      if path.startswith("/api/"):
        return self._json(full, {"detail": "Authentication required"}, 401)
      return _redirect(f"{LOGIN}?next={path}")

    if path == "/api/me/":
      return self._json(full, {"id": 1, "username": self.username})
    if path.startswith("/api/records/"):
      return self._records_api(full, method, path, json_body, data)
    if path.startswith("/api/profile/"):
      return self._json(full, {"id": 1, "username": self.username, "role": "user"})
    if path == "/api/list/":
      return self._json(full, {"items": [1, 2, 3]})
    if path == "/api/auth/signup/":
      return self._json(full, {"ok": True})
    if path.startswith("/api/"):
      return self._json(full, {"ok": True, "path": path, "echo": query})
    if path in ("/", "/dashboard/"):
      return self._page(full, (
        '<a href="/records/">Records</a><a href="/profile/">Profile</a>'
        '<a href="/admin/">Admin</a><a href="/api/records/1/">API</a>'
        '<a href="/auth/logout/">Out</a><a href="/redirect/">Go</a>'
      ), headers={"Access-Control-Allow-Origin": "*"})
    if path == "/records/":
      return self._page(full, '<a href="/records/1/">One</a>')
    if path.startswith("/records/"):
      return self._records_form(full, method, data)
    if path == "/profile/":
      return self._records_form(full, method, data)
    if path == "/redirect/":
      return _redirect(query.get("next", "/dashboard/"))
    return self._page(full, "not found", 404)

  def _login(self, session, method, full, data):
    page = (
      '<form method="post" action="/auth/login/">'
      '<input type="hidden" name="csrfmiddlewaretoken" value="tok">'
      '<input name="username"><input type="password" name="password"></form>'
    )
    if method != "POST":
      session.cookies.set("csrftoken", "pre-auth")
      return self._page(full, page)
    data = data or {}
    self.login_attempts.append((data.get("username"), data.get("password")))
    if self.users.get(data.get("username")) == data.get("password"):
      session.cookies.set("sessionid", "valid")
      session.cookies.set("csrftoken", "c")
      return _redirect("/dashboard/")
    return self._page(full, "Invalid credentials. " + page)

  def _reset(self, full, method):
    if method != "POST":
      return self._page(full, (
        '<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="tok">'
        '<input name="username"></form>'))
    self.reset_count += 1
    return self._page(full, f"Reset link sent. reset-token: tok{self.reset_count:08d}abcdef")

  def _records_api(self, full, method, path, json_body, data):
    try:
      record_id = int(path.strip("/").split("/")[-1])
    except ValueError:
      return self._json(full, {"ok": True})
    owner = self.username if record_id == 1 else "bob"
    if method in ("PATCH", "PUT", "POST"):
      body = json_body if isinstance(json_body, dict) else {}
      return self._json(full, {"id": record_id, "owner": owner, **body})
    if method == "DELETE":
      return self._json(full, {"deleted": True})
    return self._json(full, {"id": record_id, "owner": owner, "title": "t", "amount": 10})

  def _records_form(self, full, method, data):
    if method == "POST":
      return _redirect("/records/")
    return self._page(full, (
      '<form method="post" action="' + full[len(BASE):] + '">'
      '<input type="hidden" name="csrfmiddlewaretoken" value="tok">'
      '<input type="hidden" name="role" value="user">'
      '<input name="amount" value="100.00"><input name="status" value="draft">'
      '<input name="title" type="text" value="t"></form>'
    ))
