"""Structural login-form detection for graybox form auth.

Finds a login form by shape (a POST form with one password input) rather
than by configured path and field names, and lists in-page links that look
like a login entry point. Stdlib only; no product knowledge lives here.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

MAX_HTML_CHARS = 2_000_000
MAX_LOGIN_LINKS = 3
_TEXT_TYPES = ("", "text", "email", "tel")
# Matched against whole path segments (extension stripped) of a link.
_LOGIN_SEGMENTS = ("login", "log-in", "signin", "sign-in", "sign_in", "auth")


@dataclass
class LoginForm:
  action: str          # absolute URL the form posts to
  username_field: str
  password_field: str
  # Every other control a browser would submit, with its default value.
  fields: dict = field(default_factory=dict)


class _Parser(HTMLParser):
  def __init__(self):
    super().__init__(convert_charrefs=True)
    self.forms = []   # {"action", "method", "inputs": [attrs dict]}
    self.links = []
    self._form = None

  def handle_starttag(self, tag, attrs):
    a = {k: (v or "") for k, v in attrs}
    if tag == "a" and a.get("href"):
      self.links.append(a["href"])
    elif tag == "form":
      self._form = {"action": a.get("action", ""),
                    "method": a.get("method", "get").lower(), "inputs": []}
      self.forms.append(self._form)
    elif self._form is not None and tag in ("input", "button"):
      if tag == "button":
        a["type"] = a.get("type", "submit").lower()
      self._form["inputs"].append(a)

  def handle_endtag(self, tag):
    if tag == "form":
      self._form = None


def _parse(html):
  parser = _Parser()
  try:
    parser.feed((html or "")[:MAX_HTML_CHARS])
    parser.close()
  except Exception:
    pass  # keep what was parsed before the malformed part
  return parser


def _submitted_fields(inputs, skip):
  fields, submit_seen = {}, False
  for a in inputs:
    name, kind = a.get("name", ""), a.get("type", "").lower()
    if not name or name in skip:
      continue
    if kind == "hidden" or (kind in _TEXT_TYPES and a.get("value")):
      fields[name] = a.get("value", "")
    elif kind in ("checkbox", "radio") and "checked" in a:
      fields[name] = a.get("value", "on")
    elif kind == "submit" and not submit_seen:
      submit_seen = True
      fields[name] = a.get("value", "")
  return fields


def find_login_form(html, page_url, username=None, password=None,
                    fallback_username="username"):
  """Return the page's login form, or None.

  ``username`` / ``password`` are operator overrides for the field names;
  None means detect. A form with a password input and no username-like
  input falls back to ``fallback_username``.
  """
  for form in _parse(html).forms:
    if form["method"] != "post":
      continue
    inputs = form["inputs"]
    pw = [i for i, a in enumerate(inputs) if a.get("type", "").lower() == "password"]
    if len(pw) != 1:
      continue
    pw_input = inputs[pw[0]]
    if pw_input.get("autocomplete", "").lower() == "new-password":
      continue  # signup / change-password form
    texts = [(i, a["name"]) for i, a in enumerate(inputs)
             if a.get("name") and a.get("type", "").lower() in _TEXT_TYPES]
    before = [n for i, n in texts if i < pw[0]]
    after = [n for i, n in texts if i > pw[0]]
    user_field = username or (before[-1] if before else after[0] if after else fallback_username)
    pass_field = password or pw_input.get("name", "")
    if not pass_field:
      continue
    action = urldefrag(urljoin(page_url, form["action"]) if form["action"] else page_url)[0]
    return LoginForm(
      action=action, username_field=user_field, password_field=pass_field,
      fields=_submitted_fields(inputs, {user_field, pass_field}))
  return None


def login_links(html, page_url):
  """Same-origin links whose path has a login segment; at most 3."""
  origin = urlsplit(page_url)[:2]
  found = []
  for href in _parse(html).links:
    url = urldefrag(urljoin(page_url, href))[0]
    parts = urlsplit(url)
    if parts[:2] != origin or parts.query or url in found:  # query: may be an action
      continue
    segments = [s.lower().split(".")[0] for s in parts.path.split("/") if s]
    if any(s in _LOGIN_SEGMENTS for s in segments):
      found.append(url)
      if len(found) == MAX_LOGIN_LINKS:
        break
  return found
