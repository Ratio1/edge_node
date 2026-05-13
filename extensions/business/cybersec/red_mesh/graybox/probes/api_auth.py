"""API authentication probes — OWASP API2 (Broken Authentication)."""

import base64
import hashlib
import hmac
import json

import requests

from .base import ProbeBase


def _b64url(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
  pad = "=" * (-len(s) % 4)
  return base64.urlsafe_b64decode(s + pad)


def _forge_jwt(header: dict, payload: dict, secret: str | None = None) -> str:
  h = _b64url(json.dumps(header, separators=(",", ":")).encode())
  p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
  signing_input = f"{h}.{p}".encode()
  if header.get("alg") == "none":
    return f"{h}.{p}."
  if header.get("alg") == "HS256" and secret is not None:
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"
  return f"{h}.{p}."


def _decode_jwt_payload(token: str) -> dict | None:
  try:
    parts = token.split(".")
    if len(parts) < 2:
      return None
    return json.loads(_b64url_decode(parts[1]))
  except Exception:
    return None


class ApiAuthProbes(ProbeBase):
  """OWASP API2 (Broken Authentication) graybox probes.

  Scenarios:
    PT-OAPI2-01 — JWT missing-signature (alg=none) accepted.
    PT-OAPI2-02 — JWT signed with weak HMAC secret.
    PT-OAPI2-03 — Token not invalidated on logout (stateful, re-auth revert).
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return self.findings
    tok = api_security.token_endpoints
    if not (tok.token_path and tok.protected_path):
      return self.findings
    self.run_safe("api_jwt_alg_none", self._test_jwt_alg_none)
    self.run_safe("api_jwt_weak_hmac", self._test_jwt_weak_hmac)
    self.run_safe("api_token_logout_invalidation",
                   self._test_token_logout_invalidation)
    return self.findings

  # ── helpers ────────────────────────────────────────────────────────

  def _obtain_token(self):
    """POST credentials to token_path; return (token, raw_payload) or (None, None)."""
    tok = self.target_config.api_security.token_endpoints
    session = self.auth.official_session or self.auth.regular_session
    if session is None:
      return None, None
    if not self.budget():
      return None, None
    url = self.target_url + tok.token_path
    self.safety.throttle()
    try:
      resp = session.post(url, timeout=10)
    except requests.RequestException:
      return None, None
    if resp.status_code >= 400:
      return None, None
    try:
      data = resp.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
      return None, None
    token = (
      data.get("token") or data.get("access_token") or data.get("jwt") or ""
    )
    return token, data

  # ── PT-OAPI2-01 — alg=none ────────────────────────────────────────

  def _test_jwt_alg_none(self):
    title = "API JWT missing-signature accepted (alg=none)"
    owasp = "API2:2023"
    real_token, _ = self._obtain_token()
    if not real_token:
      self.emit_inconclusive(
        "PT-OAPI2-01", title, owasp, "token_issuance_failed",
      )
      return
    original_payload = _decode_jwt_payload(real_token) or {}
    forged_payload = dict(original_payload)
    forged_payload["is_admin"] = True
    forged = _forge_jwt({"alg": "none", "typ": "JWT"}, forged_payload)

    tok = self.target_config.api_security.token_endpoints
    url = self.target_url + tok.protected_path
    if not self.budget():
      return
    self.safety.throttle()
    try:
      resp = requests.get(
        url, headers={"Authorization": f"Bearer {forged}"},
        timeout=10, verify=self.auth.verify_tls if hasattr(self.auth, "verify_tls") else True,
        allow_redirects=False,
      )
    except requests.RequestException:
      self.emit_inconclusive(
        "PT-OAPI2-01", title, owasp, "protected_path_transport_error",
      )
      return

    if resp.status_code < 400:
      self.emit_vulnerable(
        "PT-OAPI2-01", title,
        "CRITICAL", owasp, ["CWE-347", "CWE-327"],
        [f"token_path={tok.token_path}",
         f"protected_path={tok.protected_path}",
         "forged_alg=none",
         f"forged_claim=is_admin",
         f"server_returned_status={resp.status_code}"],
        remediation=(
          "Reject JWTs with alg=none unconditionally. Verify the signing "
          "algorithm against an explicit allowlist before signature "
          "verification."
        ),
      )
    else:
      self.emit_clean(
        "PT-OAPI2-01", title, owasp,
        [f"forged_alg=none", f"server_returned_status={resp.status_code}"],
      )

  # ── PT-OAPI2-02 — weak HMAC secret ───────────────────────────────

  def _test_jwt_weak_hmac(self):
    title = "API JWT signed with weak HMAC secret"
    owasp = "API2:2023"
    real_token, _ = self._obtain_token()
    if not real_token:
      self.emit_inconclusive(
        "PT-OAPI2-02", title, owasp, "token_issuance_failed",
      )
      return
    parts = real_token.split(".")
    if len(parts) != 3:
      self.emit_inconclusive(
        "PT-OAPI2-02", title, owasp, "token_not_jwt_shape",
      )
      return
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
      sig = _b64url_decode(sig_b64)
    except Exception:
      self.emit_inconclusive(
        "PT-OAPI2-02", title, owasp, "token_signature_not_base64",
      )
      return

    candidates = list(
      self.target_config.api_security.token_endpoints.weak_secret_candidates
    )
    for secret in candidates:
      if not secret:
        continue
      try:
        expected = hmac.new(secret.encode(), signing_input,
                              hashlib.sha256).digest()
      except Exception:
        continue
      if hmac.compare_digest(expected, sig):
        self.emit_vulnerable(
          "PT-OAPI2-02", title,
          "HIGH", owasp, ["CWE-327", "CWE-521"],
          [f"weak_secret_was=<redacted:len={len(secret)}>",
           f"token_prefix={real_token[:8]}",
           "verification=local_HS256_compare"],
          remediation=(
            "Rotate the JWT signing secret to a high-entropy value (≥32 "
            "random bytes). Store the secret in a secret manager, not in "
            "source / env defaults / framework boilerplate."
          ),
        )
        return
    self.emit_clean(
      "PT-OAPI2-02", title, owasp,
      [f"candidates_tested={len(candidates)}",
       f"token_prefix={real_token[:8]}"],
    )

  # ── PT-OAPI2-03 — Logout doesn't invalidate (STATEFUL) ───────────

  def _test_token_logout_invalidation(self):
    title = "API token not invalidated on logout"
    owasp = "API2:2023"
    tok = self.target_config.api_security.token_endpoints
    if not tok.logout_path:
      self.emit_inconclusive(
        "PT-OAPI2-03", title, owasp, "no_logout_path_configured",
      )
      return

    real_token = [None]

    def baseline():
      t, _ = self._obtain_token()
      real_token[0] = t
      if not t:
        raise RuntimeError("token_issuance_failed")
      return t

    def mutate(base):
      if not self.budget():
        return False
      url = self.target_url + tok.logout_path
      self.safety.throttle()
      try:
        resp = requests.post(
          url, headers={"Authorization": f"Bearer {base}"},
          timeout=10, allow_redirects=False,
        )
      except requests.RequestException:
        return False
      return resp.status_code < 400

    def verify(base):
      if not self.budget():
        return False
      url = self.target_url + tok.protected_path
      try:
        resp = requests.get(
          url, headers={"Authorization": f"Bearer {base}"},
          timeout=10, allow_redirects=False,
        )
      except requests.RequestException:
        return False
      # Vulnerable iff protected path STILL accepts the supposedly-revoked token.
      return resp.status_code < 400

    def revert(base):
      # Cleanup is implicit — orchestrator can re-authenticate on demand
      # via `ensure_sessions`. We just note the rollback path here.
      return True

    self.run_stateful(
      "PT-OAPI2-03",
      baseline_fn=baseline,
      mutate_fn=mutate,
      verify_fn=verify,
      revert_fn=revert,
      finding_kwargs={
        "title": title, "owasp": owasp, "severity": "MEDIUM",
        "cwe": ["CWE-613"],
        "evidence": [f"token_path={tok.token_path}",
                     f"logout_path={tok.logout_path}",
                     f"protected_path={tok.protected_path}"],
        "replay_steps": [
          "POST to token_path and capture the issued bearer token.",
          "POST to logout_path with that token.",
          "GET protected_path with the same token after logout.",
          "Observe the protected path still returns 2xx — the token "
          "was not invalidated.",
        ],
        "remediation": (
          "Track issued JWTs server-side (e.g., a revocation list keyed "
          "on `jti`) and reject revoked tokens on every request. "
          "Pure-stateless JWTs cannot enforce logout."
        ),
      },
    )
