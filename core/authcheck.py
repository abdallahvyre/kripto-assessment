import base64
import hashlib
import hmac
import json
import re
import time
from urllib.parse import urljoin, urlparse

from config import TIMEOUT
from core.banner import found, info, vuln, warning
from core.cookies import cookie_metadata, get_set_cookie_headers, parse_set_cookie_header
from core.redact import redact_secret

OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/v2",
    "/.well-known/jwks.json",
    "/.well-known/oauth-protected-resource",
    "/.well-known/assetlinks.json",
    "/oauth/jwks.json", "/jwks.json", "/.well-known/jwks",
]

OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth/token", "/oauth/revoke", "/oauth/introspect",
    "/oauth/userinfo", "/oauth2/authorize", "/oauth2/token",
    "/authorize", "/token", "/userinfo", "/.well-known/silk",
]



WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "changeme", "test", "admin", "key", "jwt",
    "jwtsecret", "jwt-secret", "supersecret", "mysecret", "s3cr3t", "letmein",
    "qwerty", "abc123", "1234567890", "000000", "default", "token", "auth",
    "secret123", "password123", "your-256-bit-secret", "your_jwt_secret",
]

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")
SESSION_COOKIE_HINTS = ("sess", "session", "sid", "jsessionid", "phpsessid", "auth",
                        "token", "jwt", "remember", "connect.sid", "aspnet_sessionid")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def analyze_jwt(token: str) -> dict:
    """Structural analysis of a JWT. Decoding is not verification - every
    conclusion drawn here is labelled as unverified until checked."""
    out = {"raw": token[:400], "valid_structure": False, "header": {}, "payload": {},
           "claims": [], "issues": []}
    parts = token.split(".")
    if len(parts) != 3:
        return out

    try:
        out["header"] = json.loads(_b64url_decode(parts[0]))
        out["payload"] = json.loads(_b64url_decode(parts[1]))
        out["valid_structure"] = True
    except Exception:
        out["issues"].append("Token looks like a JWT but its header/payload do not decode")
        return out

    header, payload = out["header"], out["payload"]
    alg = str(header.get("alg", "")).upper()
    out["alg"] = alg
    out["typ"] = header.get("typ")
    out["kid"] = header.get("kid")

    now = time.time()
    claims = []

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        remaining = exp - now
        if remaining <= 0:
            claims.append({"claim": "exp", "state": "EXPIRED",
                           "detail": f"expired {abs(remaining) / 86400:.1f} days ago"})
        elif remaining < 3600:
            claims.append({"claim": "exp", "state": "SHORT",
                           "detail": f"expires in {remaining / 60:.0f} minutes"})
        else:
            claims.append({"claim": "exp", "state": "OK",
                           "detail": f"valid for {remaining / 86400:.0f} days"})

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now:
        claims.append({"claim": "nbf", "state": "FUTURE",
                       "detail": "token is not yet valid (clock skew or manipulation)"})

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + 60:
        claims.append({"claim": "iat", "state": "FUTURE",
                       "detail": "issued-in-the-future token"})

    if "sub" not in payload:
        claims.append({"claim": "sub", "state": "MISSING", "detail": "no subject claim"})
    if "iss" not in payload:
        claims.append({"claim": "iss", "state": "MISSING", "detail": "no issuer claim"})
    if "aud" not in payload:
        claims.append({"claim": "aud", "state": "MISSING", "detail": "no audience claim"})

    sensitive = [k for k in payload
                 if k.lower() in ("password", "pwd", "secret", "api_key", "token", "credit_card", "ssn")]
    if sensitive:
        claims.append({"claim": "data", "state": "LEAK",
                       "detail": f"claims carry sensitive fields: {', '.join(sensitive)}"})

    if alg == "NONE":
        out["issues"].append("alg=none: the signature is not verified by design")
    if payload.get("admin") in (True, 1, "1", "true"):
        claims.append({"claim": "admin", "state": "LEAK", "detail": "admin flag embedded in the token"})

    out["claims"] = claims
    out["verify"] = _verify_signature(parts, alg)
    return out


def _verify_signature(parts, alg):
    """Check the HMAC signature against common weak secrets."""
    if alg not in ("HS256", "HS384", "HS512"):
        return {"method": alg, "checked": False, "reason": "asymmetric or unsigned token"}

    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        signature = _b64url_decode(parts[2])
    except Exception:
        return {"method": alg, "checked": False, "reason": "signature is not valid base64url"}

    for secret in WEAK_JWT_SECRETS:
        expected = hmac.new(secret.encode(), signing_input, digest).digest()
        if hmac.compare_digest(expected, signature):
            return {"method": alg, "checked": True, "forged_with": secret,
                    "verdict": "SIGNATURE FORGEABLE"}
    return {"method": alg, "checked": True, "tried": len(WEAK_JWT_SECRETS),
            "verdict": "no weak secret matched"}


class AuthModule:
    """Session, token and identity-provider analysis.

    Focus is entirely on reading the target's own tokens and configuration: what
    it issues, what it trusts, and whether its own claims contradict its own
    configuration.
    """

    def __init__(self, target: str, console, surface=None):
        self.target = target
        self.console = console
        self.surface = surface
        parsed = urlparse(target)
        self.domain = parsed.hostname
        self.base = f"{parsed.scheme}://{parsed.netloc}"

        from core.http import RateLimitedSession
        self.session = RateLimitedSession()

        self.jwts = []
        self.oidc = {}
        self.jwks = {}
        self.oauth_endpoints = []
        self.cookies = []
        self.token_in_url = []
        self.issues = []
        self.tokens_checked = 0

    def _get(self, url, **kw):
        try:
            return self.session.get(url, timeout=TIMEOUT, **kw)
        except Exception:
            return None

    

    def discover_oidc(self):
        info(self.console, "Discovering identity-provider metadata...")
        for rel in OIDC_PATHS:
            url = urljoin(self.base + "/", rel.lstrip("/"))
            resp = self._get(url)
            if resp is None or resp.status_code != 200:
                continue
            try:
                doc = resp.json()
            except Exception:
                continue

            if "jwks_uri" in doc or "issuer" in doc:
                self.oidc = doc
                issuer = doc.get("issuer", "?")
                found(self.console, f"OIDC discovery document: {issuer}")
                for endpoint in ("authorization_endpoint", "token_endpoint",
                                 "userinfo_endpoint", "introspection_endpoint",
                                 "revocation_endpoint", "registration_endpoint"):
                    if doc.get(endpoint):
                        self.oauth_endpoints.append({"role": endpoint, "url": doc[endpoint]})
                self._check_issuer_consistency(doc, issuer)
                self._check_pkce(doc)
                self._check_grant_types(doc)

            if "keys" in doc and isinstance(doc["keys"], list):
                self.jwks = doc
                found(self.console, f"JWKS published with {len(doc['keys'])} key(s)")
                self._analyze_keys(doc["keys"])

        for rel in OAUTH_ENDPOINTS:
            url = urljoin(self.base + "/", rel.lstrip("/"))
            resp = self._get(url, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code in (200, 302, 400, 401, 405) and\
                    len(resp.content) > 0:
                self.oauth_endpoints.append({"role": rel, "url": url,
                                             "status": resp.status_code})
        return self.oidc

    def _check_issuer_consistency(self, doc, issuer):
        host = urlparse(str(issuer)).hostname
        if host and self.domain and host != self.domain:
            warning(self.console, f"OIDC issuer is on a different host: {issuer}")
            self.issues.append({
                "type": "OIDC issuer off-site",
                "detail": f"issuer={issuer} does not match the audited host",
                "severity": "info",
            })

    def _check_pkce(self, doc):
        methods = doc.get("code_challenge_methods_supported")
        if methods is None:
            return
        if "S256" not in methods:
            self.issues.append({
                "type": "PKCE weakened",
                "detail": f"code_challenge_methods_supported={methods} - plain is usable",
                "severity": "medium",
            })
            vuln(self.console, f"OIDC allows PKCE 'plain' or none: {methods}")
        else:
            found(self.console, "PKCE S256 is the only supported challenge method")

    def _check_grant_types(self, doc):
        grants = set(doc.get("grant_types_supported") or [])
        if "password" in grants:
            self.issues.append({
                "type": "Resource Owner Password Credentials enabled",
                "detail": "grant_types_supported includes 'password'",
                "severity": "medium",
            })
            warning(self.console, "OAuth server accepts the 'password' grant")
        if "implicit" in grants:
            self.issues.append({
                "type": "Implicit grant enabled",
                "detail": "grant_types_supported includes 'implicit'",
                "severity": "low",
            })
        scopes = doc.get("scopes_supported") or []
        for scope in scopes:
            if scope in ("openid",) and "profile" not in scopes:
                self.issues.append({
                    "type": "Scope policy",
                    "detail": "openid without profile",
                    "severity": "info",
                })

    def _analyze_keys(self, keys):
        for key in keys[:20]:
            if not isinstance(key, dict):
                continue
            kty = key.get("kty")
            info_bits = {"RSA": key.get("n"), "EC": key.get("x"), "oct": key.get("k")}
            entry = {"kid": key.get("kid"), "kty": kty, "alg": key.get("alg"),
                     "use": key.get("use")}

            if kty == "RSA" and key.get("n"):
                length = (len(key["n"]) - 1) * 4 // 3
                entry["strength"] = length
                if length < 2048:
                    self.issues.append({
                        "type": "Weak signing key",
                        "detail": f"kid={key.get('kid')} RSA {length} bits",
                        "severity": "high",
                    })
                    vuln(self.console, f"JWKS publishes an RSA key of only {length} bits")
            if kty == "oct" and key.get("k"):
                self.issues.append({
                    "type": "Symmetric key published in JWKS",
                    "detail": "the verification key is a shared secret",
                    "severity": "critical",
                })
                vuln(self.console, "JWKS publishes a symmetric (shared-secret) key")
            if key.get("use") == "enc":
                entry["note"] = "encryption key present in the signing JWKS"

            if entry not in self.jwks.setdefault("analysis", []):
                self.jwks["analysis"].append(entry)

    

    def collect_tokens(self, sources):
        """Analyse every JWT the scan has already observed."""
        seen = set()
        for label, text in sources or []:
            if not text:
                continue
            for token in JWT_RE.findall(text):
                if token in seen:
                    continue
                seen.add(token)
                report = analyze_jwt(token)
                report["source"] = label
                self.jwts.append(report)
                self.tokens_checked += 1

        for cookie in self._cookies():
            if any(hint in cookie["name"].lower() for hint in SESSION_COOKIE_HINTS):
                for token in JWT_RE.findall(cookie.get("raw", "")):
                    if token in seen:
                        continue
                    seen.add(token)
                    report = analyze_jwt(token)
                    report["source"] = f"cookie:{cookie['name']}"
                    self.jwts.append(report)
                    self.tokens_checked += 1
        return self.jwts

    def _cookies(self):
        out = []
        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
        except Exception:
            return out
        for raw in get_set_cookie_headers(resp):
            parsed = parse_set_cookie_header(raw)
            metadata = cookie_metadata(raw)
            name = parsed["name"]
            value = parsed["value"]
            entry = {
                "name": name,
                "raw": raw,
                "raw_redacted": metadata["raw_redacted"],
                "flags": metadata["flags"],
                "value_length": metadata["value_length"],
                "value_fingerprint": metadata["value_fingerprint"],
            }
            if name.lower().startswith("__host-") or name.lower().startswith("__secure-"):
                entry["prefix"] = True
            else:
                entry["prefix"] = False
                self.issues.append({
                    "type": "Cookie prefix",
                    "detail": f"'{name}' has no __Host-/__Secure- prefix",
                    "severity": "low",
                })
            if re.fullmatch(r"[0-9a-f]{16,}|\d{6,}", value or ""):
                entry["guessable_shape"] = True
            out.append(entry)
        self.cookies = out
        return out

    def _verdict(self, report):
        verify = report.get("verify", {})
        if verify.get("verdict") == "SIGNATURE FORGEABLE":
            masked = redact_secret(verify["forged_with"], "weak-jwt-secret")
            vuln(self.console, f"JWT signature forgeable with {masked} "
                               f"(source: {report.get('source')})")
            self.issues.append({
                "type": "Forgeable JWT",
                "detail": f"HS* signature reproduces with a weak secret ({masked})",
                "source": report.get("source"),
                "severity": "critical",
            })
        for claim in report.get("claims", []):
            if claim["state"] in ("EXPIRED", "LEAK", "MISSING", "FUTURE", "SHORT"):
                found(self.console, f"JWT claim {claim['claim']}: {claim['state']} - {claim['detail']}")
            if claim["state"] == "LEAK":
                self.issues.append({
                    "type": "JWT claim problem",
                    "detail": f"{claim['claim']}: {claim['detail']}",
                    "source": report.get("source"),
                    "severity": "medium",
                })
        for issue in report.get("issues", []):
            self.issues.append({"type": "JWT structure", "detail": issue,
                                "source": report.get("source"), "severity": "high"})

    def run(self, blobs=None):
        self.discover_oidc()
        self.collect_tokens(blobs or [])
        for report in self.jwts:
            self._verdict(report)

        if not self.jwts:
            warning(self.console, "No JWT was observed during the scan. Token analysis is "
                                  "INCONCLUSIVE rather than clean - the token may only appear "
                                  "after login.")

        if self.surface and self.jwks.get("analysis"):
            for key in self.jwks["analysis"]:
                self.surface.add_endpoint(self.oidc.get("jwks_uri", ""), "oidc",
                                          note=f"kid={key.get('kid')}")

        return {
            "tokens_analyzed": self.tokens_checked,
            "jwts": self.jwts,
            "oidc": self.oidc,
            "jwks": self.jwks,
            "oauth_endpoints": self.oauth_endpoints,
            "cookies": self.cookies,
            "issues": self.issues,
        }
