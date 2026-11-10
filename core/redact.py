"""Secret-safe rendering helpers for reports, logs and evidence metadata.

The scanner keeps raw findings in memory so an operator can explicitly opt in
to a full report.  Every default rendering path should pass through this module
first.  Redaction is deterministic: the short SHA-256 fingerprint lets two
occurrences be correlated without revealing the underlying value.
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Mapping


REDACTED = "<redacted>"





_REGISTERED: set = set()
_REGISTERED_LOCK = threading.Lock()


def register_secret(value) -> bool:
    """Mask *value* everywhere this module renders text from now on."""
    text = str(value or "")
    if len(text) < 4:
        return False
    with _REGISTERED_LOCK:
        _REGISTERED.add(text)
    return True


def clear_registered_secrets() -> None:
    with _REGISTERED_LOCK:
        _REGISTERED.clear()


def registered_secret_count() -> int:
    with _REGISTERED_LOCK:
        return len(_REGISTERED)


def _mask_registered(text: str) -> str:
    with _REGISTERED_LOCK:
        if not _REGISTERED:
            return text
        secrets = sorted(_REGISTERED, key=len, reverse=True)
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, redact_secret(secret, "registered"))
    return text

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{12,})")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|id_token|token|api_?key|key|secret|password)=)"
    r"([^&#\s]+)"
)
_ASSIGNED_SECRET = re.compile(
    r"(?i)(\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|"
    r"secret|password|passwd|pwd|authorization)\b[\"']?\s*[=:]\s*[\"']?)"
    r"([^\"'\s,;}{]{6,})"
)

_KNOWN_SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_/.-]+"),
    re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
)

_SENSITIVE_KEYS = {
    "token", "access_token", "refresh_token", "id_token", "auth_token",
    "secret", "client_secret", "api_key", "apikey", "access_key",
    "secret_key", "private_key", "password", "passwd", "pwd",
    "authorization", "proxy_authorization", "cookie", "set_cookie",
    "forged_with", "session_id", "sessionid",
}
_PRIVATE_JWK_KEYS = {"d", "p", "q", "dp", "dq", "qi", "oth"}
_SECRET_COLLECTIONS = {
    "secrets", "tokens_keys", "jwts", "cookies", "hidden_fields",
    "secrets_still_live", "secret_like",
}


def credential_values(headers):
    """Complete authorized header values and independently reflectable components."""
    values = []
    for key, value in (headers or {}).items():
        if not value:
            continue
        text = str(value)
        values.append(text)
        if key.lower() == "cookie":
            values.extend(part.split("=", 1)[1].strip() for part in text.split(";") if "=" in part)
        elif key.lower() in {"authorization", "proxy-authorization"} and " " in text:
            values.append(text.split(" ", 1)[1].strip())
    return [value for value in values if value]

_DERIVED_SECRET_KINDS = {"secret-leak", "credential-leak", "token-leak"}
_FORGED_SECRET = re.compile(
    r"(?i)(\b(?:signing\s+secret|forged\s+with)\b[^\w]{0,8})([\w!@#$%^&*+=:;,.?/~`|\\-]{4,})"
)
_PEM_PRIVATE = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z]+ )?PRIVATE KEY-----", re.DOTALL)
_RAW_COOKIE = re.compile(r"(?im)^(\s*(?:set-cookie|cookie):\s*)([^\r\n]+)")


def secret_fingerprint(value) -> str:
    """Return a stable, non-reversible identifier for a secret-like value."""
    raw = str(value).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:12]


def redact_secret(value, label: str = "secret") -> str:
    """Hide a complete value while retaining length and a correlation hash."""
    if value is None:
        return REDACTED
    text = str(value)
    if text.startswith("<redacted"):
        return text
    return f"<redacted:{label} sha256={secret_fingerprint(text)} len={len(text)}>"


def redact_text(value) -> str:
    """Remove common embedded credentials from an otherwise useful string."""
    text = str(value)
    text = _PEM_PRIVATE.sub(lambda m: redact_secret(m.group(0), "private-key"), text)
    text = _RAW_COOKIE.sub(lambda m: m.group(1) + redact_secret(m.group(2), "cookie"), text)

    text = _JWT.sub(lambda m: redact_secret(m.group(0), "jwt"), text)
    text = _BEARER.sub(
        lambda m: f"{m.group(1)} {redact_secret(m.group(2), 'credential')}", text
    )
    text = _QUERY_SECRET.sub(
        lambda m: f"{m.group(1)}{redact_secret(m.group(2), 'query-secret')}", text
    )
    text = _ASSIGNED_SECRET.sub(
        lambda m: f"{m.group(1)}{redact_secret(m.group(2), 'assigned-secret')}", text
    )
    for pattern in _KNOWN_SECRET_PATTERNS:
        text = pattern.sub(lambda m: redact_secret(m.group(0), "credential"), text)
    return _mask_registered(text)


def literal_text(value):
    """Keep field content inside one display record, without changing source data."""
    text = str(value)
    return "".join(char if ord(char) >= 32 and not (127 <= ord(char) <= 159)
                   and char not in "\u061c\u200e\u200f\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
                   else {"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(char, f"\\x{ord(char):02x}")
                   for char in text)


def display_text(value):
    """Redact and encode untrusted fields as literal single-line operator output."""
    return literal_text(redact_text(value))


def display_data(value):
    """Detached display-only snapshot; callers retain canonical data for JSON/retests."""
    if isinstance(value, Mapping):
        return {literal_text(key) if isinstance(key, str) else key: display_data(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [display_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(display_data(item) for item in value)
    if isinstance(value, set):
        return {display_data(item) for item in value}
    return literal_text(value) if isinstance(value, str) else value


def _normalise_key(key) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")


def _path_is_secret_collection(path) -> bool:
    return any(_normalise_key(part) in _SECRET_COLLECTIONS for part in path)


def _value_field_is_secret(mapping: Mapping, path) -> bool:
    if _path_is_secret_collection(path):
        return True
    kind = str(mapping.get("type", "")).lower()
    return any(word in kind for word in (
        "secret", "token", "key", "credential", "password", "jwt", "webhook",
        "private",
    ))


def _key_is_secret(key, mapping: Mapping, path) -> bool:
    
    
    if len(path) >= 2 and path[-2] in {"module_health", "module_notes", "module_timings"}:
        return False
    normalised = _normalise_key(key)
    if normalised in _SENSITIVE_KEYS:
        return True
    if normalised in _PRIVATE_JWK_KEYS:
        return True
    if normalised == "k" and str(mapping.get("kty", "")).lower() == "oct":
        return True
    if normalised == "value" and _value_field_is_secret(mapping, path):
        return True
    if normalised == "raw" and _path_is_secret_collection(path):
        return True
    return False


def _redact_derived_field(key, item, mapping: Mapping):
    """Protect secrets copied into normalized findings.

    Correlation changes the field name (for example from ``value`` to
    ``evidence`` or embeds a JWT signing key in ``title``).  Key-only redaction
    cannot recognise those derived values, so use the finding kind as the
    schema discriminator while preserving useful non-secret context.
    """
    normalised = _normalise_key(key)
    kind = str(mapping.get("kind", "")).lower()

    if kind in _DERIVED_SECRET_KINDS:
        if normalised in {"evidence", "value"}:
            return redact_secret(item, "derived-secret")
        if normalised == "title":
            text = str(item)
            sibling = mapping.get("evidence") or mapping.get("value")
            if sibling is not None and len(str(sibling)) >= 4 and str(sibling) in text:
                return text.replace(str(sibling), redact_secret(sibling, "derived-secret"))
            return redact_text(text)

    if kind == "forgeable-jwt" and normalised in {"title", "evidence"}:
        text = str(item)
        return _FORGED_SECRET.sub(
            lambda match: match.group(1) + redact_secret(match.group(2), "signing-secret"),
            text,
        )
    return None


def redact_data(value, _path=()):
    """Deep-copy *value* with secret-bearing fields and strings sanitised.

    Container structure and non-secret evidence remain intact so the redacted
    JSON is still useful to automation and the text reporter.
    """
    if isinstance(value, Mapping):
        output = {}
        for key, item in value.items():
            path = _path + (str(key),)
            derived = _redact_derived_field(key, item, value)
            if derived is not None:
                output[key] = derived
            elif _key_is_secret(key, value, path):
                output[key] = redact_secret(item, _normalise_key(key) or "secret")
            else:
                output[key] = redact_data(item, path)
        return output
    if isinstance(value, list):
        return [redact_data(item, _path + (str(index),)) for index, item in enumerate(value)]
    if isinstance(value, tuple):
        return tuple(redact_data(item, _path + (str(index),)) for index, item in enumerate(value))
    if isinstance(value, set):
        return {redact_data(item, _path) for item in value}
    if isinstance(value, str):
        return redact_text(value)
    return value
