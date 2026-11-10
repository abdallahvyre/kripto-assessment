"""Where test credentials come from, and how they are validated on load.

Credentials are never hard-coded and never printed.  An identity is described
by a plain JSON document (or the equivalent dict) and each secret field may
reference an environment variable as ``${ENV:NAME}`` so the engagement can keep
passwords out of the repository entirely.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse




METHODS = frozenset({"none", "headers", "cookie", "bearer", "basic", "api-key", "form"})


KNOWN_ROLES = frozenset({"anonymous", "user", "admin"})

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_ENV_REF = re.compile(r"\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}")



FORBIDDEN_HEADERS = frozenset({
    "host", "content-length", "connection", "transfer-encoding",
    "proxy-authorization", "proxy-connection", "te", "trailer", "upgrade",
})


SECRET_FIELDS = frozenset({"password", "token", "api_key", "secret", "cookie_value"})


class AuthConfigError(ValueError):
    """Raised when an identity document is malformed or unsafe."""


def _interpolate(value) -> str:
    """Replace ``${ENV:NAME}`` references with their environment value."""
    if not isinstance(value, str):
        return "" if value is None else str(value)

    def substitute(match: re.Match) -> str:
        name = match.group(1)
        resolved = os.environ.get(name)
        if resolved is None:
            raise AuthConfigError(
                f"environment variable {name} referenced by the credential file is not set"
            )
        return resolved

    return _ENV_REF.sub(substitute, value)


def _clean_headers(raw, label: str) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise AuthConfigError(f"{label}.headers must be a JSON object")

    validated, seen = {}, set()
    for name, value in raw.items():
        name = str(name)
        if not _HEADER_NAME.fullmatch(name):
            raise AuthConfigError(f"{label}.headers contains an invalid header name: {name!r}")
        lowered = name.lower()
        if lowered in FORBIDDEN_HEADERS:
            raise AuthConfigError(f"{label}.headers may not set {name!r}")
        if lowered in seen:
            raise AuthConfigError(f"{label}.headers repeats {name!r} with different casing")
        text = _interpolate(value)
        if any((ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in text):
            raise AuthConfigError(f"{label}.headers value for {name!r} must be single-line")
        seen.add(lowered)
        validated[name] = text
    return validated


@dataclass
class CredentialSource:
    """One authorised identity, resolved but not yet used for any request."""

    name: str
    method: str = "none"
    role: str = "user"
    headers: dict = field(default_factory=dict)

    
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str = ""
    csrf_cookie: str = ""
    extra_fields: dict = field(default_factory=dict)
    success_marker: str = ""
    failure_marker: str = ""

    
    validation_url: str = ""
    validation_marker: str = ""
    expires_after: float = 0.0

    def __repr__(self) -> str:  
        return (f"CredentialSource(name={self.name!r}, method={self.method!r}, "
                f"role={self.role!r}, fields={len(self.headers)})")

    @property
    def needs_login(self) -> bool:
        return self.method == "form"

    @property
    def authenticated(self) -> bool:
        return self.method != "none"

    def secret_values(self) -> list:
        """Every secret this identity holds, for redaction registries."""
        from core.redact import credential_values
        values = credential_values(self.headers)
        if self.password:
            values.append(self.password)
        for value in (self.extra_fields or {}).values():
            if value:
                values.append(str(value))
        return [v for v in values if v]

    def describe(self) -> dict:
        """Redacted description safe for the report and console."""
        return {
            "name": self.name,
            "role": self.role,
            "method": self.method,
            "header_names": sorted(self.headers),
            "login_url": self.login_url,
            "has_password": bool(self.password),
            "csrf_field": self.csrf_field or self.csrf_cookie or "",
            "validation_url": self.validation_url,
            "expires_after": self.expires_after,
        }

    @classmethod
    def from_dict(cls, raw, index: int = 0) -> "CredentialSource":
        if not isinstance(raw, dict):
            raise AuthConfigError(f"identity #{index} must be a JSON object")

        name = str(raw.get("name") or "").strip()
        if not name:
            raise AuthConfigError(f"identity #{index} needs a 'name'")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", name):
            raise AuthConfigError(
                f"identity name {name!r} must be 1-64 characters of letters, digits, _ . : -"
            )

        label = f"identity {name!r}"
        method = str(raw.get("method") or "none").strip().lower()
        if method not in METHODS:
            raise AuthConfigError(
                f"{label} uses unknown method {method!r}; supported: {', '.join(sorted(METHODS))}"
            )

        role = str(raw.get("role") or "user").strip().lower() or "user"
        headers = _clean_headers(raw.get("headers"), label)

        needs_headers = {"headers", "cookie", "bearer", "basic", "api-key"}
        if method in needs_headers and not headers:
            raise AuthConfigError(f"{label} uses method {method!r} but supplies no headers")
        if method == "none" and headers:
            raise AuthConfigError(f"{label} is method 'none' but supplies headers")

        login_url = _interpolate(raw.get("login_url") or "")
        if method == "form":
            if not login_url:
                raise AuthConfigError(f"{label} uses a login form but has no 'login_url'")
            if not raw.get("username") or not raw.get("password"):
                raise AuthConfigError(
                    f"{label} uses a login form but is missing 'username' or 'password'"
                )

        extra = raw.get("extra_fields") or {}
        if extra and not isinstance(extra, dict):
            raise AuthConfigError(f"{label}.extra_fields must be a JSON object")

        expires_after = raw.get("expires_after") or 0
        try:
            expires_after = float(expires_after)
        except (TypeError, ValueError) as exc:
            raise AuthConfigError(f"{label}.expires_after must be a number of seconds") from exc
        if expires_after < 0:
            raise AuthConfigError(f"{label}.expires_after must not be negative")

        return cls(
            name=name,
            method=method,
            role=role,
            headers=headers,
            login_url=login_url,
            username=_interpolate(raw.get("username") or ""),
            password=_interpolate(raw.get("password") or ""),
            username_field=str(raw.get("username_field") or "username"),
            password_field=str(raw.get("password_field") or "password"),
            csrf_field=str(raw.get("csrf_field") or ""),
            csrf_cookie=str(raw.get("csrf_cookie") or ""),
            extra_fields={str(k): _interpolate(v) for k, v in (extra or {}).items()},
            success_marker=str(raw.get("success_marker") or ""),
            failure_marker=str(raw.get("failure_marker") or ""),
            validation_url=_interpolate(raw.get("validation_url") or ""),
            validation_marker=str(raw.get("validation_marker") or ""),
            expires_after=expires_after,
        )


def load_credentials(source=None, data=None) -> list:
    """Load identity definitions from a file path, a dict, or nothing.

    Returns a list of :class:`CredentialSource`.  An empty list means the scan
    runs unauthenticated, which is a legitimate configuration.
    """
    if data is None and source:
        path = str(source)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except OSError as exc:
            raise AuthConfigError(f"could not read the credentials file: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AuthConfigError(f"the credentials file is not valid JSON: {exc}") from exc

    if not data:
        return []

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("identities")
        if entries is None and "name" in data:
            entries = [data]
        if entries is None:
            raise AuthConfigError("the credentials document needs an 'identities' list")
    else:
        raise AuthConfigError("credentials must be a JSON object or a list of identities")

    if not isinstance(entries, list):
        raise AuthConfigError("'identities' must be a list")

    resolved, seen = [], set()
    for index, raw in enumerate(entries):
        identity = CredentialSource.from_dict(raw, index=index)
        if identity.name in seen:
            raise AuthConfigError(f"duplicate identity name {identity.name!r}")
        seen.add(identity.name)
        resolved.append(identity)

    if not any(item.method == "none" for item in resolved):
        
        
        resolved.append(CredentialSource(name="anonymous", method="none",
                                         role="anonymous"))
    return resolved


def load_from_env(prefix: str = "KRIPTO_AUTH_") -> list:
    """Build identities from ``PREFIX<NAME>_<FIELD>`` environment variables.

    Fields: ``METHOD``, ``ROLE``, ``HEADER`` (``Name: value``), ``LOGIN_URL``,
    ``USERNAME``, ``PASSWORD``, ``VALIDATION_URL``.
    """
    field_names = ("VALIDATION_URL", "LOGIN_URL", "USERNAME", "PASSWORD",
                   "METHOD", "HEADER", "ROLE")
    grouped = {}
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        remainder = key[len(prefix):]
        
        
        for field_name in field_names:
            suffix = "_" + field_name
            if remainder.upper().endswith(suffix):
                name = remainder[:-len(suffix)]
                if name:
                    grouped.setdefault(name.lower(), {})[field_name.lower()] = value
                break

    entries = []
    for name, fields in sorted(grouped.items()):
        entry = {"name": name, "method": fields.get("method", "headers")}
        if fields.get("role"):
            entry["role"] = fields["role"]
        header = fields.get("header")
        if header:
            header_name, _, header_value = header.partition(":")
            entry["headers"] = {header_name.strip(): header_value.strip()}
        for target, key in (("login_url", "login_url"), ("username", "username"),
                            ("password", "password"),
                            ("validation_url", "validation_url")):
            if fields.get(key):
                entry[target] = fields[key]
        entries.append(entry)
    return load_credentials(data={"identities": entries} if entries else None)


def target_host_of(url: str) -> str:
    """Hostname of a URL, or an empty string when it is not absolute."""
    try:
        return (urlparse(str(url)).hostname or "").lower()
    except ValueError:
        return ""
