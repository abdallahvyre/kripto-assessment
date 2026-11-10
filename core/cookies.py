"""Utilities for preserving and safely displaying repeated Set-Cookie fields."""

from __future__ import annotations

import re

from core.redact import redact_secret, secret_fingerprint


_COOKIE_BOUNDARY = re.compile(r",(?=\s*[^;,\s]+=)")


def split_set_cookie_header(value: str) -> list[str]:
    """Split a collapsed Set-Cookie value without breaking Expires dates."""
    if not value:
        return []
    return [part.strip() for part in _COOKIE_BOUNDARY.split(str(value)) if part.strip()]


def get_set_cookie_headers(response) -> list[str]:
    """Return every Set-Cookie header from requests/urllib3-like responses."""
    if response is None:
        return []

    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None:
        for method_name in ("getlist", "get_all", "getheaders"):
            method = getattr(raw_headers, method_name, None)
            if not callable(method):
                continue
            try:
                values = method("Set-Cookie")
            except TypeError:
                continue
            if values:
                if isinstance(values, str):
                    values = [values]
                output = []
                for value in values:
                    output.extend(split_set_cookie_header(value))
                if output:
                    return output

    headers = getattr(response, "headers", {}) or {}
    try:
        combined = headers.get("Set-Cookie", "")
    except AttributeError:
        combined = ""
    return split_set_cookie_header(combined)


def parse_set_cookie_header(header: str) -> dict:
    """Parse the cookie name/value and attribute presence without decoding it."""
    parts = [part.strip() for part in str(header or "").split(";")]
    first = parts[0] if parts else ""
    name, separator, value = first.partition("=")
    attributes = {}
    for part in parts[1:]:
        attr, has_value, attr_value = part.partition("=")
        attributes[attr.lower()] = attr_value if has_value else True
    return {
        "name": name.strip(),
        "value": value if separator else "",
        "attributes": attributes,
    }


def redact_set_cookie_header(header: str) -> str:
    """Keep cookie attributes visible while masking only its value."""
    parsed = parse_set_cookie_header(header)
    name = parsed["name"] or "cookie"
    value = parsed["value"]
    suffix = str(header).split(";", 1)[1] if ";" in str(header) else ""
    masked = redact_secret(value, "cookie") if value else "<empty>"
    return f"{name}={masked}" + (f";{suffix}" if suffix else "")


def cookie_metadata(header: str) -> dict:
    """Return analysis-friendly metadata while retaining no cleartext value."""
    parsed = parse_set_cookie_header(header)
    attributes = parsed["attributes"]
    value = parsed["value"]
    return {
        "name": parsed["name"],
        "flags": {
            flag: flag in attributes
            for flag in ("secure", "httponly", "samesite", "domain", "path", "expires", "max-age")
        },
        "value_length": len(value),
        "value_fingerprint": secret_fingerprint(value) if value else None,
        "raw_redacted": redact_set_cookie_header(header),
    }
