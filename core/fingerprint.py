"""Stable finding fingerprints.

A report identifier such as ``KRP-004`` means "the fourth finding in this run".
That is the right label for a reader and the wrong key for a comparison: the
moment a scan finds one more issue, every number shifts and a retest cannot tell
whether it is looking at the same weakness.

A fingerprint is the opposite: it depends only on what the finding *is* - the
kind, the host, the normalised path and the parameter - so it survives a change
of report order, a new discovery, and a second scan weeks later. Object
identifiers and query strings are normalised away for exactly that reason:
``/orders/1`` and ``/orders/2`` are one weakness on one endpoint, and a retest
should recognise it as such.
"""

from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit



FINGERPRINT_VERSION = 3

_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_NUMBER = re.compile(r"(?<=/)\d{1,12}(?=/|$)")
_LONG_HEX = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_SCOPE = re.compile(r"^(?:form|json|body|query|path|header|cookie):", re.IGNORECASE)


def normalise_path(target: str) -> str:
    """Path with object identifiers replaced by their shape.

    ``/orders/42/items/<uuid>`` becomes ``/orders/:n/items/:uuid`` so the same
    weakness on a different record keeps the same fingerprint.
    """
    try:
        path = urlsplit(str(target or "")).path or "/"
    except ValueError:
        path = str(target or "/")
    path = re.sub(r"/{2,}", "/", path)
    path = _UUID.sub(":uuid", path)
    path = _LONG_HEX.sub(":hex", path)
    path = _NUMBER.sub(":n", path)
    return path.rstrip("/") or "/"


def host_of(target: str) -> str:
    try:
        return (urlsplit(str(target or "")).hostname or "").lower()
    except ValueError:
        return ""


def canonical(entry: dict) -> str:
    """The normalised string a fingerprint is taken over.

    Kept as a readable, ``|``-separated form so a mismatch between two runs can
    be diagnosed by eye instead of by guessing at a hash.
    """
    kind = str(entry.get("kind") or "unknown").strip().lower()
    host = host_of(entry.get("target") or entry.get("url") or "")
    path = normalise_path(entry.get("target") or entry.get("url") or "")
    parameter = str(entry.get("param") or entry.get("parameter") or "").strip().lower()
    parameter = _SCOPE.sub("", parameter)
    variant = str(entry.get("fingerprint_variant") or "").strip().lower()
    parsed = urlsplit(str(entry.get("target") or entry.get("url") or ""))
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    method = str(entry.get("method") or "GET").upper()
    return json.dumps([FINGERPRINT_VERSION, kind, parsed.scheme.lower(), host, port, path, parameter,
                       variant, method], ensure_ascii=False, separators=(",", ":"))


def fingerprint(entry: dict) -> str:
    """SHA-256 of the canonical form, as lowercase hex."""
    return hashlib.sha256(canonical(entry).encode("utf-8")).hexdigest()


def short(value: str, length: int = 12) -> str:
    """A fingerprint prefix that is unambiguous within one report."""
    return str(value or "")[:length]


def title_similarity(left: str, right: str) -> float:
    """How alike two finding titles are, ignoring case and spacing."""
    def tidy(text: str) -> str:
        return " ".join(str(text or "").lower().split())
    return SequenceMatcher(None, tidy(left), tidy(right)).ratio()


def near_duplicates(entries, threshold: float = 0.92) -> list:
    """Groups of findings that describe the same weakness in different words.

    ``core.findings.dedupe`` already collapses entries with an identical
    identity.  This catches the case it cannot: the same weakness reported twice
    with different titles on the same endpoint. Nothing is merged here - the
    groups are returned so a caller can review them.
    """
    items = [entry for entry in (entries or []) if isinstance(entry, dict)]
    fingerprints = [fingerprint(entry) for entry in items]
    groups, assigned = [], set()

    for index, entry in enumerate(items):
        if index in assigned:
            continue
        group = [index]
        for other in range(index + 1, len(items)):
            if other in assigned:
                continue
            if (str(entry.get("kind")).lower()
                    != str(items[other].get("kind")).lower()):
                continue
            left = entry.get("target") or entry.get("url") or ""
            right = items[other].get("target") or items[other].get("url") or ""
            if normalise_path(left) != normalise_path(right):
                continue
            if title_similarity(entry.get("title"),
                                items[other].get("title")) < threshold:
                continue
            group.append(other)
            assigned.add(other)
        if len(group) > 1:
            assigned.add(index)
            groups.append({
                "fingerprints": [fingerprints[i] for i in group],
                "titles": [items[i].get("title") for i in group],
                "kind": entry.get("kind"),
                "target": entry.get("target") or entry.get("url"),
            })
    return groups
