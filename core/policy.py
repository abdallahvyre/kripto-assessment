"""Central URL scope policy used by the HTTP transport.

The scanner discovers URLs from untrusted HTML, JavaScript, sitemaps and
redirects.  Keeping scope checks in each discovery module is therefore not
enough: every outbound HTTP hop must pass through the same policy immediately
before it is sent.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import fnmatch
import posixpath
import threading
import time
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, unquote, urljoin, urlsplit, urlunsplit
import idna
import requests


ALLOWED_SCHEMES = frozenset({"http", "https"})


class ScopeViolation(ValueError):
    """Raised when an outbound request falls outside the authorized scope."""

    def __init__(self, url: str, reason: str):
        super().__init__(f"blocked out-of-scope URL: {reason}: {url}")
        self.url = url
        self.reason = reason


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    url: str
    reason: str = ""


def _normalise_host(host: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        return ""
    try:
        
        
        return host if host.isascii() else idna.encode(host, uts46=True).decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid hostname {host!r}") from exc


def _normalise_path(path: str) -> str:
    """Canonical path used only for exclude matching.

    Repeated decoding catches common double-encoding bypasses while leaving the
    actual request URL untouched.
    """

    value = path or "/"
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    value = value.replace("\\", "/")
    value = "/" + value.lstrip("/")
    value = posixpath.normpath(value)
    return value if value.startswith("/") else "/" + value


def _redacted_url(url: str) -> str:
    """Keep useful audit context without storing query-string secrets."""

    try:
        parsed = urlsplit(url)
        query = urlencode([
            (key, "<redacted>")
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
        ])
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
    except Exception:
        return str(url).split("?", 1)[0]


class ScopePolicy:
    """Host allow-list, path exclusions and redirect validation.

    ``scope`` accepts exact hosts and ``*.example.com`` patterns.  The target
    host is always included, so a wildcard can safely add subdomains without
    accidentally excluding the scan root.
    """

    def __init__(self, target: str, scope=None, excludes: Iterable[str] | None = None,
                 max_redirects: int = 8, blocked_log_size: int = 1000):
        target_url = self._absolute_http_url(target)
        parsed = urlsplit(target_url)
        self.target = target_url
        self.target_host = _normalise_host(parsed.hostname or "")
        if not self.target_host:
            raise ValueError("target URL must contain a hostname")

        self.host_patterns = self._scope_patterns(scope)
        if scope is not None and self.host_patterns and not any(
                self._target_matches_pattern(pattern) for pattern in self.host_patterns):
            raise ValueError("target host is not covered by the configured scope")
        self.host_patterns.add(self.target_host)
        self.excludes = tuple(self._normalise_exclude(item) for item in (excludes or [])
                              if str(item).strip())
        if max_redirects < 0:
            raise ValueError("max_redirects must be zero or greater")
        self.max_redirects = int(max_redirects)

        self._blocked = deque(maxlen=max(1, int(blocked_log_size)))
        self._blocked_lock = threading.Lock()

    @staticmethod
    def _absolute_http_url(url: str, base_url: str | None = None) -> str:
        candidate = urljoin(base_url, str(url)) if base_url else str(url)
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ValueError(f"scheme {scheme or '<missing>'!r} is not allowed")
        if not parsed.hostname:
            raise ValueError("URL must contain a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("userinfo in URLs is not allowed")
        
        clean = urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        try:
            
            
            return requests.Request("GET", clean).prepare().url
        except requests.RequestException as exc:
            raise ValueError("URL cannot be prepared safely") from exc

    def _scope_patterns(self, scope) -> set[str]:
        if scope is None:
            return set()
        if isinstance(scope, str):
            raw_items = scope.split(",")
        else:
            raw_items = list(scope)

        patterns = set()
        for raw in raw_items:
            value = str(raw).strip()
            if not value:
                continue
            if "://" in value:
                value = urlsplit(value).hostname or ""
            value = value.rstrip(".").lower()
            if value == "*":
                raise ValueError("an unrestricted '*' scope is not allowed")
            if any(char in value for char in "?["):
                raise ValueError("scope only supports an optional leading '*.' wildcard")
            if "*" in value and (not value.startswith("*.") or value.count("*") != 1):
                raise ValueError("scope wildcards are only supported as '*.example.com'")
            suffix = value[2:] if value.startswith("*.") else value
            normalised = _normalise_host(suffix)
            if not normalised:
                raise ValueError(f"invalid scope entry {raw!r}")
            patterns.add(f"*.{normalised}" if value.startswith("*.") else normalised)
        return patterns

    def _target_matches_pattern(self, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return self.target_host == suffix or self.target_host.endswith("." + suffix)
        return self.target_host == pattern

    @staticmethod
    def _normalise_exclude(value: str) -> str:
        value = str(value).strip()
        if "://" in value:
            value = urlsplit(value).path
        return _normalise_path(value)

    def _host_allowed(self, host: str) -> bool:
        host = _normalise_host(host)
        for pattern in self.host_patterns:
            if pattern.startswith("*."):
                suffix = pattern[1:]  
                if host.endswith(suffix) and host != suffix[1:]:
                    return True
            elif fnmatch.fnmatchcase(host, pattern):
                return True
        return False

    def _path_excluded(self, path: str) -> bool:
        candidate = _normalise_path(path)
        for excluded in self.excludes:
            if any(char in excluded for char in "*?["):
                if fnmatch.fnmatchcase(candidate, excluded):
                    return True
                continue
            prefix = excluded.rstrip("/") or "/"
            if candidate == prefix or candidate.startswith(prefix + "/"):
                return True
        return False

    def evaluate(self, url: str, base_url: str | None = None) -> PolicyDecision:
        try:
            absolute = self._absolute_http_url(url, base_url=base_url)
        except ValueError as exc:
            candidate = urljoin(base_url, str(url)) if base_url else str(url)
            return PolicyDecision(False, candidate, str(exc))

        parsed = urlsplit(absolute)
        host = _normalise_host(parsed.hostname or "")
        if not self._host_allowed(host):
            return PolicyDecision(False, absolute, f"host {host!r} is outside scope")
        if self._path_excluded(parsed.path):
            return PolicyDecision(False, absolute, f"path {_normalise_path(parsed.path)!r} is excluded")
        return PolicyDecision(True, absolute)

    def authorize(self, url: str, base_url: str | None = None,
                  method: str = "GET", source: str = "request") -> str:
        decision = self.evaluate(url, base_url=base_url)
        if decision.allowed:
            return decision.url
        self.record_block(decision.url, decision.reason, method=method, source=source)
        raise ScopeViolation(decision.url, decision.reason)

    def redirect_target(self, current_url: str, location: str, method: str = "GET") -> str:
        return self.authorize(location, base_url=current_url, method=method, source="redirect")

    def record_block(self, url: str, reason: str, method: str = "GET",
                     source: str = "request") -> None:
        entry = {
            "time": time.time(),
            "method": str(method).upper(),
            "source": source,
            "url": _redacted_url(url),
            "reason": reason,
        }
        with self._blocked_lock:
            self._blocked.append(entry)

    def blocked(self) -> list[dict]:
        with self._blocked_lock:
            return list(self._blocked)

    def report(self) -> dict:
        return {
            "target": self.target,
            "scope": sorted(self.host_patterns),
            "excludes": list(self.excludes),
            "blocked_count": len(self.blocked()),
            "blocked": self.blocked(),
        }
