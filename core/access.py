"""Authorization testing: IDOR, BOLA, missing and vertical access control.

This module tests *whether the server enforces who may read what*, which is a
different question from whether an input is unsafe.  It only produces evidence
it can defend:

* identical privileged content returned to a second identity is proof that
  object-level authorization is missing;
* a protected response reproduced with no credentials at all is proof that
  authentication is missing on that route;
* a single identity cannot prove horizontal access.  With one identity the
  module only reports POTENTIAL and says so, because guessing that
  ``id=42`` belongs to another user is not evidence.

Nothing here enumerates real users' data, writes to the target, or escalates
a session.  Object identifiers tested are the ones the target itself returned
plus arithmetic neighbours, and only the shape of the response (status,
length, whether the body is a valid object rather than the login page) is
compared.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from config import TIMEOUT
from core.banner import found, info, success, vuln, warning
from core.findings import Verification
from core.http import IdentityHeaders, RateLimitedSession


OBJECT_PARAM_HINTS = frozenset({
    "id", "uid", "pid", "user_id", "userid", "account", "account_id",
    "order", "order_id", "orderid", "invoice", "invoice_id", "doc",
    "document", "document_id", "file", "file_id", "fileid", "item",
    "item_id", "itemid", "product", "product_id", "customer",
    "customer_id", "profile", "profile_id", "uuid", "guid", "key", "ref",
    "no", "number", "num", "record", "record_id", "object", "obj",
    "resource", "resource_id", "tenant", "tenant_id", "org", "org_id",
    "member", "member_id", "msg", "message_id", "post", "post_id",
    "comment", "comment_id", "thread", "thread_id", "ticket", "ticket_id",
})


_OBJECT_PATH = re.compile(r"/(\d{1,10})(?:/|$|\?)")
_UUID_PATH = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)",
    re.IGNORECASE,
)

LOGIN_MARKERS = (
    "type=\"password\"", "type='password'", "name=\"password\"",
    "name='password'", "sign in", "log in", "login", "unauthorized",
    "authentication required", "access denied", "forbidden",
)
ADMIN_MARKERS = (
    "admin", "dashboard", "user management", "manage users", "settings",
    "role", "permission", "delete user", "add user",
)

AUTH_DENIED_STATUSES = frozenset({401, 403, 407})
IDENTICAL_RATIO = 0.98


def _normalise(text: str, limit: int = 8192) -> str:
    """Collapse volatile values so two responses can be compared fairly."""
    value = str(text or "")[:limit]
    value = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", value, flags=re.I)
    value = re.sub(r"\b\d{10,}\b", "<num>", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _ratio(left: str, right: str) -> float:
    left_norm, right_norm = _normalise(left), _normalise(right)
    if not left_norm or not right_norm:
        return 0.0
    if left_norm == right_norm:
        return 1.0
    return SequenceMatcher(None, left_norm, right_norm, autojunk=True).ratio()


def _looks_like_login(text: str) -> bool:
    lowered = str(text or "").lower()[:6000]
    return any(marker in lowered for marker in LOGIN_MARKERS)


def _looks_privileged(text: str) -> bool:
    lowered = str(text or "").lower()[:6000]
    hits = sum(1 for marker in ADMIN_MARKERS if marker in lowered)
    return hits >= 2


class Identity:
    """One authorised session expressed purely as request headers."""

    def __init__(self, name: str, headers: dict):
        self.name = name
        self.headers = headers.copy() if isinstance(headers, IdentityHeaders) else dict(headers or {})

    @property
    def authenticated(self) -> bool:
        return bool(self.headers)

    def describe(self) -> dict:
        
        return {"name": self.name, "header_names": sorted(self.headers)}


class AccessControlModule:
    """Evidence-based authorization testing."""

    def __init__(self, target: str, console, surface=None, baseline=None,
                 primary_headers=None, secondary_headers=None,
                 mode: str = "active", max_targets: int = 60):
        self.target = target
        self.console = console
        self.surface = surface
        self.baseline = baseline
        self.mode = mode
        self.max_targets = max(1, int(max_targets))
        self.session = RateLimitedSession()

        self.primary = Identity("primary", primary_headers or {})
        self.secondary = Identity("secondary", secondary_headers or {})
        self.tested = 0
        self.results = {
            "missing_auth": [], "idor": [], "bola": [], "bfla": [],
            "inconsistent": [], "notes": [],
        }

    

    def _get(self, url: str, headers: dict = None):
        try:
            return self.session.get(url, timeout=TIMEOUT, headers=headers if headers is not None else {},
                                    allow_redirects=False)
        except Exception:
            return None

    def _enforced(self, response) -> bool:
        """True when the server clearly refused the request."""
        if response is None:
            return True
        if response.status_code in AUTH_DENIED_STATUSES:
            return True
        if response.status_code in (301, 302, 303, 307, 308):
            location = str(response.headers.get("Location", "")).lower()
            return any(word in location for word in ("login", "signin", "auth", "sso"))
        if response.status_code >= 500:
            return True
        if response.status_code == 200 and _looks_like_login(response.text)\
                and "password" in response.text.lower():
            return True
        return False

    def _is_baseline(self, response) -> bool:
        if self.baseline is None or response is None:
            return False
        try:
            return self.baseline.classify(response) == "catchall"
        except Exception:
            return False

    def _candidates(self) -> list:
        """Endpoints worth an authorization check."""
        urls = []
        if self.surface is not None:
            for endpoint in self.surface.endpoints()[: self.max_targets * 4]:
                url = endpoint.get("url", "")
                if url and url.startswith("http"):
                    urls.append(url)
        urls.append(self.target)
        unique = list(dict.fromkeys(urls))
        
        identified = [u for u in unique if self._object_carrier(u)]
        plain = [u for u in unique if u not in identified]
        return (identified + plain)[: self.max_targets]

    @staticmethod
    def _object_params(url: str) -> list:
        names = [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        return [name for name in names if name.lower() in OBJECT_PARAM_HINTS]

    @staticmethod
    def _object_carrier(url: str) -> bool:
        if AccessControlModule._object_params(url):
            return True
        parsed = urlparse(url)
        return bool(_OBJECT_PATH.search(parsed.path) or _UUID_PATH.search(parsed.path))

    @staticmethod
    def _substitute(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        replaced, done = [], False
        for key, current in pairs:
            if key == param and not done:
                replaced.append((key, value))
                done = True
            else:
                replaced.append((key, current))
        if not done:
            replaced.append((param, value))
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "",
                           urlencode(replaced, doseq=True), ""))

    

    def check_missing_authentication(self):
        """Is a response that requires a session also served without one?"""
        if not self.primary.authenticated:
            self.results["notes"].append(
                "missing-auth checks were skipped: no authenticated identity was "
                "supplied with --headers-file"
            )
            return

        info(self.console, "Testing for missing authentication on discovered routes...")
        for url in self._candidates():
            authed = self._get(url, self.primary.headers)
            self.tested += 1
            if authed is None or self._enforced(authed) or authed.status_code != 200:
                continue
            if self._is_baseline(authed):
                continue

            anonymous = self._get(url)
            self.tested += 1
            if anonymous is None or self._enforced(anonymous):
                continue
            if anonymous.status_code != 200 or self._is_baseline(anonymous):
                continue

            ratio = _ratio(authed.text, anonymous.text)
            if ratio >= IDENTICAL_RATIO:
                state = Verification.CONFIRMED
            elif ratio >= 0.90:
                state = Verification.LIKELY
            else:
                continue

            self.results["missing_auth"].append({
                "kind": "missing-auth",
                "title": "Route serves authenticated content without credentials",
                "severity": "high" if state is Verification.CONFIRMED else "medium",
                "target": url,
                "method": "GET",
                "parameter": "",
                "verification": state.value,
                "confidence": state.confidence,
                "evidence": (f"identical body similarity {ratio:.2f} with and without "
                             "the configured session headers"),
                "impact": ("Anyone who can reach the route reads the same data an "
                           "authenticated user sees."),
            })
            vuln(self.console, f"Missing authentication: {url} (similarity {ratio:.2f})")

    def check_horizontal(self):
        """Can the second identity read the first identity's object?"""
        if not (self.primary.authenticated and self.secondary.authenticated):
            self.results["notes"].append(
                "horizontal object access (IDOR/BOLA) could only be assessed at "
                "POTENTIAL level: a second test identity was not supplied"
            )
            self._single_identity_probe()
            return

        info(self.console, "Testing horizontal object access with two identities...")
        for url in self._candidates():
            if not self._object_carrier(url):
                continue

            as_primary = self._get(url, self.primary.headers)
            self.tested += 1
            if as_primary is None or as_primary.status_code != 200:
                continue
            if self._is_baseline(as_primary) or self._enforced(as_primary):
                continue

            as_secondary = self._get(url, self.secondary.headers)
            self.tested += 1
            if as_secondary is None or self._enforced(as_secondary):
                continue
            if as_secondary.status_code != 200 or self._is_baseline(as_secondary):
                continue

            ratio = _ratio(as_primary.text, as_secondary.text)
            if ratio >= IDENTICAL_RATIO:
                
                kind = "bola" if "/api" in urlparse(url).path.lower() else "idor"
                self.results[kind].append({
                    "kind": kind,
                    "title": ("Object-level authorization missing: a second identity "
                              "reads the same object"),
                    "severity": "high",
                    "target": url,
                    "method": "GET",
                    "parameter": ", ".join(self._object_params(url)),
                    "verification": Verification.CONFIRMED.value,
                    "confidence": 1.0,
                    "evidence": (f"body similarity {ratio:.2f} between two distinct "
                                 "authenticated identities on the same object URL"),
                    "impact": ("Any authenticated user can read another user's object "
                               "by reusing its identifier."),
                })
                vuln(self.console, f"{kind.upper()}: two identities received the same "
                                   f"object at {url}")

    def _single_identity_probe(self):
        """Neighbouring identifiers only ever produce a POTENTIAL finding."""
        if not self.primary.authenticated:
            return
        info(self.console, "Probing identifier neighbours (potential-level only)...")
        for url in self._candidates():
            params = self._object_params(url)
            if not params:
                continue
            param = params[0]
            parsed = urlparse(url)
            current = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(param, "")
            if not current.isdigit():
                continue
            base = self._get(url, self.primary.headers)
            self.tested += 1
            if base is None or base.status_code != 200 or self._is_baseline(base):
                continue

            for neighbour in (int(current) + 1, int(current) - 1):
                if neighbour < 1:
                    continue
                probe_url = self._substitute(url, param, str(neighbour))
                probe = self._get(probe_url, self.primary.headers)
                self.tested += 1
                if probe is None or probe.status_code != 200:
                    continue
                if self._is_baseline(probe) or self._enforced(probe):
                    continue
                similarity = _ratio(base.text, probe.text)
                if similarity >= 0.995:
                    continue  
                self.results["idor"].append({
                    "kind": "idor",
                    "title": "Sequential object identifier resolves to a distinct record",
                    "severity": "medium",
                    "target": probe_url,
                    "method": "GET",
                    "parameter": param,
                    "verification": Verification.POTENTIAL.value,
                    "confidence": 0.5,
                    "evidence": (f"identifier {neighbour} returned a different, valid "
                                 f"object (similarity {similarity:.2f} to {current})"),
                    "impact": ("If these identifiers belong to other users, object-level "
                               "authorization is missing. Confirm with a second account."),
                })
                found(self.console, f"Potential IDOR: {param}={neighbour} on "
                                    f"{urlparse(url).path}")
                break

    def check_vertical(self):
        """Can the second identity reach a privileged page?"""
        targets = self._privileged_targets()
        if not targets:
            self.results["notes"].append(
                "vertical authorization checks found no privileged path to test"
            )
            return
        identity = self.secondary if self.secondary.authenticated else Identity("anonymous", {})
        label = "the second identity" if identity.authenticated else "no credentials"
        info(self.console, f"Testing vertical authorization against {len(targets)} "
                           f"privileged path(s) as {label}...")
        for url in targets:
            response = self._get(url, identity.headers)
            self.tested += 1
            if response is None or self._enforced(response):
                continue
            if response.status_code != 200 or self._is_baseline(response):
                continue
            if not _looks_privileged(response.text):
                continue
            self.results["bfla"].append({
                "kind": "bfla",
                "title": "Privileged function reachable by an unprivileged identity",
                "severity": "high",
                "target": url,
                "method": "GET",
                "parameter": "",
                "verification": Verification.LIKELY.value,
                "confidence": 0.75,
                "evidence": (f"privileged page served to {label} with admin markers "
                             "present in the body"),
                "impact": ("Function-level authorization is missing, so a low-privilege "
                           "user can operate administrative features."),
            })
            vuln(self.console, f"BFLA: privileged page served to {label} at {url}")

    def _privileged_targets(self) -> list:
        base = self.target.rstrip("/")
        paths = ["admin", "administrator", "dashboard", "admin/users", "admin/settings",
                 "api/admin", "api/v1/admin", "manage", "internal", "console"]
        urls = [f"{base}/{path}" for path in paths]
        if self.surface is not None:
            for endpoint in self.surface.endpoints():
                path = endpoint.get("path", "").lower()
                if any(word in path for word in ("admin", "manage", "internal", "console")):
                    urls.append(endpoint.get("url", ""))
        return list(dict.fromkeys(u for u in urls if u.startswith("http")))[:12]

    def check_inconsistent_enforcement(self):
        """Two routes to the same resource where only one checks authorization."""
        by_path = {}
        for url in self._candidates():
            parsed = urlparse(url)
            key = parsed.path.rstrip("/").lower()
            by_path.setdefault(key, []).append(url)

        for key, urls in by_path.items():
            if len(urls) < 2:
                continue
            outcomes = []
            for url in urls[:4]:
                response = self._get(url, self.primary.headers)
                self.tested += 1
                outcomes.append((url, response is None or self._enforced(response)))
            if not outcomes:
                continue
            enforced = [url for url, blocked in outcomes if blocked]
            open_routes = [url for url, blocked in outcomes if not blocked]
            if enforced and open_routes:
                self.results["inconsistent"].append({
                    "kind": "missing-auth",
                    "title": "Authorization enforced on one route and not on an equivalent one",
                    "severity": "medium",
                    "target": open_routes[0],
                    "method": "GET",
                    "parameter": "",
                    "verification": Verification.POTENTIAL.value,
                    "confidence": 0.5,
                    "evidence": (f"{len(enforced)} equivalent route(s) refused the request "
                                 f"while {open_routes[0]} did not"),
                    "impact": ("Protection depends on which URL is used, so the check can "
                               "be bypassed by switching route."),
                })

    

    def _finish(self) -> dict:
        """Attach the counters the pipeline and report both read."""
        self.results["tested"] = self.tested
        self.results["identities"] = sum(
            1 for identity in (self.primary, self.secondary) if identity.authenticated
        )
        self.results["identity_detail"] = [identity.describe()
                                           for identity in (self.primary, self.secondary)]
        return self.results

    def run(self) -> dict:
        if self.mode == "safe":
            self.results["notes"].append("access-control testing requires --mode active")
            
            
            return self._finish()

        if not self.primary.authenticated and not self.secondary.authenticated:
            warning(self.console, "No identities were supplied: authorization testing "
                                  "falls back to unauthenticated route checks only.")

        self.check_missing_authentication()
        self.check_horizontal()
        self.check_vertical()
        self.check_inconsistent_enforcement()

        total = sum(len(self.results[key]) for key in
                    ("missing_auth", "idor", "bola", "bfla", "inconsistent"))
        self._finish()
        if total:
            success(self.console, f"Access control: {total} finding(s) across "
                                  f"{self.tested} request(s)")
        else:
            success(self.console, f"Access control: no authorization gap observed in "
                                  f"{self.tested} request(s)")
        return self.results
