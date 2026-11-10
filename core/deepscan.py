"""Deep audit: checks that the classic modules did not cover, with confirmation.

Every finding carries an explicit ``confidence`` and ``verified`` flag so the
reporting layer can separate proof from suspicion. Bucket names line up with
``core.vuln.VulnModule`` so the results merge into the existing report without
changing the pipeline's stage structure.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from config import TIMEOUT
from core.banner import info, vuln
from core.http import RateLimitedSession
from core import evasion

TOKEN_RE = re.compile(r"(csrf|xsrf|authenticity|nonce|token)", re.IGNORECASE)
STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

REDIRECT_PARAMS = {
    "url", "uri", "redirect", "redirect_uri", "next", "return", "returnurl",
    "return_to", "redir", "go", "out", "continue", "dest", "destination",
    "target", "link", "callback", "forward", "to",
}

BYPASS_PAYLOADS = [
    "//evil.com/%2f..",
    "\\/\\/evil.com",
    "https:%2f%2fevil.com",
    "////evil.com/%2e%2e",
    "http://evil.com#@target",
    "//evil.com?target=1",
    "https://target@evil.com",
    "%09/evil.com",
    "//evil.com:80@target",
    "/\\evil.com",
]


class DeepScanner:
    def __init__(self, target: str, console, params=None, forms=None, pages=None,
                 baseline=None, session=None, mode: str = "active"):
        self.target = target
        self.console = console
        self.params = params or []
        self.forms = forms or []
        self.pages = pages or []
        self.baseline = baseline
        self.session = session or RateLimitedSession()
        self.mode = mode
        self.domain = urlparse(target).hostname or ""
        self.results = {
            "csrf": [], "xxe": [], "cache_poisoning": [],
            "open_redirects": [], "cors": [],
        }
        self._seen = set()

    

    def _get(self, url, headers=None, allow_redirects=False):
        try:
            return self.session.get(url, timeout=TIMEOUT, request_headers=headers,
                                    allow_redirects=allow_redirects)
        except Exception:
            return None

    def _post(self, url, data, headers=None):
        try:
            return self.session.post(url, data=data, timeout=TIMEOUT,
                                     request_headers=headers, allow_redirects=False)
        except Exception:
            return None

    def _catchall(self, resp):
        if resp is None or self.baseline is None:
            return False
        try:
            return self.baseline.classify(resp) == "catchall"
        except Exception:
            return False

    def _add(self, bucket, entry, key):
        if key in self._seen:
            return
        self._seen.add(key)
        self.results[bucket].append(entry)

    

    def check_csrf(self):
        info(self.console, "Auditing state-changing forms for CSRF token posture...")
        seen = set()
        for form in self.forms[:120]:
            action = form.get("action") or self.target
            method = (form.get("method") or "GET").upper()
            if method not in STATE_METHODS or action in seen:
                continue
            seen.add(action)
            names = [str(i.get("name", "")) for i in form.get("inputs", [])]
            if any(TOKEN_RE.search(name) for name in names):
                continue
            self._add("csrf", {
                "url": action,
                "param": "",
                "evidence": f"{method} form has no anti-CSRF token field",
                "severity": "medium",
                "confidence": 0.7,
                "verified": False,
                "method": method,
                "fields": len(names),
            }, ("csrf", action, method))

        resp = self._get(self.target)
        if resp is not None:
            cookie = resp.headers.get("Set-Cookie", "").lower()
            if "samesite=none" in cookie and "secure" not in cookie:
                self._add("csrf", {
                    "url": self.target,
                    "param": "",
                    "evidence": "session cookie uses SameSite=None without Secure",
                    "severity": "low",
                    "confidence": 0.8,
                    "verified": True,
                }, ("csrf-cookie", self.target))

        for entry in self.results["csrf"]:
            vuln(self.console, f"CSRF weakness: {entry['evidence']} @ {entry['url'][:70]}")

    

    def check_xxe(self):
        candidates = []
        for form in self.forms:
            if (form.get("method") or "").upper() == "POST":
                candidates.append(form.get("action") or self.target)
        candidates = list(dict.fromkeys([self.target] + candidates))[:12]

        info(self.console, f"Testing XML entity expansion on {len(candidates)} endpoint(s)...")
        token = "kripto" + secrets.token_hex(6)
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE r [<!ENTITY xxe "{token}">]><r><v>&xxe;</v></r>'
        )

        for url in candidates:
            for content_type in ("application/xml", "text/xml"):
                headers = evasion.headers({
                    "Content-Type": content_type,
                    "Accept": "application/xml,text/xml,*/*",
                })
                resp = self._post(url, body, headers=headers)
                if resp is None:
                    continue
                if token in resp.text:
                    self._add("xxe", {
                        "url": url,
                        "param": "",
                        "payload": body,
                        "evidence": "internal XML entity expanded into the response",
                        "severity": "critical",
                        "confidence": 0.8,
                        "verified": True,
                    }, ("xxe", url))
                    vuln(self.console, f"XXE: XML entity expansion confirmed @ {url[:70]}")
                    break

    

    def check_cache_poisoning(self):
        info(self.console, "Probing unkeyed headers on cacheable responses...")
        token = secrets.token_hex(8)
        canary = f"kripto-{token}.example"
        separator = "&" if "?" in self.target else "?"
        url = f"{self.target}{separator}kripto_cb={token}"
        headers = evasion.headers({
            "X-Forwarded-Host": canary,
            "X-Forwarded-Scheme": "http",
            "X-Host": canary,
            "X-Forwarded-Server": canary,
        })
        resp = self._get(url, headers=headers, allow_redirects=False)
        if resp is None or canary not in resp.text or self._catchall(resp):
            return

        cache_headers = {h: resp.headers.get(h, "") for h in
                         ("Age", "X-Cache", "CF-Cache-Status", "X-Cache-Status",
                          "Cache-Control", "Surrogate-Control")}
        cacheable = bool(
            cache_headers.get("Age") or cache_headers.get("X-Cache")
            or cache_headers.get("CF-Cache-Status")
            or cache_headers.get("X-Cache-Status")
            or "public" in cache_headers.get("Cache-Control", "").lower()
        )
        if not cacheable:
            return

        self._add("cache_poisoning", {
            "url": url,
            "param": "",
            "payload": canary,
            "evidence": "unkeyed X-Forwarded-Host reflected on a cacheable response",
            "severity": "high",
            "confidence": 0.8,
            "verified": True,
            "cache": {k: v for k, v in cache_headers.items() if v},
        }, ("cache", self.target))
        vuln(self.console, "Cache poisoning: unkeyed X-Forwarded-Host reflected on a "
                           "cacheable response")

    

    @staticmethod
    def _redirect_target(location: str) -> str:
        location = (location or "").strip()
        if location.startswith("//"):
            location = "https:" + location
        try:
            return (urlparse(location).hostname or "").lower()
        except ValueError:
            return ""

    def check_open_redirect(self):
        targets = [p for p in self.params
                   if str(p.get("param", "")).lower() in REDIRECT_PARAMS]
        if not targets:
            return

        info(self.console, f"Testing open-redirect bypasses on {len(targets)} params...")
        for item in targets[:40]:
            url = item.get("url") or self.target
            param = item.get("param", "")
            parsed = urlparse(url)
            for base_payload in BYPASS_PAYLOADS:
                for payload in evasion.variants(base_payload):
                    query = urlencode({param: payload})
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                           "", query, ""))
                    resp = self._get(test_url)
                    if resp is None:
                        continue
                    host = self._redirect_target(resp.headers.get("Location", ""))
                    if host == "evil.com" or host.endswith(".evil.com"):
                        self._add("open_redirects", {
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "redirect_to": resp.headers.get("Location", ""),
                            "evidence": "external redirect accepted through a bypass encoding",
                            "severity": "medium",
                            "confidence": 0.9,
                            "verified": True,
                        }, ("redirect", url, param))
                        vuln(self.console, f"Open Redirect bypass @ {param} -> "
                                           f"{resp.headers.get('Location', '')[:60]}")
                        break
                else:
                    continue
                break

    

    def check_cors(self):
        origins = ["null", f"https://evil.{self.domain}", f"https://{self.domain}.evil.com"]
        info(self.console, "Testing CORS origin-reflection bypasses...")
        for origin in origins:
            resp = self._get(self.target, headers={"Origin": origin})
            if resp is None:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if not acao:
                continue
            reflected = acao == origin or acao == "*"
            if not reflected:
                continue
            if acao == "*" and acac != "true":
                continue
            self._add("cors", {
                "url": self.target,
                "param": "",
                "evidence": f"Origin {origin!r} accepted (ACAO {acao!r}, credentials {acac or 'false'})",
                "severity": "high" if acac == "true" else "low",
                "confidence": 0.9 if acac == "true" else 0.6,
                "verified": True,
                "origin": origin,
                "acao": acao,
                "credentials": acac == "true",
            }, ("cors", origin))
            vuln(self.console, f"CORS accepts origin {origin!r} (credentials: {acac or 'false'})")

    

    def run(self) -> dict:
        checks = [self.check_csrf, self.check_open_redirect, self.check_cors]
        if self.mode == "intrusive":
            checks.extend((self.check_xxe, self.check_cache_poisoning))
        for check in checks:
            try:
                check()
            except Exception as exc:
                info(self.console, f"Deep audit check {check.__name__} skipped: "
                                   f"{type(exc).__name__}")
        return self.results
