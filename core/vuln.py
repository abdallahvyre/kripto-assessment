import concurrent.futures
import base64
import hashlib
import json
import os
import re
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from config import *
from core.banner import info, success, warning, vuln, found, make_table
from core.baseline import Baseline
from core.deepscan import DeepScanner
from core.http import RateLimitedSession
from core.pool import WorkerPool
from core.redact import redact_text


class VulnModule:
    def __init__(self, target: str, console, params=None, pages=None, baseline=None,
                 surface=None, workers=None, download_evidence: bool = False,
                 output_dir: str = "output", evidence_body_cap: int = 1_000_000,
                 mode: str = "active"):
        self.target = target
        self.console = console
        self.params = params or []
        self.pages = pages or []
        self.session = RateLimitedSession()
        self.baseline = baseline or Baseline(self.session, self.target, console).collect()
        self.surface = surface
        self.worker_pool = WorkerPool(workers=workers)
        self.download_evidence = bool(download_evidence)
        self.output_dir = output_dir
        self.evidence_body_cap = max(1, int(evidence_body_cap))
        self.mode = mode
        self._evidence_manifest = []
        self._evidence_lock = threading.Lock()
        self.results = {
            "sensitive_files": [], "admin_panels": [], "lfi": [],
            "open_redirects": [], "cors_misconfig": False,
            "clickjacking": False, "crlf": [], "backup_files": [],
            "info_disclosure": [], "ssti": [], "command_injection": [],
            "ssrf": [], "host_header": [], "verbose_errors": [],
            "csrf": [], "xxe": [], "cache_poisoning": [], "cors": [],
        }

    def _injection_targets(self, limit=200):
        if self.surface:
            return self.surface.injection_targets(limit=limit)
        return self.params[:limit]

    def _record_injection(self, kind, count=1):
        if self.surface and hasattr(self.surface, "record_injection"):
            self.surface.record_injection(kind, count)

    def check_template_injection(self):
        targets = self._injection_targets()
        if not targets:
            return
        info(self.console, f"Testing server-side template injection on {len(targets)} params...")
        for p in targets:
            url, param = p.get("url", self.target), p.get("param", "")
            if not param:
                continue
            parsed = urlparse(url)
            base = self._request_text(url)
            seed = int(hashlib.sha256(f"{url}|{param}".encode()).hexdigest()[:6], 16)
            left = 700 + (seed % 211)
            right = 800 + ((seed // 211) % 197)
            expected = str(left * right)
            probes = [
                (f"{{{{{left}*{right}}}}}", f"{{{{{left}*{right}x}}}}"),
                (f"${{{left}*{right}}}", f"${{{left}*{right}x}}"),
                (f"<%= {left}*{right} %>", f"<%= {left}*{right}x %>"),
                (f"#{{{left}*{right}}}", f"#{{{left}*{right}x}}"),
            ]
            for probe, control in probes:
                test_url = self._with_param(parsed, {param: probe})
                self._record_injection("ssti")
                resp = self._safe(test_url)
                if resp is None or self.baseline.classify(resp) == "catchall":
                    continue
                self._record_injection("ssti")
                control_resp = self._safe(self._with_param(parsed, {param: control}))
                if control_resp is None or self.baseline.classify(control_resp) == "catchall":
                    continue
                body = resp.text
                control_body = control_resp.text
                if (expected in body and expected not in base and expected not in control_body
                        and probe not in body):
                    self.results["ssti"].append({
                        "url": url, "param": param, "payload": probe,
                        "evidence": (f"unique expression evaluated to {expected}; malformed "
                                     "negative control did not"),
                        "confidence": 0.9, "verified": True, "severity": "critical",
                    })
                    vuln(self.console, f"SSTI @ {param} | {probe} -> {expected}")
                    break

    def check_command_injection(self):
        targets = self._injection_targets()
        if not targets:
            return
        info(self.console, f"Testing OS command injection on {len(targets)} params...")
        token = "kripto" + hashlib.sha256(os.urandom(12)).hexdigest()[:10]
        probes = [
            (f";echo {token}", token), (f"|echo {token}", token),
            (f"& echo {token}", token), (f"$(echo {token})", token),
        ]

        for p in targets:
            url, param = p.get("url", self.target), p.get("param", "")
            if not param:
                continue
            parsed = urlparse(url)
            base = self._request_text(url)
            for probe, marker in probes:
                test_url = self._with_param(parsed, {param: probe})
                self._record_injection("command_injection")
                resp = self._safe(test_url)
                if resp is None or self.baseline.classify(resp) == "catchall":
                    continue
                body = resp.text
                hit = marker in body and marker not in base
                evidence = "random echo canary returned by the command interpreter"
                if hit:
                    self.results["command_injection"].append({
                        "url": url, "param": param, "payload": probe,
                        "evidence": evidence, "confidence": 0.95,
                        "verified": True, "severity": "critical",
                    })
                    vuln(self.console, f"Command Injection @ {param} | {probe}")
                    break

    def check_ssrf(self):
        targets = self._injection_targets()
        if not targets:
            return
        info(self.console, f"Testing SSRF on {len(targets)} params...")
        probes = [
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://127.0.0.1:80/kripto-ssrf-canary",
        ]
        markers = ("instance-id", "ami-", "kripto-ssrf-canary")

        for p in targets[:80]:
            url, param = p.get("url", self.target), p.get("param", "")
            name = param.lower()
            if name not in ("url", "uri", "link", "src", "dest", "destination", "target",
                            "path", "endpoint", "webhook", "callback", "fetch", "proxy",
                            "redirect", "return", "next", "image", "site", "host", "domain"):
                continue
            parsed = urlparse(url)
            base = self._request_text(url)
            for probe in probes:
                test_url = self._with_param(parsed, {param: probe})
                self._record_injection("ssrf")
                resp = self._safe(test_url)
                if resp is None or self.baseline.classify(resp) == "catchall":
                    continue
                body = resp.text
                hit = next((m for m in markers if m in body and m not in base), None)
                if hit:
                    self.results["ssrf"].append({
                        "url": url, "param": param, "payload": probe,
                        "evidence": f"server-side fetch returned {hit!r}",
                        "confidence": 0.85, "verified": True, "severity": "high",
                    })
                    vuln(self.console, f"SSRF @ {param} | {probe} | {hit}")
                    break

    def check_host_header(self):
        info(self.console, "Testing Host header handling...")
        marker = "kripto-probe.example"
        try:
            self._record_injection("host_header")
            resp = self.session.get(self.target, request_headers={"Host": marker}, timeout=TIMEOUT,
                                    allow_redirects=False)
        except Exception:
            return
        if resp is None:
            return

        reflected = marker in resp.text
        location = resp.headers.get("Location", "")
        if location and marker in location:
            reflected = True

        try:
            self._record_injection("host_header")
            password_reset = self.session.get(self.target, request_headers={"X-Forwarded-Host": marker,
                                                                    "X-Original-URL": marker},
                                              timeout=TIMEOUT, allow_redirects=False)
            reflected = reflected or (password_reset is not None and marker in password_reset.text)
        except Exception:
            pass

        if reflected:
            self.results["host_header"].append({
                "url": self.target,
                "evidence": "attacker-controlled Host header value appears in the response",
                "confidence": 0.7, "verified": True, "severity": "high",
            })
            vuln(self.console, f"Host header value is reflected back ({marker}) - cache-poisoning and "
                               "password-reset-poisoning risk")

    def check_verbose_errors(self):
        targets = self._injection_targets(limit=60) if self.surface else self.params[:60]
        if not targets:
            return
        info(self.console, "Probing for debug/verbose modes...")
        probes = ["debug", "test", "verbose", "trace", "dev", "env", "XDEBUG_SESSION_START"]
        signatures = ("stack trace", "traceback (most recent call last)", "exception occurred",
                      "debug mode", "internal server error", "whoops", "laravel debug",
                      "you are seeing this because", "n+1 queries")

        for p in targets:
            url, param = p.get("url", self.target), p.get("param", "")
            if not param:
                continue
            parsed = urlparse(url)
            base = self._request_text(url).lower()
            for probe in probes:
                test_url = self._with_param(parsed, {param: probe})
                self._record_injection("verbose_errors")
                resp = self._safe(test_url)
                if resp is None or resp.status_code < 500:
                    continue
                lowered = resp.text.lower()
                sig = next((s for s in signatures if s in lowered), None)
                if sig and sig not in base:
                    self.results["verbose_errors"].append({
                        "url": url, "param": param, "probe": probe, "signature": sig,
                        "confidence": 0.8, "verified": True, "severity": "medium",
                    })
                    vuln(self.console, f"Debug/verbose mode @ {param}={probe} ({sig})")
                    break

    @staticmethod
    def _with_param(parsed, overrides):
        base_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        base_params.update(overrides)
        query = urlencode(base_params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

    def _safe(self, url):
        try:
            return self.session.get(url, timeout=TIMEOUT)
        except Exception:
            return None

    def _request_text(self, url: str) -> str:
        """Body of an unmodified request, used as the comparison baseline.

        Compared as text, not as a Response, so a template that happens to be
        in the clean page is not reported as injection.
        """
        resp = self._safe(url)
        return resp.text if resp is not None else ""

    @staticmethod
    def _safe_evidence_name(value: str, fallback: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
        return (cleaned[:80] or fallback)

    def _write_evidence_manifest(self, root: str):
        manifest = os.path.join(root, "manifest.json")
        temporary = manifest + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"artifacts": self._evidence_manifest}, handle, indent=2)
        os.replace(temporary, manifest)

    def _download_file(self, url: str, category: str, response=None,
                       verified: bool = True) -> dict:
        """Create metadata by default; persist capped bytes only when opted in."""
        if response is None and not self.download_evidence:
            return {
                "saved": False,
                "reason": "evidence download disabled",
                "body_cap": self.evidence_body_cap,
            }

        try:
            resp = response
            if resp is None:
                resp = self.session.get(url, timeout=TIMEOUT, stream=True)
            if resp is None or resp.status_code != 200:
                return {"saved": False, "reason": "evidence response unavailable"}

            body = bytes(resp.content)
            observed = len(body)
            full_digest = hashlib.sha256(body).hexdigest()
            captured = body[: self.evidence_body_cap]
            metadata = {
                "saved": False,
                "sha256": full_digest,
                "observed_bytes": observed,
                "captured_bytes": 0,
                "body_cap": self.evidence_body_cap,
                "truncated": observed > self.evidence_body_cap,
                "content_type": resp.headers.get("Content-Type", ""),
            }
            if not self.download_evidence or not verified:
                if self.download_evidence and not verified:
                    metadata["reason"] = "finding is not verified"
                return metadata

            parsed = urlparse(url)
            host = self._safe_evidence_name(urlparse(self.target).hostname or "target", "target")
            safe_category = self._safe_evidence_name(category, "evidence")
            root = os.path.join(self.output_dir, "evidence", host)
            dest_dir = os.path.join(root, safe_category)
            filename = self._safe_evidence_name(os.path.basename(parsed.path), "artifact.bin")
            filename = f"{full_digest[:12]}_{filename}"
            filepath = os.path.join(dest_dir, filename)

            with self._evidence_lock:
                os.makedirs(dest_dir, exist_ok=True)
                with open(filepath, "wb") as handle:
                    handle.write(captured)
                metadata.update({
                    "saved": True,
                    "saved_path": filepath,
                    "captured_bytes": len(captured),
                    "artifact_sha256": hashlib.sha256(captured).hexdigest(),
                })
                self._evidence_manifest.append({
                    "url": redact_text(url),
                    "category": safe_category,
                    **metadata,
                })
                self._write_evidence_manifest(root)

            found(self.console, f"Evidence saved: {filename} ({len(captured)} bytes)")
            return metadata
        except Exception as exc:
            return {"saved": False, "reason": f"{type(exc).__name__}: {exc}"}

    def _interesting(self, resp):
        """Returns (keep, verified). Drops proven catch-all pages."""
        verdict = self.baseline.classify(resp)
        if verdict == "catchall":
            return False, False
        return True, verdict == "unique"

    def check_sensitive_files(self):
        info(self.console, f"Checking {len(SENSITIVE_PATHS)} sensitive paths...")

        def check_path(path):
            url = urljoin(self.target + "/", path)
            try:
                resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=False)
            except Exception:
                return None
            if resp.status_code != 200 or len(resp.content) < 10:
                return None
            keep, verified = self._interesting(resp)
            if not keep:
                return None
            return {
                "path": path, "url": url, "status": 200,
                "size": len(resp.content),
                "preview": redact_text(resp.text[:200].strip()),
                "verified": verified,
                "evidence": self._download_file(
                    url, "sensitive_files", response=resp, verified=verified
                ),
            }

        workers = self.worker_pool.size()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check_path, p): p for p in SENSITIVE_PATHS}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    result = None
                if not result:
                    continue
                self.results["sensitive_files"].append(result)
                tag = "" if result["verified"] else " [UNVERIFIED]"
                vuln(self.console, f"Sensitive file: {result['path']} ({result['size']}B){tag}")

    def check_admin_panels(self):
        info(self.console, f"Checking {len(ADMIN_PATHS)} admin paths...")

        login_pattern = re.compile(
            r'type\s*=\s*["\']?password|<form[^>]+(?:login|signin|auth)',
            re.IGNORECASE,
        )

        def check_admin(path):
            url = urljoin(self.target + "/", path)
            try:
                resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
            except Exception:
                return None

            if self.baseline.classify(resp) == "catchall":
                return None

            if resp.status_code in (401, 403):
                return {"path": path, "url": url, "status": resp.status_code,
                        "has_login": False, "verified": True}

            if resp.status_code != 200:
                return None

            keep, verified = self._interesting(resp)
            if not keep:
                return None

            if login_pattern.search(resp.text):
                return {"path": path, "url": url, "status": 200,
                        "has_login": True, "verified": verified}
            return None

        workers = self.worker_pool.size()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check_admin, p): p for p in ADMIN_PATHS}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    self.results["admin_panels"].append(result)
                    tag = "" if result["verified"] else " [UNVERIFIED]"
                    found(self.console, f"Admin panel: {result['path']} [{result['status']}]{tag}")

    def check_lfi(self):
        targets = self._injection_targets(limit=150)
        if not targets:
            info(self.console, "Skipping LFI: no URL parameters were discovered.")
            return

        info(self.console, f"Testing LFI on {len(targets)} params...")
        lfi_indicators = [
            "pretty_name=", "version_id=", "[boot loader]", "[fonts]",
            "[extensions]", "for 16-bit app support",
        ]

        for p in targets:
            url = p.get("url", self.target)
            param = p.get("param", "")
            if not param:
                continue

            parsed = urlparse(url)
            base_params = parse_qs(parsed.query)

            for payload in LFI_PAYLOADS:
                try:
                    test_params = dict(base_params)
                    test_params[param] = payload
                    query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

                    self._record_injection("lfi")
                    resp = self.session.get(test_url, timeout=TIMEOUT)
                    if self.baseline.classify(resp) == "catchall":
                        continue
                    body = resp.text.lower()

                    evidence = next((i for i in lfi_indicators if i.lower() in body), None)
                    if evidence:
                        self.results["lfi"].append({
                            "url": url, "param": param,
                            "payload": payload, "evidence": evidence,
                            "confidence": 0.9, "verified": True,
                            "severity": "critical",
                        })
                        vuln(self.console, f"LFI @ {param} | {payload}")
                        break
                except Exception:
                    continue

    def check_open_redirect(self):
        targets = self._injection_targets(limit=200)
        if not targets:
            return

        redirect_params = ["url", "redirect", "next", "return", "returnurl",
                           "redir", "redirect_uri", "return_to", "go", "out",
                           "continue", "dest", "destination", "target", "link"]
        redirect_payloads = [
            "//evil.com", "https://evil.com", "/\\evil.com",
            "//evil%252ecom", "////evil.com", "https:evil.com",
        ]

        for p in targets:
            param = p.get("param", "").lower()
            if param not in redirect_params:
                continue

            url = p.get("url", self.target)
            parsed = urlparse(url)

            for payload in redirect_payloads:
                try:
                    test_params = {param: payload}
                    query = urlencode(test_params)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

                    self._record_injection("open_redirect")
                    resp = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    location = resp.headers.get("Location", "")
                    destination = urlparse(urljoin(test_url, location)).hostname or ""

                    if destination.lower() == "evil.com":
                        self.results["open_redirects"].append({
                            "url": url, "param": param,
                            "payload": payload, "redirect_to": location,
                            "confidence": 0.85, "verified": True, "severity": "medium",
                        })
                        vuln(self.console, f"Open Redirect @ {param} -> {location}")
                        break
                except Exception:
                    continue

    def check_cors(self):
        urls = [self.target] + [e["url"] for e in
                                (self.surface.endpoints()[:15] if self.surface else [])]
        for url in dict.fromkeys(urls):
            try:
                self._record_injection("cors")
                resp = self.session.get(url, request_headers={"Origin": "https://evil-attacker.com"},
                                        timeout=TIMEOUT)
            except Exception:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.results["cors_misconfig"] = True
                self.results["info_disclosure"].append({
                    "type": "CORS Wildcard", "detail": f"{url} -> Access-Control-Allow-Origin: *",
                    "severity": "low",
                })
                vuln(self.console, f"CORS wildcard origin on {url} (low impact without credentials)")
            elif "evil-attacker.com" in acao:
                self.results["cors_misconfig"] = True
                self.results["info_disclosure"].append({
                    "type": "CORS Origin Reflection", "detail": f"{url} -> reflected: {acao}",
                    "severity": "high" if acac.lower() == "true" else "medium",
                })
                vuln(self.console, f"CORS reflects arbitrary origin on {url}: {acao}")
                if acac.lower() == "true":
                    vuln(self.console, "CORS + Allow-Credentials = credential theft possible")

    def check_clickjacking(self):
        urls = [self.target] + [p for p in (self.pages[:25] if self.pages else [])]
        unguarded = 0
        for url in dict.fromkeys(urls):
            try:
                resp = self.session.get(url, timeout=TIMEOUT)
            except Exception:
                continue
            content_type = resp.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                continue
            if self.baseline.classify(resp) == "catchall":
                continue
            xfo = resp.headers.get("X-Frame-Options", "")
            csp = resp.headers.get("Content-Security-Policy", "")
            if not xfo and "frame-ancestors" not in csp.lower():
                unguarded += 1
        self.results["clickjacking"] = unguarded > 0
        if unguarded:
            warning(self.console, f"Clickjacking possible on {unguarded} page(s): "
                                  "no X-Frame-Options and no CSP frame-ancestors")

    def check_crlf(self):
        targets = self._injection_targets(limit=120)
        if not targets:
            return

        crlf_payloads = [
            "%0d%0aSet-Cookie:crlf=injected",
            "%0aSet-Cookie:crlf=injected",
            "\r\nSet-Cookie:crlf=injected",
            "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injected",
        ]

        for p in targets:
            url = p.get("url", self.target)
            param = p.get("param", "")
            parsed = urlparse(url)

            for payload in crlf_payloads:
                try:
                    test_params = {param: payload}
                    query = urlencode(test_params)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

                    self._record_injection("crlf")
                    resp = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    if "crlf=injected" in resp.headers.get("Set-Cookie", ""):
                        self.results["crlf"].append({
                            "url": url, "param": param, "payload": payload,
                            "evidence": "injected Set-Cookie header observed",
                            "confidence": 0.95, "verified": True, "severity": "high",
                        })
                        vuln(self.console, f"CRLF Injection @ {param}")
                        break
                except Exception:
                    continue

    def check_backup_files(self):
        backup_exts = [".bak", ".old", ".copy", ".orig", ".save",
                        ".swp", ".swo", "~", ".tmp", ".temp"]

        pages_to_check = self.pages[:120] if self.pages else [self.target]
        checked = 0

        for page in pages_to_check:
            parsed = urlparse(page)
            path = parsed.path
            if not path or path == "/":
                continue

            for ext in backup_exts:
                backup_url = f"{parsed.scheme}://{parsed.netloc}{path}{ext}"
                try:
                    resp = self.session.get(backup_url, timeout=TIMEOUT, allow_redirects=False)
                except Exception:
                    continue

                if resp.status_code != 200 or len(resp.content) < 100:
                    continue

                keep, verified = self._interesting(resp)
                if not keep:
                    continue

                checked += 1
                self.results["backup_files"].append({
                    "url": backup_url, "status": 200,
                    "size": len(resp.content), "verified": verified,
                    "evidence": self._download_file(
                        backup_url, "backup_files", response=resp, verified=verified
                    ),
                })
                tag = "" if verified else " [UNVERIFIED]"
                found(self.console, f"Backup file: {path}{ext} ({len(resp.content)}B){tag}")

    def run(self) -> dict:
        if self.baseline.catch_all:
            warning(
                self.console,
                "Host serves a catch-all page for unknown paths - content-based checks "
                "will discard baseline matches.",
            )

        self.check_sensitive_files()
        self.check_admin_panels()
        self.check_template_injection()
        if self.mode == "intrusive":
            self.check_command_injection()
            self.check_ssrf()
            self.check_lfi()
        self.check_open_redirect()
        self.check_cors()
        self.check_clickjacking()
        self.check_crlf()
        self.check_host_header()
        self.check_verbose_errors()
        self.check_backup_files()

        deep = DeepScanner(
            self.target,
            self.console,
            params=self.params,
            forms=self.surface.forms() if self.surface else [],
            pages=self.pages,
            baseline=self.baseline,
            session=self.session,
            mode=self.mode,
        ).run()
        for key in ("csrf", "xxe", "cache_poisoning"):
            self.results[key].extend(deep.get(key, []))
        self.results["open_redirects"].extend(deep.get("open_redirects", []))
        if deep.get("cors"):
            self.results["cors"] = deep["cors"]
            self.results["cors_misconfig"] = True
            for entry in deep["cors"]:
                self.results["info_disclosure"].append({
                    "type": "CORS Origin Acceptance",
                    "detail": entry["evidence"],
                    "severity": entry["severity"],
                })

        total = (len(self.results["sensitive_files"]) + len(self.results["admin_panels"])
                 + len(self.results["lfi"]) + len(self.results["open_redirects"])
                 + len(self.results["crlf"]) + len(self.results["backup_files"])
                 + len(self.results["ssti"]) + len(self.results["command_injection"])
                 + len(self.results["ssrf"]) + len(self.results["host_header"])
                 + len(self.results["verbose_errors"])
                 + len(self.results["csrf"]) + len(self.results["xxe"])
                 + len(self.results["cache_poisoning"])
                 + (1 if self.results["cors_misconfig"] else 0)
                 + (1 if self.results["clickjacking"] else 0))

        rows = [
            ("Sensitive Files", str(len(self.results["sensitive_files"])), "HIGH"),
            ("Admin Panels", str(len(self.results["admin_panels"])), "MEDIUM"),
            ("LFI", str(len(self.results["lfi"])), "CRITICAL"),
            ("SSTI", str(len(self.results["ssti"])), "CRITICAL"),
            ("Command Injection", str(len(self.results["command_injection"])), "CRITICAL"),
            ("SSRF", str(len(self.results["ssrf"])), "HIGH"),
            ("Open Redirects", str(len(self.results["open_redirects"])), "MEDIUM"),
            ("Host Header Injection", str(len(self.results["host_header"])), "HIGH"),
            ("Verbose/Debug Modes", str(len(self.results["verbose_errors"])), "MEDIUM"),
            ("CORS Misconfig", "Yes" if self.results["cors_misconfig"] else "No", "HIGH"),
            ("Clickjacking", "Yes" if self.results["clickjacking"] else "No", "LOW"),
            ("CRLF Injection", str(len(self.results["crlf"])), "HIGH"),
            ("Backup Files", str(len(self.results["backup_files"])), "MEDIUM"),
            ("CSRF Posture", str(len(self.results["csrf"])), "MEDIUM"),
            ("XXE", str(len(self.results["xxe"])), "CRITICAL"),
            ("Cache Poisoning", str(len(self.results["cache_poisoning"])), "HIGH"),
        ]
        self.console.print(make_table("Vulnerability Summary", ["Check", "Findings", "Severity"], rows))

        success(self.console, f"Vuln scan complete: {total} total findings")
        return self.results
