import re
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlencode, urlparse

from config import TIMEOUT
from core.banner import info, success, vuln, warning
from core.findings import Verification
from core.http import RateLimitedSession





_STATE_TO_VERIFICATION = {
    "verified": Verification.CONFIRMED,
    "refuted": Verification.FALSE_POSITIVE,
    "inconclusive": Verification.INCONCLUSIVE,
    "unstable": Verification.POTENTIAL,
}


class Verifier:
    """Re-request candidate findings and preserve their verification state."""

    def __init__(self, target, console, baseline=None, attempts=2):
        self.target = target
        self.console = console
        self.baseline = baseline
        self.attempts = max(1, int(attempts))
        self.session = RateLimitedSession()
        self.records = {}
        self.summary = {"checked": 0, "verified": 0, "unstable": 0, "refuted": 0}
        self.file_inconclusive = []

    def _get(self, url, **kw):
        try:
            return self.session.get(url, timeout=TIMEOUT, **kw)
        except Exception:
            return None

    def _fetch_attempts(self, url, headers=None):
        responses = []
        for _ in range(self.attempts):
            resp = self._get(url, headers=headers, allow_redirects=False)
            if resp is not None:
                responses.append(resp)
        return responses

    def _fetch_twice(self, url, headers=None):
        """Compatibility alias for the original helper name."""
        return self._fetch_attempts(url, headers=headers)

    def _record(self, key, ok, detail, state=None):
        state = state or ("verified" if ok else "refuted")
        verification = _STATE_TO_VERIFICATION.get(state, Verification.INCONCLUSIVE)
        self.records[key] = {
            "verified": bool(ok),
            "state": state,
            "detail": detail,
            "verification": verification.value,
            "confidence": verification.confidence,
        }
        self.summary["checked"] += 1
        if ok:
            self.summary["verified"] += 1
        elif state == "refuted":
            self.summary["refuted"] += 1
        else:
            self.summary["unstable"] += 1
        return ok

    def verdict_for(self, key) -> tuple:
        """Return (Verification, reason) for a recorded check."""
        record = self.records.get(key) or {}
        state = _STATE_TO_VERIFICATION.get(record.get("state", ""),
                                           Verification.INCONCLUSIVE)
        return state, record.get("detail", "")

    def retest_finding(self, entry):
        """Reuse supported verification checks; unsupported evidence stays inconclusive."""
        url = entry.get("target") or entry.get("url")
        kind, param = entry.get("kind"), entry.get("param", "")
        payload = entry.get("payload", "")
        method = str(entry.get("method") or "GET").upper()
        if method != "GET" or re.match(r"(?i)^(form|body|json|header|cookie|path):", param):
            return {"attempts": 0, "reproduced": 0, "conclusive": False,
                    "reason": "stored request context is not supported by GET-only deterministic retesting"}
        param = re.sub(r"(?i)^query:", "", param)
        if kind == "xss" and payload:
            self.verify_reflection(url, param, payload)
            key = f"reflect:{url}#{param}"
        elif kind == "sqli" and payload and entry.get("error_signature"):
            self.verify_sql_error(url, param, payload, entry["error_signature"])
            key = f"sqli:{url}#{param}"
        elif kind == "open-redirect" and payload and entry.get("expected_location"):
            self.verify_redirect(url, param, payload, entry["expected_location"])
            key = f"redirect:{url}#{param}"
        elif kind in {"sensitive-file", "backup-file", "vcs-exposure", "source-map"}:
            self.verify_files([{"url": url}])
            key = f"file:{url}"
        else:
            return {"attempts": 0, "reproduced": 0, "conclusive": False,
                    "reason": "stored finding has no supported deterministic retest recipe"}
        record = self.records[key]
        conclusive = record["state"] in {"verified", "refuted"}
        return {"attempts": self.attempts, "reproduced": self.attempts if record["verified"] else 0,
                "conclusive": conclusive, "reason": record["detail"]}

    def annotate(self, entries, prefix: str) -> None:
        """Stamp each finding with its verification state and reason in place.

        Findings this run never re-checked stay POTENTIAL with an explicit
        reason instead of silently inheriting the scanner's own claim.
        """
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url") or entry.get("target") or ""
            param = entry.get("param") or entry.get("parameter") or ""
            key = f"{prefix}:{url}#{param}" if prefix not in ("leak",) else f"{prefix}:{url}"
            if key not in self.records:
                entry.setdefault("verification", Verification.POTENTIAL.value)
                entry.setdefault("verification_reason",
                                 "candidate was not re-requested in this run")
                continue
            state, reason = self.verdict_for(key)
            entry["verification"] = state.value
            entry["verification_reason"] = reason
            entry["confidence"] = state.confidence

    def _is_baseline(self, resp):
        if self.baseline is None or resp is None:
            return False
        try:
            return self.baseline.classify(resp) == "catchall"
        except Exception:
            return False

    @staticmethod
    def _normalise_body(text):
        """Remove common per-request values without erasing meaningful content."""
        value = str(text or "")
        patterns = (
            (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
             "<uuid>"),
            (r"\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?Z?\b",
             "<timestamp>"),
            (r"(?i)(nonce|csrf(?:token)?|request[_-]?id)(\s*[=:]\s*[\"']?)"
             r"[A-Za-z0-9._~+/=-]{8,}", r"\1\2<volatile>"),
            (r"(?i)(nonce|csrf(?:token)?|request[_-]?id)(\s*=\s*[\"'])[^\"']+",
             r"\1\2<volatile>"),
            (r"\b[0-9a-f]{24,}\b", "<hex>"),
        )
        for pattern, replacement in patterns:
            value = re.sub(pattern, replacement, value)
        return " ".join(value.split())

    @classmethod
    def _responses_equivalent(cls, responses):
        if not responses or len({r.status_code for r in responses}) != 1:
            return False
        normalised = [cls._normalise_body(r.text) for r in responses]
        first = normalised[0]
        for current in normalised[1:]:
            if first == current:
                continue
            if not first or not current:
                return False
            length_ratio = min(len(first), len(current)) / max(len(first), len(current))
            if length_ratio < 0.90 or SequenceMatcher(None, first, current).ratio() < 0.97:
                return False
        return True

    @staticmethod
    def _injected(url, param, payload):
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        params[param] = payload
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()

    def verify_files(self, entries, key="url", label="file"):
        confirmed, refuted = [], []
        self.file_inconclusive = []
        for entry in entries or []:
            url = entry.get(key)
            if not url:
                continue
            responses = self._fetch_attempts(url)
            record_key = f"{label}:{url}"
            if len(responses) < self.attempts:
                item = {"url": url, "why": "not reproducible", "state": "inconclusive"}
                self.file_inconclusive.append(item)
                self._record(record_key, False, "did not answer on every attempt",
                             state="inconclusive")
                continue

            statuses = {r.status_code for r in responses}
            status = responses[0].status_code if len(statuses) == 1 else None
            all_baseline = all(self._is_baseline(r) for r in responses)
            equivalent = self._responses_equivalent(responses)
            baseline_reliable = (self.baseline is not None and
                                 bool(getattr(self.baseline, "reliable", True)))

            if (status is not None and 200 <= status < 300 and equivalent and
                    baseline_reliable and not all_baseline):
                confirmed.append({"url": url, "status": status,
                                  "size": len(responses[0].content)})
                self._record(record_key, True, "stable after normalising per-request values")
            elif status in (404, 410) or all_baseline:
                why = "matched the catch-all baseline page" if all_baseline else f"HTTP {status}"
                refuted.append({"url": url, "why": why, "state": "refuted"})
                self._record(record_key, False, why, state="refuted")
            else:
                if not baseline_reliable and status is not None and 200 <= status < 300:
                    why = "no reliable catch-all baseline was available"
                elif status is None or not (200 <= status < 300):
                    why = f"HTTP status was not confirmable ({sorted(statuses)})"
                else:
                    why = "response content was not stable enough to confirm"
                item = {"url": url, "why": why, "state": "inconclusive"}
                self.file_inconclusive.append(item)
                self._record(record_key, False, why, state="inconclusive")
        return confirmed, refuted

    def verify_reflection(self, url, param, payload):
        if re.match(r"(?i)^(form|body|json|header|cookie|path):", str(param)):
            self._record(f"reflect:{url}#{param}", False, "request context is unsupported",
                         state="inconclusive")
            return False
        marker = str(payload or "")[:24]
        hits = 0
        responses = 0
        for _ in range(self.attempts):
            resp = self._get(self._injected(url, param, payload))
            if resp is not None and 200 <= resp.status_code < 300:
                responses += 1
            if resp is not None and 200 <= resp.status_code < 300 and marker and marker in resp.text and not self._is_baseline(resp):
                hits += 1
        ok = hits == self.attempts
        state = "refuted" if responses == self.attempts and hits == 0 else "inconclusive"
        self._record(f"reflect:{url}#{param}", ok, f"{hits}/{self.attempts} reflected",
                     state="verified" if ok else state)
        return ok

    def verify_sql_error(self, url, param, payload, signature):
        hits = 0
        responses = 0
        signature = str(signature or "").strip()
        if not signature:
            self._record(f"sqli:{url}#{param}", False, "no SQL error signature supplied",
                         state="inconclusive")
            return False
        for _ in range(self.attempts):
            resp = self._get(self._injected(url, param, payload))
            if resp is not None and 200 <= resp.status_code < 500 and resp.status_code not in {401, 403, 405, 407, 429}:
                responses += 1
            if resp is not None and 200 <= resp.status_code < 500 and resp.status_code not in {401, 403, 405, 407, 429} and signature.lower() in resp.text.lower():
                hits += 1
        ok = hits == self.attempts
        state = "refuted" if responses == self.attempts and hits == 0 else "inconclusive"
        self._record(f"sqli:{url}#{param}", ok, f"{hits}/{self.attempts} raised the signature",
                     state="verified" if ok else state)
        return ok

    def verify_redirect(self, url, param, payload, expected):
        responses = 0
        hits = 0
        for _ in range(self.attempts):
            resp = self._get(self._injected(url, param, payload))
            if resp is None:
                continue
            if not (200 <= resp.status_code < 400):
                continue
            responses += 1
            if expected in resp.headers.get("Location", ""):
                hits += 1
        if hits == self.attempts:
            self._record(f"redirect:{url}#{param}", True,
                         "redirect reproduced on every attempt")
            return True
        state = "refuted" if responses == self.attempts and hits == 0 else "inconclusive"
        detail = ("Location never pointed off-site" if state == "refuted"
                  else f"redirect reproduced on {hits}/{self.attempts} attempts")
        self._record(f"redirect:{url}#{param}", False, detail, state=state)
        return False

    def verify_leak(self, secret):
        source = secret.get("source", "")
        if not source.startswith("http"):
            return None
        value = str(secret.get("value", "")).split("...")[0][:40]
        if not value:
            self._record(f"leak:{source}", False, "no secret value supplied",
                         state="inconclusive")
            return False
        outcomes = []
        for _ in range(self.attempts):
            resp = self._get(source)
            outcomes.append(None if resp is None else value in resp.text)
        if all(outcome is True for outcome in outcomes):
            self._record(f"leak:{source}", True,
                         "value still present in every unauthenticated response")
            return True
        if all(outcome is False for outcome in outcomes):
            self._record(f"leak:{source}", False, "value no longer present", state="refuted")
            return False
        self._record(f"leak:{source}", False, "source/value result was not stable",
                     state="inconclusive")
        return False

    def _state(self, key):
        return (self.records.get(key) or {}).get("state")

    @staticmethod
    def _entries(value):
        if not isinstance(value, (list, tuple)):
            return []
        return [item for item in value if isinstance(item, dict)]

    def run(self, results):
        info(self.console, "Re-verifying findings against independent requests...")
        vulns = results.get("vulns", {}) or {}
        leaks = results.get("leaks", {}) or {}
        xss = results.get("xss", {}) or {}
        sqli = results.get("sqli", {}) or {}

        file_entries = (self._entries(vulns.get("sensitive_files"))
                        + self._entries(vulns.get("backup_files"))
                        + self._entries(vulns.get("admin_panels")))
        file_ok, file_bad = self.verify_files(file_entries, label="exposed-file")

        redirect_candidates = self._entries(vulns.get("open_redirects"))
        redirects_ok, redirects_bad, redirects_inconclusive = [], [], []
        for item in redirect_candidates[:10]:
            key = f"redirect:{item.get('url', '')}#{item.get('param', '')}"
            if self.verify_redirect(item.get("url", ""), item.get("param", ""),
                                    item.get("payload", ""), "evil.com"):
                redirects_ok.append(item)
            elif self._state(key) == "refuted":
                redirects_bad.append(item)
            else:
                redirects_inconclusive.append(item)

        reflection_candidates = self._entries(xss.get("reflected"))
        reflections_ok, reflections_bad, reflections_inconclusive = [], [], []
        for item in reflection_candidates[:12]:
            key = f"reflect:{item.get('url', '')}#{item.get('param', '')}"
            if self.verify_reflection(item.get("url", ""), item.get("param", ""),
                                      item.get("payload", "")):
                reflections_ok.append(item)
            elif self._state(key) == "refuted":
                reflections_bad.append(item)
            else:
                reflections_inconclusive.append(item)

        sqli_candidates = self._entries(sqli.get("vulnerable_params"))
        supported_sqli = [item for item in sqli_candidates
                          if item.get("type", "").startswith("Error")]
        unsupported_sqli = [item for item in sqli_candidates
                            if not item.get("type", "").startswith("Error")]
        sqli_ok, sqli_bad, sqli_inconclusive = [], [], []
        for item in supported_sqli[:12]:
            key = f"sqli:{item.get('url', '')}#{item.get('param', '')}"
            if self.verify_sql_error(item.get("url", ""), item.get("param", ""),
                                     item.get("payload", ""), item.get("evidence", "")):
                sqli_ok.append(item)
            elif self._state(key) == "refuted":
                sqli_bad.append(item)
            else:
                sqli_inconclusive.append(item)

        leak_candidates = self._entries(leaks.get("secrets"))
        leaks_still, leaks_bad, leaks_inconclusive = [], [], []
        for secret in leak_candidates[:25]:
            outcome = self.verify_leak(secret)
            if outcome is None:
                continue
            key = f"leak:{secret.get('source', '')}"
            if outcome:
                leaks_still.append(secret)
            elif self._state(key) == "refuted":
                leaks_bad.append(secret)
            else:
                leaks_inconclusive.append(secret)

        limits = {"redirects": 10, "reflections": 12, "sqli": 12, "secrets": 25}
        capped = {
            "redirects": max(0, len(redirect_candidates) - limits["redirects"]),
            "reflections": max(0, len(reflection_candidates) - limits["reflections"]),
            "sqli": max(0, len(supported_sqli) - limits["sqli"]),
            "secrets": max(0, len(leak_candidates) - limits["secrets"]),
        }
        def capped_items(items, limit):
            return [dict(item, verification_state="inconclusive",
                         verification_reason="verification cap reached")
                    for item in items[limit:]]

        redirects_capped = capped_items(redirect_candidates, limits["redirects"])
        reflections_capped = capped_items(reflection_candidates, limits["reflections"])
        sqli_capped = capped_items(supported_sqli, limits["sqli"])
        secrets_capped = capped_items(leak_candidates, limits["secrets"])
        coverage = {
            "candidates": {
                "files": len(file_entries), "redirects": len(redirect_candidates),
                "reflections": len(reflection_candidates), "sqli": len(sqli_candidates),
                "secrets": len(leak_candidates),
            },
            "capped": capped,
            "unsupported": {"sqli": len(unsupported_sqli)},
        }
        self.summary["candidates"] = sum(coverage["candidates"].values())
        self.summary["capped"] = sum(capped.values())
        self.summary["unsupported"] = len(unsupported_sqli)
        self.records["_summary"] = dict(self.summary)

        if file_bad:
            warning(self.console, f"{len(file_bad)} 'exposed file' finding(s) were refuted.")
            for item in file_bad[:8]:
                vuln(self.console, f"REFUTED: {item['url']} - {item['why']}")
        if leaks_still:
            for secret in leaks_still[:8]:
                vuln(self.console, f"CONFIRMED live: {secret['type']} still served at "
                                   f"{str(secret.get('source'))[:90]}")
        success(self.console, f"Verification: {self.summary['verified']}/{self.summary['checked']} "
                              "findings reproduced on every attempt")

        return {
            "summary": dict(self.summary), "coverage": coverage,
            "exposed_files_verified": file_ok,
            "exposed_files_refuted": file_bad,
            "exposed_files_inconclusive": list(self.file_inconclusive),
            "redirects_verified": redirects_ok,
            "redirects_refuted": redirects_bad,
            "redirects_inconclusive": redirects_inconclusive + redirects_capped,
            "reflection_verified": reflections_ok,
            "reflection_refuted": reflections_bad,
            "reflection_inconclusive": reflections_inconclusive + reflections_capped,
            "sqli_verified": sqli_ok,
            "sqli_refuted": sqli_bad,
            "sqli_inconclusive": sqli_inconclusive + unsupported_sqli + sqli_capped,
            "secrets_still_live": leaks_still,
            "secrets_refuted": leaks_bad,
            "secrets_inconclusive": leaks_inconclusive + secrets_capped,
            "records": self.records,
        }
