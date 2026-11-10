"""REST assessment of a documented API.

Every check here is read-oriented.  The only non-GET request this module makes
is a malformed JSON body against an operation the document already declares as
accepting JSON, and that is limited to ``intrusive`` mode; the checks that
matter most - "the document says this needs a credential, the server answered
anyway" - need nothing more than a GET.

Requests travel through the caller's ``RateLimitedSession``, so scope, rate and
transport are enforced where they are enforced everywhere else.
"""

from __future__ import annotations

import json

from config import TIMEOUT
from core import findings as finding_model


_REFUSAL_CODES = frozenset({401, 403, 407})


_ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "sqlexception", "sqlstate", "syntax error at or near",
    "at java.", "at org.springframework",
    "system.nullreferenceexception",
    "stack trace:", "debug mode", "werkzeug debugger",
    "you have an error in your sql syntax",
    "notice: undefined", "warning: mysqli",
)

_MALFORMED_JSON = '{"probe": '


class RestAssessor:
    """Assess documented operations against what the server actually allows."""

    def __init__(self, target: str, console, session, spec=None,
                 surface=None, mode: str = "safe", budget: int = 40):
        self.target = target.rstrip("/")
        self.console = console
        self.session = session
        self.spec = spec
        self.surface = surface
        self.mode = mode
        self.budget = max(1, int(budget))
        self.spent = 0

    

    def _spend(self, count: int = 1) -> bool:
        """Charge the run-wide probe budget; refuse when it is exhausted."""
        if self.spent + count > self.budget:
            return False
        if self.surface is not None and not self.surface.record_probe(count):
            return False
        self.spent += count
        return True

    def _request(self, method: str, url: str, **kwargs):
        try:
            return self.session.request(method, url, timeout=TIMEOUT,
                                        allow_redirects=False, **kwargs)
        except Exception:
            return None

    def _operations(self) -> tuple:
        if self.spec is None:
            return ()
        return tuple(self.spec.operations)

    @staticmethod
    def _looks_like_error_disclosure(body: str) -> str:
        lowered = str(body or "").lower()
        for signature in _ERROR_SIGNATURES:
            if signature in lowered:
                return signature
        return ""

    

    def check_documented_auth(self) -> tuple:
        """Operations the document marks private that answer without a session.

        Two independent requests are needed before the finding is called
        CONFIRMED, because a single 200 can be a cached or catch-all response.
        """
        results = []
        for operation in self.spec.documented_private_operations() if self.spec else ():
            if operation.method not in ("GET", "HEAD"):
                
                
                continue
            if not self._spend():
                break

            first = self._request(operation.method, operation.url, headers={})
            if first is None or first.status_code in _REFUSAL_CODES:
                continue
            if not 200 <= first.status_code < 300:
                continue

            if not self._spend():
                reproduced = 1
            else:
                second = self._request(operation.method, operation.url, headers={})
                reproduced = 2 if (second is not None
                                   and second.status_code == first.status_code
                                   and len(second.content) == len(first.content)) else 1

            state = finding_model.classify(reproduced, 2)
            results.append({
                "kind": "missing-auth",
                "title": (f"Documented protected operation {operation.method} "
                          f"{operation.path} answers without a credential"),
                "severity": "high" if operation.method == "GET" else "medium",
                "cvss_score": 7.5 if operation.method == "GET" else 6.5,
                "target": operation.url,
                "method": operation.method,
                "param": "",
                "payload": "",
                "evidence": (f"The specification declares "
                             f"{', '.join(operation.security_schemes) or 'authentication'} "
                             f"for this operation; unauthenticated {operation.method} "
                             f"returned HTTP {first.status_code} "
                             f"({len(first.content)} bytes)."),
                "verification": state.value,
                "confidence": state.confidence,
                "api_operation": operation.as_dict(),
            })
        return tuple(results)

    def check_error_disclosure(self) -> tuple:
        """Malformed input that produces a framework or database error."""
        results = []
        candidates = [op for op in self._operations()
                      if op.method == "POST" and op.body_properties]
        for operation in candidates[:5]:
            if self.mode != "intrusive":
                
                
                continue
            if not self._spend():
                break
            response = self._request(
                "POST", operation.url,
                data=_MALFORMED_JSON,
                request_headers={"Content-Type": "application/json"},
            )
            if response is None:
                continue
            body = response.text[:8000] if response.text else ""
            signature = self._looks_like_error_disclosure(body)
            if not signature:
                continue
            results.append({
                "kind": "verbose-errors",
                "title": f"Malformed JSON body discloses internal errors on {operation.path}",
                "severity": "low",
                "cvss_score": 3.1,
                "target": operation.url,
                "method": "POST",
                "param": "",
                "payload": _MALFORMED_JSON,
                "evidence": f"Response contained {signature!r} after a truncated JSON body.",
                "verification": finding_model.Verification.CONFIRMED.value,
                "confidence": finding_model.Verification.CONFIRMED.confidence,
            })
        return tuple(results)

    def check_trace(self) -> tuple:
        """TRACE enabled on an API origin reflects the request back."""
        if not self._spend():
            return ()
        response = self._request("TRACE", self.target)
        if response is None or response.status_code != 200:
            return ()
        echoed = "TRACE" in (response.text or "")[:2000]
        if not echoed:
            return ()
        return ({
            "kind": "verb-tampering",
            "title": "TRACE method is enabled and echoes the request",
            "severity": "low",
            "cvss_score": 3.5,
            "target": self.target,
            "method": "TRACE",
            "param": "",
            "payload": "",
            "evidence": "TRACE returned HTTP 200 with the request line reflected back.",
            "verification": finding_model.Verification.CONFIRMED.value,
            "confidence": finding_model.Verification.CONFIRMED.confidence,
        },)

    def check_deprecated_live(self) -> dict:
        """Deprecated operations that still answer - inventory, not a finding."""
        live = []
        for operation in self._operations():
            if not operation.deprecated or operation.method not in ("GET", "HEAD"):
                continue
            if not self._spend():
                break
            response = self._request(operation.method, operation.url)
            if response is not None and response.status_code < 400:
                live.append({"method": operation.method, "path": operation.path,
                             "url": operation.url, "status": response.status_code})
        return {"deprecated_operations_still_live": live}

    def check_alternative_versions(self) -> dict:
        """Version prefixes documented by the spec that also answer."""
        if self.spec is None:
            return {"alternative_versions": []}
        paths = [op.path for op in self.spec.operations]
        prefixes = {path.split("/")[1] for path in paths
                    if path.count("/") >= 2 and path.split("/")[1] in
                    ("v1", "v2", "v3", "v4", "beta", "internal", "private")}
        observed = []
        for prefix in sorted(prefixes):
            if not self._spend():
                break
            root = f"{self.target}/{prefix}/"
            response = self._request("GET", root)
            if response is not None and response.status_code < 400:
                observed.append({"prefix": prefix, "url": root,
                                 "status": response.status_code})
        return {"alternative_versions": observed,
                "documented_prefixes": sorted(prefixes)}

    

    def run(self) -> dict:
        report = {
            "spec": self.spec.summary() if self.spec is not None else {},
            "checked_operations": len(self._operations()),
            "probes_used": 0,
            "findings": [],
            "notes": [],
        }
        if self.spec is None or not self.spec.operations:
            report["notes"].append(
                "No API specification was parsed, so documented-operation checks "
                "were not attempted.")
            report["skipped"] = True
            return report

        if self.mode == "safe":
            report["notes"].append(
                "Safe mode: only read-oriented API checks ran; malformed-body "
                "error probing needs --mode intrusive.")

        collected = []
        collected.extend(self.check_documented_auth())
        collected.extend(self.check_error_disclosure())
        collected.extend(self.check_trace())
        report.update(self.check_deprecated_live())
        report.update(self.check_alternative_versions())

        report["findings"] = list(collected)
        report["probes_used"] = self.spent
        report["missing_auth_count"] = sum(
            1 for item in collected if item["kind"] == "missing-auth")
        return report
