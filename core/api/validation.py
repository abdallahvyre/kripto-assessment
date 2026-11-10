"""API input validation checks.

Two different claims live here and they are kept apart:

* an operation that answers HTTP 500 to a value its own specification says is
  an integer has an input-handling defect - that is measured, so it is a
  finding;
* an operation that documents a privileged field (``role``, ``is_admin``) in a
  writable body is a mass-assignment *candidate* - nothing was written, so it
  is reported as POTENTIAL with wording that makes that clear.

Only GET operations are probed on the wire.  A write operation is never sent a
synthesised body, because "the field is accepted" and "the field is honoured"
would then be indistinguishable from a real state change.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, urlunparse

from config import TIMEOUT
from core import findings as finding_model


_TYPE_CONFUSION_VALUE = "kripto-not-a-number"
_BOUNDARY_VALUES = ("-1", "0", "9999999999999999999", "")

_NUMERIC_TYPES = frozenset({"integer", "number"})


class ValidationAssessor:
    """Input-handling checks over documented query parameters."""

    def __init__(self, target: str, console, session, spec=None,
                 surface=None, mode: str = "safe", budget: int = 30):
        self.target = target.rstrip("/")
        self.console = console
        self.session = session
        self.spec = spec
        self.surface = surface
        self.mode = mode
        self.budget = max(1, int(budget))
        self.spent = 0

    

    def _spend(self, count: int = 1) -> bool:
        if self.spent + count > self.budget:
            return False
        if self.surface is not None and not self.surface.record_probe(count):
            return False
        self.spent += count
        return True

    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=TIMEOUT, allow_redirects=False)
        except Exception:
            return None

    @staticmethod
    def _with_query(url: str, name: str, value: str) -> str:
        """Set one query parameter, leaving every other byte untouched."""
        parsed = urlparse(url)
        pairs, replaced = [], False
        for chunk in (parsed.query or "").split("&"):
            if not chunk:
                continue
            key, _, current = chunk.partition("=")
            if key == name and not replaced:
                pairs.append((key, value))
                replaced = True
            else:
                pairs.append((key, current))
        if not replaced:
            pairs.append((name, value))
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "",
                           urlencode(pairs, doseq=True), ""))

    def _numeric_query_operations(self):
        for operation in (self.spec.operations if self.spec else ()):
            if operation.method != "GET":
                continue
            parameters = [p for p in operation.parameters
                          if p.location == "query"
                          and p.schema_type in _NUMERIC_TYPES]
            if parameters:
                yield operation, parameters

    def _finding(self, operation, parameter, url, value, status, evidence) -> dict:
        return {
            "kind": "input-validation",
            "title": (f"Improper input validation on {parameter.name} "
                      f"({operation.path})"),
            "severity": "low",
            "cvss_score": 3.7,
            "target": url,
            "method": operation.method,
            "param": parameter.name,
            "payload": value,
            "evidence": evidence,
            "verification": finding_model.Verification.CONFIRMED.value,
            "confidence": finding_model.Verification.CONFIRMED.confidence,
        }

    

    def check_type_confusion(self) -> tuple:
        """A declared integer that the server fails to validate."""
        results = []
        for operation, parameters in self._numeric_query_operations():
            for parameter in parameters:
                if not self._spend():
                    return tuple(results)
                url = self._with_query(operation.url, parameter.name,
                                       _TYPE_CONFUSION_VALUE)
                response = self._get(url)
                if response is None or response.status_code < 500:
                    continue
                results.append(self._finding(
                    operation, parameter, url, _TYPE_CONFUSION_VALUE,
                    response.status_code,
                    f"{operation.method} {operation.path} documents "
                    f"{parameter.name} as {parameter.schema_type} and answered "
                    f"HTTP {response.status_code} to a non-numeric value "
                    f"instead of rejecting it."))
        return tuple(results)

    def check_boundaries(self) -> tuple:
        """Negative, zero and oversized values that end in a server error."""
        results = []
        for operation, parameters in self._numeric_query_operations():
            for parameter in parameters:
                for boundary in _BOUNDARY_VALUES:
                    if not self._spend():
                        return tuple(results)
                    url = self._with_query(operation.url, parameter.name, boundary)
                    response = self._get(url)
                    if response is None or response.status_code < 500:
                        continue
                    results.append(self._finding(
                        operation, parameter, url, boundary,
                        response.status_code,
                        f"{operation.method} {operation.path} answered HTTP "
                        f"{response.status_code} for {parameter.name}="
                        f"{boundary!r} instead of a validation error."))
                    break
        return tuple(results)

    def check_mass_assignment(self) -> tuple:
        """Documented writable privileged fields - a candidate, never a proof."""
        results = []
        for operation in (self.spec.operations if self.spec else ()):
            if operation.method not in ("POST", "PUT", "PATCH"):
                continue
            sensitive = operation.sensitive_body_fields
            if not sensitive:
                continue
            results.append({
                "kind": "mass-assignment",
                "title": (f"Privileged field(s) documented as writable on "
                          f"{operation.method} {operation.path}"),
                "severity": "medium",
                "cvss_score": 5.4,
                "target": operation.url,
                "method": operation.method,
                "param": ",".join(sensitive),
                "payload": "",
                "evidence": ("The specification lists "
                             f"{', '.join(sensitive)} as client-settable on this "
                             "operation. Nothing was written during this run: the "
                             "field is documented as accepted, not proven honoured."),
                "verification": finding_model.Verification.POTENTIAL.value,
                "confidence": finding_model.Verification.POTENTIAL.confidence,
            })
        return tuple(results)

    

    def run(self) -> dict:
        report = {
            "findings": [],
            "notes": [],
            "probes_used": 0,
            "mass_assignment_candidates": 0,
        }
        if self.spec is None or not self.spec.operations:
            report["notes"].append(
                "No API specification was parsed, so input validation was not "
                "assessed against a documented contract.")
            report["skipped"] = True
            return report

        collected = []
        collected.extend(self.check_type_confusion())
        collected.extend(self.check_boundaries())
        collected.extend(self.check_mass_assignment())

        report["findings"] = list(collected)
        report["probes_used"] = self.spent
        report["mass_assignment_candidates"] = sum(
            1 for item in collected if item["kind"] == "mass-assignment")
        report["notes"].append(
            "Input validation was probed with read-only GET requests only; write "
            "operations were assessed from the specification, not exercised.")
        return report
