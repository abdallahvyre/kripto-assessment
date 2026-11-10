"""GraphQL analysis: schema inventory and bounded resolver-abuse checks.

The distinction this module keeps is between what is *proven* and what is
*inventory*.  An open introspection endpoint is a finding: it is a fact about
the deployment with a CWE and an OWASP mapping.  Query batching and deep
nesting are reported as inventory instead, because turning "the server accepted
ten aliases" into a severity claim would be inventing a measurement we did not
make - we never tried to exhaust anything.
"""

from __future__ import annotations

import json
import re

from config import TIMEOUT
from core import findings as finding_model

INTROSPECTION_QUERY = (
    "query KriptoIntrospection { __schema { queryType { name } "
    "mutationType { name } subscriptionType { name } "
    "types { name kind fields { name args { name } type { name kind } } } } }"
)


FALLBACK_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql")


SENSITIVE_NAME = re.compile(
    r"(passw|secret|token|api[_-]?key|credit|card|cvv|ssn|salary|admin|role|"
    r"permission|impersonat|delete|drop|wipe|reset|internal|private|debug)",
    re.IGNORECASE,
)

_MAX_TYPES = 300
_MAX_FIELDS = 40


class GraphqlAnalyzer:
    """Assess a GraphQL endpoint without writing to it."""

    def __init__(self, target: str, console, session, endpoint: str = "",
                 surface=None, mode: str = "safe", budget: int = 10):
        self.target = target.rstrip("/")
        self.console = console
        self.session = session
        self.endpoint = endpoint
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

    def _post(self, url: str, payload: dict, anonymous=False):
        try:
            identity = {"headers": {}} if anonymous else {}
            return self.session.post(url, data=json.dumps(payload),
                                     request_headers={"Content-Type": "application/json"},
                                     timeout=TIMEOUT, allow_redirects=False, **identity)
        except Exception:
            return None

    def _json(self, response):
        if response is None or response.status_code != 200:
            return None
        try:
            return response.json()
        except Exception:
            return None

    def candidates(self) -> tuple:
        found = []
        if self.endpoint:
            found.append(self.endpoint)
        if self.surface is not None:
            for entry in self.surface.endpoints():
                path = str(entry.get("path") or "").lower()
                if "graphql" in path or path.endswith("/gql"):
                    found.append(entry["url"])
        found.extend(self.target + path for path in FALLBACK_PATHS)
        return tuple(dict.fromkeys(found))

    

    def introspect(self) -> dict:
        """Return the schema document if introspection is open."""
        for url in self.candidates()[:6]:
            if not self._spend():
                break
            document = self._json(self._post(url, {"query": INTROSPECTION_QUERY}, anonymous=True))
            if not isinstance(document, dict):
                continue
            schema = (document.get("data") or {}).get("__schema")
            if isinstance(schema, dict):
                return {"endpoint": url, "schema": schema}
        return {}

    def analyse_schema(self, schema: dict) -> dict:
        """Summarise the schema into something a report can carry."""
        types = schema.get("types") or []
        named = [t for t in types
                 if isinstance(t, dict) and not str(t.get("name", "")).startswith("__")]
        fields = []
        sensitive = []
        for entry in named[:_MAX_TYPES]:
            for field in entry.get("fields") or []:
                if not isinstance(field, dict) or not field.get("name"):
                    continue
                fields.append(field["name"])
                if SENSITIVE_NAME.search(str(field["name"])):
                    sensitive.append({"type": entry.get("name"),
                                      "field": field["name"]})
        mutations = []
        mutation_type = (schema.get("mutationType") or {}).get("name")
        if mutation_type:
            for entry in named:
                if entry.get("name") == mutation_type:
                    mutations = [f.get("name") for f in (entry.get("fields") or [])
                                 if isinstance(f, dict) and f.get("name")]
                    break
        return {
            "types": [str(entry.get("name")) for entry in named[:_MAX_TYPES]],
            "type_count": len(named),
            "field_count": len(fields),
            "query_root": (schema.get("queryType") or {}).get("name"),
            "mutation_root": mutation_type,
            "mutations": mutations[:_MAX_FIELDS],
            "mutation_count": len(mutations),
            "sensitive_fields": sensitive[:_MAX_FIELDS],
            "sensitive_field_count": len(sensitive),
        }

    def check_field_suggestions(self, url: str) -> dict:
        """A misspelled field that comes back with 'Did you mean' leaks names."""
        if not self._spend():
            return {}
        document = self._json(self._post(
            url, {"query": "query KriptoProbe { __kripto_nonexistent_field }"}))
        if not isinstance(document, dict):
            return {}
        errors = document.get("errors") or []
        for error in errors:
            if not isinstance(error, dict):
                continue
            message = str(error.get("message") or "")
            if "did you mean" in message.lower():
                return {"suggestions_enabled": True, "message": message[:300]}
        return {"suggestions_enabled": bool(errors), "message": ""}

    def check_batching(self, url: str, count: int = 10) -> dict:
        """Whether N aliased selections are answered in a single request."""
        count = max(1, min(int(count), 20))
        if not self._spend():
            return {}
        aliases = " ".join(
            f"k{index}: __typename" for index in range(count))
        document = self._json(self._post(
            url, {"query": f"query KriptoBatch {{ {aliases} }}"}))
        if not isinstance(document, dict):
            return {}
        data = document.get("data") or {}
        answered = sum(1 for index in range(count) if f"k{index}" in data)
        return {"aliases_sent": count, "aliases_answered": answered,
                "batched": answered == count}

    def check_depth(self, url: str, depth: int = 8) -> dict:
        """Whether a deep selection is executed rather than rejected."""
        depth = max(2, min(int(depth), 15))
        if not self._spend():
            return {}
        selection = "__typename"
        for _ in range(depth):
            selection = f"__schema {{ {selection} }}"
        document = self._json(self._post(
            url, {"query": f"query KriptoDepth {{ {selection} }}"}))
        if not isinstance(document, dict):
            return {}
        return {"requested_depth": depth,
                "executed": bool(document.get("data")),
                "rejected": bool(document.get("errors"))}

    

    def run(self) -> dict:
        report = {
            "endpoint": "",
            "open": False,
            "findings": [],
            "inventory": {},
            "notes": [],
            "probes_used": 0,
        }
        found = self.introspect()
        if not found:
            report["notes"].append(
                "No GraphQL endpoint answered introspection; GraphQL checks were "
                "not attempted on this target.")
            report["skipped"] = True
            return report

        url = found["endpoint"]
        schema = found["schema"]
        summary = self.analyse_schema(schema)
        report.update({
            "endpoint": url,
            "open": True,
            "schema": summary,
            "suggestions": self.check_field_suggestions(url),
            "batching": self.check_batching(url),
            "depth": self.check_depth(url),
        })
        report["probes_used"] = self.spent

        if self.surface is not None:
            self.surface.add_endpoint(url, "graphql")

        report["findings"].append({
            "kind": "graphql-introspection",
            "title": "GraphQL introspection is enabled without authentication",
            "severity": "medium",
            "cvss_score": 5.3,
            "target": url,
            "method": "POST",
            "param": "",
            "payload": INTROSPECTION_QUERY,
            "evidence": (f"__schema returned {summary['type_count']} types, "
                         f"{summary['field_count']} fields and "
                         f"{summary['mutation_count']} mutations without a session."),
            "verification": finding_model.Verification.CONFIRMED.value,
            "confidence": finding_model.Verification.CONFIRMED.confidence,
        })

        report["inventory"] = {
            "mutations": summary["mutations"],
            "sensitive_fields": summary["sensitive_fields"],
            "suggestions_enabled": bool(report["suggestions"].get("suggestions_enabled")),
            "batching": report.get("batching") or {},
            "depth": report.get("depth") or {},
        }
        if summary["mutation_count"]:
            report["notes"].append(
                f"{summary['mutation_count']} mutation(s) are exposed; each was "
                "inventoried but not executed, so their authorisation is unverified.")
        if (report.get("batching") or {}).get("batched"):
            report["notes"].append(
                "The endpoint answered ten aliased selections in one request. That "
                "is a rate-limit consideration, not a measured exhaustion.")
        return report
