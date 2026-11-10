"""Canonical finding model, verification states and report identifiers.

Every detection module emits its own shape of dict.  Before a finding reaches
a report it needs one identity, one verification verdict, one CWE and one
OWASP category.  This module is the single place those are assigned, so the
TXT report, the JSON report and the attack-path graph cannot disagree about
what a finding is.

The verification rubric is deliberately conservative.  A confirmed finding
needs a reproducible observation; a suspicious status code on its own is never
enough.
"""

from __future__ import annotations

import re
from enum import Enum
from urllib.parse import urlsplit







class Verification(str, Enum):
    """How much is actually known about a finding."""

    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POTENTIAL = "POTENTIAL"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"

    @property
    def label(self) -> str:
        return self.value

    @property
    def is_reportable(self) -> bool:
        """Should this reach the findings list at all?"""
        return self is not Verification.FALSE_POSITIVE

    @property
    def confidence(self) -> float:
        """Numeric confidence carried into scoring."""
        return {
            Verification.CONFIRMED: 1.0,
            Verification.LIKELY: 0.8,
            Verification.POTENTIAL: 0.5,
            Verification.FALSE_POSITIVE: 0.0,
            Verification.INCONCLUSIVE: 0.3,
        }[self]

    @property
    def rank(self) -> int:
        return {
            Verification.CONFIRMED: 4,
            Verification.LIKELY: 3,
            Verification.POTENTIAL: 2,
            Verification.INCONCLUSIVE: 1,
            Verification.FALSE_POSITIVE: 0,
        }[self]


def coerce(value, default: Verification = Verification.POTENTIAL) -> Verification:
    """Accept a Verification, its name, or its value; never raise."""
    if isinstance(value, Verification):
        return value
    text = str(value or "").strip().upper().replace(" ", "_").replace("-", "_")
    for state in Verification:
        if text in (state.name, state.value):
            return state
    return default


def classify(reproduced: int, attempts: int, *,
             baseline_reliable: bool = True,
             suspicious_only: bool = False) -> Verification:
    """Map a verification result onto a state.

    ``reproduced`` is how many attempts showed the same evidence out of
    ``attempts``.  This is the only supported way to reach CONFIRMED, which
    keeps the rule in one place instead of scattered across modules.
    """
    attempts = max(1, int(attempts))
    reproduced = max(0, int(reproduced))
    if not baseline_reliable:
        return Verification.INCONCLUSIVE
    if reproduced >= attempts:
        return Verification.FALSE_POSITIVE if suspicious_only else Verification.CONFIRMED
    if suspicious_only and reproduced == 0:
        return Verification.POTENTIAL
    if reproduced == 0:
        return Verification.FALSE_POSITIVE
    if reproduced >= max(1, attempts - 1):
        return Verification.LIKELY
    return Verification.POTENTIAL






OWASP_WEB = {
    "sqli": "A03:2021 Injection",
    "command-injection": "A03:2021 Injection",
    "ssti": "A03:2021 Injection",
    "ldap-injection": "A03:2021 Injection",
    "xpath-injection": "A03:2021 Injection",
    "xss": "A03:2021 Injection",
    "dom-sink": "A03:2021 Injection",
    "crlf": "A03:2021 Injection",
    "xxe": "A05:2021 Security Misconfiguration",
    "lfi": "A01:2021 Broken Access Control",
    "path-traversal": "A01:2021 Broken Access Control",
    "idor": "A01:2021 Broken Access Control",
    "bola": "A01:2021 Broken Access Control",
    "bfla": "A01:2021 Broken Access Control",
    "missing-auth": "A01:2021 Broken Access Control",
    "forced-browsing": "A01:2021 Broken Access Control",
    "admin-panel": "A01:2021 Broken Access Control",
    "verb-tampering": "A01:2021 Broken Access Control",
    "open-redirect": "A01:2021 Broken Access Control",
    "csrf": "A01:2021 Broken Access Control",
    "cors": "A01:2021 Broken Access Control",
    "secret-leak": "A02:2021 Cryptographic Failures",
    "sensitive-file": "A02:2021 Cryptographic Failures",
    "backup-file": "A02:2021 Cryptographic Failures",
    "vcs-exposure": "A02:2021 Cryptographic Failures",
    "forgeable-jwt": "A02:2021 Cryptographic Failures",
    "ssrf": "A10:2021 Server-Side Request Forgery",
    "deserialization": "A08:2021 Software and Data Integrity Failures",
    "prototype-pollution": "A08:2021 Software and Data Integrity Failures",
    "smuggling": "A04:2021 Insecure Design",
    "cache-poisoning": "A04:2021 Insecure Design",
    "host-header": "A04:2021 Insecure Design",
    "verbose-errors": "A05:2021 Security Misconfiguration",
    "clickjacking": "A05:2021 Security Misconfiguration",
    "eol-library": "A06:2021 Vulnerable and Outdated Components",
    "source-map": "A05:2021 Security Misconfiguration",
    "api-spec": "A05:2021 Security Misconfiguration",
    "graphql-introspection": "A05:2021 Security Misconfiguration",
    "auth-config": "A07:2021 Identification and Authentication Failures",
    "jwt-structure": "A07:2021 Identification and Authentication Failures",
    "jwt-claim": "A07:2021 Identification and Authentication Failures",
    "session": "A07:2021 Identification and Authentication Failures",
    "internal-host": "A05:2021 Security Misconfiguration",
    "internal-ip": "A05:2021 Security Misconfiguration",
    "cloud-bucket": "A05:2021 Security Misconfiguration",
}

OWASP_API = {
    "bola": "API1:2023 Broken Object Level Authorization",
    "idor": "API1:2023 Broken Object Level Authorization",
    "missing-auth": "API2:2023 Broken Authentication",
    "auth-config": "API2:2023 Broken Authentication",
    "jwt-structure": "API2:2023 Broken Authentication",
    "forgeable-jwt": "API2:2023 Broken Authentication",
    "bfla": "API5:2023 Broken Function Level Authorization",
    "admin-panel": "API5:2023 Broken Function Level Authorization",
    "verb-tampering": "API5:2023 Broken Function Level Authorization",
    "sqli": "API8:2023 Security Misconfiguration",
    "ssrf": "API7:2023 Server Side Request Forgery",
    "api-spec": "API9:2023 Improper Inventory Management",
    "graphql-introspection": "API9:2023 Improper Inventory Management",
    "secret-leak": "API8:2023 Security Misconfiguration",
    "input-validation": "API8:2023 Security Misconfiguration",
    "mass-assignment": "API3:2023 Broken Object Property Level Authorization",
}


API_KINDS = frozenset({
    "bola", "bfla", "missing-auth", "api-spec", "graphql-introspection",
    "verb-tampering", "input-validation", "mass-assignment",
})

CWE_BY_KIND = {
    "weak-csp": "CWE-693", "weak-hsts": "CWE-319", "dns-policy": "CWE-345",
    "dependency-advisory": "CWE-1104", "cloud-config": "CWE-732", "websocket-protocol": "CWE-345",
    "sqli": "CWE-89",
    "command-injection": "CWE-78",
    "ssti": "CWE-1336",
    "ldap-injection": "CWE-90",
    "xpath-injection": "CWE-643",
    "xss": "CWE-79",
    "dom-sink": "CWE-79",
    "crlf": "CWE-93",
    "xxe": "CWE-611",
    "lfi": "CWE-22",
    "path-traversal": "CWE-22",
    "idor": "CWE-639",
    "bola": "CWE-639",
    "bfla": "CWE-862",
    "missing-auth": "CWE-306",
    "forced-browsing": "CWE-425",
    "admin-panel": "CWE-284",
    "verb-tampering": "CWE-863",
    "open-redirect": "CWE-601",
    "csrf": "CWE-352",
    "cors": "CWE-942",
    "secret-leak": "CWE-798",
    "sensitive-file": "CWE-200",
    "backup-file": "CWE-530",
    "vcs-exposure": "CWE-527",
    "forgeable-jwt": "CWE-347",
    "jwt-structure": "CWE-347",
    "jwt-claim": "CWE-200",
    "session": "CWE-384",
    "ssrf": "CWE-918",
    "smuggling": "CWE-444",
    "cache-poisoning": "CWE-524",
    "host-header": "CWE-644",
    "verbose-errors": "CWE-209",
    "clickjacking": "CWE-1021",
    "eol-library": "CWE-1104",
    "source-map": "CWE-540",
    "api-spec": "CWE-200",
    "graphql-introspection": "CWE-200",
    "auth-config": "CWE-306",
    "internal-host": "CWE-200",
    "internal-ip": "CWE-200",
    "cloud-bucket": "CWE-732",
    "deserialization": "CWE-502",
    "prototype-pollution": "CWE-1321",
    "input-validation": "CWE-20",
    "mass-assignment": "CWE-915",
}

DETECTION_METHOD = {
    "input-validation": ("Documented parameter type compared against the server's "
                         "handling of a conflicting value"),
    "mass-assignment": ("Privileged writable field identified from the published "
                        "request schema; not written during the run"),
    "sqli": "Differential response comparison with error-signature and boolean-pair validation",
    "xss": "Payload reflection with output-context analysis",
    "dom-sink": "Static data-flow match from user-controlled source to dangerous sink",
    "ssti": "Unique arithmetic expression evaluated server-side against a malformed control",
    "command-injection": "Random echo canary returned by the command interpreter",
    "ldap-injection": "Boolean-pair response differential on LDAP filter syntax",
    "xpath-injection": "Boolean-pair response differential on XPath predicate syntax",
    "ssrf": "Server-side fetch of an attacker-chosen URL returning unique content",
    "lfi": "Known file-signature markers in the response body",
    "path-traversal": "Known file-signature markers in the response body",
    "idor": "Object identifier substitution across two authorised identities",
    "bola": "Object identifier substitution across two authorised identities",
    "bfla": "Privileged endpoint reached with an unprivileged identity",
    "missing-auth": "Protected response reproduced without credentials",
    "forced-browsing": "Restricted path reachable without authorisation",
    "open-redirect": "Location header pointing off-origin after a controlled payload",
    "crlf": "Injected header observed in the response",
    "xxe": "External entity expansion observed in the response or callback",
    "cors": "Origin reflection or wildcard with credentials",
    "csrf": "State-changing request accepted without an anti-CSRF token",
    "secret-leak": "Value matched a known credential pattern or a secret-bearing field",
    "sensitive-file": "Response body distinct from the catch-all baseline",
    "backup-file": "Response body distinct from the catch-all baseline",
    "vcs-exposure": "Version-control metadata served as text",
    "forgeable-jwt": "Signature verified against a signing secret recovered from the target",
    "jwt-structure": "Token structure and claim inspection",
    "jwt-claim": "Claim comparison against declared issuer policy",
    "session": "Cookie attribute and lifetime inspection",
    "smuggling": "Framing differential between baseline and split request",
    "cache-poisoning": "Unkeyed input reflected into a cacheable response",
    "host-header": "Attacker-controlled Host value reflected into the response",
    "verbose-errors": "Debug signature present only when a probe parameter is supplied",
    "clickjacking": "Missing X-Frame-Options and CSP frame-ancestors",
    "eol-library": "Version fingerprint matched against an end-of-life record",
    "source-map": "Source map served with original sources",
    "api-spec": "Machine-readable API description served publicly",
    "graphql-introspection": "Introspection query answered without authentication",
    "auth-config": "Authentication configuration missing a required control",
    "admin-panel": "Login form or authentication challenge on a privileged path",
    "verb-tampering": "Non-standard verb accepted on a state-changing path",
    "internal-host": "Internal hostname present in client-served content",
    "internal-ip": "Private IP address present in client-served content",
    "cloud-bucket": "Object storage reference present in client-served content",
}


def cwe_for(kind: str) -> str:
    return CWE_BY_KIND.get(str(kind or ""), "CWE-0")


def cwe_url(cwe: str) -> str:
    number = str(cwe).split("-")[-1]
    return f"https://cwe.mitre.org/data/definitions/{number}.html"


def owasp_for(kind: str) -> tuple:
    """Return (category, url) for a finding kind."""
    kind = str(kind or "")
    if kind in API_KINDS and kind in OWASP_API:
        category = OWASP_API[kind]
        return category, "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
    category = OWASP_WEB.get(kind, "A05:2021 Security Misconfiguration")
    return category, "https://owasp.org/Top10/"






_PATH_NOISE = re.compile(r"/{2,}")


def _host_of(target: str) -> str:
    try:
        return (urlsplit(str(target)).hostname or "").lower()
    except ValueError:
        return ""


def _path_of(target: str) -> str:
    try:
        path = urlsplit(str(target)).path or "/"
    except ValueError:
        path = str(target) or "/"
    return _PATH_NOISE.sub("/", path).lower().rstrip("/") or "/"




_PARAM_SCOPE = re.compile(r"^(?:form|json|body|query|path|header|cookie):", re.IGNORECASE)


def identity(entry: dict) -> tuple:
    """A stable key that decides whether two findings are the same finding.

    The query string is deliberately excluded: ``/item?id=1`` and
    ``/item?id=2`` are one weakness, not two findings.
    """
    kind = str(entry.get("kind") or "unknown").lower()
    target = str(entry.get("target") or entry.get("url") or "")
    param = str(entry.get("param") or entry.get("parameter") or "").lower()
    param = _PARAM_SCOPE.sub("", param).strip()
    from core.fingerprint import normalise_path
    parsed = urlsplit(target)
    host = _host_of(target)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (kind, f"{host}:{port}", normalise_path(target), param,
            str(entry.get("method") or "GET").upper(), str(entry.get("fingerprint_variant") or ""))


def dedupe(entries) -> list:
    """Collapse duplicate findings, keeping the strongest evidence.

    When the same weakness is reported twice the surviving record keeps the
    higher verification state and the earlier identifier, and records how many
    occurrences were merged so the count stays honest.
    """
    merged = {}
    order = []

    def key_for(entry):
        """Resolve a record onto an existing key when it is the same weakness.

        A parameterless record is a less specific description of the entry that
        names the parameter, so the two are one finding: the specific entry
        wins and the generic one is folded into it rather than published twice.
        """
        key = identity(entry)
        if key in merged:
            return key
        if not key[3]:
            for candidate in merged:
                if candidate[:3] == key[:3] and candidate[4:] == key[4:] and candidate[3]:
                    return candidate
            return key
        generic = key[:3] + ("",) + key[4:]
        return generic if generic in merged else key

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        key = key_for(entry)
        if key not in merged:
            merged[key] = dict(entry)
            merged[key]["occurrences"] = 1
            order.append(key)
            continue
        current = merged[key]
        current["occurrences"] = int(current.get("occurrences", 1)) + 1
        incoming_state = coerce(entry.get("verification"), Verification.POTENTIAL)
        current_state = coerce(current.get("verification"), Verification.POTENTIAL)
        if incoming_state.rank > current_state.rank:
            preserved_id = current.get("id")
            occurrences = current["occurrences"]
            replacement = dict(entry)
            replacement["occurrences"] = occurrences
            if preserved_id:
                replacement["id"] = preserved_id
            merged[key] = replacement
            continue
        
        if not current.get("param") and entry.get("param"):
            current["param"] = entry["param"]
            current["parameter"] = entry.get("parameter") or entry["param"]
        for field in ("payload", "evidence", "impact", "detection_method"):
            if not current.get(field) and entry.get(field):
                current[field] = entry[field]
    return [merged[key] for key in order]






_SEVERITY_PREFIX = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}


def assign_ids(entries) -> list:
    """Give every finding one report identifier from a single namespace.

    Detection modules mint their own ids (hash digests, module prefixes).  A
    report where half the findings are ``KRP-007`` and the other half are a
    truncated SHA-256 cannot be cross-referenced, so the module id is preserved
    as ``fingerprint`` and a uniform ``KRP-NNN`` is assigned to every entry.
    """
    width = max(3, len(str(max(1, len(entries or [])))))
    for index, entry in enumerate(entries or [], start=1):
        existing = entry.get("id")
        if existing and not str(existing).startswith("KRP-"):
            entry.setdefault("module_reference", str(existing))
        from core.fingerprint import fingerprint
        entry["fingerprint"] = fingerprint(entry)
        entry["id"] = f"KRP-{index:0{width}d}"
    return entries


def enrich_fields(entry: dict) -> dict:
    """Attach the report fields every finding is required to carry."""
    kind = str(entry.get("kind") or "unknown")
    cwe = entry.get("cwe") or cwe_for(kind)
    category, owasp_url = owasp_for(kind)

    state = coerce(entry.get("verification"), Verification.POTENTIAL)
    entry["verification"] = state.value
    entry["verification_state"] = state.value
    entry["confidence"] = float(entry.get("confidence", state.confidence))
    entry["cwe"] = cwe
    entry["cwe_url"] = cwe_url(cwe)
    entry["owasp"] = category
    entry["owasp_url"] = owasp_url
    entry.setdefault("detection_method", DETECTION_METHOD.get(kind, "Engine heuristic"))
    entry.setdefault("method", "GET")
    entry.setdefault("parameter", entry.get("param") or "")
    entry.setdefault("severity_key", _SEVERITY_PREFIX.get(
        str(entry.get("severity", "info")).lower(), "I"))
    return entry


def reproduce_steps(entry: dict) -> list:
    """Human-readable reproduction steps derived from the finding itself."""
    target = str(entry.get("target") or entry.get("url") or "")
    method = str(entry.get("method") or "GET").upper()
    param = str(entry.get("parameter") or entry.get("param") or "")
    payload = entry.get("payload") or entry.get("probe") or ""

    steps = [f"1. Send {method} {target or '<target>'} and record the baseline response."]
    if param and payload:
        steps.append(
            f"2. Repeat the request with {param}={payload} while keeping every other "
            "input identical."
        )
    elif payload:
        steps.append(f"2. Repeat the request substituting the payload {payload}.")
    else:
        steps.append("2. Repeat the request that produced the evidence below.")
    steps.append(
        "3. Compare status, length and body: the difference must be repeatable and "
        "specific to the payload, not to session noise."
    )
    evidence = entry.get("evidence")
    if evidence:
        steps.append(f"4. Expected observation: {str(evidence)[:200]}")
    return steps


def enrich(entries) -> list:
    """Full report pipeline: enrich fields, de-duplicate, assign IDs."""
    prepared = [enrich_fields(dict(entry)) for entry in (entries or [])
                if isinstance(entry, dict)]
    collapsed = dedupe(prepared)
    for entry in collapsed:
        entry["reproduction"] = entry.get("reproduction") or reproduce_steps(entry)
    return assign_ids(collapsed)


def count_by_state(entries) -> dict:
    counts = {state.value: 0 for state in Verification}
    for entry in entries or []:
        counts[coerce(entry.get("verification")).value] += 1
    return counts


def reportable(entries) -> list:
    """Drop findings that verification proved wrong."""
    return [entry for entry in (entries or [])
            if coerce(entry.get("verification")).is_reportable]
