"""Modular testing profiles.

A profile is a named, documented bundle of pipeline stages plus the budget
overrides it needs.  Operators pick one or several; the union of their stages
decides what actually runs, so ``--profile injection --profile configuration-audit``
covers both families without re-running the whole scan.

Profiles never weaken a safety control.  They can only choose *which* modules
execute, never the mode, the scope, the rate, or the request budget - those
stay under the operator's explicit flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field






STAGES = {
    "extended": "Passive header/DNS/technology/secret analysis and supplied dependency/cloud configuration",
    "waf": "WAF / CDN fingerprinting",
    "ssl": "TLS configuration analysis",
    "baseline": "Catch-all / soft-404 baseline",
    "recon": "DNS, WHOIS and subdomain enumeration",
    "ports": "TCP port scanning",
    "intel": "Well-known files, VCS exposure, API specs, GraphQL",
    "crawl": "HTML crawling, forms and parameter extraction",
    "discovery": "Convergent discovery loop and parameter probing",
    "bruteforce": "Directory and file bruteforce",
    "js": "JavaScript and source-map analysis",
    "extraction": "Data, secret and endpoint extraction",
    "leaks": "Secret and internal-reference leak scan",
    "headers": "Security headers, cookie attributes, HTTP methods",
    "sqli": "SQL injection testing",
    "xss": "Reflected, DOM and stored XSS testing",
    "vulns": "Injection families, SSRF, LFI, redirects, CORS, XXE, cache",
    "access": "IDOR / BOLA / broken and vertical access control",
    "api": "OpenAPI/Swagger assessment, GraphQL analysis, API input validation",
    "auth": "JWT, session and authentication configuration analysis",
    "protocol": "Request framing, WebSocket, GraphQL and verb analysis",
    "verify": "Independent re-verification of every candidate",
    "oob": "Out-of-band confirmation for blind findings",
    "correlate": "Attack-path correlation and CVSS scoring",
    "impact": "Impact modelling",
    "remediation": "Code-level remediation guidance",
}



ALWAYS_ON = frozenset({"baseline", "verify", "correlate", "impact", "remediation"})

MODE_ORDER = {"safe": 0, "active": 1, "intrusive": 2}


@dataclass(frozen=True)
class Profile:
    """One selectable bundle of tests."""

    name: str
    summary: str
    stages: frozenset
    min_mode: str = "safe"
    limits: dict = field(default_factory=dict)
    enables: tuple = ()

    def describe(self) -> dict:
        return {
            "name": self.name,
            "summary": self.summary,
            "min_mode": self.min_mode,
            "stages": sorted(self.stages | ALWAYS_ON),
            "enables": list(self.enables),
            "limits": dict(self.limits),
        }






PROFILES = {
    "web-standard": Profile(
        name="web-standard",
        summary="Balanced web application assessment: recon, crawl, headers, "
                "config, SQLi, XSS and the standard server-side families.",
        stages=frozenset({
            "waf", "ssl", "recon", "intel", "crawl", "discovery",
            "extraction", "leaks", "headers", "sqli", "xss", "vulns", "auth",
        }),
        min_mode="safe",
        enables=(
            "TLS configuration and certificate review",
            "DNS, WHOIS, subdomain and technology enumeration",
            "Well-known file, VCS and API specification discovery",
            "Crawling with form and parameter extraction",
            "Security header, cookie attribute and HTTP method review",
            "Reflected and DOM XSS testing",
            "Error and boolean based SQL injection testing",
            "CORS, clickjacking, open redirect and info disclosure checks",
            "JWT and session configuration analysis",
        ),
    ),
    "web-deep": Profile(
        name="web-deep",
        summary="Everything web-standard does with production budgets: more "
                "crawl pages, more bruteforce paths, more probes, more rounds.",
        stages=frozenset({
            "waf", "ssl", "recon", "ports", "intel", "crawl", "discovery",
            "bruteforce", "js", "extraction", "leaks", "headers", "sqli",
            "xss", "vulns", "access", "auth", "protocol",
        }),
        min_mode="active",
        limits={
            "crawl_pages": 2500, "crawl_depth": 7, "js_bytes": 30_000_000,
            "injection_budget": 9000, "brute_budget": 40000,
            "param_probe_names": 120, "spec_endpoints": 2000,
        },
        enables=(
            "All web-standard coverage",
            "Port scanning of the assessed host",
            "Bounded directory and file bruteforce",
            "Deep JavaScript, source-map and route analysis",
            "Differential parameter discovery",
            "Access-control verification",
            "Protocol-level framing, WebSocket and GraphQL checks",
        ),
    ),
    "api-security": Profile(
        name="api-security",
        summary="API attack surface: specifications, GraphQL introspection, "
                "verbs, JSON bodies, mass assignment and object references.",
        stages=frozenset({
            "intel", "crawl", "discovery", "js", "protocol", "access",
            "vulns", "auth", "api",
        }),
        min_mode="active",
        enables=(
            "OpenAPI and Swagger specification discovery",
            "GraphQL introspection availability",
            "HTTP method and verb tampering",
            "Object-level and function-level authorization checks",
            "Mass-assignment and parameter pollution probes",
            "CORS policy evaluation for API consumers",
            "JWT configuration and claim validation",
        ),
    ),
    "authentication": Profile(
        name="authentication",
        summary="Authentication and session security: tokens, cookies, "
                "reset flow weaknesses and authorization boundaries.",
        stages=frozenset({"headers", "auth", "access", "protocol", "crawl"}),
        min_mode="active",
        enables=(
            "JWT structure, algorithm and claim validation",
            "JWKS and OIDC discovery inspection",
            "Cookie flag and prefix analysis",
            "Session fixation and expiration indicators",
            "Password-reset implementation weaknesses",
            "Authentication-bypass indicators on protected routes",
            "Vertical authorization boundaries",
        ),
    ),
    "injection": Profile(
        name="injection",
        summary="Every injection family the engine implements, with "
                "verification enabled.",
        stages=frozenset({"discovery", "sqli", "xss", "vulns", "oob", "crawl"}),
        min_mode="active",
        limits={"injection_budget": 2500},
        enables=(
            "SQL injection: error, boolean and (intrusive) time based",
            "Reflected, partial-reflection and DOM-based XSS",
            "Server-side template injection with arithmetic proofs",
            "OS command injection indicators using random canaries",
            "LDAP and XPath injection indicators",
            "SSRF through URL-accepting parameters",
            "CRLF and host-header injection",
            "Out-of-band confirmation for blind families",
        ),
    ),
    "access-control": Profile(
        name="access-control",
        summary="Authorization testing with explicitly supplied identities: "
                "IDOR, BOLA, missing object authorization, vertical boundaries.",
        stages=frozenset({"crawl", "discovery", "access", "auth", "vulns"}),
        min_mode="active",
        enables=(
            "Object-level authorization (IDOR / BOLA) with paired identities",
            "Missing object-level authorization on enumerated identifiers",
            "Horizontal privilege boundary checks",
            "Vertical authorization checks against privileged paths",
            "Inconsistent enforcement across equivalent endpoints",
        ),
    ),
    "javascript-analysis": Profile(
        name="javascript-analysis",
        summary="Front-end surfaces: bundles, source maps, routes, sinks and "
                "client-side secrets.",
        stages=frozenset({"crawl", "js", "extraction", "leaks", "xss"}),
        min_mode="safe",
        limits={"js_bytes": 30_000_000},
        enables=(
            "Bundle and inline script analysis",
            "Source-map availability and original-source recovery",
            "Client-side route and API endpoint mining",
            "DOM sink and user-controlled source correlation",
            "Client-side secret detection with redaction",
            "Front-end configuration object inspection",
        ),
    ),
    "configuration-audit": Profile(
        name="configuration-audit",
        summary="Low-impact configuration review: headers, cookies, TLS, "
                "verbs, disclosure and caching.",
        stages=frozenset({"waf", "ssl", "headers", "intel", "crawl", "vulns", "extended"}),
        min_mode="safe",
        enables=(
            "Security header presence and strength",
            "Cookie Secure / HttpOnly / SameSite / prefix analysis",
            "TLS version, cipher and certificate validity",
            "Insecure HTTP method acceptance",
            "Directory listing, VCS and backup file exposure",
            "Verbose error and debug mode disclosure",
            "Cache-control weaknesses on sensitive responses",
        ),
    ),
    "full-assessment": Profile(
        name="full-assessment",
        summary="Every stage the engine has, at the largest documented budgets. "
                "Use only with an explicit engagement scope.",
        stages=frozenset(STAGES) - {"oob"},
        min_mode="active",
        limits={
            "crawl_pages": 2500, "crawl_depth": 7, "js_bytes": 30_000_000,
            "injection_budget": 9000, "brute_budget": 40000,
            "param_probe_names": 120, "spec_endpoints": 2000,
        },
        enables=("Every stage listed by `--list-profiles`",),
    ),
}

DEFAULT_PROFILE = "web-standard"


class ProfileError(ValueError):
    """Raised for an unknown profile or an impossible mode combination."""


def normalise(names) -> list:
    """Accept a string, a comma-separated string, or an iterable of names."""
    if names is None:
        return [DEFAULT_PROFILE]
    if isinstance(names, str):
        raw = [part.strip() for part in names.split(",")]
    else:
        raw = []
        for item in names:
            if isinstance(item, str) and "," in item:
                raw.extend(part.strip() for part in item.split(","))
            else:
                raw.append(str(item).strip())
    chosen = [name.lower() for name in raw if name]
    return chosen or [DEFAULT_PROFILE]


def get(name: str) -> Profile:
    key = str(name or "").strip().lower()
    if key not in PROFILES:
        raise ProfileError(
            f"unknown profile {name!r}; available: {', '.join(sorted(PROFILES))}"
        )
    return PROFILES[key]


@dataclass
class Resolution:
    """The union of one or more profiles, ready to drive the pipeline."""

    names: tuple
    stages: frozenset
    limits: dict
    min_mode: str = "safe"
    notes: list = field(default_factory=list)

    def enabled(self, stage: str) -> bool:
        return stage in self.stages

    def report(self) -> dict:
        return {
            "profiles": list(self.names),
            "stages": sorted(self.stages),
            "limits": dict(self.limits),
            "min_mode": self.min_mode,
        }


def resolve(names, mode: str = "safe") -> Resolution:
    """Combine profiles into one stage set and one limit map.

    Raises :class:`ProfileError` when the requested profiles need a stronger
    mode than the operator selected - the caller decides whether to escalate
    or abort, but it never happens silently.
    """
    chosen = normalise(names)
    stages = set(ALWAYS_ON)
    limits = []
    required_mode = "safe"

    for name in chosen:
        profile = get(name)
        stages.update(profile.stages)
        limits.append(profile.limits)
        if MODE_ORDER[profile.min_mode] > MODE_ORDER[required_mode]:
            required_mode = profile.min_mode

    if MODE_ORDER.get(mode, 0) < MODE_ORDER[required_mode]:
        raise ProfileError(
            f"profile(s) {', '.join(chosen)} need --mode {required_mode} or higher "
            f"(currently {mode}). Re-run with --mode {required_mode} --ack-authorized."
        )

    merged = {}
    for mapping in limits:
        for key, value in mapping.items():
            
            merged[key] = max(int(value), int(merged.get(key, 0)))

    return Resolution(
        names=tuple(chosen),
        stages=frozenset(stages),
        limits=merged,
        min_mode=required_mode,
    )


def catalogue() -> list:
    """Every profile with its documentation, for `--list-profiles`."""
    return [PROFILES[name].describe() for name in sorted(PROFILES)]


def format_catalogue() -> str:
    lines = ["Kripto testing profiles", "=" * 72, ""]
    for entry in catalogue():
        lines.append(f"{entry['name']}  (minimum mode: {entry['min_mode']})")
        lines.append(f"  {entry['summary']}")
        lines.append("  Enables:")
        for item in entry["enables"]:
            lines.append(f"    - {item}")
        lines.append("")
    lines.append("Select one or more:  --profile web-deep --profile injection")
    lines.append("List them from the CLI:  python main.py --list-profiles")
    return "\n".join(lines)
