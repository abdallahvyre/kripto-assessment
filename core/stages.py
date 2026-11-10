"""Stable terminal stage IDs and their actual module health keys."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    number: int
    name: str
    category: str
    description: str
    modules: tuple[str, ...]


STAGES = (
    Stage(1, "WAF & CDN", "DEFENSE", "Edge, CDN and WAF fingerprint", ("WAF/CDN",)),
    Stage(2, "SSL / TLS", "CRYPTO", "Certificate and transport checks", ("SSL/TLS",)),
    Stage(3, "Baseline", "ANALYSIS", "Catch-all page baseline", ("Baseline",)),
    Stage(4, "Recon", "RECON", "WHOIS, DNS and subdomains", ("Recon",)),
    Stage(5, "Port Scan", "RECON", "Authorized service discovery", ("Ports",)),
    Stage(6, "Easy-Win", "RECON", "VCS, specs and well-known files", ("Easy Discovery",)),
    Stage(7, "Crawl", "RECON", "Crawl and link extraction", ("Crawler",)),
    Stage(8, "Deep JS", "ANALYSIS", "Bundles, routes and source maps", ("JS Analysis",)),
    Stage(9, "Extraction", "ANALYSIS", "Emails, keys and tokens", ("Extraction",)),
    Stage(10, "Leaks", "ANALYSIS", "Passive credential leak analysis", ("Leak Scan",)),
    Stage(11, "Headers", "DEFENSE", "Headers and HTTP methods", ("Headers",)),
    Stage(12, "SQLi", "ASSESS", "Bounded injection checks", ("SQLi",)),
    Stage(13, "XSS", "ASSESS", "Reflection and DOM sinks", ("XSS",)),
    Stage(14, "Vuln Audit", "ASSESS", "Paths, CSRF, XXE and cache", ("Vuln Audit",)),
    Stage(15, "Auth Token", "CRYPTO", "Session, token and JWT review", ("Auth/Token",)),
    Stage(16, "Protocol", "ANALYSIS", "Framing, WebSocket and GraphQL", ("Protocol",)),
    Stage(17, "Verification", "VERIFY", "Independent finding verification", ("Verification",)),
    Stage(18, "OOB", "VERIFY", "Bounded callback confirmation", ("OOB",)),
    Stage(19, "Correlation", "ANALYSIS", "Attack-path correlation", ("Correlation",)),
    Stage(20, "Impact", "ANALYSIS", "Reach supported by findings", ("Impact",)),
    Stage(21, "Remediation", "OUTPUT", "Fixes and guidance", ("Remediation",)),
    Stage(22, "Access Control", "ASSESS", "IDOR, BOLA and role checks", ("Access Control",)),
    Stage(23, "API", "ASSESS", "OpenAPI, REST and GraphQL", ("API",)),
    Stage(24, "SPA", "ANALYSIS", "Routes, chunks and browser coverage", ("SPA",)),
    Stage(25, "Extended", "ASSESS", "Headers, DNS, technology, dependencies and cloud", ("Extended", "Extended/")),
    Stage(26, "Plugins", "EXTEND", "Trusted versioned extensions", ("Plugins", "Plugin/")),
    Stage(27, "Evidence", "OUTPUT", "Lifecycle and redacted evidence storage", ("Evidence",)),
    Stage(28, "Reports", "OUTPUT", "Executive and technical TXT, JSON and PDF", ("Reports",)),
)

STAGES_TOTAL = len(STAGES)
