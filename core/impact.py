import re



CAPABILITY_MODEL = {
    "command-injection": {
        "capabilities": [
            "Execute arbitrary OS commands as the application service account",
            "Read every file that account can read",
            "Reach hosts reachable only from the application host",
            "Obtain cloud instance credentials from the instance metadata service",
        ],
        "ceiling": "host", "ceiling_score": 4,
    },
    "ssti": {
        "capabilities": [
            "Evaluate attacker-supplied expressions inside the server runtime",
            "In most engines this is equivalent to code execution",
            "Read application configuration reachable from that runtime",
        ],
        "ceiling": "host", "ceiling_score": 4,
    },
    "deserialization": {
        "capabilities": ["Instantiate arbitrary types during deserialisation",
                         "Depending on the gadget chain, reach code execution"],
        "ceiling": "host", "ceiling_score": 4,
    },
    "prototype-pollution": {
        "capabilities": ["Modify base object prototypes at runtime",
                         "Influence authorization decisions in client-side code"],
        "ceiling": "client", "ceiling_score": 2,
    },
    "sqli": {
        "capabilities": [
            "Read every table the application's database credentials can reach",
            "Modify data through the same credentials",
            "Bypass row-level and tenant filters implemented in SQL",
        ],
        "ceiling": "data", "ceiling_score": 3,
    },
    "lfi": {
        "capabilities": [
            "Read arbitrary files the service account can read",
            "Retrieve source code and configuration that were meant to be private",
        ],
        "ceiling": "data", "ceiling_score": 3,
    },
    "xxe": {
        "capabilities": ["Make the XML parser resolve external entities",
                         "Read local files and, on some stacks, reach internal services"],
        "ceiling": "data", "ceiling_score": 3,
    },
    "ssrf": {
        "capabilities": [
            "Issue requests to hosts that are not routable from outside",
            "Reach cloud instance metadata and obtain temporary credentials",
            "Enumerate internal services from inside the trust boundary",
        ],
        "ceiling": "network", "ceiling_score": 3,
    },
    "smuggling": {
        "capabilities": [
            "Desynchronise request framing between front end and back end",
            "Poison a shared cache when an unkeyed header is accepted",
            "Reach back-end hosts that are not directly routable",
        ],
        "ceiling": "network", "ceiling_score": 3,
    },
    "forgeable-jwt": {
        "capabilities": [
            "Mint a token the server accepts for any subject, including administrators",
            "Access every authenticated surface without any credential",
        ],
        "ceiling": "application", "ceiling_score": 3,
    },
    "auth-config": {
        "capabilities": ["Weaken or bypass the identity layer depending on the issue"],
        "ceiling": "application", "ceiling_score": 2,
    },
    "verb-tampering": {
        "capabilities": ["Perform writes that the authorization layer was meant to restrict",
                         "Bypass a check that keys off the HTTP method"],
        "ceiling": "application", "ceiling_score": 2,
    },
    "xss": {
        "capabilities": [
            "Run script inside a victim's authenticated session",
            "Read anything that session can read",
            "Perform state-changing actions as the victim without their knowledge",
        ],
        "ceiling": "session", "ceiling_score": 2,
    },
    "dom-sink": {
        "capabilities": ["The same as reflected XSS, but the payload never reaches the server"],
        "ceiling": "session", "ceiling_score": 2,
    },
    "cors": {
        "capabilities": ["Read authenticated responses from any origin the victim visits"],
        "ceiling": "session", "ceiling_score": 2,
    },
    "open-redirect": {
        "capabilities": ["Deliver an authorization code or token to a controlled origin",
                         "Lend credibility to a phishing page under a trusted hostname"],
        "ceiling": "session", "ceiling_score": 1,
    },
    "vcs-exposure": {
        "capabilities": [
            "Recover the complete application source, including deleted history",
            "Enumerate the internal infrastructure from configuration",
            "Recover credentials that were committed and later removed",
        ],
        "ceiling": "application", "ceiling_score": 3,
    },
    "backup-file": {
        "capabilities": ["Download the complete source tree and any included database dump"],
        "ceiling": "data", "ceiling_score": 3,
    },
    "sensitive-file": {
        "capabilities": ["Read configuration that was never meant to be served"],
        "ceiling": "data", "ceiling_score": 2,
    },
    "secret-leak": {
        "capabilities": ["Act as whichever service principal the credential belongs to"],
        "ceiling": "third-party", "ceiling_score": 4,
    },
    "cloud-bucket": {
        "capabilities": ["Enumerate and read the referenced storage container"],
        "ceiling": "third-party", "ceiling_score": 3,
    },
    "admin-panel": {
        "capabilities": ["Reach an administrative interface that requires no credential"],
        "ceiling": "application", "ceiling_score": 1,
    },
    "graphql-introspection": {
        "capabilities": ["Obtain the complete data model, including hidden types and resolvers"],
        "ceiling": "application", "ceiling_score": 1,
    },
    "host-header": {
        "capabilities": ["Make the application trust an attacker-chosen Host value"],
        "ceiling": "application", "ceiling_score": 1,
    },
    "crlf": {
        "capabilities": ["Inject response headers into replies"],
        "ceiling": "application", "ceiling_score": 1,
    },
}

PII_CLASSES = {
    "email": ("Email addresses", "personal data, subject to GDPR/CCPA"),
    "phone": ("Telephone numbers", "personal data"),
    "credential": ("Reachable credentials", "authorises access as a service principal"),
    "internal_host": ("Internal hostnames", "internal topology disclosure"),
    "internal_ip": ("Internal addresses", "internal topology disclosure"),
}

ESCALATION_LADDER = [
    (4, "Application host", "arbitrary code execution as the service account"),
    (4, "Internal network", "lateral movement to hosts not routable from outside"),
    (4, "Cloud account", "access to the resources the instance role permits"),
    (3, "Customer data", "every record the application's own credentials can reach"),
    (3, "Third-party services", "anything the leaked credentials authenticate to"),
    (2, "User sessions", "act as any visitor in their authenticated session"),
    (2, "Application data", "configuration and internal logic"),
    (1, "Perimeter only", "impact stops at the unauthenticated entry point"),
]


class ImpactModel:
    """Models what the confirmed findings would add up to.

    Nothing here is performed or verified by this module. It is a structured
    statement of the worst case implied by evidence the scan already gathered -
    the internal hosts, storage containers, open ports and credentials that were
    actually observed - so the operator can decide remediation order without
    having to infer it from a flat list of findings.
    """

    def __init__(self, console=None):
        self.console = console

    def _entries(self, findings):
        return [f for f in findings if f.get("kind") in CAPABILITY_MODEL]

    def build(self, results, findings=None):
        from core.graph import AttackGraph

        if findings is None:
            findings = [(f.to_dict() if hasattr(f, "to_dict") else f)
                        for f in AttackGraph().harvest(results).values()]

        entries = self._entries(findings)
        capabilities, ceilings = [], []
        for finding in entries:
            model = CAPABILITY_MODEL[finding["kind"]]
            capabilities.append({
                "from_finding": finding["title"],
                "kind": finding["kind"],
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "target": finding.get("target", ""),
                "capabilities": model["capabilities"],
                "ceiling": model["ceiling"],
            })
            ceilings.append(model["ceiling_score"])

        reachable = self._reachable_assets(results)
        data_at_risk = self._data_at_risk(results)
        ceiling = max(ceilings) if ceilings else 0
        blast = self._blast_radius(entries, reachable, ceiling)
        worst_case = self._worst_case(blast, reachable)

        return {
            "capabilities": sorted(capabilities,
                                   key=lambda c: -CAPABILITY_MODEL[c["kind"]]["ceiling_score"]),
            "entry_count": len(entries),
            "ceiling": ceiling,
            "blast_radius": blast,
            "reachable_assets": reachable,
            "data_at_risk": data_at_risk,
            "worst_case": worst_case,
            "fix_first": self._fix_order(capabilities, blast),
            "modeled_not_performed": True,
        }

    def _reachable_assets(self, results):
        """Assets the scan already observed. Only evidence, never speculation."""
        leaks = results.get("leaks", {}) or {}
        ports = results.get("ports", {}) or {}
        recon = results.get("recon", {}) or {}
        vulns = results.get("vulns", {}) or {}
        extraction = results.get("extraction", {}) or {}

        assets = []
        for host in leaks.get("internal_hosts", []) or []:
            assets.append({"type": "internal-host", "value": host,
                           "note": "referenced in content served by the application"})
        for ip in leaks.get("internal_ips", []) or []:
            assets.append({"type": "internal-ip", "value": ip,
                           "note": "referenced in content served by the application"})
        for bucket in leaks.get("buckets", []) or []:
            assets.append({"type": "cloud-bucket", "value": bucket,
                           "note": "referenced in content served by the application"})
        for sub in recon.get("subdomains", []) or []:
            assets.append({"type": "subdomain", "value": sub.get("subdomain", ""),
                           "note": f"resolves to {', '.join(sub.get('ips', []))}"})
        for port in ports.get("open_ports", []) or []:
            if port.get("confirmed"):
                assets.append({"type": "port", "value": f"{port.get('port')}/{port.get('service')}",
                               "note": str(port.get("banner", ""))[:120]})

        seen, unique = set(), []
        for asset in assets:
            key = (asset["type"], asset["value"])
            if key in seen or not asset["value"]:
                continue
            seen.add(key)
            unique.append(asset)
        return unique

    def _data_at_risk(self, results):
        extraction = results.get("extraction", {}) or {}
        leaks = results.get("leaks", {}) or {}

        buckets = [
            {"class": "email", "count": len(extraction.get("emails", []) or []),
             "description": PII_CLASSES["email"][0],
             "regulatory": PII_CLASSES["email"][1],
             "samples": (extraction.get("emails") or [])[:5]},
            {"class": "phone", "count": len(extraction.get("phones", []) or []),
             "description": PII_CLASSES["phone"][0],
             "regulatory": PII_CLASSES["phone"][1],
             "samples": (extraction.get("phones") or [])[:5]},
            {"class": "credential", "count": len(leaks.get("secrets", []) or []),
             "description": PII_CLASSES["credential"][0],
             "regulatory": PII_CLASSES["credential"][1],
             "samples": [s.get("type") for s in (leaks.get("secrets") or [])[:5]]},
            {"class": "internal_topology",
             "count": len(leaks.get("internal_hosts", []) or []) +
                      len(leaks.get("internal_ips", []) or []),
             "description": "Internal hostnames and addresses",
             "regulatory": "not regulated, but materially assists intrusion",
             "samples": (leaks.get("internal_hosts") or [])[:5]},
            {"class": "author", "count": len(leaks.get("git_authors", []) or []),
             "description": "Contributor identities from version-control history",
             "regulatory": "personal data",
             "samples": (leaks.get("git_authors") or [])[:5]},
        ]
        return [b for b in buckets if b["count"]]

    def _blast_radius(self, entries, reachable, ceiling):
        kinds = {e["kind"] for e in entries}
        layers = []

        host_reachable = ceiling >= 4
        layers.append({
            "layer": "Application host",
            "reached": host_reachable,
            "basis": "code execution or file read capability was confirmed"
                     if host_reachable else "no code execution capability confirmed",
        })
        layers.append({
            "layer": "Internal network",
            "reached": bool(host_reachable and reachable),
            "basis": "internal hosts or addresses were disclosed and a code-execution "
                     "or SSRF capability exists" if (host_reachable and reachable)
                     else "either no internal disclosure or no internal reach capability",
        })
        layers.append({
            "layer": "Cloud account",
            "reached": "cloud-bucket" in kinds or "secret-leak" in kinds,
            "basis": "a storage container or a cloud credential was disclosed"
                     if ("cloud-bucket" in kinds or "secret-leak" in kinds)
                     else "no cloud asset or credential was disclosed",
        })
        data_layer = {"sqli", "lfi", "backup-file", "sensitive-file"} & kinds
        layers.append({
            "layer": "Customer data",
            "reached": bool(data_layer),
            "basis": f"data access confirmed via {', '.join(sorted(data_layer))}"
                     if data_layer else "no direct data access confirmed",
        })
        session_layer = {"xss", "dom-sink", "cors", "open-redirect"} & kinds
        layers.append({
            "layer": "User sessions",
            "reached": bool(session_layer),
            "basis": f"session impact via {', '.join(sorted(session_layer))}"
                     if session_layer else "no session impact confirmed",
        })
        return layers

    def _worst_case(self, blast, reachable):
        reached = [layer["layer"] for layer in blast if layer["reached"]]
        if not reached:
            return ("No confirmed finding reaches past the unauthenticated perimeter. "
                    "On the evidence gathered, compromise stops at the entry point.")
        if "Application host" in reached:
            assets = ", ".join(a["value"] for a in reachable[:4]) or "no further assets enumerated"
            return (f"Code execution on the application host escalates to every asset already "
                    f"reachable from it. The scan disclosed {assets}. Compromise does not stop "
                    f"at this host unless the network is segmented.")
        return (f"Compromise reaches: {', '.join(reached)}. The individual impact of each is "
                f"listed above; combined, they widen each other's reach.")

    def _fix_order(self, capabilities, blast):
        order = []
        for cap in capabilities:
            model = CAPABILITY_MODEL[cap["kind"]]
            order.append({
                "capability": cap["from_finding"],
                "kind": cap["kind"],
                "ceiling": cap["ceiling"],
                "ceiling_score": model["ceiling_score"],
                "target": cap["target"],
                "why": model["capabilities"][0],
                "severity": cap["severity"],
            })
        order.sort(key=lambda item: -item["ceiling_score"])
        return order