import hashlib
import re

SEVERITY_SCORE = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 0.8}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _sev(rank: float) -> str:
    if rank >= 9:
        return "critical"
    if rank >= 6:
        return "high"
    if rank >= 3:
        return "medium"
    if rank >= 1.5:
        return "low"
    return "info"


class Finding:
    __slots__ = ("fid", "kind", "title", "severity", "confidence", "target",
                 "evidence", "stage", "tags")

    def __init__(self, kind, title, severity="medium", confidence=1.0, target="",
                 evidence="", stage="", tags=None, identity=""):
        discriminator = identity or evidence
        self.fid = hashlib.sha1(
            f"{kind}|{target}|{discriminator}".encode()
        ).hexdigest()[:12]
        self.kind = kind
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.target = target
        self.evidence = evidence
        self.stage = stage
        self.tags = tags or []

    def score(self):
        return round(SEVERITY_SCORE.get(self.severity, 1.0) * self.confidence, 2)

    def to_dict(self):
        return {
            "id": self.fid, "kind": self.kind, "title": self.title,
            "severity": self.severity, "confidence": round(self.confidence, 2),
            "score": self.score(), "target": self.target, "evidence": self.evidence,
            "stage": self.stage, "tags": self.tags,
        }


class AttackGraph:
    """Correlates independent findings into attack paths.

    A scanner that reports 40 findings as 40 unrelated lines makes the operator
    do the prioritisation. Here each finding becomes a node, and a rule library
    links nodes into the chains that actually matter - the ones where a low
    severity discovery is the first hop of a critical outcome.
    """

    def __init__(self, console=None):
        self.console = console
        self.findings = {}
        self.paths = []
        self.coverage_gaps = []

    

    def _add(self, finding):
        if finding.fid not in self.findings:
            self.findings[finding.fid] = finding
        return self.findings[finding.fid]

    @staticmethod
    def _add_many(target, kind, items, key, title, severity, confidence, stage, tags,
                  evidence=""):
        for item in items or []:
            value = item.get(key) if isinstance(item, dict) else str(item)
            if not value:
                continue
            if isinstance(item, dict) and item.get("verified") is False:
                continue
            detail = item.get("evidence") if isinstance(item, dict) else evidence
            item_severity = item.get("severity", severity) if isinstance(item, dict) else severity
            item_confidence = item.get("confidence", confidence) if isinstance(item, dict) else confidence
            try:
                item_confidence = max(0.0, min(1.0, float(item_confidence)))
            except (TypeError, ValueError):
                item_confidence = confidence
            identity = ""
            if isinstance(item, dict):
                identity = "|".join(str(item.get(field, "")) for field in
                                    ("param", "method", "payload", "path", "evidence"))
            target._add(Finding(
                kind, title.format(value=str(value)[:120]), severity=item_severity,
                confidence=item_confidence, target=str(value), evidence=str(detail or "")[:300],
                stage=stage, tags=tags, identity=identity,
            ))

    @staticmethod
    def _entry_keys(item):
        if not isinstance(item, dict):
            return {str(item)}
        url = str(item.get("url") or item.get("path") or item.get("target") or "")
        param = str(item.get("param") or "")
        payload = str(item.get("payload") or "")
        if payload:
            return {f"{url}#{param}#{payload}"}
        if param:
            return {f"{url}#{param}"}
        return {url}

    @classmethod
    def _verification_filter(cls, items, verified=None, excluded=None):
        verified_keys = set().union(*(cls._entry_keys(i) for i in (verified or [])))\
            if verified else set()
        excluded_keys = set().union(*(cls._entry_keys(i) for i in (excluded or [])))\
            if excluded else set()
        output = []
        for original in items or []:
            keys = cls._entry_keys(original)
            if keys & excluded_keys:
                continue
            if isinstance(original, dict):
                item = dict(original)
                if keys & verified_keys:
                    item["verified"] = True
                    try:
                        current = float(item.get("confidence", 0.0) or 0.0)
                    except (TypeError, ValueError):
                        current = 0.0
                    item["confidence"] = max(current, 0.95)
                output.append(item)
            else:
                output.append(original)
        return output

    @staticmethod
    def _secret_fingerprint(value):
        if not value:
            return "secret value redacted"
        digest = hashlib.sha256(str(value).encode()).hexdigest()[:12]
        return f"secret value redacted (sha256:{digest})"

    def harvest(self, results):
        target = self
        vulns = results.get("vulns", {}) or {}
        sqli_results = results.get("sqli", {}) or {}
        xss_results = results.get("xss", {}) or {}
        intel = results.get("intel", {}) or {}
        js = results.get("js_analysis", {}) or {}
        leaks = results.get("leaks", {}) or {}
        auth = results.get("auth", {}) or {}
        proto = results.get("protocol", {}) or {}
        oob = results.get("oob", {}) or {}
        verification = results.get("verification", {}) or {}
        headers = results.get("headers", {}) or {}
        surface = results.get("attack_surface", {}) or {}

        file_excluded = ((verification.get("exposed_files_refuted") or []) +
                         (verification.get("exposed_files_inconclusive") or []))
        redirect_excluded = ((verification.get("redirects_refuted") or []) +
                             (verification.get("redirects_inconclusive") or []))
        sqli_excluded = ((verification.get("sqli_refuted") or []) +
                         (verification.get("sqli_inconclusive") or []))
        xss_excluded = ((verification.get("reflection_refuted") or []) +
                        (verification.get("reflection_inconclusive") or []))
        secret_excluded = ((verification.get("secrets_refuted") or []) +
                           (verification.get("secrets_inconclusive") or []))

        admin_panels = self._verification_filter(
            vulns.get("admin_panels"), verification.get("exposed_files_verified"), file_excluded)
        sensitive_files = self._verification_filter(
            vulns.get("sensitive_files"), verification.get("exposed_files_verified"), file_excluded)
        backup_files = self._verification_filter(
            vulns.get("backup_files"), verification.get("exposed_files_verified"), file_excluded)
        redirects = self._verification_filter(
            vulns.get("open_redirects"), verification.get("redirects_verified"), redirect_excluded)
        sqli_entries = self._verification_filter(
            sqli_results.get("vulnerable_params") or vulns.get("sqli"),
            verification.get("sqli_verified"), sqli_excluded)
        reflected_xss = self._verification_filter(
            xss_results.get("reflected"), verification.get("reflection_verified"), xss_excluded)
        secret_entries = self._verification_filter(
            leaks.get("secrets"), verification.get("secrets_still_live"), secret_excluded)

        self._add_many(target, "admin-panel", admin_panels, "url",
                       "Administrative interface reachable without credentials",
                       "medium", 1.0, "vuln-audit", ["entry-point"])
        self._add_many(target, "sqli", sqli_entries, "url",
                       "SQL injection", "critical", 1.0, "sqli", ["injection"])
        self._add_many(target, "xss", reflected_xss, "url",
                       "Reflected cross-site scripting", "high", 0.85, "xss",
                       ["xss", "client-side"])
        for entry in xss_results.get("dom_based", []) or []:
            if entry.get("verified") is False or not entry.get("has_source"):
                continue
            try:
                dom_confidence = float(entry.get("confidence", 0.75))
            except (TypeError, ValueError):
                dom_confidence = 0.75
            self._add(Finding(
                "dom-sink", f"DOM XSS sink '{entry.get('sink', 'unknown')}' receives user input",
                entry.get("severity", "high"), dom_confidence,
                entry.get("url", ""), entry.get("context", "")[:300], "xss",
                ["xss", "client-side"], identity=str(entry.get("sink", "")),
            ))
        self._add_many(target, "ssti", vulns.get("ssti"), "url",
                       "Server-side template injection", "critical", 1.0, "vuln-audit",
                       ["injection", "rce"])
        self._add_many(target, "command-injection", vulns.get("command_injection"), "url",
                       "OS command injection", "critical", 1.0, "vuln-audit",
                       ["injection", "rce"])
        self._add_many(target, "lfi", vulns.get("lfi"), "url",
                       "Local file inclusion / read", "high", 1.0, "vuln-audit", ["read"])
        self._add_many(target, "ssrf", vulns.get("ssrf"), "url",
                       "Server-side request forgery", "high", 1.0, "vuln-audit", ["network"])
        self._add_many(target, "crlf", vulns.get("crlf"), "url",
                       "CRLF injection", "high", 1.0, "vuln-audit", ["response"])
        self._add_many(target, "open-redirect", redirects, "url",
                       "Open redirect", "medium", 0.9, "vuln-audit", ["redirect"])
        self._add_many(target, "host-header", vulns.get("host_header"), "url",
                       "Host header reflected by the application", "high", 0.8,
                       "vuln-audit", ["cache", "password-reset"])
        self._add_many(target, "verbose-errors", vulns.get("verbose_errors"), "url",
                       "Debug / verbose mode reachable by parameter", "medium", 0.9,
                       "vuln-audit", ["disclosure"])
        self._add_many(target, "sensitive-file", sensitive_files, "path",
                       "Sensitive file exposed", "high", 1.0, "vuln-audit", ["disclosure"])
        self._add_many(target, "backup-file", backup_files, "url",
                       "Backup or source archive downloadable", "high", 1.0,
                       "vuln-audit", ["disclosure", "source"])

        for entry in vulns.get("csrf", []) or []:
            if entry.get("verified") is False:
                continue
            self._add(Finding(
                "csrf",
                "State-changing request without an anti-CSRF token",
                entry.get("severity", "medium"), float(entry.get("confidence", 0.7)),
                entry.get("url", ""), entry.get("evidence", ""), "vuln-audit",
                ["csrf", "session"],
            ))
        for entry in vulns.get("xxe", []) or []:
            if entry.get("verified") is False:
                continue
            self._add(Finding(
                "xxe",
                "XML external entity expansion confirmed",
                entry.get("severity", "critical"), float(entry.get("confidence", 0.8)),
                entry.get("url", ""), entry.get("evidence", ""), "vuln-audit",
                ["injection", "file-read"],
            ))
        for entry in vulns.get("cache_poisoning", []) or []:
            if entry.get("verified") is False:
                continue
            self._add(Finding(
                "cache-poisoning",
                "Unkeyed header reflected on a cacheable response",
                entry.get("severity", "high"), float(entry.get("confidence", 0.8)),
                entry.get("url", ""), entry.get("evidence", ""), "vuln-audit",
                ["cache", "host-header"],
            ))

        self._add_many(target, "vcs-exposure", intel.get("git_exposure"), "path",
                       "Version-control metadata readable", "critical", 1.0,
                       "easy-discovery", ["source-disclosure"])
        self._add_many(target, "api-spec", intel.get("spec_endpoints"), "url",
                       "Undocumented API operation published in a public specification",
                       "medium", 1.0, "easy-discovery", ["api-surface"])

        graphql = proto.get("graphql") or intel.get("graphql") or {}
        if isinstance(graphql, dict) and graphql.get("open"):
            types = graphql.get("types", 0)
            type_count = types if isinstance(types, int) else len(types or [])
            self._add(Finding(
                "graphql-introspection", "GraphQL schema is introspectable without credentials",
                "high", 1.0, graphql.get("endpoint", ""),
                f"{type_count} types disclosed", "protocol",
                ["api-surface", "schema"],
            ))

        smuggling = proto.get("smuggling") or []
        for item in smuggling:
            if isinstance(item, dict) and item.get("vector"):
                self._add(Finding(
                    "smuggling", f"HTTP request framing anomaly ({item['vector']})",
                    "critical", 0.85, self_target(item), item.get("verdict", ""),
                    "protocol", ["network", "cache-poisoning"],
                ))

        for report in auth.get("jwts", []) or []:
            verify = report.get("verify", {})
            if verify.get("verdict") == "SIGNATURE FORGEABLE":
                self._add(Finding(
                    "forgeable-jwt", "JWT accepted with a guessable signing secret",
                    "critical", 1.0, report.get("source", ""),
                    f"algorithm {verify.get('method')}; "
                    f"{self._secret_fingerprint(verify.get('forged_with'))}",
                    "auth", ["auth-bypass", "credential"],
                ))
            for issue in report.get("issues", []) or []:
                self._add(Finding(
                    "jwt-structure", f"JWT: {issue}", "high", 0.9,
                    report.get("source", ""), "", "auth", ["auth-bypass"],
                ))
            for claim in report.get("claims", []) or []:
                if claim["state"] == "LEAK":
                    self._add(Finding(
                        "jwt-claim", f"JWT claim {claim['claim']}: {claim['detail']}",
                        "medium", 0.9, report.get("source", ""), "", "auth",
                        ["credential", "disclosure"],
                    ))

        for issue in auth.get("issues", []) or []:
            self._add(Finding(
                "auth-config", issue.get("type", "auth configuration"),
                issue.get("severity", "medium"), 0.9, "", issue.get("detail", ""),
                "auth", ["auth-bypass"],
            ))

        for secret in secret_entries:
            try:
                secret_confidence = float(secret.get("confidence", 0.95))
            except (TypeError, ValueError):
                secret_confidence = 0.95
            self._add(Finding(
                "secret-leak", f"{secret.get('type')} published in client-visible content",
                secret.get("severity", "critical"), secret_confidence,
                str(secret.get("source", ""))[:160],
                self._secret_fingerprint(secret.get("value")), "leak-scan", ["credential"],
                identity=str(secret.get("type", "")),
            ))

        for event in oob.get("confirmed", []) or []:
            if not isinstance(event, dict):
                continue
            confirmed_kind = str(event.get("kind") or "oob-callback")
            confirmed_target = str(event.get("target") or event.get("path") or
                                   event.get("source") or self_target(event))
            self._add(Finding(
                confirmed_kind,
                f"Out-of-band callback confirmed {confirmed_kind}",
                event.get("severity", "high"), 1.0, confirmed_target,
                f"{event.get('method', 'CALLBACK')} callback received",
                "oob", ["out-of-band", "verified"],
                identity=str(event.get("received_at") or event.get("payload_token") or ""),
            ))

        for host in leaks.get("internal_hosts", []) or []:
            self._add(Finding("internal-host", f"Internal hostname disclosed: {host}",
                              "medium", 0.9, host, "", "leak-scan", ["network"]))
        for ip in leaks.get("internal_ips", []) or []:
            self._add(Finding("internal-ip", f"Internal IP disclosed: {ip}",
                              "medium", 0.9, ip, "", "leak-scan", ["network"]))
        for bucket in leaks.get("buckets", []) or []:
            self._add(Finding("cloud-bucket", f"Cloud storage bucket disclosed: {bucket}",
                              "medium", 0.9, bucket, "", "leak-scan", ["cloud"]))

        for sink in js.get("sinks_with_user_source", []) or []:
            self._add(Finding(
                "dom-sink",
                f"Client-side sink '{sink['sink']}' receives {', '.join(sink.get('sources', []))}",
                "high", 0.85, str(sink.get("file", ""))[:160], sink.get("context", "")[:200],
                "js-analysis", ["xss", "client-side"],
            ))

        for item in js.get("sourcemaps", []) or []:
            if item.get("with_content"):
                self._add(Finding(
                    "source-map", "JavaScript source map ships the original source code",
                    "high", 1.0, item.get("map_url", ""),
                    f"{item.get('sources')} sources, {item.get('with_content')} with content",
                    "js-analysis", ["source-disclosure"],
                ))

        for item in results.get("library_eol", []) or []:
            self._add(Finding(
                "eol-library",
                f"Unmaintained client library: {item.get('library')} {item.get('version')}",
                "low", 0.9, item.get("library", ""), item.get("note", ""),
                "headers", ["supply-chain"],
            ))

        if vulns.get("cors_misconfig"):
            for disclosure in vulns.get("info_disclosure", []) or []:
                if disclosure.get("type", "").startswith("CORS"):
                    self._add(Finding(
                        "cors", f"{disclosure['type']}: {disclosure.get('detail', '')}",
                        disclosure.get("severity", "medium"), 0.9, "", "", "vuln-audit",
                        ["cross-origin", "session-theft"],
                    ))

        for entry in proto.get("verb_tampering", []) or []:
            if entry.get("verb") in ("PUT", "DELETE", "MOVE", "COPY"):
                self._add(Finding(
                    "verb-tampering", f"{entry['verb']} accepted on {entry.get('path')}",
                    "high", 0.8, str(entry.get("path")), f"HTTP {entry.get('status')}",
                    "protocol", ["authorization-bypass"],
                ))

        return self.findings

    

    def _kind(self, kind):
        return [f for f in self.findings.values() if f.kind == kind]

    def _any(self, *kinds):
        return [f for f in self.findings.values() if f.kind in kinds]

    def _chain(self, name, hops, consequence, severity):
        """hops: list of (finding, action, result) - what the operator does at each step."""
        if not hops:
            return
        first = hops[0][0]

        hop_scores = [SEVERITY_SCORE.get(f.severity, 1.0) for f, _, _ in hops]
        worst = max(hop_scores)
        total = sum(hop_scores)
        
        
        
        rank = worst + 0.25 * (len(hops) - 1) * worst

        self.paths.append({
            "name": name,
            "severity": _sev(rank),
            "score": round(total, 2),
            "steps": [
                {
                    "step": i + 1,
                    "action": action,
                    "result": result,
                    "finding": f.title,
                    "target": f.target,
                    "severity": f.severity,
                    "evidence": f.evidence,
                }
                for i, (f, action, result) in enumerate(hops)
            ],
            "consequence": consequence,
            "entry_finding": first.fid,
        })

    def correlate(self):
        self.paths = []

        admins = self._kind("admin-panel")
        sqli = self._kind("sqli")
        ssti = self._kind("ssti")
        cmd = self._kind("command-injection")
        lfi = self._kind("lfi")
        ssrf = self._kind("ssrf")
        graphql = self._kind("graphql-introspection")
        vcs = self._kind("vcs-exposure")
        maps = self._kind("source-map")
        secrets = self._kind("secret-leak")
        forgeable = self._kind("forgeable-jwt")
        smuggled = self._kind("smuggling")
        cors = self._kind("cors")
        buckets = self._kind("cloud-bucket")
        internals = self._kind("internal-host") + self._kind("internal-ip")
        specs = self._kind("api-spec")
        verbs = self._kind("verb-tampering")
        sinks = self._kind("dom-sink")
        host_header = self._kind("host-header")
        redirects = self._kind("open-redirect")
        verbose = self._kind("verbose-errors")
        headers_any = self._headers_present()

        for admin in admins[:3]:
            for s in ssti[:2]:
                self._chain(
                    "Unauthenticated admin access to server-side code execution",
                    [(admin, "Open the exposed administrative interface", "Authenticated role without any credential"),
                     (s, "Submit a template expression to an injectable parameter", "Server-side code evaluation")],
                    "The admin interface needs no credential, and the injectable endpoint executes code "
                    "server-side. The administrative surface is the shortest path to full host control.",
                    "critical",
                )
            for s in sqli[:2]:
                self._chain(
                    "Unauthenticated admin access to the database",
                    [(admin, "Open the exposed administrative interface", "Authenticated role without any credential"),
                     (s, "Exploit the injectable parameter", "Read or modify the database")],
                    "No credential is required to reach an administrative role, and that role's endpoints "
                    "accept injected queries.",
                    "critical",
                )

        for v in vcs[:2]:
            hops = [(v, "Read .git/ and reconstruct the working tree", "Complete application source")]
            if maps:
                hops.append((maps[0], "Read the published source maps", "Unminified source with comments"))
            if secrets:
                hops.append((secrets[0], "Harvest the credentials embedded in that source", "Valid credentials"))
            if len(hops) > 1:
                self._chain(
                    "Full source disclosure to credential compromise",
                    hops,
                    "The repository metadata plus the source maps reconstruct the application, and the "
                    "credentials inside it are usable without further work.",
                    "critical",
                )

        if forgeable:
            hops = [(forgeable[0], "Sign an arbitrary token with the recovered secret",
                    "A token the server accepts as authentic")]
            if admins:
                hops.append((admins[0], "Present that token to the administrative interface",
                             "Administrative access"))
            elif specs:
                hops.append((specs[0], "Present that token to the documented API operations",
                             "Authenticated API access"))
            self._chain(
                "Forge any user session",
                hops,
                "The signing secret is guessable, so identity is not established at all - the operator "
                "can mint a token for any subject, including an administrator.",
                "critical",
            )

        for s in ssrf[:3]:
            hops = [(s, "Make the server issue the request on the operator's behalf", "Server-side request forgery")]
            if internals:
                hops.append((internals[0], "Aim it at the disclosed internal host", "Internal network access"))
            self._chain(
                "Server-side request forgery into the internal network",
                hops,
                "The request is issued from inside the trust boundary, so it reaches hosts the operator "
                "cannot address directly.",
                "high",
            )

        for g in graphql[:2]:
            hops = [(g, "Introspect the schema", "Complete data model, including hidden types")]
            if sqli:
                hops.append((sqli[0], "Target the injectable field", "Database access"))
            elif specs:
                hops.append((specs[0], "Map the schema against the published operations", "Full API coverage"))
            self._chain(
                "Schema disclosure into targeted injection",
                hops,
                "Introspection removes the main obstacle to exploiting a GraphQL surface: the operator "
                "knows every type, argument and resolver before sending a single payload.",
                "high",
            )

        if smuggled:
            hops = [(smuggled[0], "Send conflicting framing headers", "The server frames the request differently")]
            if host_header:
                hops.append((host_header[0], "Vary a header the cache does not key on", "Cache poisoning"))
            self._chain(
                "Request smuggling to cache poisoning",
                hops,
                "Desynchronised framing lets one request be interpreted as another. Combined with an "
                "unkeyed header this is enough to poison a shared cache.",
                "critical",
            )

        if cors and headers_any:
            self._chain(
                "Cross-origin credential theft",
                [(cors[0], "Host the payload on an attacker origin", "The browser releases the response"),
                 (Finding("session", "Authenticated session", "high", 0.7), "Read the authenticated response",
                  "The victim's data exposed to the attacker's script")],
                "The policy lets an arbitrary origin read an authenticated response, so a victim only has "
                "to visit a page.",
                "high",
            )

        if buckets and secrets:
            self._chain(
                "Client-side secret to cloud storage exposure",
                [(secrets[0], "Use the published credential", "Authenticated cloud access"),
                 (buckets[0], "Enumerate the disclosed bucket", "Object listing and contents")],
                "The credential and the target were both published client-side; nothing has to be guessed.",
                "critical",
            )

        if lfi and (secrets or self._kind("sensitive-file")):
            self._chain(
                "File read into credential disclosure",
                [(lfi[0], "Read a file outside the web root", "Arbitrary file contents"),
                 (self._kind("sensitive-file")[0] if self._kind("sensitive-file") else secrets[0],
                  "Read the discovered configuration file", "Database or service credentials")],
                "Local file read plus a known configuration path turns an information leak into "
                "authenticated access to whatever the application talks to.",
                "high",
            )

        if redirects and self._oidc_authorize():
            self._chain(
                "Open redirect to identity-token theft",
                [(redirects[0], "Point the redirect parameter at an attacker page", "Victim is redirected out"),
                 (Finding("oidc", "Authorization endpoint in the redirect chain", "high", 0.8),
                  "The authorization code or token is delivered to the attacker", "Session takeover")],
                "Redirecting out of an authorization flow lets the attacker receive the code that was "
                "issued for the victim's login.",
                "high",
            )

        if sinks and not self._kind("sqli"):
            self._chain(
                "Client-side injection without a server round-trip",
                [(sinks[0], "Deliver the payload through the URL fragment or a referrer",
                  "The sink executes in the victim's browser")],
                "The injection completes entirely client-side, so it works even where every server-side "
                "control is correct.",
                "high",
            )

        for v in verbose[:2]:
            hops = [(v, "Enable the debug switch", "Verbose errors and internal traces")]
            if internals:
                hops.append((internals[0], "Read the internal references", "Internal topology"))
            self._chain(
                "Debug mode into internal reconnaissance",
                hops,
                "A parameter that turns on diagnostics hands over stack traces, configuration values and "
                "internal names at once.",
                "medium",
            )

        if verbs:
            self._chain(
                "Authorization bypass through HTTP method tampering",
                [(verbs[0], "Repeat the request with an unexpected verb",
                  "The endpoint performs a write that the verb policy was supposed to restrict")],
                "If the authorization check keys off the method rather than the route, the restriction is "
                "decorative.",
                "high",
            )

        self.paths.sort(key=lambda p: -p["score"])
        return self.paths

    def _headers_present(self):
        return any(f.kind == "auth-config" for f in self.findings.values()) or\
            any("session" in f.tags for f in self.findings.values())

    def _oidc_authorize(self):
        return any(f.kind == "auth-config" and "oidc" in f.title.lower()
                   for f in self.findings.values())

    

    def coverage(self, results):
        """States explicitly what the scan did NOT establish."""
        surface = results.get("attack_surface", {}) or {}
        gaps = []

        if surface.get("params", 0) == 0:
            gaps.append({
                "gap": "No parameter was discovered anywhere in the application",
                "consequence": "Injection testing was structurally impossible. Absence of findings here "
                               "carries no information at all.",
                "severity": "high",
            })
        elif surface.get("uncovered_params"):
            gaps.append({
                "gap": f"{surface['uncovered_params']} discovered parameters were never tested",
                "consequence": "The injection budget ran out; these remain untested.",
                "severity": "medium",
            })

        convergence = results.get("convergence", {})
        if convergence and not convergence.get("converged"):
            gaps.append({
                "gap": "Discovery stopped because the round limit was reached",
                "consequence": "More endpoints almost certainly exist. The map below is a lower bound.",
                "severity": "medium",
            })

        if (results.get("js_analysis", {}) or {}).get("reached_bundle_cap"):
            gaps.append({
                "gap": "The JavaScript bundle cap was reached",
                "consequence": "Some client-side code, and therefore some endpoints, were never parsed.",
                "severity": "medium",
            })

        if not ((results.get("auth", {}) or {}).get("jwts") or []):
            gaps.append({
                "gap": "No token was observed",
                "consequence": "Session handling, token lifetime and signature strength are all unverified.",
                "severity": "medium",
            })

        settings = results.get("settings", {}) or {}
        if settings.get("pages") and (results.get("crawl", {}) or {}).get("page_cap_reached"):
            gaps.append({
                "gap": f"The crawl stopped at the {settings['pages']}-page cap",
                "consequence": "Crawling was truncated; deeper content was never reached.",
                "severity": "medium",
            })

        self.coverage_gaps = gaps
        return gaps

    

    def run(self, results):
        self.harvest(results)
        self.correlate()
        self.coverage(results)

        ranked = sorted(self.findings.values(), key=lambda f: -f.score())
        return {
            "finding_count": len(self.findings),
            "by_severity": {
                level: sum(1 for f in self.findings.values() if f.severity == level)
                for level in _SEVERITY_ORDER
            },
            "top_findings": [f.to_dict() for f in ranked[:60]],
            "attack_paths": self.paths[:25],
            "attack_path_count": len(self.paths),
            "highest_path_score": self.paths[0]["score"] if self.paths else 0.0,
            "coverage_gaps": self.coverage_gaps,
        }


def self_target(item):
    return str(item.get("path") or item.get("url") or "")
