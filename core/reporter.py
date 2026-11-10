import json
import os
from datetime import datetime

from core.redact import redact_data, redact_text, display_text, display_data, literal_text


class Reporter:
    def __init__(self, target: str, output_dir: str = "output",
                 include_secrets: bool = False, formats=("txt", "json"),
                 language="en", font=None, engagement=None):
        self.target = target
        self.output_dir = output_dir
        self.include_secrets = bool(include_secrets)
        self.formats, self.language, self.font, self.engagement = formats, language, font, engagement
        self.outputs = []
        os.makedirs(self.output_dir, exist_ok=True)

        from urllib.parse import urlparse
        domain = urlparse(target).hostname or "target"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.txt_filename = os.path.join(self.output_dir, f"{domain}_{timestamp}.txt")
        self.json_filename = os.path.join(self.output_dir, f"{domain}_{timestamp}.json")

    def generate(self, results: dict, include_secrets: bool = None) -> str:
        expose = self.include_secrets if include_secrets is None else bool(include_secrets)
        results = results if expose else redact_data(results)
        try:
            with open(self.json_filename, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, default=str)
        except OSError as e:
            raise OSError(f"Could not write JSON report: {e}") from e

        report_results = results
        results = display_data(results)
        L = []
        L.append("=" * 80)
        L.append("  KRIPTO - PENETRATION TESTING & EXTRACTION REPORT")
        display_target = literal_text(self.target if expose else redact_text(self.target))
        L.append(f"  Target: {display_target}")
        L.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        L.append(f"  Secrets: {'INCLUDED BY OPERATOR REQUEST' if expose else 'REDACTED (default)'}")
        L.append("=" * 80)

        health = results.get("module_health", {})
        if health:
            L.append("")
            L.append("[!] MODULE STATUS")
            L.append("    FAILED = execution error; SKIPPED = intentionally not run;")
            L.append("    INCONCLUSIVE = ran without enough evidence to decide.")
            L.append("-" * 40)
            notes = results.get("module_notes", {})
            for module, state in health.items():
                marker = state if state in {"OK", "FAILED", "SKIPPED", "INCONCLUSIVE"}\
                    else "UNKNOWN"
                L.append(f"  [{marker}] {module:<16} {notes.get(module, '')}")

        baseline = results.get("baseline", {})
        if baseline:
            L.append("")
            L.append("[i] CATCH-ALL / SOFT-404 BASELINE")
            L.append("-" * 40)
            L.append(f"  Baseline reliable:        {baseline.get('reliable')}")
            L.append(f"  Catch-all routing active: {baseline.get('catch_all_detected')}")
            L.append(f"  Sampled statuses:         {baseline.get('sample_statuses')}")
            L.append(f"  Sampled sizes:            {baseline.get('sample_sizes')}")
            if baseline.get("catch_all_detected"):
                L.append("  NOTE: the host returns one generic page for unknown paths.")
                L.append("        Baseline matches were discarded to avoid false findings.")

        settings = results.get("settings", {})
        if settings:
            L.append("")
            L.append("[i] SCAN SETTINGS / COVERAGE LIMITS")
            L.append("-" * 40)
            for k, v in settings.items():
                L.append(f"  {k}: {v}")
            L.append("  A finding count of 0 under a capped setting means 'not tested', not 'clean'.")

        L.append("")

        self._attack_surface(L, results)
        self._easy_discovery(L, results)
        self._js_analysis(L, results)
        self._spa(L, results)
        self._leaks(L, results)
        self._correlated(L, results)
        self._api(L, results)
        self._auth(L, results)
        self._protocol(L, results)
        self._verification(L, results)
        self._scoring(L, results)
        self._impact(L, results)
        self._oob(L, results)
        self._remediation(L, results)
        self._findings(L, results)
        self._transport(L, results)

        
        waf = results.get("waf", {})
        L.append("[+] WAF / CDN DETECTION")
        L.append("-" * 40)
        if waf.get("error"):
            L.append(f"  INCONCLUSIVE - target unreachable: {waf['error']}")
        else:
            L.append(f"  WAF Detected: {waf.get('detected', False)}")
            if waf.get("waf_name"):
                L.append(f"  WAF Name:    {waf['waf_name']}")
            if waf.get("evidence"):
                L.append(f"  Evidence:    {waf['evidence']}")
        L.append("")

        
        ssl_info = results.get("ssl", {})
        L.append("[+] SSL/TLS ANALYSIS")
        L.append("-" * 40)
        L.append(f"  HTTPS Enabled:  {ssl_info.get('has_ssl', False)}")
        L.append(f"  TLS Version:    {ssl_info.get('tls_version') or 'N/A'}")
        L.append(f"  Cipher:         {ssl_info.get('cipher') or 'N/A'}")
        cert = ssl_info.get("cert_info") or {}
        if cert:
            L.append(f"  Common Name:    {cert.get('common_name', 'N/A')}")
            L.append(f"  Issuer:         {(cert.get('issuer') or {}).get('organizationName', 'N/A')}")
            L.append(f"  Valid Until:    {cert.get('not_after', 'N/A')} ({ssl_info.get('days_left')} days)")
            sans = cert.get("sans") or []
            if sans:
                L.append(f"  SANs ({len(sans)}): {', '.join(sans[:10])}")
        if ssl_info.get("error"):
            L.append(f"  ERROR: {ssl_info['error']}")
        for issue in ssl_info.get("issues", []):
            L.append(f"  - {issue}")
        L.append("")

        
        recon = results.get("recon", {})
        L.append("[+] RECONNAISSANCE & DISCOVERY")
        L.append("-" * 40)
        whois = recon.get("whois", {})
        if whois:
            L.append("WHOIS Data:")
            for k, v in whois.items():
                L.append(f"  {k}: {v}")
            L.append("")

        dns_data = recon.get("dns", {})
        if dns_data:
            L.append("DNS Records:")
            for rtype, rvals in dns_data.items():
                L.append(f"  {rtype}: {rvals}")
            L.append("")

        subdomains = recon.get("subdomains", [])
        L.append(f"Discovered Subdomains ({len(subdomains)}):")
        for sub in subdomains:
            extra = f" CNAME={', '.join(sub.get('cnames', []))}" if sub.get("cnames") else ""
            L.append(f"  - {sub.get('subdomain')} -> {', '.join(sub.get('ips', []))}{extra}")
        L.append("")

        tech = recon.get("technologies", {})
        if tech:
            L.append("Technologies:")
            for cat, items in tech.items():
                if items:
                    L.append(f"  {cat}: {', '.join(items)}")
            L.append("")

        rev = recon.get("reverse_ip", {})
        if rev:
            L.append(f"Reverse IP ({rev.get('ip')}) - {len(rev.get('domains', []))} domain(s):")
            if rev.get("note"):
                L.append(f"  NOTE: {rev['note']}")
            for d in rev.get("domains", [])[:25]:
                L.append(f"  - {d}")
            L.append("")

        
        ports = results.get("ports", {}).get("open_ports", [])
        if "ports" in results:
            L.append(f"[+] OPEN PORTS ({len(ports)})")
            L.append("-" * 40)
            if results["ports"].get("cdn_detected"):
                L.append(f"  ! Host is behind {results['ports']['cdn_detected']} - these ports belong")
                L.append("    to shared CDN edge infrastructure, not the origin.")
            for p in ports:
                conf = "confirmed" if p.get("confirmed") else "UNCONFIRMED (no banner)"
                L.append(f"  Port {p.get('port')} ({p.get('service')}) [{conf}]: {p.get('banner') or '-'}")
            L.append("")

        
        crawl = results.get("crawl", {})
        if crawl:
            L.append("[+] CRAWL SUMMARY")
            L.append("-" * 40)
            L.append(f"  Pages fetched:      {crawl.get('pages_crawled', 0)}")
            L.append(f"  Internal links:     {len(crawl.get('internal_links', []))}")
            L.append(f"  External links:     {len(crawl.get('external_links', []))}")
            L.append(f"  Forms:              {len(crawl.get('forms', []))}")
            L.append(f"  URL parameters:     {len(crawl.get('params', []))}")
            L.append(f"  JS bundles:         {len(crawl.get('js_files', []))}")
            L.append(f"  Client-side routes: {len(crawl.get('spa_routes', []))}")
            if not crawl.get("params") and not crawl.get("forms"):
                L.append("  ! No forms/parameters discovered - injection modules had nothing to test.")
            L.append("")

        
        dirs = results.get("directories")
        if dirs:
            found = dirs.get("found", [])
            verified = [d for d in found if d.get("verified")]
            L.append(f"[+] DISCOVERED PATHS ({len(verified)} confirmed, "
                     f"{len(found) - len(verified)} unverified)")
            L.append("-" * 40)
            L.append(f"  Tested: {dirs.get('total_tested')} | "
                     f"Catch-all responses discarded: {dirs.get('catchall_discarded')}")
            for d in verified:
                L.append(f"  {d['status']}  {d['path']} ({d['size']}B)")
            unverified = [d for d in found if not d.get("verified")]
            if unverified:
                L.append(f"  UNVERIFIED (baseline unavailable) - {len(unverified)} path(s):")
                for d in unverified[:20]:
                    L.append(f"    ? {d['status']}  {d['path']} ({d['size']}B)")
            L.append("")

        
        extract = results.get("extraction", {})
        L.append("[+] EXTRACTED DATA & CREDENTIALS")
        L.append("-" * 40)
        L.append(f"Emails ({len(extract.get('emails', []))}):")
        for e in extract.get("emails", []):
            L.append(f"  - {e}")
        L.append(f"Phone Numbers ({len(extract.get('phones', []))}):")
        for ph in extract.get("phones", []):
            L.append(f"  - {ph}")
        L.append(f"Social Links ({len(extract.get('social_links', []))}):")
        for s in extract.get("social_links", []):
            L.append(f"  - {s}")
        L.append(f"Tokens / Keys Found ({len(extract.get('tokens_keys', []))}):")
        for tk in extract.get("tokens_keys", []):
            L.append(f"  - [{tk.get('type')}] {tk.get('value')} (Source: {tk.get('page')})")
        L.append(f"JS API Endpoints ({len(extract.get('js_endpoints', []))}):")
        for ep in extract.get("js_endpoints", []):
            L.append(f"  - {ep}")
        meta = extract.get("metadata", {})
        if meta:
            L.append("Metadata:")
            for k, v in meta.items():
                L.append(f"  {display_text(k)}: {display_text(v)[:120]}")
        L.append("")

        
        headers = results.get("headers", {})
        L.append(f"[+] SECURITY HEADERS (score {headers.get('score', 0):.0f}%)")
        L.append("-" * 40)
        if headers.get("error"):
            L.append(f"  INCONCLUSIVE - {headers['error']}")
        else:
            for h, data in headers.get("headers", {}).items():
                L.append(f"  {data['status']:<10} {h}: {str(data['value'])[:60]}")
            for c in headers.get("cookies", []):
                if c.get("issues"):
                    L.append(f"  COOKIE    {c['name']}: {', '.join(c['issues'])}")
        L.append("")

        
        sqli = results.get("sqli", {})
        if sqli:
            items = sqli.get("vulnerable_params", [])
            L.append(f"[+] SQL INJECTION VULNERABILITIES ({len(items)})")
            L.append("-" * 40)
            if not sqli.get("tested_count"):
                L.append("  NOT TESTED - no parameters or forms were discovered.")
            if sqli.get("uncovered_params"):
                L.append(f"  INCOMPLETE - {sqli['uncovered_params']} discovered parameter(s) were")
                L.append("  not tested because the injection budget was exhausted. Re-run with")
                L.append("  --deep or --budget to cover them.")
            for item in items:
                L.append(f"  Parameter: {item.get('param')}")
                L.append(f"  Type:      {item.get('type')}")
                L.append(f"  Payload:   {item.get('payload')}")
                L.append(f"  Evidence:  {item.get('evidence')}")
                L.append("  " + "-" * 20)
            L.append("")

        
        xss = results.get("xss", {})
        if xss:
            xss_ref = xss.get("reflected", [])
            dom = xss.get("dom_based", [])
            L.append(f"[+] XSS VULNERABILITIES ({len(xss_ref)} reflected, {len(dom)} DOM sinks)")
            L.append("-" * 40)
            if not xss.get("tested_count"):
                L.append("  NOT TESTED - no parameters or forms were discovered.")
            if xss.get("uncovered_params"):
                L.append(f"  INCOMPLETE - {xss['uncovered_params']} discovered parameter(s) were")
                L.append("  not tested because the injection budget was exhausted.")
            for item in xss_ref:
                L.append(f"  Parameter: {item.get('param')}")
                L.append(f"  Payload:   {item.get('payload')}")
                L.append(f"  URL:       {item.get('url')}")
                L.append(f"  Context:   {str(item.get('context'))[:100]}")
                L.append("  " + "-" * 20)
            if dom:
                L.append("  DOM-based sinks:")
                for d in dom:
                    L.append(f"    - {d.get('sink')} (user source: {d.get('has_source')})")
            L.append("")

        
        vulns = results.get("vulns", {})
        L.append("[+] GENERAL VULNERABILITIES & EXPOSURES")
        L.append("-" * 40)
        for cat in ["sensitive_files", "admin_panels", "ssti", "command_injection", "ssrf",
                    "lfi", "open_redirects", "host_header", "verbose_errors", "crlf",
                    "backup_files", "csrf", "xxe", "cache_poisoning"]:
            items = vulns.get(cat, [])
            if not items:
                continue
            verified = [i for i in items if i.get("verified")]
            L.append(f"{cat.upper()} ({len(items)} total, {len(verified)} confirmed):")
            for it in verified:
                label = it.get("path") or it.get("url") or it.get("param", "")
                L.append(f"  - {label}")
            for it in items:
                if not it.get("verified"):
                    label = it.get("path") or it.get("url") or it.get("param", "")
                    detail = it.get("evidence") or it.get("payload") or ""
                    L.append(f"  - [UNVERIFIED] {label} {str(detail)[:80]}")
            L.append("")
        for disclosure in vulns.get("info_disclosure", []) or []:
            L.append(f"{disclosure.get('type')} ({disclosure.get('severity')}): "
                     f"{disclosure.get('detail')}")
        L.append(f"CORS misconfiguration: {vulns.get('cors_misconfig')}")
        L.append(f"Clickjacking possible:  {vulns.get('clickjacking')}")
        L.append("")

        L.append("=" * 80)
        L.append("  END OF REPORT")
        L.append("=" * 80)

        with open(self.txt_filename, "w", encoding="utf-8") as f:
            f.write("\n".join(L))

        from core.reports import ReportService
        self.outputs = ReportService().generate(self.target, report_results,
                        os.path.splitext(self.txt_filename)[0], self.formats,
                        self.language, self.font, self.engagement)

        return self.txt_filename

    

    @staticmethod
    def _transport(L, results):
        """How the scan framed itself in time, scope and network route."""
        settings = results.get("settings", {}) or {}
        profiles = results.get("profiles", {}) or {}
        transport = settings.get("transport", {}) or {}
        if not (profiles or transport):
            return
        L.append("[+] ENGAGEMENT METADATA")
        L.append("-" * 40)
        if profiles.get("profiles"):
            L.append(f"  Testing profiles:      {', '.join(profiles['profiles'])}")
        if profiles.get("stages"):
            L.append(f"  Stages enabled:        {len(profiles['stages'])}")
        if transport:
            L.append(f"  Network transport:     {transport.get('mode')}")
            L.append(f"  Proxy endpoint:        {transport.get('proxy') or 'none (direct)'}")
            for note in transport.get("notes") or []:
                L.append(f"    note: {note}")
            tor = transport.get("tor") or {}
            if tor:
                L.append(f"  Tor version:           {tor.get('version') or 'n/a'}")
                L.append(f"  Tor running:           {tor.get('running')}")
                L.append(f"  Tor bootstrap:         {tor.get('bootstrap_percent')}")
                L.append(f"  Tor SOCKS listener:    {tor.get('socks_listening')}")
        L.append("  A proxy mode is never downgraded to a direct connection: if the")
        L.append("  route failed, the run aborted rather than continuing unproxied.")
        L.append("")

    @staticmethod
    def _findings(L, results):
        """The canonical finding list: identity, scoring, evidence and fix."""
        entries = results.get("findings") or []
        states = results.get("finding_states") or {}

        L.append("[+] FINDINGS")
        L.append("=" * 80)
        if not entries:
            L.append("  No finding survived detection and verification in this run.")
            L.append("  This is not proof of absence: read the coverage gaps above.")
            L.append("")
            return

        if states:
            summary = ", ".join(f"{name}={count}" for name, count in states.items() if count)
            L.append(f"  Verification states: {summary}")
            L.append("")

        for item in entries:
            L.append(f"  [{item.get('id', 'KRP-???')}] {item.get('title', 'Finding')}")
            L.append("  " + "-" * 74)
            if item.get("fingerprint"):
                L.append(f"    Fingerprint      : {item['fingerprint']}")
            if item.get("module_reference"):
                L.append(f"    Module reference : {item['module_reference']}")
            L.append(f"    Lifecycle        : {item.get('status', 'candidate')}")
            for ref in item.get("evidence_refs") or []:
                L.append(f"    Evidence SHA-256 : {ref['sha256']} ({ref['size']} bytes)")
            L.append(f"    Severity         : {item.get('severity', 'info')}")
            L.append(f"    CVSS 3.1         : {item.get('cvss_score', 0)} "
                     f"({item.get('cvss_rating', 'n/a')})")
            L.append(f"    CVSS vector      : {item.get('cvss_vector', 'n/a')}")
            L.append(f"    Verification     : {item.get('verification', 'POTENTIAL')}  "
                     f"(confidence {item.get('confidence', 0)})")
            if item.get("verification_reason"):
                L.append(f"    Verdict reason   : {item['verification_reason']}")
            L.append(f"    Affected URL     : {item.get('target', '')}")
            L.append(f"    HTTP method      : {item.get('method', 'GET')}")
            if item.get("parameter"):
                L.append(f"    Affected param   : {item['parameter']}")
            L.append(f"    Detection method : {item.get('detection_method', 'engine heuristic')}")
            L.append(f"    CWE              : {item.get('cwe', 'CWE-0')}")
            L.append(f"    OWASP            : {item.get('owasp', 'unclassified')}")
            if item.get("payload"):
                L.append(f"    Payload          : {str(item['payload'])[:160]}")
            if item.get("evidence"):
                L.append(f"    Evidence         : {str(item['evidence'])[:400]}")
            if item.get("impact"):
                L.append(f"    Security impact  : {str(item['impact'])[:300]}")
            if item.get("occurrences", 1) > 1:
                L.append(f"    Occurrences      : {item['occurrences']} merged into this entry")
            reproduction = item.get("reproduction") or []
            if reproduction:
                L.append("    Reproduction:")
                for step in reproduction:
                    L.append(f"      {step}")
            if item.get("remediation"):
                L.append(f"    Remediation      : {str(item['remediation'])[:300]}")
            L.append("")

    @staticmethod
    def _attack_surface(L, results):
        surface = results.get("attack_surface", {})
        if not surface:
            return

        L.append("[+] ATTACK SURFACE MAP")
        L.append("-" * 40)
        L.append(f"  Endpoints discovered:      {surface.get('endpoints')}")
        L.append(f"  Parameters discovered:     {surface.get('params')}")
        L.append(f"  Probe-confirmed params:    {surface.get('confirmed_params')}")
        L.append(f"  Forms:                     {surface.get('forms')}")
        L.append(f"  Injection budget:          {surface.get('budget')}")

        by_source = surface.get("by_source", {})
        if by_source:
            L.append("  Parameters by discovery source:")
            for source, count in by_source.items():
                L.append(f"    {source:<18} {count}")

        convergence = results.get("convergence", {})
        if convergence:
            L.append(f"  Discovery rounds:          {convergence.get('rounds')}")
            L.append(f"  Last round delta:          {convergence.get('last_delta')} new endpoints")
            if not convergence.get("converged"):
                L.append("  ! Discovery did NOT converge within the round limit.")
                L.append("    The surface map below is incomplete; re-run with --deep.")

        if surface.get("params", 0) == 0:
            L.append("  ! No parameters were found at all - injection modules had nothing")
            L.append("    to test. Read every injection result below as INCONCLUSIVE.")

        params = surface.get("params_detail", [])
        if params:
            L.append("")
            L.append(f"  Parameter inventory ({len(params)} shown):")
            for p in params[:120]:
                marker = "*" if p.get("confirmed") else " "
                L.append(f"   {marker} {p.get('param'):<28} {p.get('source'):<14} {p.get('url')}")

        endpoints = surface.get("endpoints_detail", [])
        if endpoints:
            L.append("")
            L.append(f"  Endpoint inventory ({len(endpoints)} shown):")
            for e in endpoints[:150]:
                L.append(f"     {e.get('method', '')}{' ' if e.get('method') else ''}"
                         f"{e.get('url')}   <- {', '.join(e.get('sources', []))}")
        L.append("")
        L.append("  * = parameter name confirmed live by differential probing")
        L.append("")

    @staticmethod
    def _easy_discovery(L, results):
        intel = results.get("intel", {})
        if not intel:
            return

        L.append("[+] EASY-WIN DISCOVERY")
        L.append("-" * 40)

        passive = intel.get("passive_subdomains", {}) or {}
        if passive:
            L.append(f"Passive subdomains ({len(passive)}):")
            for name, data in list(passive.items())[:80]:
                extra = f"  CNAME={', '.join(data.get('cnames', []))}" if data.get("cnames") else ""
                L.append(f"  - {name} -> {', '.join(data.get('ips', []))}{extra}")
        elif intel.get("passive_disabled"):
            L.append("Passive sources were disabled for this run.")

        wk = intel.get("well_known", []) or []
        if wk:
            L.append("")
            L.append(f"Exposed well-known / low-hanging files ({len(wk)}):")
            for entry in wk:
                L.append(f"  - {entry['path']}  [{entry['status']}, {entry['size']}B, "
                         f"{entry.get('content_type', '?')}]")
                if entry.get("preview"):
                    L.append(f"      {display_text(entry['preview'])[:140]}")

        git = intel.get("git_exposure", []) or []
        if git:
            L.append("")
            L.append(f"EXPOSED VERSION-CONTROL FILES ({len(git)}):")
            for entry in git:
                L.append(f"  - {entry['path']}  [{entry['status']}, {entry['size']}B]")

        details = intel.get("git_details", {}) or {}
        if details:
            if details.get("remotes"):
                L.append("  Remotes:")
                for r in details["remotes"]:
                    L.append(f"    - {display_text(r)}")
            if details.get("commits"):
                L.append(f"  Commits readable from logs/HEAD: {details['commits']}")
            if details.get("authors"):
                L.append("  Contributor addresses:")
                for a in details["authors"]:
                    L.append(f"    - {a}")
            if details.get("recent"):
                L.append("  Recent history:")
                for c in details["recent"][:10]:
                    L.append(f"    {c['sha']} {c['author']:<24} {c['msg'][:70]}")
        elif git:
            L.append("  Partial VCS exposure - config unreadable, source disclosure unconfirmed.")

        specs = intel.get("api_specs", []) or []
        spec_endpoints = intel.get("spec_endpoints", []) or []
        if specs:
            L.append("")
            L.append(f"PUBLIC API SPECIFICATIONS ({len(specs)}):")
            for s in specs:
                L.append(f"  - {s['path']} -> {s['endpoints']} documented operations")
        if spec_endpoints:
            L.append(f"  Documented operations ({len(spec_endpoints)}):")
            for e in spec_endpoints[:200]:
                L.append(f"    {e['method']:<7} {e['path']}"
                         + (f"   params: {', '.join(e['params'])}" if e.get("params") else ""))

        graphql = intel.get("graphql", {}) or {}
        if graphql.get("open"):
            L.append("")
            L.append("  GRAPHQL INTROSPECTION IS OPEN WITHOUT AUTHENTICATION")
            L.append(f"    endpoint: {graphql.get('endpoint')}")
            L.append(f"    types exposed: {len(graphql.get('types', []))}")

        sec = intel.get("security_txt", {}) or {}
        if sec:
            L.append("")
            L.append("security.txt:")
            for k, v in sec.items():
                L.append(f"  {k}: {v}")

        methods = intel.get("http_methods", {}) or {}
        if methods:
            L.append("")
            L.append(f"HTTP methods on {methods.get('url')}: "
                     f"{', '.join(methods.get('accepted', [])) or 'unknown'}")
            if methods.get("allow_header"):
                L.append(f"  Allow header: {methods['allow_header']}")

        inventory = intel.get("header_inventory", {}) or {}
        if inventory:
            L.append("")
            L.append("Infrastructure / debug headers in use:")
            for k, v in inventory.items():
                L.append(f"  {k}: {v}")

        recon = results.get("recon", {})
        dmarc = (recon.get("dns", {}) or {}).get("dmarc", {})
        spf = (recon.get("dns", {}) or {}).get("spf", {})
        if dmarc or spf:
            L.append("")
            L.append("Mail configuration:")
            if spf:
                L.append(f"  SPF: {spf.get('record', '')[:200]}")
                if spf.get("third_parties"):
                    L.append(f"    authorised third parties: {', '.join(spf['third_parties'][:10])}")
            if dmarc:
                L.append(f"  DMARC: {dmarc.get('record') or 'ABSENT - ' + dmarc.get('note', '')}")
        L.append("")

    @staticmethod
    def _js_analysis(L, results):
        js = results.get("js_analysis", {})
        if not js:
            return

        L.append("[+] JAVASCRIPT / SOURCE-MAP ANALYSIS")
        L.append("-" * 40)
        L.append(f"  Bundles analyzed:    {js.get('bundle_count')}")
        L.append(f"  Bytes read:          {js.get('bytes_read')}")
        L.append(f"  Source maps found:   {len(js.get('sourcemaps', []) or [])}")
        L.append(f"  With original code:  {js.get('source_maps_with_content')}")
        L.append(f"  Endpoints mined:     {js.get('endpoints_count')}")
        if js.get("reached_bundle_cap"):
            L.append("  ! Bundle cap reached - JavaScript coverage is incomplete.")

        if js.get("original_sources"):
            L.append("")
            L.append("  Original source paths leaked by source maps:")
            for path in js["original_sources"][:80]:
                L.append(f"    - {path}")

        if js.get("routes"):
            L.append("")
            L.append(f"  Routes/endpoints from JavaScript ({len(js['routes'])}):")
            for route in js["routes"][:200]:
                L.append(f"    {route}")

        if js.get("env_vars"):
            L.append("")
            L.append(f"  Client-side environment variables referenced: "
                     f"{', '.join(js['env_vars'][:25])}")

        if js.get("versions"):
            L.append("")
            L.append("  Client library versions fingerprinted:")
            for v in js["versions"]:
                L.append(f"    {v['library']} {v['version']}")

        eol = results.get("library_eol", []) or []
        for item in eol:
            L.append(f"    ! {item['library']} {item['version']} is unmaintained - {item['note']}")

        if js.get("config_objects"):
            L.append("")
            L.append("  Client-side configuration objects:")
            for name, body in list(js["config_objects"].items())[:10]:
                L.append(f"    {name}: {body[:200]}")
        L.append("")

    @staticmethod
    def _spa(L, results):
        """Client-side routes, lazy chunks and what they contributed."""
        spa = results.get("spa") or {}
        if not spa or spa.get("error"):
            return

        L.append("[+] SPA / CLIENT-SIDE ROUTES")
        L.append("-" * 40)
        L.append(f"  Client-side router:    {spa.get('has_client_router')}")
        L.append(f"  Routes identified:     {spa.get('route_count')}")
        L.append(f"  Lazy chunks found:     {spa.get('chunk_count')}")
        L.append(f"  Routes registered:     {len(spa.get('registered_routes') or [])}")
        L.append(f"  Chunks registered:     {len(spa.get('registered_chunks') or [])}")

        if spa.get("templates"):
            L.append("")
            L.append("  Route templates:")
            for template in spa["templates"][:120]:
                L.append(f"    {template}")

        dynamic = spa.get("dynamic_routes") or []
        if dynamic:
            L.append("")
            L.append("  Parameterised routes (probed with a placeholder identifier):")
            for item in dynamic[:40]:
                marker = " [privileged]" if item.get("privileged") else ""
                L.append(f"    {item.get('template')} -> {item.get('probe')}{marker}")

        privileged = spa.get("privileged_routes") or []
        if privileged:
            L.append("")
            L.append(f"  PRIVILEGED CLIENT ROUTES ({len(privileged)}) - registered for "
                     "authorization testing:")
            for item in privileged[:40]:
                label = item.get("probe") or item.get("path") or item.get("template")
                L.append(f"    {label}")

        if spa.get("chunks"):
            L.append("")
            L.append(f"  Lazy chunks ({len(spa['chunks'])}):")
            for url in spa["chunks"][:60]:
                L.append(f"    {url}")

        if spa.get("manifests"):
            L.append("")
            L.append("  Build-manifest route -> chunk mapping:")
            for route, files in list(spa["manifests"].items())[:30]:
                L.append(f"    {route}: {', '.join(files)}")

        rendered = spa.get("browser") or {}
        if rendered.get("available"):
            L.append("")
            L.append(f"  Browser rendering ({rendered.get('engine')}): "
                     f"{len(rendered.get('documents') or [])} document(s), "
                     f"{len(rendered.get('links') or [])} link(s), "
                     f"{len(rendered.get('inline_scripts') or [])} inline script(s)")

        for note in (spa.get("notes") or []):
            L.append(f"  NOTE: {note}")
        L.append("")

    @staticmethod
    def _leaks(L, results):
        leaks = results.get("leaks", {})
        if not leaks:
            return

        L.append("[+] LEAK SCAN")
        L.append("-" * 40)
        L.append(f"  Sources scanned: {leaks.get('scanned_blobs', 0)}")

        if leaks.get("secrets"):
            L.append("")
            L.append(f"  SECRETS / CREDENTIALS ({len(leaks['secrets'])}):")
            for s in leaks["secrets"]:
                L.append(f"    [{s['type']}] {s['value']}")
                L.append(f"        source: {s.get('source')}")
        if leaks.get("emails"):
            L.append("")
            L.append(f"  Emails ({len(leaks['emails'])}):")
            for e in leaks["emails"]:
                L.append(f"    - {e}")
        for key, label in (("internal_ips", "Internal IP references"),
                           ("internal_hosts", "Internal hostname references"),
                           ("buckets", "Cloud storage buckets")):
            values = leaks.get(key) or []
            if values:
                L.append("")
                L.append(f"  {label} ({len(values)}):")
                for v in values:
                    L.append(f"    - {v}")
        if leaks.get("git_authors"):
            L.append("")
            L.append("  Contributor addresses from VCS history:")
            for a in leaks["git_authors"]:
                L.append(f"    - {a}")

        probe = results.get("probe_hits", []) or []
        if probe:
            L.append("")
            L.append(f"  PARAMETERS CONFIRMED BY DIFFERENTIAL PROBING ({len(probe)}):")
            for p in probe[:80]:
                L.append(f"    {p['param']:<24} on {p['url']}  ({p['size_delta']:+d} bytes)")
        L.append("")

    

    @staticmethod
    def _correlated(L, results):
        data = results.get("correlated", {})
        if not data:
            return

        L.append("[+] ATTACK PATHS  (ranked, multi-step)")
        L.append("=" * 80)
        L.append("  These are the chains that matter. A low-severity entry point followed")
        L.append("  by a high-severity sink is worth more than any single finding alone.")
        L.append("")

        paths = data.get("attack_paths", []) or []
        if not paths:
            L.append("  No multi-step chain was formed from the findings that were detected.")
            L.append("")
        for path in paths:
            L.append(f"  [{path['severity'].upper()}] {path['name']}   (score {path['score']})")
            L.append("  " + "-" * 74)
            for step in path["steps"]:
                L.append(f"    {step['step']}. {step['action']}")
                L.append(f"         -> {step['result']}")
                if step.get("target"):
                    L.append(f"         at: {str(step['target'])[:110]}")
            L.append(f"    OUTCOME: {path['consequence']}")
            L.append("")

        by_sev = data.get("by_severity", {}) or {}
        L.append(f"  Findings: {data.get('finding_count', 0)}  " +
                 "  ".join(f"{k}={v}" for k, v in by_sev.items()))
        L.append("")

        top = data.get("top_findings", []) or []
        if top:
            L.append("  RANKED FINDINGS")
            L.append("  " + "-" * 74)
            for f in top[:30]:
                L.append(f"   {f['score']:>5}  {f['severity']:<8} {f['title'][:74]}")
                if f.get("target"):
                    L.append(f"          at: {str(f['target'])[:100]}")
                if f.get("evidence"):
                    L.append(f"          evidence: {str(f['evidence'])[:100]}")
            L.append("")

        gaps = data.get("coverage_gaps", []) or []
        if gaps:
            L.append("[!] COVERAGE GAPS  (what this scan did NOT establish)")
            L.append("-" * 40)
            for gap in gaps:
                L.append(f"  [{gap['severity']}] {gap['gap']}")
                L.append(f"      {gap['consequence']}")
            L.append("")
            L.append("  Read every gap as 'unknown'. A missing finding inside a gap")
            L.append("  carries no information about the target.")
            L.append("")

    @staticmethod
    def _api(L, results):
        """API assessment: what the contract said versus what the server did."""
        api = results.get("api") or {}
        if not api:
            return
        L.append("[+] API SECURITY ASSESSMENT")
        L.append("-" * 40)

        rest = api.get("rest") or {}
        spec = rest.get("spec") or {}
        if spec:
            L.append(f"  Specification:       {spec.get('source')}")
            L.append(f"  Title / version:     {spec.get('title') or 'n/a'} "
                     f"{spec.get('version') or ''}".rstrip())
            L.append(f"  Documented ops:      {spec.get('operations')}")
            L.append(f"  Object operations:   {spec.get('object_operations')}")
            L.append(f"  Private operations:  {spec.get('private_operations')}")
            L.append(f"  Unauthenticated:     {rest.get('missing_auth_count', 0)} "
                     "documented protected operation(s) answered without a session")
        else:
            L.append("  Specification:       none retrieved - documented-operation "
                     "checks were not attempted")

        authz = api.get("authz") or {}
        if authz.get("concrete_endpoints"):
            L.append(f"  API routes registered for authorization testing: "
                     f"{authz['concrete_endpoints']}")

        graphql = api.get("graphql") or {}
        if graphql.get("open"):
            schema = graphql.get("schema") or {}
            L.append(f"  GraphQL endpoint:    {graphql.get('endpoint')}")
            L.append(f"  GraphQL schema:      {schema.get('type_count')} types, "
                     f"{schema.get('field_count')} fields, "
                     f"{schema.get('mutation_count')} mutations")
            inventory = graphql.get("inventory") or {}
            if inventory.get("sensitive_fields"):
                names = ", ".join(f"{item['type']}.{item['field']}"
                                  for item in inventory["sensitive_fields"][:8])
                L.append(f"  Sensitive fields:    {names}")
        elif graphql:
            L.append("  GraphQL:             no endpoint answered introspection")

        for note in (rest.get("notes") or []):
            L.append(f"  NOTE: {note}")
        for note in (graphql.get("notes") or []):
            L.append(f"  NOTE: {note}")
        for note in (authz.get("unverified") or []):
            L.append(f"  NOTE: {note}")
        validation = api.get("validation") or {}
        if validation.get("mass_assignment_candidates"):
            L.append("  Mass-assignment candidates (documented, not exploited): "
                     f"{validation['mass_assignment_candidates']}")
        L.append("")

    @staticmethod
    def _auth(L, results):
        auth = results.get("auth", {})
        if not auth:
            return

        L.append("[+] AUTHENTICATION / TOKEN ANALYSIS")
        L.append("-" * 40)
        L.append(f"  Tokens analysed: {auth.get('tokens_analyzed', 0)}")

        oidc = auth.get("oidc", {})
        if oidc:
            L.append(f"  OIDC issuer: {oidc.get('issuer')}")
            for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                        "introspection_endpoint", "revocation_endpoint", "jwks_uri"):
                if oidc.get(key):
                    L.append(f"    {key}: {oidc[key]}")
            methods = oidc.get("code_challenge_methods_supported")
            if methods is not None:
                L.append(f"  PKCE challenge methods: {methods}")

        jwks = auth.get("jwks", {}) or {}
        for key in (jwks.get("analysis") or []):
            L.append(f"  JWKS key kid={key.get('kid')} type={key.get('kty')} "
                     f"alg={key.get('alg')} use={key.get('use')} "
                     f"strength={key.get('strength', '?')}")

        for report in (auth.get("jwts", []) or [])[:15]:
            L.append(f"  JWT ({report.get('alg')}) from {report.get('source')}")
            verify = report.get("verify", {})
            L.append(f"    signature: {verify.get('verdict', 'not checked')} "
                     f"({verify.get('reason') or verify.get('tried', '')})")
            for claim in (report.get("claims", []) or []):
                L.append(f"    {claim['claim']:<8} {claim['state']:<10} {claim['detail']}")

        endpoints = auth.get("oauth_endpoints", []) or []
        if endpoints:
            L.append(f"  OAuth endpoints discovered ({len(endpoints)}):")
            for item in endpoints[:30]:
                L.append(f"    {item.get('role'):<28} {item.get('url')}")

        for cookie in (auth.get("cookies", []) or []):
            flags = cookie.get("flags", {})
            missing = [f for f, present in flags.items() if not present and f in
                       ("secure", "httponly", "samesite")]
            prefix = "ok" if cookie.get("prefix") else "NO __Host-/__Secure- PREFIX"
            L.append(f"  Cookie {cookie['name']}: {prefix}"
                     + (f", missing {', '.join(missing)}" if missing else ""))

        for issue in (auth.get("issues", []) or []):
            L.append(f"  [{issue.get('severity', 'info').upper()}] {issue.get('type')}: "
                     f"{issue.get('detail')}")
        L.append("")

    @staticmethod
    def _protocol(L, results):
        proto = results.get("protocol", {})
        if not proto:
            return

        L.append("[+] PROTOCOL-LEVEL ANALYSIS")
        L.append("-" * 40)

        vectors = proto.get("smuggling_vectors_tried", [])
        L.append(f"  Request framing vectors tried: {', '.join(vectors) if vectors else 'none'}")
        smuggling = proto.get("smuggling", []) or []
        if smuggling:
            for item in smuggling:
                L.append(f"  [{item.get('vector')}] {item.get('verdict')}")
                L.append(f"      baseline={item.get('baseline_status')} "
                         f"probe={item.get('probe_status')}")
        elif proto.get("smuggling") is not None:
            L.append("  No desync observed on the standard framing vectors.")

        ws = proto.get("websocket", {})
        if ws:
            L.append(f"  WebSocket: supported={ws.get('supported')} status={ws.get('status')}")
            if ws.get("extensions"):
                L.append(f"    extensions: {ws['extensions']}")
            if ws.get("supported") and not ws.get("accept_valid"):
                L.append("    handshake accepted without a valid Sec-WebSocket-Accept header")

        gql = proto.get("graphql", {}) or {}
        if gql:
            if gql.get("open"):
                L.append(f"  GraphQL: introspection OPEN at {gql.get('url')} "
                         f"({gql.get('types')} types)")
            else:
                L.append(f"  GraphQL: {gql.get('note', 'not introspectable')}")
            for note in (gql.get("notes", []) or []):
                L.append(f"    - {note}")

        verbs = proto.get("verb_tampering", []) or []
        if verbs:
            L.append(f"  Non-standard verbs accepted ({len(verbs)}):")
            for item in verbs[:30]:
                L.append(f"    {item['verb']:<10} {item['path']:<30} "
                         f"HTTP {item['status']} ({item['length']}B)")

        for err in (proto.get("errors", []) or [])[:5]:
            L.append(f"  probe error: {err}")
        L.append("")

    @staticmethod
    def _verification(L, results):
        verification = results.get("verification", {})
        if not verification:
            return

        summary = verification.get("summary", {})
        L.append("[+] VERIFICATION  (re-requested from independent connections)")
        L.append("-" * 40)
        L.append(f"  Checked:   {summary.get('checked', 0)}")
        L.append(f"  Reproduced on every attempt: {summary.get('verified', 0)}")
        L.append(f"  Unstable:  {summary.get('unstable', 0)}")
        L.append(f"  Refuted:   {summary.get('refuted', 0)}")
        L.append(f"  Candidates seen: {summary.get('candidates', summary.get('checked', 0))}")
        L.append(f"  Not checked because of caps: {summary.get('capped', 0)}")
        L.append(f"  Unsupported verification type: {summary.get('unsupported', 0)}")

        categories = (
            ("Exposed files", "exposed_files_refuted", "exposed_files_inconclusive"),
            ("Redirects", "redirects_refuted", "redirects_inconclusive"),
            ("Reflected XSS", "reflection_refuted", "reflection_inconclusive"),
            ("SQL injection", "sqli_refuted", "sqli_inconclusive"),
            ("Secrets", "secrets_refuted", "secrets_inconclusive"),
        )
        if any(verification.get(key) for _, *keys in categories for key in keys):
            L.append("")
            L.append("  Verification state by category:")
            for label, refuted_key, inconclusive_key in categories:
                refuted_count = len(verification.get(refuted_key, []) or [])
                inconclusive_count = len(verification.get(inconclusive_key, []) or [])
                if refuted_count or inconclusive_count:
                    L.append(f"    {label}: {refuted_count} refuted, "
                             f"{inconclusive_count} inconclusive")

        refuted = verification.get("exposed_files_refuted", []) or []
        if refuted:
            L.append("")
            L.append("  REFUTED - these did not survive re-testing and should be discarded:")
            for item in refuted[:20]:
                L.append(f"    {item['url']}  ({item['why']})")

        live = verification.get("secrets_still_live", []) or []
        if live:
            L.append("")
            L.append("  CONFIRMED STILL SERVED WITHOUT AUTHENTICATION:")
            for item in live[:20]:
                L.append(f"    [{item.get('type')}] {item.get('value')}")
                L.append(f"        {item.get('source')}")
        L.append("")

    

    @staticmethod
    def _scoring(L, results):
        scored = results.get("scored", {})
        if not scored:
            return

        L.append("[+] RISK SCORING  (CVSS v3.1 base vectors)")
        L.append("-" * 40)
        L.append(f"  Findings scored: {scored.get('count', 0)}   "
                 f"Average CVSS: {scored.get('average', 0)}")
        L.append("  Ratings: " + ", ".join(f"{k}={v}" for k, v in (scored.get("ratings") or {}).items()))
        L.append("  Priority bands: " +
                 ", ".join(f"{k}={v}" for k, v in (scored.get("bands") or {}).items()))
        L.append("")

        for item in (scored.get("top") or [])[:30]:
            L.append(f"  {item['cvss']:>4}  [{item['band']}] {item['title'][:64]}")
            if item.get("target"):
                L.append(f"         at: {str(item['target'])[:96]}")
            L.append(f"         {item['vector']}")
            L.append(f"         {item['cwe']}   confidence {item.get('confidence')}")
        L.append("")

    

    @staticmethod
    def _impact(L, results):
        impact = results.get("impact", {})
        if not impact:
            return

        L.append("[+] IMPACT MODEL  (worst-case reach implied by the confirmed findings)")
        L.append("=" * 80)
        L.append("  Modeled, not performed. Every claim below is derived from evidence the")
        L.append("  scan already gathered - nothing here was executed against the target.")
        L.append("")

        for layer in impact.get("blast_radius", []) or []:
            state = "REACHED" if layer["reached"] else "not reached"
            L.append(f"  [{state:<11}] {layer['layer']}")
            L.append(f"                basis: {layer['basis']}")
        L.append("")

        for capability in (impact.get("capabilities") or [])[:30]:
            L.append(f"  From: {capability['from_finding']}  "
                     f"(ceiling {capability['ceiling']}, "
                     f"confidence {capability.get('confidence')})")
            for item in capability["capabilities"]:
                L.append(f"     - {item}")
        L.append("")

        if impact.get("data_at_risk"):
            L.append("  Data at risk observed on this target:")
            for bucket in impact["data_at_risk"]:
                L.append(f"    {bucket['count']:>5}  {bucket['description']}")
                L.append(f"           {bucket['regulatory']}")
                if bucket.get("samples"):
                    L.append(f"           samples: {', '.join(str(s)[:40] for s in bucket['samples'][:4])}")
            L.append("")

        assets = impact.get("reachable_assets", []) or []
        if assets:
            L.append(f"  Assets already reachable if the ceiling is reached ({len(assets)}):")
            for asset in assets[:40]:
                L.append(f"    [{asset['type']}] {asset['value']}  - {asset['note']}")
            L.append("")

        if impact.get("worst_case"):
            L.append(f"  Worst case: {impact['worst_case']}")
            L.append("")

        L.append("  Fix in this order (highest capability ceiling first):")
        for item in (impact.get("fix_first") or [])[:20]:
            L.append(f"    {item['ceiling']:<14} {item['why'][:64]}")
            L.append(f"                    at {str(item['target'])[:80]}")
        L.append("")

    

    @staticmethod
    def _oob(L, results):
        oob = results.get("oob", {})
        if not oob:
            return

        L.append("[+] OUT-OF-BAND CONFIRMATION")
        L.append("-" * 40)
        if not oob.get("started"):
            L.append(f"  Not started: {oob.get('note', 'unknown reason')}")
            L.append("")
            return

        L.append(f"  Listener: {oob.get('address')}   token {oob.get('token')}")
        L.append(f"  Payload families generated: {len(oob.get('payloads', []))}")
        for group in oob.get("payloads", []) or []:
            L.append(f"    {group['label']} - {group['context']}")
            for payload in group.get("payloads", [])[:4]:
                L.append(f"        {payload[:100]}")

        confirmed = oob.get("confirmed", []) or []
        if confirmed:
            L.append("")
            L.append(f"  CONFIRMED BY OUT-OF-BAND CALLBACK ({len(confirmed)}):")
            for event in confirmed[:30]:
                L.append(f"    {event['method']} {event['path']}  from {event['source']}")
                L.append(f"        at {event.get('received_at')}  UA: {event.get('user_agent', '')[:60]}")
        else:
            L.append("")
            L.append("  No callback was received. The payloads were generated for the operator")
            L.append("  to submit manually - a silent listener means nothing was executed.")
        if oob.get("note"):
            L.append("")
            L.append(f"  NOTE: {oob['note']}")
        L.append("")

    

    @staticmethod
    def _remediation(L, results):
        fix = results.get("remediation", {})
        if not fix:
            return

        L.append("[+] REMEDIATION  (code-level fixes for the detected stack)")
        L.append("=" * 80)
        L.append(f"  Framework in use: {fix.get('framework')}")
        L.append(f"  {fix.get('caveat', '')}")
        L.append("")

        for item in fix.get("guidance", []) or []:
            L.append(f"  {item['finding']}")
            if item.get("target"):
                L.append(f"      at:      {str(item['target'])[:96]}")
            if item.get("cvss"):
                L.append(f"      CVSS:    {item['cvss']}  ({item.get('cwe')})")
            L.append(f"      problem: {item['principle']}")
            if item.get("before"):
                L.append("")
                L.append("        BEFORE:")
                L.append(f"          {item['before']}")
                L.append("        AFTER:")
                L.append(f"          {item['after']}")
            L.append("")
            L.append(f"      verify:  {item['verify']}")
            L.append("  " + "-" * 74)
