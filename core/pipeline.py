import hashlib
import threading
import time
import traceback

import config
from config import PARAM_PROBE_DELTA, PARAM_PROBE_NAMES, STAGE_LIMITS, REQUESTS_PER_SECOND, TIMEOUT
from core import findings as finding_model
from core.access import AccessControlModule
from core.api.authz import materialise as materialise_api_routes
from core.api.graphql import GraphqlAnalyzer
from core.api.rest import RestAssessor
from core.api.spec import parse_spec
from core.api.validation import ValidationAssessor
from core.attack import AttackSurface
from core.authcheck import AuthModule
from core.banner import (
    error,
    found,
    info,
    make_table,
    section_header,
    success,
    vuln,
    warning,
)
from core.baseline import Baseline
from core.crawler import CrawlerModule
from core.dir_buster import DirBusterModule
from core.extractor import ExtractorModule
from core.graph import AttackGraph
from core.headers import HeaderModule
from core.http import RateLimitedSession
from core.oob import OOBModule
from core.intel import IntelModule, eol_check
from core.impact import ImpactModel
from core.jscan import JSBundleScanner
from core.pool import WorkerPool, RequestTimer
from core.profiles import ProfileError
from core.profiles import resolve as resolve_profiles
from core.proto import ProtoModule
from core.recon import ReconModule
from core.remediation import Remediation
from core.scanner import PortScannerModule
from core import scoring as scoring_model
from core.scoring import enrich, summarize
from core.ssl_check import SSLModule
from core.verify import Verifier
from core.vuln import VulnModule
from core.waf import WAFModule
from core.xss import XSSModule
from core.spa.assess import SpaAssessor
from core.sqli import SQLiModule
from core.stages import STAGES, STAGES_TOTAL


class Health:
    """Tracks whether each stage actually ran, so a failure is never reported as 'no findings'."""

    def __init__(self, observer=None):
        self.states = {}
        self.notes = {}
        self.timings = {}
        self.observer = observer

    def _notify(self):
        if self.observer:
            self.observer()

    def record(self, module: str, ok: bool, note: str = ""):
        self.states[module] = "OK" if ok else "FAILED"
        if note:
            self.notes[module] = note
        self._notify()

    def skip(self, module: str, note: str = ""):
        self.states[module] = "SKIPPED"
        if note:
            self.notes[module] = note
        self._notify()

    def inconclusive(self, module: str, note: str = ""):
        self.states[module] = "INCONCLUSIVE"
        if note:
            self.notes[module] = note
        self._notify()

    def modules(self, state: str):
        return [module for module, current in self.states.items() if current == state]

    def failures(self):
        return self.modules("FAILED")

    def rows(self):
        out = []
        for module, state in self.states.items():
            color = {
                "OK": "green", "FAILED": "bright_red",
                "SKIPPED": "yellow", "INCONCLUSIVE": "magenta",
            }.get(state, "white")
            timing = self.timings.get(module)
            detail = self.notes.get(module, "")[:60]
            if timing is not None:
                detail = f"{detail} ({timing:.1f}s)".strip()
            out.append((module, f"[{color}]{state}[/{color}]", detail))
        return out


class Pipeline:
    """Runs discovery as a converging loop rather than a straight line.

    Each round feeds what it found into the next one: bruteforced directories
    become crawl seeds, routes mined from JavaScript become crawl seeds,
    endpoints listed in an OpenAPI document become crawl seeds, and every
    parameter name confirmed by differential probing becomes an injection
    target. Rounds continue while new endpoints keep appearing.
    """

    def __init__(self, target: str, console, args):
        self.target = target
        self.console = console
        self.args = args
        self.profile = "deep" if getattr(args, "deep", False) else "default"
        self.mode = getattr(args, "mode", "safe")
        selected = getattr(args, "selected_stages", None)
        self.selected_stages = frozenset(selected) if selected is not None else None
        from core.runtime import RunControl
        self.control = getattr(args, "run_control", None) or RunControl(
            getattr(args, "request_budget", None), getattr(args, "threads", None) or 16)
        RateLimitedSession.configure_runtime(self.control)

        
        
        
        self.profile_names = tuple(getattr(args, "profile", None) or ())
        self.profile_resolution = None
        self.profile_error = ""
        if self.profile_names:
            try:
                self.profile_resolution = resolve_profiles(self.profile_names,
                                                           mode=self.mode)
            except ProfileError as exc:
                self.profile_resolution = None
                self.profile_error = str(exc)

        
        self.secondary_headers = (getattr(args, "test_account_headers", None) or {}).copy()
        self.access_result = None
        self.limits = dict(STAGE_LIMITS["default"])
        self.limits.update(STAGE_LIMITS.get(self.profile, {}))
        if self.profile_resolution is not None:
            
            for key, value in self.profile_resolution.limits.items():
                self.limits[key] = max(int(value), int(self.limits.get(key, 0)))
        requested_depth = getattr(args, "depth", None)
        if requested_depth is not None:
            self.limits["crawl_depth"] = requested_depth

        self.max_rounds = 6 if self.profile == "deep" else 3
        self.converge_threshold = 5

        self.health = Health(self._publish_ui)
        surface_policy = RateLimitedSession.configure_policy(
            target,
            scope=getattr(args, "scope", None),
            excludes=getattr(args, "exclude", None) or [],
        )
        self.surface = AttackSurface(
            console,
            budget=self.limits["injection_budget"],
            probe_names=PARAM_PROBE_NAMES[: self.limits["param_probe_names"]],
            policy=surface_policy,
        )
        self.blobs = []
        self.blob_bytes = 0
        self.seen_blobs = set()
        self.results = {}
        self.bruteforced_dirs = []
        self.js_scan_results = None
        self.crawl_results = None
        self.intel_module = None
        self.crawler = None
        self.js_scanner = None
        self.baseline = None
        self.visited_subdirs = set()
        self._last_traceback = ""
        self.probe_workers = WorkerPool(
            workers=getattr(args, "threads", None),
            adaptive=not getattr(args, "no_adaptive_threads", False),
            rate=config.REQUESTS_PER_SECOND,
        )
        self._probe_cache = {}
        self._probe_cache_lock = threading.Lock()
        self._probed_jobs = set()
        self.probe_confirmed = 0
        self.probe_session = RateLimitedSession()
        self.brute_budget = getattr(args, 'brute_budget', None) or self.limits["brute_budget"]
        self.brute_spent = 0

        
        
        self.store = getattr(args, "scan_store", None)
        self.scan_id = getattr(args, "scan_id", None)
        self.resume_state = getattr(args, "resume_state", None)

    

    def _stage(self, number, title):
        self._publish_ui()
        section_header(self.console, title, number=number, total=STAGES_TOTAL)

    def _publish_ui(self):
        dashboard = getattr(self.console, "dashboard", None)
        if dashboard is None:
            return
        from core.redact import redact_text
        fields = ("id", "kind", "title", "target", "method", "verification", "status",
                  "confidence", "cvss_score", "cwe", "fingerprint", "evidence",
                  "evidence_refs", "reproduction", "remediation", "status_history", "reproducibility")
        findings = [{key: item.get(key) for key in fields if key in item}
                    for item in self.results.get("findings") or []]
        api = self.results.get("api") or {}
        spa = self.results.get("spa") or {}
        snapshot = {"module_health": dict(self.health.states), "module_notes": dict(self.health.notes),
                    "module_timings": dict(self.health.timings), "findings": findings,
                    "runtime": self.control.report(), "lifecycle": self.results.get("lifecycle") or {},
                    "interrupted": bool(self.results.get("interrupted")),
                    "stop_reason": self.results.get("stop_reason", ""),
                    "plugins": self.results.get("plugins") or {}, "scan_id": self.scan_id,
                    "persistence_error": self.results.get("persistence_error"),
                    "settings": {"mode": self.mode},
                    "authentication": (getattr(self.args, "auth_context", None).report()
                                       if getattr(self.args, "auth_context", None) else {}),
                    "coverage_summary": {
                        "API": redact_text(api.get("summary", f"{len(api.get('findings') or [])} findings")),
                        "SPA": redact_text(spa.get("summary", f"{len(spa.get('routes') or [])} routes")),
                        "Extended": ", ".join((self.results.get("extended") or {}).keys()) or "pending / skipped",
                        "Surface": f"{len(self.surface.endpoints())} endpoints, {len(self.surface.params())} parameters"}}
        dashboard.publish(snapshot)

    def _timed(self, module, fn, ok=None, note="", network=True):
        profile_stage = {"WAF/CDN": "waf", "SSL/TLS": "ssl", "Recon": "recon"}.get(module)
        if profile_stage and not self._want(profile_stage):
            self.health.skip(module, "disabled by selected profile")
            return None
        start = time.time()
        started_work = False
        try:
            self.control.check()
            if network and self.control.exhausted:
                from core.runtime import BudgetExceeded
                raise BudgetExceeded("run-wide request budget reached")
            started_work = True
            result = fn()
            self.control.check()
            passed = ok(result) if callable(ok) else (ok if ok is not None else result is not None)
        except Exception as e:
            from core.runtime import Cancelled, BudgetExceeded
            if isinstance(e, (Cancelled, BudgetExceeded)):
                self.health.timings[module] = time.time() - start
                if started_work:
                    self.health.inconclusive(module, str(e))
                else:
                    self.health.skip(module, "not run: " + str(e))
                raise
            self.health.timings[module] = time.time() - start
            self.health.record(module, False, f"{type(e).__name__}: {e}")
            error(self.console, f"{module} crashed: {type(e).__name__}: {e}")
            self._last_traceback = traceback.format_exc()
            return None
        elapsed = time.time() - start
        self.health.timings[module] = elapsed
        self.health.record(module, passed, note)
        if not passed:
            self.health.notes.setdefault(module, (note + " (no usable data produced)")[:60])
        if self.store is not None and self.scan_id:
            self._persist_run()
        return result

    def _store_blob(self, label, text):
        if not text or label in self.seen_blobs:
            return
        size = len(text.encode("utf-8", errors="replace"))
        maximum = min(int(self.limits.get("js_bytes", 24000000)), 32000000)
        if self.blob_bytes + size > maximum:
            self.results["resource_limits"] = {"blob_bytes": self.blob_bytes,
                                               "blob_limit": maximum, "blob_limit_reached": True}
            self.health.inconclusive("Collected Content", "in-memory content budget reached")
            return
        self.blob_bytes += size
        self.seen_blobs.add(label)
        self.blobs.append((label, text))

    def _page_seeds_from_results(self):
        """Turn discovered paths into crawl seeds, skipping obvious files."""
        seeds = set()
        for entry in self.bruteforced_dirs:
            path = entry.get("path", "")
            if not path or path == "/":
                continue
            tail = path.rsplit("/", 1)[-1]
            if "." in tail and not tail.endswith((".php", ".html", ".htm", ".asp", ".aspx", ".jsp")):
                continue
            if entry.get("status") in (301, 302, 307, 308):
                continue
            seeds.add(self.target.rstrip("/") + path)
        return sorted(seeds)

    def _js_route_seeds(self):
        routes = (self.js_scan_results or {}).get("routes", [])
        return [self.target.rstrip("/") + r for r in routes if r.startswith("/")]

    def _spec_seeds(self):
        specs = (self.intel_module.spec_endpoints if self.intel_module else []) or []
        seeds = []
        for endpoint in specs[: self.limits["spec_endpoints"]]:
            url = endpoint.get("url", "")
            if not url:
                continue
            policy = getattr(self.surface, "policy", None)
            decision = policy.evaluate(url) if policy is not None else None
            if decision is not None and not decision.allowed:
                policy.record_block(decision.url, decision.reason, source="openapi-seed")
                continue
            seeds.append(decision.url if decision is not None else url)
        return sorted(set(seeds))[: self.limits["spec_endpoints"]]

    

    def stage_basics(self):
        if self._want("waf"):
            self._stage(1, "WAF & CDN Detection")
            waf_result = self._timed(
                "WAF/CDN", lambda: WAFModule(
                    self.target, self.console, active=self.mode != "safe"
                ).run(),
                ok=lambda r: not r.get("error"),
            )
            self.results["waf"] = waf_result or {"error": "stage failed"}
            if waf_result is None:
                self.health.notes.setdefault("WAF/CDN", "stage failed")
            elif waf_result.get("error"):
                self.health.notes["WAF/CDN"] = waf_result["error"]
            else:
                self.health.notes["WAF/CDN"] = waf_result.get("waf_name") or "no WAF signature matched"
        else:
            self.health.skip("WAF/CDN", "disabled by module selection or profile")
            self.results["waf"] = {"skipped": True}

        if self._want("ssl"):
            self._stage(2, "SSL/TLS Security Analysis")
            ssl_result = self._timed("SSL/TLS", lambda: SSLModule(self.target, self.console).run())
            self.results["ssl"] = ssl_result or {"has_ssl": False, "issues": [], "error": "stage failed"}
            if ssl_result is None:
                self.health.notes.setdefault("SSL/TLS", "stage failed")
            else:
                self.health.notes["SSL/TLS"] = (
                    f"{ssl_result.get('tls_version') or 'no TLS'}, "
                    f"{len(ssl_result.get('issues', []))} issues"
                )
        else:
            self.health.skip("SSL/TLS", "disabled by module selection or profile")
            self.results["ssl"] = {"skipped": True}

        self._stage(3, "Baseline / Catch-All Detection")
        baseline_session = RateLimitedSession()
        self.baseline = Baseline(baseline_session, self.target, self.console).collect()
        self.results["baseline"] = {
            "reliable": self.baseline.reliable,
            "catch_all_detected": self.baseline.catch_all,
            "sample_statuses": sorted(self.baseline.statuses),
            "sample_sizes": self.baseline.catchall_sizes,
            "content_type": self.baseline.content_type,
        }
        self.health.record("Baseline", self.baseline.reliable,
                           "catch-all detected" if self.baseline.catch_all else "distinct responses")

        if self._want("recon"):
            self._stage(4, "Reconnaissance & Infrastructure")
            recon = self._timed("Recon", lambda: ReconModule(self.target, self.console).run(),
                                ok=lambda r: bool(r.get("whois") or r.get("dns")))
            self.results["recon"] = recon or {}
            if recon and recon.get("limitations"):
                self.health.inconclusive("Recon", "; ".join(recon["limitations"]))
            if recon:
                self.health.notes["Recon"] = (
                    f"{len(recon.get('subdomains', []))} subdomains, "
                    f"{len(recon.get('cert_expansion_candidates', []))} SAN candidates"
                )
        else:
            self.health.skip("Recon", "disabled by module selection or profile")
            self.results["recon"] = {"skipped": True}

        if not self.args.skip_ports:
            self._stage(5, "Port Scanning")
            ports = self._timed("Ports", lambda: PortScannerModule(self.target, self.console).run())
            self.results["ports"] = ports or {}
            if ports:
                self.health.notes["Ports"] = ports.get("cdn_detected") or "direct host"
        else:
            self.health.skip("Ports", f"disabled in {self.mode} mode or by operator")

    def stage_easy_discovery(self):
        """The pass that is supposed to leave nothing obvious behind."""
        self._stage(6, "Easy-Win Discovery (passive names, VCS, specs, well-known files)")
        intel = IntelModule(
            self.target, self.console, self.surface,
            max_spec_endpoints=self.limits["spec_endpoints"],
        )
        self.intel_module = intel

        if self.args.skip_passive:
            warning(self.console, "Passive sources disabled by --skip-passive. Subdomain coverage "
                                  "will be limited to the wordlist.")
            intel.passive_subdomains = lambda: {}
            def discover():
                return {
                    "passive_subdomains": {}, "well_known": intel.wellknown_sweep(),
                    "git_exposure": intel.git_exposure(), "git_details": intel.git_details,
                    "api_specs": intel.api_specs(), "spec_endpoints": intel.spec_endpoints,
                    "graphql": intel.graphql, "security_txt": intel.security_txt,
                    "http_methods": intel.http_methods(),
                    "header_inventory": intel.header_inventory(),
                    "leaks": {"secrets": [], "emails": [], "internal_ips": [],
                              "internal_hosts": [], "buckets": [], "git_authors": [],
                              "scanned_blobs": 0},
                    "passive_disabled": True,
                }
        else:
            discover = intel.run

        results = self._timed("Easy Discovery", discover, ok=lambda r: isinstance(r, dict))
        self.results["intel"] = results or {}
        if results is not None:
            suffix = " (passive sources skipped)" if self.args.skip_passive else ""
            self.health.notes["Easy Discovery"] = (
                f"{len(results.get('well_known', []))} well-known, "
                f"{len(results.get('git_exposure', []))} VCS, "
                f"{len(results.get('spec_endpoints', []))} spec endpoints{suffix}"
            )

    def stage_crawl(self):
        self._stage(7, "Web Crawling & Link Extraction")
        self.crawler = CrawlerModule(self.target, self.console, surface=self.surface,
                                     max_depth=self.limits["crawl_depth"], profile=self.profile,
                                     max_pages=self.limits.get("crawl_pages"),
                                     scope=getattr(self.args, "scope", None),
                                     exclude=getattr(self.args, "exclude", None))
        self.crawl_results = self._timed(
            "Crawler", lambda: self.crawler.run(),
            ok=lambda r: r["pages_crawled"] > 0,
        ) or {"pages_crawled": 0, "internal_links": [], "js_files": [], "forms": [],
              "params": [], "inline_script_sources": [], "spa_routes": []}
        self.results["crawl"] = self.crawl_results
        if self.health.states.get("Crawler") == "OK":
            self.health.notes["Crawler"] = (
                f"{self.crawl_results['pages_crawled']} pages, "
                f"{len(self.crawl_results['params'])} params, "
                f"{len(self.crawl_results['js_files'])} scripts"
            )
        for label, text in self.crawler.blobs:
            self._store_blob(label, text)

    def stage_js(self, first=False):
        if first:
            self._stage(8, "Deep JavaScript / Source-Map Analysis")
        else:
            info(self.console, "Deep JavaScript / Source-Map Analysis (incremental pass)")

        if self.crawl_results is None:
            self.crawl_results = {}
        crawl = self.crawl_results
        crawler = getattr(self, "crawler", None)
        current_js = list(crawl.get("js_files", []))
        current_inline = list(crawl.get("inline_script_sources", []))
        if crawler is not None:
            current_js.extend(getattr(crawler, "js_files", set()) or [])
            current_inline.extend(getattr(crawler, "inline_scripts", []) or [])
        current_js = list(dict.fromkeys(current_js))
        current_inline = list(dict.fromkeys(current_inline))
        crawl["js_files"] = current_js
        crawl["inline_script_sources"] = current_inline
        if self.js_scanner is None:
            self.js_scanner = JSBundleScanner(self.target, self.console, self.surface,
                                              self.profile,
                                              scope=getattr(self.args, "scope", None))

        bundles = list(current_js)
        for path in self.bruteforced_dirs:
            p = path.get("path", "")
            if p.endswith((".js", ".mjs")):
                bundles.append(self.target.rstrip("/") + p)
        for endpoint in self.surface.endpoints():
            if endpoint["path"].endswith((".js", ".mjs")):
                bundles.append(endpoint["url"])
        bundles = list(dict.fromkeys(bundles))

        if (not bundles and not current_inline and
                not getattr(self.js_scanner, "analyzed", [])):
            self.js_scan_results = {
                "routes": [], "sourcemaps": [], "bundle_count": 0,
                "source_maps_with_content": 0, "blobs": [],
            }
            self.results["js_analysis"] = self.js_scan_results
            self.health.skip("JS Analysis", "no JavaScript sources were discovered")
            return

        self.js_scan_results = self._timed(
            "JS Analysis",
            lambda: self.js_scanner.analyze(
                js_urls=bundles,
                inline_scripts=current_inline,
                page_sources=None,
            ),
            ok=lambda r: bool(r.get("routes") or r.get("bundle_count")),
        ) or {"routes": [], "sourcemaps": [], "bundle_count": 0}

        if "blobs" in self.js_scan_results:
            for lbl, text in self.js_scan_results.pop("blobs"):
                self._store_blob(lbl, text)

        self.results["js_analysis"] = self.js_scan_results
        if self.js_scan_results.get("analysis_limits"):
            self.health.inconclusive("JS Analysis", "; ".join(self.js_scan_results["analysis_limits"]))
        if self.health.states.get("JS Analysis") == "OK":
            self.health.notes["JS Analysis"] = (
                f"{self.js_scan_results['bundle_count']} bundles, "
                f"{len(self.js_scan_results['routes'])} endpoints, "
                f"{self.js_scan_results['source_maps_with_content']} source maps"
            )
        for lbl, text in self.js_scanner.blobs:
            self._store_blob(lbl, text)

        self._assess_spa()

    def _assess_spa(self):
        """Fold client-side routes and lazy chunks onto the attack surface.

        This issues no request of its own: it reads the JavaScript the run has
        already retrieved and registers the routes and chunks it found, so the
        next discovery round crawls them like any other endpoint. Idempotent,
        because ``stage_js`` runs once per round.
        """
        if not self._want("spa"):
            self.health.skip("SPA", "disabled by module selection")
            return
        self._stage(24, "SPA Routes & Chunk Analysis")
        assessor = SpaAssessor(
            self.target, self.console, surface=self.surface,
            max_routes=int(self.limits.get("spa_routes", 300)),
            max_chunks=int(self.limits.get("spa_chunks", 100)),
            use_browser=bool(getattr(self.args, "browser", False)),
        )
        result = self._timed(
            "SPA",
            lambda: assessor.run(blobs=list(self.blobs),
                                 scanner_result=self.js_scan_results),
            ok=lambda value: isinstance(value, dict),
        )
        if result is None:
            self.results["spa"] = {"error": "stage failed"}
            return
        self.results["spa"] = result
        self.health.notes["SPA"] = (
            f"{result.get('route_count', 0)} client route(s), "
            f"{result.get('chunk_count', 0)} lazy chunk(s), "
            f"{len(result.get('registered_routes') or [])} registered"
        )
        privileged = result.get("privileged_routes") or []
        if privileged:
            info(self.console, f"{len(privileged)} client-side route(s) read as "
                               "privileged and were registered for authorization testing.")

    def stage_bruteforce(self, base=None, label="root"):
        """Bruteforce under a bounded run-wide path budget.

        Descending into every directory that was just discovered would repeat
        the root wordlist once per directory, so the budget is shared across
        the whole run instead of being spent again in each round.
        """
        target_base = base or self.target
        remaining = self.brute_budget - self.brute_spent
        if remaining <= 0:
            warning(self.console, f"Bruteforce budget of {self.brute_budget} paths is spent - "
                                  f"{target_base} was not enumerated. Raise --brute-budget.")
            return {"found": [], "total_tested": 0, "catchall_discarded": 0,
                    "unverified": 0, "catchall_detected": False, "base": target_base,
                    "skipped": "budget"}

        result = DirBusterModule(
            target_base, self.console, full=self.args.full_exts,
            workers=getattr(self.args, "threads", None),
            max_paths=remaining,
            exclude=getattr(self.args, "exclude", None),
        ).run()
        self.brute_spent += result.get("total_tested", 0)
        for entry in result.get("found", []):
            if not any(b["path"] == entry["path"] and b["url"].startswith(target_base)
                       for b in self.bruteforced_dirs):
                self.bruteforced_dirs.append(entry)
            self.surface.add_endpoint(entry["url"], "bruteforce")
            self.surface.add_params_from_url(entry["url"], "bruteforce")

        self.health.notes["Bruteforce"] = (
            f"{self.brute_spent}/{self.brute_budget} paths used, "
            f"{len(self.bruteforced_dirs)} found"
        )
        return result

    def stage_expand(self, seeds, label):
        if not seeds:
            return 0
        before = len(self.surface.endpoints())
        added = self.crawler.crawl(seeds[:400], label=label)
        for endpoint in self.surface.endpoints()[before:]:
            if endpoint["path"].endswith((".js", ".mjs")):
                self.surface.add_endpoint(endpoint["url"], "crawl-script")
        for lbl, text in self.crawler.blobs:
            self._store_blob(lbl, text)
        return added

    def _probe_params(self, base, name, delta):
        probe_limit = self.surface.budget * 2
        if not self.surface.record_probe(limit=probe_limit):
            return None
        test_url = AttackSurface._with_param(base, name, "1")
        baseline = self._probe_baseline(base)
        if baseline is None:
            return None
        try:
            resp = self.probe_session.get(test_url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return None
        if resp.status_code != baseline.status_code:
            return None
        if abs(len(resp.content) - len(baseline.content)) < delta:
            return None
        return {"url": base, "param": name,
                "size_delta": len(resp.content) - len(baseline.content)}

    def _probe_baseline(self, base):
        with self._probe_cache_lock:
            cached = self._probe_cache.get(base, ...)
            if cached is not ...:
                return cached
            try:
                response = self.probe_session.get(base, timeout=TIMEOUT, allow_redirects=True)
            except Exception:
                response = None
            self._probe_cache[base] = response
            return response

    def stage_probe_params(self):
        if self.mode == "safe":
            self.health.skip("Param Probing", "disabled in safe mode")
            return
        endpoints = self.surface.endpoints()
        promising = []
        for endpoint in endpoints:
            path = endpoint["path"]
            if any(hint in path for hint in ("search", "api", "query", "product", "user",
                                            "article", "post", "page", "item", "list",
                                            "detail", "report")):
                promising.append(endpoint["url"])
            if len(promising) >= 25:
                break
        promising = list(dict.fromkeys(promising or [self.target]))[:25]

        names = self.surface.probe_names
        if not names or not promising:
            self.health.skip("Param Probing", "no candidate parameters")
            return

        jobs = [
            (base, name) for base in promising for name in names
            if (base, name) not in self._probed_jobs
        ]
        probe_limit = self.surface.budget * 2
        remaining = max(0, probe_limit - self.surface.probe_budget_used)
        jobs = jobs[:remaining]
        if not jobs:
            reason = ("probe budget exhausted" if remaining == 0
                      else "all candidate pairs already tested")
            self.health.notes["Param Probing"] = reason
            self.health.states.setdefault("Param Probing", "INCONCLUSIVE" if remaining == 0 else "OK")
            return
        self._probed_jobs.update(jobs)
        info(self.console, f"Differentially probing {len(names)} parameter names against "
                           f"{len(promising)} endpoint(s) - {len(jobs)} probe(s), "
                           f"{self.probe_workers.size()} workers...")

        from core.pool import parallel
        timer = RequestTimer(self.probe_workers)

        def run(job):
            base, name = job
            return self._probe_params(base, name, PARAM_PROBE_DELTA)

        live = [hit for hit in parallel(run, jobs, workers=self.probe_workers.size(),
                                        timer=timer) if hit]

        for hit in sorted(live, key=lambda h: -abs(h["size_delta"])):
            if self.surface.add_param(hit["url"], hit["param"], "probe"):
                self.surface.mark_confirmed(hit["url"], hit["param"])
                self.probe_confirmed += 1
                found(self.console, f"Live parameter by probing: {hit['param']} on "
                                    f"{hit['url']} (delta {hit['size_delta']:+d} bytes)")

        if live:
            self.health.notes["Param Probing"] = f"{len(live)} live parameters"
        else:
            self.health.notes["Param Probing"] = "no parameter changed the response"
        self.health.states.setdefault("Param Probing", "OK")
        self.results["probe_hits"] = live
        self.health.timings["Param Probing"] = self.probe_workers.average_latency

    def stage_extraction(self):
        self._stage(9, "Data & Secret Extraction")
        crawl = self.crawl_results or {}
        pages = list(dict.fromkeys([self.target] + crawl.get("internal_links", []) +
                                   [e["url"] for e in self.surface.endpoints()[:400]]))
        extractor = ExtractorModule(self.target, self.console, pages=pages,
                                    surface=self.surface, profile=self.profile)
        result = self._timed(
            "Extraction",
            lambda: extractor.run(js_files=crawl.get("js_files", []),
                                  inline_scripts=crawl.get("inline_script_sources", [])),
        )
        self.results["extraction"] = result or {}
        for route in (result or {}).get("js_endpoints", []) or []:
            if not route.startswith("/"):
                route = "/" + route
            candidate = self.target.rstrip("/") + route
            self.surface.add_endpoint(candidate, "extractor-js")
        if result is not None:
            self.health.notes["Extraction"] = (
                f"{len(result.get('emails', []))} emails, "
                f"{len(result.get('tokens_keys', []))} keys"
            )

    def stage_leaks(self):
        self._stage(10, "Leak Scan Across Everything Retrieved")
        intel = self.intel_module
        if intel is None:
            intel = IntelModule(
                self.target, self.console, self.surface,
                max_spec_endpoints=self.limits["spec_endpoints"],
            )
            self.intel_module = intel

        sources = list(self.blobs)
        for entry in (self.results.get("intel", {}).get("well_known") or []):
            if entry.get("preview"):
                sources.append((entry["path"], entry["preview"]))
        if self.results.get("intel", {}).get("git_details"):
            sources.append((".git/logs/HEAD", json_dumps(self.results["intel"]["git_details"])))
        for version in (self.js_scan_results or {}).get("versions", []):
            sources.append(("js-version", str(version)))

        def scan_leaks():
            leaks = intel.leak_scan(sources)
            for token in (self.results.get("extraction") or {}).get("tokens_keys", []):
                leaks["secrets"].append({
                    "type": token.get("type"), "value": token.get("value"),
                    "source": token.get("page"),
                })
            deduped, seen = [], set()
            for secret in leaks["secrets"]:
                key = (secret.get("type"), str(secret.get("value"))[:60])
                if not secret.get("value") or key in seen:
                    continue
                seen.add(key)
                deduped.append(secret)
            leaks["secrets"] = deduped
            return leaks

        leaks = self._timed("Leak Scan", scan_leaks, network=False)
        self.results["leaks"] = leaks or {}
        if leaks is not None:
            self.health.notes["Leak Scan"] = (
                f"{len(leaks['secrets'])} secrets, {len(leaks['emails'])} emails, "
                f"{len(leaks['internal_ips'])} internal IPs"
            )

    def stage_headers(self):
        self._stage(11, "Security Header & Method Analysis")
        header_result = self._timed(
            "Headers", lambda: HeaderModule(self.target, self.console).run(),
            ok=lambda r: not r.get("error"),
        )
        self.results["headers"] = header_result or {
            "error": "stage failed", "score": 0.0, "headers": {}, "cookies": []
        }
        if header_result is None:
            self.health.notes.setdefault("Headers", "stage failed")
        elif header_result.get("error"):
            self.health.notes["Headers"] = header_result["error"]
        else:
            self.health.notes["Headers"] = f"score {header_result.get('score', 0):.0f}%"

        eol = eol_check((self.js_scan_results or {}).get("versions", []))
        self.results["library_eol"] = eol
        if eol:
            for item in eol:
                warning(self.console, f"Unmaintained client library: {item['library']} "
                                      f"{item['version']} - {item['note']}")

    def stage_injection(self):
        params = self.crawl_results.get("params", [])
        forms = self.crawl_results.get("forms", [])
        for form in forms:
            self.surface.add_form(form)

        stats = self.surface.stats()
        info(self.console, f"Attack surface: {stats['params']} parameters "
                           f"({stats['confirmed_params']} probe-confirmed), "
                           f"{stats['forms']} forms, {stats['endpoints']} endpoints")

        if not self.args.skip_sqli:
            self._stage(12, "SQL Injection Testing")
            result = self._timed(
                "SQLi",
                lambda: SQLiModule(self.target, self.console, params=params, forms=forms,
                                   baseline=self.baseline, surface=self.surface,
                                   intrusive=self.mode == "intrusive").run(),
                ok=lambda r: r.get("tested_count", 0) > 0,
            )
            self.results["sqli"] = result or {"vulnerable_params": [], "tested_count": 0}
            if result is not None and result.get("tested_count", 0) == 0 and not self.surface.params():
                self.health.inconclusive("SQLi", "no injectable parameters were discovered")
            elif self.health.states.get("SQLi") == "OK":
                self.health.notes["SQLi"] = (
                    f"{result['tested_count']} tests on {len(params) + len(forms)} surfaces, "
                    f"{result.get('uncovered_params', 0)} untested"
                )
        else:
            self.results["sqli"] = {"vulnerable_params": [], "tested_count": 0,
                                     "skipped": True}
            self.health.skip("SQLi", f"disabled in {self.mode} mode or by operator")

        if not self.args.skip_xss:
            self._stage(13, "Cross-Site Scripting (XSS) Testing")
            result = self._timed(
                "XSS",
                lambda: XSSModule(self.target, self.console, params=params, forms=forms,
                                  baseline=self.baseline, surface=self.surface,
                                  intrusive=self.mode == "intrusive"
                                  ).run(js_files=self.crawl_results.get("js_files", []),
                                        js_sinks=(self.js_scan_results or {}).get("sinks")),
                ok=lambda r: r.get("tested_count", 0) > 0,
            )
            self.results["xss"] = result or {"reflected": [], "dom_based": [], "tested_count": 0}
            if result is not None and result.get("tested_count", 0) == 0 and not self.surface.params():
                self.health.inconclusive("XSS", "no injectable parameters were discovered")
            elif self.health.states.get("XSS") == "OK":
                self.health.notes["XSS"] = (
                    f"{result['tested_count']} tests, {len(result['reflected'])} reflected, "
                    f"{len(result['dom_based'])} DOM sinks"
                )
        else:
            self.results["xss"] = {"reflected": [], "dom_based": [],
                                    "tested_count": 0, "skipped": True}
            self.health.skip("XSS", f"disabled in {self.mode} mode or by operator")

    def stage_vulns(self):
        if self.mode == "safe":
            self.results["vulns"] = {"skipped": True, "reason": "safe mode"}
            self.health.skip("Vuln Audit", "disabled in safe mode")
            return
        self._stage(14, "Additional Vulnerability Auditing")
        params = self.crawl_results.get("params", [])
        pages = list(dict.fromkeys([self.target] + self.crawl_results.get("internal_links", [])[:300]))
        result = self._timed(
            "Vuln Audit",
            lambda: VulnModule(self.target, self.console, params=params, pages=pages,
                               baseline=self.baseline, surface=self.surface,
                               workers=getattr(self.args, "threads", None),
                               download_evidence=getattr(self.args, "download_evidence", False),
                               output_dir=getattr(self.args, "output", "output"),
                               mode=self.mode).run(),
        )
        self.results["vulns"] = result or {}
        if result is not None:
            self.health.notes["Vuln Audit"] = f"{self.mode} checks completed"

    

    def discovery_loop(self):
        """Repeat discovery while it keeps producing new endpoints."""
        info(self.console, "")
        info(self.console, f"Entering convergence loop (max {self.max_rounds} rounds)...")

        roots_result = None
        for round_no in range(1, self.max_rounds + 1):
            section_header(self.console, f"Round {round_no}/{self.max_rounds} - Discovery expansion")
            before = len(self.surface.endpoints())

            if not self.args.skip_dirs:
                if round_no == 1:
                    roots_result = self.stage_bruteforce(self.target, "root")
                    self.results.setdefault("directories", roots_result)
                else:
                    subdirs = self._next_subdirs()
                    for subdir in subdirs:
                        self.stage_bruteforce(f"{self.target.rstrip('/')}/{subdir}", subdir)
                    if not subdirs:
                        info(self.console, "No new directories to descend into - stopping descent.")

            if self._want("js"):
                self.stage_js(first=(round_no == 1))
            else:
                self.health.skip("JS Analysis", "disabled by module selection or profile")

            seeds = list(dict.fromkeys(
                self._page_seeds_from_results() + self._js_route_seeds() + self._spec_seeds()
            ))
            if self._want("crawl") and self.crawler is not None:
                self.stage_expand(seeds, f"round-{round_no}")

            unlinked = (self.js_scan_results or {}).get("routes", [])
            walked = (self.crawler.crawl_route_seeds(unlinked, f"js-routes-{round_no}")
                      if self._want("crawl") and self.crawler is not None else 0)
            if walked:
                info(self.console, f"Walked {walked} JS route(s) that were never linked from HTML.")
            for lbl, text in (self.crawler.blobs if self.crawler is not None else []):
                self._store_blob(lbl, text)

            self.stage_probe_params()

            added = len(self.surface.endpoints()) - before
            info(self.console, f"Round {round_no}: +{added} new endpoints "
                               f"(total {len(self.surface.endpoints())})")

            pending_descent = (not self.args.skip_dirs and self._has_pending_subdirs())
            pending_js = self._want("js") and self._has_pending_js()
            pending_work = pending_descent or pending_js
            if added < self.converge_threshold and not pending_work:
                info(self.console, f"Discovery converged after round {round_no} "
                                   f"(+{added} < {self.converge_threshold}).")
                self.results["convergence"] = {"rounds": round_no, "last_delta": added,
                                               "converged": True}
                break
            if added < self.converge_threshold and pending_work:
                reasons = []
                if pending_descent:
                    reasons.append("directory descent")
                if pending_js:
                    reasons.append("new JavaScript analysis")
                info(self.console, "Endpoint growth is low, but pending " +
                                   " and ".join(reasons) + " requires another round.")

            self.results["convergence"] = {"rounds": round_no, "last_delta": added,
                                           "converged": False}
        else:
            warning(self.console, f"Stopped after {self.max_rounds} rounds without converging - "
                                  "the surface is NOT fully mapped. Raise --deep.")

    TEMPORARY_ASSET_DIRS = {"static", "css", "js", "assets", "img", "images", "media",
                            "fonts", "uploads", "downloads", "font", "public"}
    _DESCEND_LIMIT = 3

    def _next_subdirs(self):
        """First-level directories worth descending into, newest discovery first."""
        candidates = []
        for entry in self.bruteforced_dirs:
            path = entry.get("path", "")
            if entry.get("status") not in (200, 401, 403):
                continue
            if path.count("/") != 1:
                continue
            name = path.strip("/")
            if not name or "." in name or name in self.visited_subdirs:
                continue
            if name.lower() in self.TEMPORARY_ASSET_DIRS:
                continue
            candidates.append((0 if entry.get("status") == 403 else 1, name))

        candidates.sort()
        chosen = [name for _, name in candidates[:self._DESCEND_LIMIT]]
        self.visited_subdirs.update(chosen)
        if not chosen and self.bruteforced_dirs:
            info(self.console, "No further first-level directories deserve a descent - "
                               "stopping brute-force expansion.")
        return chosen

    def _has_pending_subdirs(self):
        for entry in self.bruteforced_dirs:
            path = entry.get("path", "")
            name = path.strip("/")
            if entry.get("status") not in (200, 401, 403):
                continue
            if path.count("/") != 1 or not name or "." in name:
                continue
            if name in self.visited_subdirs or name.lower() in self.TEMPORARY_ASSET_DIRS:
                continue
            return True
        return False

    def _has_pending_js(self):
        crawler = getattr(self, "crawler", None)
        if crawler is None:
            return False
        urls = set(getattr(crawler, "js_files", set()) or [])
        inline = list(getattr(crawler, "inline_scripts", []) or [])
        scanner = self.js_scanner
        if scanner is None:
            return bool(urls or inline)
        done = set(getattr(scanner, "_done", set()) or [])
        done.update(getattr(scanner, "analyzed", []) or [])
        if urls - done:
            return True
        inline_done = set(getattr(scanner, "_inline_done", set()) or [])
        for code in inline:
            if not code or not code.strip():
                continue
            signature = hashlib.sha256(code.encode("utf-8", "ignore")).hexdigest()
            if signature not in inline_done:
                return True
        return False

    def stage_api(self):
        self._stage(23, "API Security Assessment")
        """API assessment driven by the target's own published contract.

        Without a specification there is no contract to contradict, so the
        documented-operation and validation checks report themselves as skipped
        rather than as clean. GraphQL is still probed, because an endpoint can
        exist with no specification anywhere.
        """
        section_header(self.console, "API Security Assessment")

        session = RateLimitedSession()
        spec = None
        for entry in list(getattr(self.intel_module, "specs", []) or [])[:3]:
            url = str(entry.get("url") or "")
            if not url:
                continue
            try:
                response = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            except Exception:
                continue
            if response is None or response.status_code != 200:
                continue
            candidate = parse_spec(response.text, url)
            if candidate.operations:
                spec = candidate
                info(self.console, f"Assessing {len(candidate.operations)} documented "
                                   f"API operation(s) from {url}")
                break
        if spec is None:
            warning(self.console, "No API specification could be retrieved; documented-"
                                  "operation and schema checks are skipped, not clean.")

        budget = int(self.limits.get("api_budget", 60))
        prior_graphql = (self.results.get("intel", {}) or {}).get("graphql") or {}
        graphql_endpoint = ""
        if isinstance(prior_graphql, dict):
            graphql_endpoint = str(prior_graphql.get("endpoint") or "")

        def assess():
            assessment = {
                "rest": RestAssessor(self.target, self.console, session, spec=spec,
                                     surface=self.surface, mode=self.mode,
                                     budget=budget).run(),
                "graphql": GraphqlAnalyzer(self.target, self.console, session,
                                           endpoint=graphql_endpoint,
                                           surface=self.surface, mode=self.mode,
                                           budget=budget).run(),
                "validation": ValidationAssessor(self.target, self.console, session,
                                                 spec=spec, surface=self.surface,
                                                 mode=self.mode, budget=budget).run(),
                "authz": materialise_api_routes(spec, self.surface),
            }
            collected = []
            for section in ("rest", "graphql", "validation"):
                collected.extend(assessment[section].get("findings") or [])
            assessment["findings"] = collected
            return assessment

        result = self._timed("API", assess, ok=lambda value: isinstance(value, dict))
        if result is None:
            self.results["api"] = {"error": "stage failed"}
            return
        self.results["api"] = result
        self.health.notes["API"] = (
            f"{len(result.get('findings') or [])} finding(s), "
            f"{(result.get('authz') or {}).get('concrete_endpoints', 0)} route(s) registered"
        )

    def stage_auth(self):
        self._stage(15, "Authentication & Token Analysis")
        auth = AuthModule(self.target, self.console, self.surface)
        result = self._timed(
            "Auth/Token",
            lambda: auth.run(blobs=self.blobs),
            ok=lambda r: True,
        )
        self.results["auth"] = result or {}
        if result is None:
            self.health.notes.setdefault("Auth/Token", "module failed")
            return
        self.health.notes["Auth/Token"] = (
            f"{len(result.get('jwts', []))} token(s), "
            f"{len(result.get('issues', []))} issue(s)"
        )

    def stage_protocol(self):
        if self.mode == "safe":
            self.results["protocol"] = {"skipped": True, "reason": "safe mode"}
            self.health.skip("Protocol", "disabled in safe mode")
            return
        self._stage(16, "Protocol-Level Analysis (framing, WebSocket, GraphQL, verbs)")
        proto = ProtoModule(self.target, self.console, self.baseline, mode=self.mode)
        graphql_paths = [e["path"] for e in self.surface.endpoints()
                         if "graphql" in e["path"].lower() or "gql" in e["path"].lower()]
        verb_paths = list(dict.fromkeys(
            [self.target] + [e["url"] for e in self.surface.endpoints()[:12]]
        ))

        result = self._timed(
            "Protocol",
            lambda: proto.run(graphql_candidates=graphql_paths or None, verb_paths=verb_paths),
        )
        self.results["protocol"] = result or {}
        if result is None:
            return
        check_names = ["websocket", "graphql", "verb_tampering"]
        if self.mode == "intrusive":
            check_names.insert(0, "smuggling")
        failed_checks = [
            name for name in check_names
            if isinstance(result.get(name), dict) and result[name].get("error")
        ]
        if len(failed_checks) == len(check_names):
            self.health.record("Protocol", False,
                               f"all protocol checks failed: {', '.join(failed_checks)}")
        elif failed_checks:
            self.health.inconclusive(
                "Protocol", f"partial protocol coverage; failed: {', '.join(failed_checks)}"
            )
        elif proto.smuggling:
            self.health.notes["Protocol"] = f"{len(proto.smuggling)} framing anomaly/anomalies"
        elif proto.graphql.get("open"):
            self.health.notes["Protocol"] = "GraphQL introspection open"
        else:
            self.health.notes["Protocol"] = "framing consistent, no exposed GraphQL"

    def stage_verify(self):
        self._stage(17, "Re-verification of Findings")
        verifier = Verifier(self.target, self.console, self.baseline)
        result = self._timed("Verification", lambda: verifier.run(self.results))
        self.results["verification"] = result or {}
        if result is None:
            return
        summary = (result or {}).get("summary", {})
        if summary.get("checked", 0) == 0:
            self.health.skip("Verification", "no verifiable candidates were produced")
        else:
            self.health.notes["Verification"] = (
                f"{summary.get('verified', 0)}/{summary.get('checked', 0)} reproduced, "
                f"{summary.get('refuted', 0)} refuted"
            )

    def stage_extended(self):
        self._stage(25, "Additional Passive Assessments")
        from core.assessments import (header_analysis, dns_analysis, technology_analysis,
                                      passive_secrets, dependency_audit, cloud_audit)
        raw = (self.results.get("headers") or {}).get("raw_headers") or {}
        checks = {"headers": lambda: header_analysis(raw, self.target),
                  "dns": lambda: dns_analysis((self.results.get("recon") or {}).get("dns") or {}, self.target),
                  "technology": lambda: technology_analysis(raw, self.blobs),
                  "secrets": lambda: passive_secrets(self.blobs, self.target)}
        for key, function in (("dependencies", dependency_audit), ("cloud", cloud_audit)):
            path = getattr(self.args, key + "_file", None)
            if path:
                checks[key] = lambda fn=function, source=path: fn(source, self.target)
        results = {}
        for name, check in checks.items():
            results[name] = self._timed("Extended/" + name, check) or {}
        self.results["extended"] = results

    def stage_plugins(self):
        self._stage(26, "Trusted Plugin Execution")
        from core.plugins import PluginRegistry
        registry = PluginRegistry(getattr(self.args, "plugin_dir", None))
        enabled = getattr(self.args, "enable_plugin", None) or []
        snapshot = {"headers": (self.results.get("headers") or {}).get("raw_headers", {}),
                    "target": self.target}
        result = registry.run(enabled, getattr(self.args, "disable_plugin", None), self.target,
                              self.surface.policy, RateLimitedSession._control, snapshot,
                              self.mode, getattr(self.args, "ack_authorized", False))
        self.results["plugins"] = result
        for key, item in result["plugins"].items():
            if item["state"] == "SKIPPED":
                self.health.skip("Plugin/" + key, item.get("reason", ""))
            else:
                self.health.record("Plugin/" + key, item["state"] == "OK", item.get("error", ""))

    def stage_correlate(self):
        self._stage(19, "Attack-Path Correlation & Prioritisation")
        self._publish_runtime_context()
        graph = AttackGraph(self.console)
        result = self._timed("Correlation", lambda: graph.run(self.results), network=False)
        self.results["correlated"] = result or {}
        summary = result or {}

        paths = summary.get("attack_paths", [])
        for path in paths:
            path["cvss"] = max(
                (step.get("cvss_score", 0) for step in path.get("steps", [])), default=0.0
            )

        if paths:
            warning(self.console, f"{len(paths)} multi-step attack path(s) identified.")
            for path in paths[:5]:
                marker = "[VULN]" if path["severity"] == "critical" else "[!]"
                lines = [
                    f"{marker} {path['name'].upper()}  (score {path['score']}, "
                    f"CVSS {path['cvss']})",
                    f"      1. {path['steps'][0]['action']} -> {path['steps'][0]['result']}",
                ]
                for step in path["steps"][1:]:
                    lines.append(f"      {step['step']}. {step['action']} -> {step['result']}")
                lines.append(f"      => {path['consequence']}")
                for line in lines:
                    vuln(self.console, line)
        else:
            found(self.console, "No multi-step chain links the findings that were detected.")

        gaps = summary.get("coverage_gaps", [])
        if gaps:
            warning(self.console, f"{len(gaps)} coverage gap(s): parts of this surface were never "
                                  "established. Read these as 'unknown', not as 'safe'.")
            for gap in gaps:
                warning(self.console, f"  {gap['gap']} -> {gap['consequence']}")

        scored = self._score_findings(findings=summary.get("top_findings", []))
        rows = [("Findings", str(summary.get("finding_count", 0)))]
        rows += [(f"CVSS {k}", str(v)) for k, v in (scored.get("ratings") or {}).items()]
        rows += [(f"Priority {k}", str(v)) for k, v in (scored.get("bands") or {}).items()]
        rows.append(("Attack paths", str(summary.get("attack_path_count", 0))))
        self.console.print(make_table("Correlated & Scored Findings", ["Metric", "Value"], rows))

        if result is not None:
            self.health.notes["Correlation"] = (
                f"{summary.get('finding_count', 0)} findings, "
                f"{summary.get('attack_path_count', 0)} paths"
            )

    def _score_findings(self, findings):
        """Attach CVSS, CWE and priority bands. Reused by the impact and fix stages."""
        enriched = [enrich(finding, self._exposure_of(finding)) for finding in findings]
        scored = summarize(enriched)
        self.results["scored"] = scored
        return scored

    def _exposure_of(self, finding):
        exposure = {}
        target = str(finding.get("target", ""))
        if not target:
            return exposure

        admin_paths = (self.results.get("vulns", {}) or {}).get("admin_panels", []) or []
        if any(entry.get("url") == target for entry in admin_paths):
            exposure["requires_auth"] = False
            exposure["user_interaction"] = False

        header_score = (self.results.get("headers", {}) or {}).get("score", 0)
        if header_score and header_score >= 50:
            exposure["scope_changed"] = False
        return exposure

    def stage_impact(self):
        self._publish_findings()
        self._stage(20, "Impact Modeling (worst-case reach from confirmed findings)")
        scored_all = (self.results.get("scored", {}) or {}).get("all", [])
        model = self._timed("Impact",
                            lambda: ImpactModel(self.console).build(self.results, scored_all), network=False)
        self.results["impact"] = model or {}

        for layer in (model or {}).get("blast_radius", []):
            if layer["reached"]:
                vuln(self.console, f"[VULN] {layer['layer']}: reached - {layer['basis']}")
            else:
                found(self.console, f"[+] {layer['layer']}: not reached - {layer['basis']}")

        worst = (model or {}).get("worst_case")
        if worst:
            warning(self.console, f"Worst case: {worst}")

        for chain in ((model or {}).get("fix_first") or [])[:6]:
            vuln(self.console, f"  capability -> {chain['ceiling']}: {chain['why'][:88]}")

        assets = (model or {}).get("reachable_assets", [])
        if assets:
            found(self.console, f"Assets reachable if the ceiling is reached: {len(assets)} "
                                f"observed, {', '.join(a['value'] for a in assets[:6])}")

    def stage_oob(self):
        self._stage(18, "Out-of-Band Confirmation (blind injections)")
        if getattr(self.args, "skip_oob", False):
            warning(self.console, "Blind findings remain at their response-based confidence. "
                                  "No payload was executed for them.")
            self.results["oob"] = {"started": False, "note": "skipped by operator",
                                   "payloads": [], "confirmed": []}
            self.health.skip("OOB", "skipped by operator")
            return

        self._publish_runtime_context()
        blind_findings = OOBModule.blind_candidates(self.results)
        if not blind_findings:
            self.results["oob"] = {"started": False, "note": "no blind candidates",
                                   "payloads": [], "confirmed": [], "candidates": []}
            self.health.skip("OOB", "no blind candidates")
            return

        module = OOBModule(
            self.target, self.console,
            bind_host=getattr(self.args, "oob_bind", "127.0.0.1"),
            public_host=getattr(self.args, "oob_host", None),
        )
        try:
            result = module.run(blind_findings=blind_findings, wait_seconds=1.0, start=True)
        except Exception as e:
            error(self.console, f"OOB stage failed: {type(e).__name__}: {e}")
            result = {"started": False, "note": str(e), "payloads": [], "confirmed": []}
        finally:
            try:
                module.stop()
            except Exception:
                pass

        result = result or {"started": False, "note": "module returned no result",
                            "payloads": [], "confirmed": []}
        result["candidates"] = blind_findings
        self.results["oob"] = result
        if result.get("started"):
            self.health.record(
                "OOB", True,
                f"{len(result.get('payloads', []))} families, "
                f"{len(result.get('confirmed', []))} callback(s)"
            )
        else:
            self.health.states.setdefault("OOB", "FAILED")
            self.health.notes["OOB"] = (result.get("note") or "listener unavailable")[:60]

    def stage_remediation(self):
        self._stage(21, "Remediation & Code-Level Fixes")
        findings = (self.results.get("scored", {}) or {}).get("all", [])
        result = self._timed("Remediation",
                             lambda: Remediation(self.console, self.results).run(findings), network=False)
        self.results["remediation"] = result or {}
        if result:
            self.health.notes.setdefault("Remediation", f"{result.get('guidance_count')} fixes")

    def _pool_report(self) -> dict:
        """Throughput telemetry: was the configured rate actually honoured?"""
        shared = RateLimitedSession.shared()
        report = dict(shared.report()) if hasattr(shared, "report") else {}
        report.update({
            "bruteforce_paths_used": self.brute_spent,
            "bruteforce_budget": self.brute_budget,
            "probe_requests": self.probe_workers and self.surface.probe_budget_used,
            "workers_chosen": self.probe_workers._current,
            "adaptive_threads": self.probe_workers.adaptive,
            "observed_latency": round(self.probe_workers.average_latency, 3),
        })
        return report

    def _apply_resume(self):
        """Reuse what an earlier run already established.

        Only *discovery* is carried over: the endpoints.  Findings from the
        earlier run are attached as ``prior_findings`` so the report can show
        them and the comparison can diff them, but they are never presented as
        results of this run - this run did not re-verify them.
        """
        state = self.resume_state
        if not state:
            return
        seeded = 0
        for url in state.get("endpoints") or []:
            if self.surface.add_endpoint(url, "resume"):
                seeded += 1
        prior = state.get("findings") or []
        self.results["resumed_from"] = state.get("scan_id")
        self.results["prior_findings"] = prior
        self.results["resume"] = {
            "scan_id": state.get("scan_id"),
            "endpoints_restored": seeded,
            "endpoints_available": len(state.get("endpoints") or []),
            "completed_stages_not_replayed": state.get("completed_stages") or [],
            "prior_findings": len(prior),
        }
        info(self.console, f"Resumed from {state.get('scan_id')}: "
                           f"{seeded} endpoint(s) restored, {len(prior)} prior finding(s) "
                           f"kept for comparison")

    def _persist_run(self):
        """Write stages, endpoints and findings to the local store."""
        if self.store is None or not self.scan_id:
            return
        try:
            for name, state in self.health.states.items():
                self.store.record_stage(
                    self.scan_id, name, state,
                    self.health.notes.get(name, ""),
                    self.health.timings.get(name),
                )
            self.store.record_endpoints(self.scan_id, self.surface.endpoints())
            self.store.record_findings(self.scan_id, self.results.get("findings") or [])
            from core.lifecycle import Status
            current = self.results.get("findings") or []
            self.results["lifecycle"] = {
                "summary": {"findings": len(current), "by_status": {
                    state.value: sum(item.get("status") == state.value for item in current)
                    for state in Status}},
                "records": [{key: item.get(key) for key in
                             ("fingerprint", "status", "status_history", "reproducibility")}
                            for item in current],
            }
            self.health.record("Evidence", True, f"{len(current)} findings persisted with lifecycle and evidence")
        except Exception as exc:  
            self.results["persistence_error"] = f"{type(exc).__name__}: {exc}"
            self.health.record("Evidence", False, self.results["persistence_error"])

    def _publish_runtime_context(self):
        """Publish the live contracts consumed by correlation, OOB and reports."""
        surface = self.surface.stats()
        surface["params_detail"] = self.surface.params()[:600]
        surface["endpoints_detail"] = self.surface.endpoints()[:600]
        self.results["attack_surface"] = surface
        self.results["settings"] = {
            "mode": self.mode,
            "tls_verification": not getattr(self.args, "insecure", False),
            "rate": REQUESTS_PER_SECOND,
            "depth": self.limits["crawl_depth"],
            "pages": self.limits["crawl_pages"],
            "injection_budget": self.limits["injection_budget"],
            "brute_budget": self.brute_budget,
            "rounds": getattr(self.args, "rounds", None) or self.max_rounds,
            "scope": getattr(self.args, "scope", None),
            "excluded_paths": getattr(self.args, "exclude", []) or [],
            "threads": ("adaptive" if getattr(self.args, "threads", None) is None
                        else self.args.threads),
        }
        return surface

    def stage_access(self):
        """Authorization testing: IDOR, BOLA, BFLA and missing authentication."""
        if self.mode == "safe":
            self.results["access"] = {"skipped": True, "reason": "safe mode"}
            self.health.skip("Access Control", "requires --mode active")
            return
        self._stage(22, "Access-Control Verification (IDOR / BOLA / vertical)")
        module = AccessControlModule(
            self.target, self.console, surface=self.surface, baseline=self.baseline,
            primary_headers=getattr(config, "REQUEST_HEADERS", {}) or {},
            secondary_headers=self.secondary_headers,
            mode=self.mode,
        )
        result = self._timed("Access Control", lambda: module.run(),
                             ok=lambda r: isinstance(r, dict))
        self.access_result = result or {}
        self.results["access"] = self.access_result
        if result is None:
            return
        total = sum(len(self.access_result.get(key) or []) for key in
                    ("missing_auth", "idor", "bola", "bfla", "inconsistent"))
        self.health.notes["Access Control"] = (
            f"{total} finding(s) over {self.access_result.get('tested', 0)} request(s), "
            f"{self.access_result.get('identities', 0)} identity/identities"
        )

    

    def _want(self, stage: str) -> bool:
        """Is *stage* enabled by module selection and the selected profiles?"""
        from core.profiles import ALWAYS_ON
        if self.selected_stages is not None and stage not in ALWAYS_ON and stage not in self.selected_stages:
            return False
        if stage in {"spa", "plugins"}:
            return True
        if self.profile_resolution is None:
            return True
        return self.profile_resolution.enabled(stage)

    def _apply_profile_gates(self):
        """Translate profile choices into the pipeline's existing skip flags.

        Reusing the operator-facing flags keeps one code path in charge of
        safety limits: a profile can only turn work *off*, never lift a cap.
        """
        if not self._want("ports"):
            self.args.skip_ports = True
        if not self._want("bruteforce"):
            self.args.skip_dirs = True
        if not self._want("sqli"):
            self.args.skip_sqli = True
        if not self._want("xss"):
            self.args.skip_xss = True
        if not self._want("oob"):
            self.args.skip_oob = True

    def _stage_summary(self) -> dict:
        """What the selected profiles actually enabled, for the report."""
        if self.profile_resolution is None:
            return {"profiles": [], "stages": "all stages (no profile selected)"}
        return self.profile_resolution.report()

    VULN_TITLES = {
        "ssti": "Server-side template injection",
        "command-injection": "OS command injection",
        "ssrf": "Server-side request forgery",
        "lfi": "Local file inclusion / path traversal",
        "open-redirect": "Open redirect",
        "crlf": "CRLF header injection",
        "host-header": "Host header injection",
        "verbose-errors": "Verbose error / debug mode disclosure",
        "sensitive-file": "Sensitive file exposed",
        "admin-panel": "Administrative interface exposed",
        "backup-file": "Backup file exposed",
        "csrf": "Cross-site request forgery weakness",
        "xxe": "XML external entity processing",
        "cache-poisoning": "Web cache poisoning weakness",
        "cors": "CORS policy misconfiguration",
        "graphql-introspection": "GraphQL introspection exposed",
        "vcs-exposure": "Version-control metadata exposed",
        "secret-leak": "Credential or secret exposed",
        "source-map": "Source map discloses original source",
        "eol-library": "Unmaintained client library",
        "forgeable-jwt": "JWT signature can be forged",
        "jwt-structure": "JWT configuration weakness",
        "clickjacking": "Clickjacking protection missing",
        "sqli": "SQL injection",
        "xss": "Cross-site scripting",
        "dom-sink": "DOM-based cross-site scripting sink",
        "missing-auth": "Authentication missing on a protected route",
        "idor": "Insecure direct object reference",
        "bola": "Broken object-level authorization",
        "bfla": "Broken function-level authorization",
    }

    def _absolute(self, value) -> str:
        """Resolve a discovered target against the scan target.

        Discovery emits a mix of absolute URLs and bare relative paths.  Without
        this, ``/health`` and ``http://host/health`` are recorded as two
        findings for one exposed file and the count is wrong.
        """
        text = str(value or "").strip()
        if not text:
            return self.target
        if text.startswith(("http://", "https://")):
            return text
        if not text.startswith("/"):
            text = "/" + text
        return self.target.rstrip("/") + text

    @staticmethod
    def _evidence_text(value) -> str:
        """Render evidence as one readable line rather than a dict repr."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value[:600]
        if isinstance(value, dict):
            preferred = ("status", "status_code", "observed_bytes", "bytes", "size",
                         "content_type", "sha256", "verified", "saved", "reason",
                         "detail", "why")
            parts = [f"{key}={value[key]}" for key in preferred
                     if value.get(key) not in (None, "", False)]
            if not parts:
                parts = [f"{key}={val}" for key, val in list(value.items())[:5]
                         if val not in (None, "", False)]
            return ", ".join(parts)[:600]
        if isinstance(value, (list, tuple)):
            return ", ".join(str(item) for item in list(value)[:8])[:600]
        return str(value)[:600]

    def _finding(self, kind, item, **overrides) -> dict:
        """Normalise one module-specific record into the canonical shape."""
        record = {
            "kind": kind,
            "title": item.get("title") or self.VULN_TITLES.get(kind, kind),
            "severity": item.get("severity") or "medium",
            "target": self._absolute(item.get("url") or item.get("target")
                                     or item.get("path")),
            "method": item.get("method") or "GET",
            "param": item.get("param") or item.get("parameter") or "",
            "payload": item.get("payload") or item.get("probe") or "",
            "evidence": self._evidence_text(item.get("evidence")),
            "verification": item.get("verification")
            or ("CONFIRMED" if item.get("verified") else "POTENTIAL"),
            "confidence": item.get("confidence", 0.6),
        }
        record.update(overrides)
        for key in ("error_signature", "expected_location", "request_context"):
            if key in item:
                record[key] = item[key]
        return record

    def _collect_findings(self) -> list:
        """Gather every detected weakness into one list before reporting.

        The correlation graph only knows the families it was taught; this
        collector is the authoritative inventory the report is built from, so a
        confirmed access-control finding is never dropped just because the
        graph had no rule for it.
        """
        collected = list((self.results.get("scored", {}) or {}).get("all") or [])
        for result in (self.results.get("extended") or {}).values():
            collected.extend(result.get("findings") or [])
        for result in (self.results.get("plugins") or {}).get("plugins", {}).values():
            collected.extend(result.get("findings") or [])
        collected.extend((self.results.get("api") or {}).get("findings") or [])
        collected.extend(((self.results.get("protocol") or {}).get("websocket") or {}).get("findings") or [])

        vulns = self.results.get("vulns", {}) or {}
        for key, kind in (
            ("ssti", "ssti"), ("command_injection", "command-injection"),
            ("ssrf", "ssrf"), ("lfi", "lfi"), ("open_redirects", "open-redirect"),
            ("crlf", "crlf"), ("host_header", "host-header"),
            ("verbose_errors", "verbose-errors"), ("sensitive_files", "sensitive-file"),
            ("admin_panels", "admin-panel"), ("backup_files", "backup-file"),
            ("csrf", "csrf"), ("xxe", "xxe"), ("cache_poisoning", "cache-poisoning"),
        ):
            for item in vulns.get(key) or []:
                if isinstance(item, dict):
                    collected.append(self._finding(kind, item))

        for entry in vulns.get("cors") or []:
            if isinstance(entry, dict):
                collected.append(self._finding("cors", entry))

        for item in (self.results.get("xss", {}) or {}).get("reflected") or []:
            if isinstance(item, dict):
                collected.append(self._finding("xss", item, severity="medium"))
        for item in (self.results.get("xss", {}) or {}).get("dom_based") or []:
            if isinstance(item, dict):
                collected.append(self._finding("dom-sink", item, severity="low"))

        for item in (self.results.get("sqli", {}) or {}).get("vulnerable_params") or []:
            if isinstance(item, dict):
                collected.append(self._finding("sqli", item, severity="critical"))

        access = self.results.get("access", {}) or {}
        for key in ("missing_auth", "idor", "bola", "bfla", "inconsistent"):
            for item in access.get(key) or []:
                if isinstance(item, dict):
                    collected.append(self._finding(item.get("kind", key), item))

        for item in (self.results.get("leaks", {}) or {}).get("secrets") or []:
            if isinstance(item, dict) and item.get("value"):
                collected.append({
                    "kind": "secret-leak", "title": (
                        f"{item.get('type', 'Secret')} exposed in client-served content"),
                    "severity": "high", "target": item.get("source") or self.target,
                    "method": "GET", "param": "", "payload": "",
                    "evidence": f"{item.get('type')} value served without authentication",
                    "verification": "CONFIRMED", "confidence": 0.9,
                })

        graphql = (self.results.get("protocol", {}) or {}).get("graphql") or {}
        if graphql.get("open"):
            collected.append({
                "kind": "graphql-introspection",
                "title": "GraphQL introspection is open without authentication",
                "severity": "low", "target": graphql.get("url") or self.target,
                "method": "POST", "param": "", "payload": "",
                "evidence": f"{graphql.get('types')} types returned by introspection",
                "verification": "CONFIRMED", "confidence": 0.9,
            })

        for item in (self.results.get("intel", {}) or {}).get("git_exposure") or []:
            if isinstance(item, dict):
                collected.append({
                    "kind": "vcs-exposure", "title": "Version-control metadata exposed",
                    "severity": "high",
                    "target": self.target.rstrip("/") + "/" + str(item.get("path", "")).lstrip("/"),
                    "method": "GET", "param": "", "payload": "",
                    "evidence": f"{item.get('status')} with {item.get('size')} bytes",
                    "verification": "CONFIRMED" if item.get("details") else "LIKELY",
                    "confidence": 0.85,
                })

        for item in self.results.get("library_eol") or []:
            if isinstance(item, dict):
                collected.append({
                    "kind": "eol-library",
                    "title": f"Unmaintained client library: {item.get('library')} "
                             f"{item.get('version')}",
                    "severity": "low", "target": self.target, "method": "GET",
                    "param": "", "payload": "", "evidence": item.get("note", ""),
                    "verification": "CONFIRMED", "confidence": 0.9,
                })

        for item in (self.results.get("js_analysis", {}) or {}).get("sourcemaps") or []:
            url = item if isinstance(item, str) else (item or {}).get("url", "")
            if url:
                collected.append({
                    "kind": "source-map", "title": "Source map publicly served",
                    "severity": "low", "target": url, "method": "GET",
                    "param": "", "payload": "",
                    "evidence": "sourceMappingURL resolved to a readable map",
                    "verification": "CONFIRMED", "confidence": 0.9,
                })

        return collected

    def _apply_verification(self, findings):
        """Independent decisions also govern entries outside graph-supported families."""
        verification = self.results.get("verification") or {}
        families = {
            "exposed_files": {"sensitive-file", "backup-file", "admin-panel"},
            "redirects": {"open-redirect"}, "reflection": {"xss"},
            "sqli": {"sqli"}, "secrets": {"secret-leak"},
        }
        for family, kinds in families.items():
            for suffix, verdict in (("verified", "CONFIRMED"), ("still_live", "CONFIRMED"),
                                    ("inconclusive", "INCONCLUSIVE"), ("refuted", "FALSE_POSITIVE")):
                for decision in verification.get(f"{family}_{suffix}") or []:
                    url = self._absolute(decision.get("url") or decision.get("source") or decision.get("target"))
                    param = decision.get("param") or decision.get("parameter") or ""
                    for finding in findings:
                        if finding.get("kind") not in kinds or self._absolute(finding.get("target")) != url:
                            continue
                        if family not in {"exposed_files", "secrets"} and (finding.get("param") or "") != param:
                            continue
                        finding["verification"] = verdict
                        finding["confidence"] = finding_model.Verification(verdict).confidence
                        finding["verification_reason"] = decision.get("why") or decision.get("verification_reason") or "independent verification"
        return findings

    def _publish_findings(self):
        """Score, de-duplicate and identify every finding exactly once.

        The correlation graph only scores the families it models, so every
        entry is scored here instead: a finding without a CVSS vector is not
        actionable and cannot be prioritised against the rest.
        """
        findings = self._apply_verification(self._collect_findings())
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                         "info": 0, "none": 0}
        for finding in findings:
            finding["target"] = self._absolute(finding.get("target"))
            scored = scoring_model.enrich(dict(finding),
                                          self._exposure_of(finding))
            finding.update(scored)
            finding["cvss_score"] = scored["cvss_score"]
            finding["cvss_vector"] = scored["cvss_vector"]
            finding["cvss_rating"] = scored["cvss_rating"]
            finding["band"] = scored["band"]
            
            
            
            rating = str(scored["cvss_rating"]).lower()
            stated = str(finding.get("severity") or "info").lower()
            if severity_rank.get(rating, 0) > severity_rank.get(stated, 0):
                finding["severity"] = rating

        
        
        findings = finding_model.enrich(findings)
        from core.lifecycle import LifecycleRegistry
        registry = LifecycleRegistry()
        registry.annotate(findings)
        self.results["lifecycle"] = registry.as_dict()
        self.results["finding_states"] = finding_model.count_by_state(findings)
        
        
        reportable = finding_model.reportable(findings)
        self.results["findings"] = reportable
        self.results["finding_count"] = len(reportable)
        self.results["scored"] = scoring_model.summarize(reportable)
        self._publish_ui()
        return reportable

    

    def _mark_unrun_stages(self, reason):
        """Retain the difference between an attempted check and work never started."""
        for stage in STAGES:
            if stage.number in (27, 28):  
                continue
            if any(key.startswith(pattern) if pattern.endswith("/") else key == pattern
                   for key in self.health.states for pattern in stage.modules):
                continue
            self.health.skip(stage.modules[0], "not run: " + reason)
        if self.store is None:
            self.health.skip("Evidence", "scan storage disabled")

    def _finalize_without_network(self):
        """Process collected evidence after an explicit cap, without new probes."""
        for module, enabled, finish in (
            ("Leak Scan", self._want("leaks"), self.stage_leaks),
            ("Correlation", True, self.stage_correlate),
            ("Impact", True, self.stage_impact),
            ("Remediation", True, self.stage_remediation),
        ):
            if enabled and self.health.states.get(module) not in ("OK", "FAILED"):
                finish()

    def run(self):
        from core.runtime import Cancelled, BudgetExceeded
        try:
            return self._run()
        except (Cancelled, BudgetExceeded) as exc:
            self.results["interrupted"] = True
            self.results["stop_reason"] = str(exc)
            self.health.inconclusive("Pipeline", str(exc))
            if isinstance(exc, BudgetExceeded):
                try:
                    self._finalize_without_network()
                except Cancelled as cancelled:
                    self.results["stop_reason"] = str(cancelled)
                    self.health.inconclusive("Pipeline", str(cancelled))
            self._mark_unrun_stages(self.results["stop_reason"])
            self._publish_findings()
            return self.results
        finally:
            self.results["runtime"] = self.control.report()
            self.results["module_health"] = dict(self.health.states)
            self.results["module_notes"] = dict(self.health.notes)
            self.results["module_timings"] = dict(self.health.timings)
            self._persist_run()
            self.results["module_health"] = dict(self.health.states)
            self.results["module_notes"] = dict(self.health.notes)
            self._publish_runtime_context()
            self._publish_ui()
            self.probe_workers.close()
            RateLimitedSession.close_all()

    def cancel(self):
        self.control.cancel()

    def checkpoint(self):
        self._publish_findings()
        self._persist_run()

    def _run(self):
        start_ticks = time.time()
        if self.profile_error:
            raise ProfileError(self.profile_error)
        if self.profile_resolution is not None:
            self.results["profiles"] = self.profile_resolution.report()

        self._apply_profile_gates()
        self._apply_resume()

        self.stage_basics()
        if self._want("intel"):
            self.stage_easy_discovery()
        else:
            self.health.skip("Easy Discovery", "disabled by the selected profile")
            self.results["intel"] = {}
        if self._want("crawl"):
            self.stage_crawl()
        else:
            self.health.skip("Crawler", "disabled by the selected profile")
            self.crawl_results = {"pages_crawled": 0, "internal_links": [], "js_files": [],
                                  "forms": [], "params": [],
                                  "inline_script_sources": [], "spa_routes": []}
            self.results["crawl"] = self.crawl_results
        if self._want("discovery"):
            self.discovery_loop()
        else:
            self.health.skip("JS Analysis", "discovery expansion disabled by module selection or profile")
        if self._want("spa") and "SPA" not in self.health.states:
            self._assess_spa()
        elif not self._want("spa"):
            self.health.skip("SPA", "disabled by module selection")
        if self._want("extraction"):
            self.stage_extraction()
        else:
            self.health.skip("Extraction", "disabled by the selected profile")
        if self._want("leaks"):
            self.stage_leaks()
        else:
            self.health.skip("Leak Scan", "disabled by the selected profile")
        if self._want("headers"):
            self.stage_headers()
        else:
            self.health.skip("Headers", "disabled by the selected profile")
            self.results["headers"] = {"score": 0.0, "headers": {}, "cookies": []}
        self.stage_injection()
        if self._want("vulns"):
            self.stage_vulns()
        else:
            self.health.skip("Vuln Audit", "disabled by the selected profile")
            self.results["vulns"] = {"skipped": True, "reason": "profile"}
        if self._want("access"):
            self.stage_access()
        else:
            self.health.skip("Access Control", "disabled by selected profile")
            self.results["access"] = {"skipped": True, "reason": "profile"}
        if self._want("api"):
            self.stage_api()
        else:
            self.health.skip("API", "disabled by the selected profile")
        if self._want("auth"):
            self.stage_auth()
        else:
            self.health.skip("Auth/Token", "disabled by the selected profile")
        if self._want("protocol"):
            self.stage_protocol()
        else:
            self.health.skip("Protocol", "disabled by the selected profile")
        self.stage_verify()
        if self._want("extended"):
            self.stage_extended()
        else:
            self.health.skip("Extended", "disabled by profile")
        self.stage_oob()
        if self._want("plugins") and getattr(self.args, "enable_plugin", None):
            self._timed("Plugins", self.stage_plugins, ok=True)
        else:
            self.health.skip("Plugins", "no plugins enabled")
        self.stage_correlate()
        self.stage_impact()
        self.stage_remediation()
        self._publish_findings()
        self._stage(27, "Lifecycle & Evidence Persistence")
        if self.store is None:
            self.health.skip("Evidence", "scan storage disabled")
        self._persist_run()

        self._publish_runtime_context()
        self.results["pool_stats"] = self._pool_report()
        self.results["module_health"] = self.health.states
        self.results["module_notes"] = self.health.notes
        self.results["module_timings"] = {k: round(v, 2) for k, v in self.health.timings.items()}
        if self._last_traceback:
            self.results["module_traceback"] = self._last_traceback
        self.results["bruteforced_paths"] = self.bruteforced_dirs[:800]
        self.results["elapsed_seconds"] = round(time.time() - start_ticks, 2)
        return self.results


def json_dumps(obj):
    import json
    try:
        return json.dumps(obj)
    except Exception:
        return str(obj)
