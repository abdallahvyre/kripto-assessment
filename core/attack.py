import re
import threading
from urllib.parse import parse_qs, parse_qsl, urlparse, urlunparse, urlencode

from config import PARAM_PROBE_DELTA, TIMEOUT


_TRACKING = re.compile(r"^(utm_|ga_|gclid|fbclid|_ga|_gid|msclkid|mc_|ref$|referrer$)", re.I)


def path_of(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.path or "/").lower()


class AttackSurface:
    """One registry every discovery module writes to and every testing module reads from.

    The old pipeline handed the crawler a params list and threw away everything
    found afterwards: a parameter mined out of a JS bundle, a route read from an
    OpenAPI spec or a name confirmed live by differential probing all ended up
    invisible to the injection modules. Everything now lands here instead.
    """

    def __init__(self, console=None, budget: int = 1200, probe_names=None, policy=None):
        self.console = console
        self.budget = budget
        self.probe_names = list(probe_names or [])
        self.policy = policy
        self._lock = threading.Lock()

        self._params = {}
        self._endpoints = {}
        self._forms = []
        self._sources = {}
        self._warned_injection_limits = set()
        self._injection_requests = {}

        
        
        
        self.spent = 0
        self.injection_dropped = 0
        self.probe_budget_used = 0
        self.probe_confirmed = 0
        self.out_of_scope_rejected = 0

    def _allowed(self, url: str) -> bool:
        if not url or self.policy is None:
            return bool(url)
        decision = self.policy.evaluate(url)
        if decision.allowed:
            return True
        with self._lock:
            self.out_of_scope_rejected += 1
        self.policy.record_block(url, decision.reason, source="attack-surface")
        return False

    

    @staticmethod
    def _param_identity(url: str, param: str):
        """Identify a parameter without discarding request-shaping query context.

        The value of the parameter under test is excluded because injection
        modules replace it. Other query pairs remain part of the identity, so
        tenant/locale/version contexts cannot collapse into one target.
        """
        parsed = urlparse(url)
        context = sorted(
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key != param
        )
        return parsed.netloc.lower(), parsed.path or "/", param, tuple(context)

    @staticmethod
    def _stored_param_url(parsed):
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "",
                           parsed.query, ""))

    def add_param(self, url: str, param: str, source: str):
        if not param or _TRACKING.match(param) or not self._allowed(url):
            return False
        parsed = urlparse(url)
        key = self._param_identity(url, param)
        with self._lock:
            if key in self._params:
                if source == "probe" and not self._params[key]["confirmed"]:
                    self._params[key]["confirmed"] = True
                    self.probe_confirmed += 1
                return False
            confirmed = source == "probe"
            self._params[key] = {
                "url": self._stored_param_url(parsed),
                "param": param,
                "source": source,
                "confirmed": confirmed,
            }
            if confirmed:
                self.probe_confirmed += 1
            self._sources.setdefault(source, 0)
            self._sources[source] += 1
        return True

    def add_params_from_url(self, url: str, source: str):
        parsed = urlparse(url)
        added = 0
        for param in parse_qs(parsed.query).keys():
            if self.add_param(url, param, source):
                added += 1
        return added

    def add_endpoint(self, url: str, source: str, methods=None, note=""):
        if not self._allowed(url):
            return False
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        path = parsed.path or "/"
        key = (parsed.netloc, path, parsed.query)
        with self._lock:
            entry = self._endpoints.get(key)
            if entry:
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                if methods:
                    entry["methods"] = sorted(set(entry["methods"]) | set(methods))
                return False
            self._endpoints[key] = {
                "url": f"{parsed.scheme}://{parsed.netloc}{path}"
                       + (f"?{parsed.query}" if parsed.query else ""),
                "path": path,
                "host": parsed.netloc,
                "sources": [source],
                "methods": list(methods or []),
                "note": note,
            }
            self._sources.setdefault(source, 0)
            self._sources[source] += 1
        return True

    def add_form(self, form: dict):
        if not self._allowed(form.get("action", "")):
            return False
        signature = (form.get("action", ""), form.get("method", "GET"),
                     tuple(sorted(i.get("name", "") for i in form.get("inputs", []))))
        with self._lock:
            if any(f.get("_signature") == signature for f in self._forms):
                return False
            form = dict(form)
            form["_signature"] = signature
            self._forms.append(form)
        for inp in form.get("inputs", []):
            self.add_param(form.get("action", ""), inp.get("name", ""), "form")
        return True

    def mark_confirmed(self, url: str, param: str):
        key = self._param_identity(url, param)
        with self._lock:
            entry = self._params.get(key)
            if entry:
                if not entry["confirmed"]:
                    entry["confirmed"] = True
                    self.probe_confirmed += 1

    def record_injection(self, kind: str, count: int = 1):
        """Record requests actually attempted by an injection family."""
        amount = max(0, int(count))
        with self._lock:
            self.spent += amount
            label = str(kind or "unknown")
            self._injection_requests[label] = self._injection_requests.get(label, 0) + amount
            return self.spent

    def record_probe(self, count: int = 1, limit=None):
        """Atomically reserve probe attempts, including failed HTTP attempts.

        Returns ``False`` without incrementing when the requested reservation
        would exceed ``limit``. Callers should reserve before sending work.
        """
        amount = max(0, int(count))
        with self._lock:
            if limit is not None and self.probe_budget_used + amount > max(0, int(limit)):
                return False
            self.probe_budget_used += amount
            return True

    

    def params(self):
        with self._lock:
            return sorted(self._params.values(), key=lambda p: (not p["confirmed"], p["source"], p["param"]))

    def endpoints(self):
        with self._lock:
            return sorted(self._endpoints.values(), key=lambda e: (-len(e["sources"]), e["path"]))

    def forms(self):
        with self._lock:
            return list(self._forms)

    def confirmed_params(self):
        return [p for p in self.params() if p["confirmed"]]

    def injection_targets(self, limit=None):
        """Injection modules read this instead of the crawler's params list."""
        limit = limit if limit is not None else self.budget
        targets = self.params()
        if len(targets) > limit:
            dropped = len(targets) - limit
            with self._lock:
                self.injection_dropped = max(self.injection_dropped, dropped)
                warning_key = (int(limit), len(targets))
                should_warn = warning_key not in self._warned_injection_limits
                self._warned_injection_limits.add(warning_key)
            if self.console and should_warn:
                from core.banner import warning
                warning(
                    self.console,
                    f"Injection budget of {limit} parameters exceeded - {dropped} lower-priority "
                    "parameters were not tested. Raise --budget or --deep for full coverage.",
                )
            targets = targets[:limit]
        return targets

    

    def probe_params(self, session, base_urls, names=None, delta=PARAM_PROBE_DELTA):
        """Differential probing: does this parameter name change what the server returns?

        This is the mechanism that gives the tool something to inject into on
        single-page apps, where no HTML link, form or sitemap entry ever exposes
        the query string that the JavaScript actually uses.
        """
        candidates = [n for n in (names or self.probe_names) if n]
        if not candidates or not base_urls:
            return []

        live = []
        probe_limit = self.budget * 2
        for base in base_urls[:40]:
            baseline = self._safe_get(session, base)
            if baseline is None:
                continue

            for name in candidates:
                if not self.record_probe(limit=probe_limit):
                    return live
                test_url = self._with_param(base, name, "1")
                resp = self._safe_get(session, test_url)
                if resp is None:
                    continue

                if resp.status_code != baseline.status_code:
                    continue
                if abs(len(resp.content) - len(baseline.content)) < delta:
                    continue

                live.append({"url": base, "param": name, "size_delta": len(resp.content) - len(baseline.content)})
                if self.add_param(base, name, "probe"):
                    self.mark_confirmed(base, name)

        return live

    @staticmethod
    def _with_param(base: str, name: str, value: str) -> str:
        parsed = urlparse(base)
        params = parse_qs(parsed.query)
        params[name] = [value]
        query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

    @staticmethod
    def _safe_get(session, url):
        try:
            return session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return None

    

    def stats(self):
        with self._lock:
            by_source = dict(sorted(self._sources.items(), key=lambda kv: -kv[1]))
            return {
                "endpoints": len(self._endpoints),
                "params": len(self._params),
                "confirmed_params": self.probe_confirmed,
                "forms": len(self._forms),
                "probe_requests": self.probe_budget_used,
                "injection_requests": self.spent,
                "injection_requests_by_kind": dict(self._injection_requests),
                "injection_targets_dropped": self.injection_dropped,
                "uncovered_params": max(0, len(self._params) - self.budget),
                "by_source": by_source,
                "budget": self.budget,
                "out_of_scope_rejected": self.out_of_scope_rejected,
            }
