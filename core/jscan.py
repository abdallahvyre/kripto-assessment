import json
import hashlib
import fnmatch
import os
import re
from urllib.parse import urljoin, urlparse

from config import (
    LIB_VERSION_SIGNATURES,
    SOURCE_MAP_HINTS,
    STAGE_LIMITS,
    TIMEOUT,
)
from core.banner import found, info, success, vuln, warning
from core.jparse import JSModule

_JS_BUNDLE = re.compile(r"\.js(?:\?|$)|\.mjs(?:\?|$)", re.I)

_QUOTED = re.compile(r"""["']((?:/|\./|\.\./)[^"'\\\s]{1,140})["']""")
_TEMPLATE = re.compile(r"""`([^`$\\]{2,140})`""")
_CONCAT_PATH = re.compile(r"""["'](/[a-z0-9][^"'\\\s]{0,120})["']\s*\+\s*[A-Za-z_$][\w$]*""", re.I)

_FETCH_CALL = re.compile(
    r"""(?:fetch|axios|axios\.\w+|request|superagent|ky|got)\s*[(.]\s*["'`]([^"'`]{2,200})["'`]""",
    re.I,
)
_AJAX = re.compile(r"""\$\s*\.\s*(?:get|post|ajax|getJSON)\s*\(\s*["'`]([^"'`]{2,200})["'`]""", re.I)
_URL_KEY = re.compile(
    r"""(?:url|endpoint|apiUrl|api_url|baseURL|baseUrl|apiBase|API_URL|BASE_URL|"
        r""PATH|path|route|href|action|src|uri|link)\s*[:=]\s*["'`]([^"'`]{2,200})["'`]""",
    re.I | re.X,
)
_ENV_URL = re.compile(r"""process\.env(?:\.|\[["'])([A-Z0-9_]{3,40})""")

_IMPORT_REL = re.compile(
    r"""(?:import\s*\(\s*|require\s*\(\s*|from\s*)["']([^"']+\.(?:m?js|css))(?:\?[^"']*)?["']""",
)
_CHUNK_URL = re.compile(
    r'["\'`]\s*(\+?[A-Za-z_$][\w$.]*\s*\+\s*)?["\'`]'
    r'([A-Za-z0-9._\-/]*?)([0-9a-f]{6,}|\d{1,4})(\.[a-z0-9]{2,5})["\'`]',
    re.I,
)
_PUBLIC_PATH = re.compile(r"""[_\w$]+\.p\s*=\s*["']([^"']+)["']""")
_SOURCEMAP = re.compile(r"""sourceMappingURL=([^\s'"*]+)""")
_NEXT_DATA = re.compile(r"""<script[^>]+id=["']__NEXT_DATA__["'][^>]*>(.*?)</script>""", re.S)

_PATH_PARAM = re.compile(r"""\{([A-Za-z_$][\w$]{0,40})\}|:([A-Za-z_$][\w$]{1,40})(?=[/?"'\s])|\[([A-Za-z_$][\w$]{1,40})\]""")
_QUERY_IN_PATH = re.compile(r"""["']([^"']{2,200}?\?[A-Za-z_][\w]*=[^"'&\s]{0,40}[^"']{0,120})["']""")
_OBJ_BLOCK = re.compile(r"""\b(?:params|query|queryParams|searchParams|data|body|payload|form)\s*:\s*\{([^{}]{1,600})\}""")
_OBJ_KEY = re.compile(r"""([A-Za-z_$][\w$]{0,40})\s*[:=,}]""")
_PATH_TOKEN = re.compile(r"""["'`]\s*/[a-zA-Z0-9_.\-/{]""")




_ROUTE_PLACEHOLDER = re.compile(r"\{[A-Za-z_$][\w$]{0,40}\}|:[A-Za-z_$][\w$]{1,40}")
_BAD_PATH_CHARS = set('"\'`+()[]<>$,;|&=!\\')
_JS_MEMBER = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")
_MINUS_NUMBER = re.compile(r"^-\d")
_URLSEARCH = re.compile(r"""URLSearchParams\(\s*["']([^"']{2,300})["']""")
_CONFIG_OBJ = re.compile(r"""(?:window\.|globalThis\.)?(__[A-Z][A-Z0-9_]{2,30}__|__[A-Z][A-Z0-9_]*CONFIG[A-Z0-9_]*)\s*=\s*(\{.{0,4000}?\})""", re.S)

_INLINE_SECRET = re.compile(
    r"""["']([A-Za-z0-9_\-]{6,})["']\s*[,}]?\s*(?:$|[,;])"""
)

_ASSET_TAIL = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".map", ".json")


class _Stop(Exception):
    pass


class JSBundleScanner:
    """Walks the JavaScript graph of a site: bundles, their imports, their chunks
    and their source maps, then reports every endpoint, parameter name and secret
    those files contain.

    A source map is the highest-value artifact in this whole tool. When one is
    published the original TypeScript/JSX comes back with comments intact, which
    routinely exposes internal hostnames, disabled routes and hardcoded keys that
    the minified production bundle has already erased.
    """

    def __init__(self, target: str, console, surface, profile: str = "default",
                 scope=None):
        self.target = target
        parsed = urlparse(target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = parsed.hostname
        self.console = console
        self.surface = surface
        self.scope = scope

        limits = dict(STAGE_LIMITS["default"])
        limits.update(STAGE_LIMITS.get(profile, {}))
        self.max_bundles = limits["js_bundles"]
        self.max_bytes = limits["js_bytes"]
        self.max_inline = limits["inline_scripts"]

        from core.http import RateLimitedSession
        self.session = RateLimitedSession()

        self.queued = set()
        self.analyzed = []
        self._done = set()
        self._inline_seen = 0
        self._inline_done = set()
        self._inline_cap_reached = False
        self._bundle_cap_reached = False
        self.truncated = []
        self.sourcemaps = []
        self.routes = set()
        self.api_endpoints = set()
        self.chunk_files = []
        self.env_vars = set()
        self.config_objects = {}
        self.original_sources = []
        self.vendor_sources = 0
        self.versions = []
        self.sinks = []
        self.secret_like = []
        self.user_sources = set()
        self.inferred_routes = set()
        self.http_calls = {}
        self.tokens_parsed = 0
        self.max_parse_bytes = 2_000_000
        self.blobs = []
        self._blob_bytes = 0
        self.bytes_read = 0
        self._version_scanned = False
        self.analysis_limits = []

    

    def _internal(self, url: str) -> bool:
        host = urlparse(url).hostname
        if host is None:
            return True
        policy = getattr(self.surface, "policy", None)
        if policy is not None:
            try:
                return bool(policy.evaluate(url).allowed)
            except Exception:
                return False
        host = host.lower().rstrip(".")
        if host == (self.domain or "").lower().rstrip("."):
            return True
        raw_scope = self.scope or []
        patterns = raw_scope.split(",") if isinstance(raw_scope, str) else list(raw_scope)
        for raw in patterns:
            pattern = str(raw).strip().lower().rstrip(".")
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if host.endswith(suffix) and host != suffix[1:]:
                    return True
            elif pattern and fnmatch.fnmatchcase(host, pattern):
                return True
        return False

    def _get_text(self, url: str, budget: int):
        if not self._internal(url):
            return None
        if self._blob_bytes >= self.max_bytes:
            return None
        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return None
        if resp.status_code >= 400:
            return None
        body = resp.content
        if len(body) > budget:
            body = body[:budget]
            self.truncated.append(url)
        self.bytes_read += len(body)
        return resp.text[:len(body)] if isinstance(body, bytes) else str(body)

    

    _ASSET_TAIL = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".map", ".json")

    @staticmethod
    def _looks_like_path(value: str) -> bool:
        if not value or len(value) < 2 or len(value) > 160:
            return False
        if value.startswith(("http://", "https://", "//", "data:", "javascript:",
                             "mailto:", "tel:", "#")):
            return False
        if " " in value or "\n" in value or "\t" in value:
            return False
        if value.startswith(("./", "../", "~")):
            return False

        probe = _ROUTE_PLACEHOLDER.sub("x", value)
        path_part, _, query = probe.partition("?")
        if any(ch in _BAD_PATH_CHARS for ch in path_part):
            return False
        if ".." in path_part or "%" in path_part[:2]:
            return False
        if path_part.count("/") > 8:
            return False
        if re.search(r"[\x00\x01]", probe):
            return False
        if query and not re.fullmatch(r"[A-Za-z0-9_\-.&=%+:,$]*", query):
            return False

        tail = path_part.rstrip("/").rsplit("/", 1)[-1]
        if tail.endswith(_ASSET_TAIL):
            return False
        if tail.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
                          ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".css")):
            return False
        if not tail:
            return False

        segments = [s for s in path_part.split("/") if s]
        if not segments:
            return False
        if ":" in segments[0]:
            return False
        if re.search(r"[a-z]{2,10}://", path_part):
            return False
        for segment in segments:
            if segment in (".", ".."):
                return False
            if not re.search(r"[A-Za-z0-9]", segment):
                return False
            if _JS_MEMBER.match(segment):
                return False
            if _MINUS_NUMBER.match(segment):
                return False
        return True

    def _resolve(self, base_url: str, value: str):
        if value.startswith("http"):
            return value
        if value.startswith("//"):
            return f"{urlparse(self.target).scheme}:{value}"
        try:
            return urljoin(base_url, value)
        except Exception:
            return None

    

    def _harvest_paths(self, origin: str, code: str):
        """Mine a script for endpoints, parameters, config objects and sinks.

        Large bundles fall back to the pattern scanner: tokenizing a multi-megabyte
        vendor file costs seconds and yields nothing the pattern pass misses.
        """
        candidates = set()
        self.blobs.append((origin, code))
        self._blob_bytes += len(code)

        if len(code) <= self.max_parse_bytes:
            try:
                parsed = JSModule(code, origin, origin).analyze()
            except Exception:
                parsed = None

            if parsed is not None:
                self.analysis_limits.extend(parsed.get("limitations") or [])
                self.tokens_parsed += 1
                for route in parsed["routes"]:
                    cleaned = self._strip_placeholders(route["path"])
                    if not self._looks_like_path(cleaned):
                        continue
                    self.api_endpoints.add(cleaned)
                    self.surface.add_endpoint(f"{self.base}{cleaned}", "js-bundle",
                                              note=route["callee"])
                    for param in route["params"]:
                        if param and len(param) <= 40:
                            self.surface.add_param(f"{self.base}{cleaned}", param,
                                                   "js-bundle")
                    if route.get("inferred"):
                        self.inferred_routes.add(cleaned)
                    if route["callee"]:
                        self.http_calls[route["callee"]] =\
                            self.http_calls.get(route["callee"], 0) + 1

                for name, data in parsed["env_objects"].items():
                    if name not in self.config_objects:
                        self.config_objects[name] = data["raw"][:2000]
                    for key in data["keys"]:
                        self.env_vars.add(key)

                for sink in parsed["sinks"]:
                    self.sinks.append(dict(sink, file=origin))
                for value in parsed["secret_like"]:
                    self.secret_like.append({"value": value, "file": origin})
                self.user_sources.update(parsed["user_sources"])

                if parsed["routes"]:
                    return

        for pattern in (_FETCH_CALL, _AJAX, _URL_KEY, _QUERY_IN_PATH):
            for match in pattern.findall(code):
                candidates.add(match if isinstance(match, str) else match[-1])
        for match in _QUOTED.findall(code):
            candidates.add(match)
        for match in _TEMPLATE.findall(code):
            candidates.add(match)
        for match in _CONCAT_PATH.findall(code):
            candidates.add(match)

        for env in _ENV_URL.findall(code):
            self.env_vars.add(env)

        for raw in candidates:
            raw = raw.strip().rstrip("\\")
            if not raw or raw in ("/", "//"):
                continue
            self._register_path(raw, code, origin)

    @staticmethod
    def _strip_placeholders(text: str) -> str:
        return re.sub(r"[\x00\x01]\s*\+\s*", "", text).strip("\x00\x01+ ")

    def _register_path(self, raw: str, code: str, origin: str):
        path = raw.split("#")[0]
        if not path.startswith("/"):
            path = "/" + path
        if not self._looks_like_path(path):
            return

        normalized = self._normalize_route(path)
        if not normalized:
            return

        self.api_endpoints.add(normalized)
        self.surface.add_endpoint(
            f"{self.base}{normalized}", "js-bundle", note=origin,
        )
        for param in self._params_from_path(code, raw):
            self.surface.add_param(f"{self.base}{normalized}", param, "js-bundle")

    @staticmethod
    def _normalize_route(path: str):
        if not path.startswith("/"):
            return ""
        if path.count("/") > 8:
            return ""
        return path

    @staticmethod
    def _params_from_path(code: str, raw: str):
        """Parameters that belong to THIS path.

        Searching the whole file for `params: {...}` would attach every request's
        parameter names to every path in the bundle, so the object literal is
        only read from a window around the call site that mentions the path.
        """
        found = set()
        for a, b, c in _PATH_PARAM.findall(raw):
            found.add(a or b or c)

        for match in _QUERY_IN_PATH.findall(raw):
            for chunk in match.split("?", 1)[-1].split("&"):
                if "=" in chunk:
                    found.add(chunk.split("=", 1)[0])

        for query in _URLSEARCH.findall(raw):
            for chunk in query.split("&"):
                if "=" in chunk:
                    found.add(chunk.split("=", 1)[0])

        bare = raw.split("?")[0].rstrip("/")
        anchor = code.find(bare) if len(bare) > 3 else -1
        if anchor == -1:
            anchor = code.find(raw.split("/")[-1]) if len(raw.split("/")[-1]) > 3 else -1

        if anchor == -1:
            return {p for p in found if p}

        start = max(0, anchor - 60)
        window = code[start: anchor + 320]
        path_pos = anchor - start

        next_path = _PATH_TOKEN.search(window, path_pos + len(bare))
        if next_path:
            window = window[: next_path.start()]

        blocks = [m.group(1) for m in _OBJ_BLOCK.finditer(window)
                  if m.start() >= path_pos - 5]
        if not blocks:
            all_blocks = [m.group(1) for m in _OBJ_BLOCK.finditer(code)]
            if len(all_blocks) == 1:
                blocks = all_blocks

        for block in blocks:
            for key in _OBJ_KEY.findall(block):
                if 1 <= len(key) <= 40 and not key.isdigit():
                    found.add(key)

        return {p for p in found if p and "$" not in p}

    def _harvest_config(self, origin: str, code: str):
        for name, body in _CONFIG_OBJ.findall(code):
            if name not in self.config_objects:
                self.config_objects[name] = body[:2000]
            for raw in _URL_KEY.findall(body):
                self._register_path(raw.strip(), body, origin)
        for chunk in _CHUNK_URL.findall(code):
            combined = f"{chunk[1] or ''}{chunk[2]}{chunk[3]}"
            if "/" in combined or combined.endswith((".js", ".mjs")):
                self.chunk_files.append(combined.strip("/"))
        public = _PUBLIC_PATH.search(code)
        if public:
            self.chunk_files.append(public.group(1).strip("/"))

    def _harvest_versions(self, code: str):
        if self._version_scanned:
            return
        for lib, pattern in LIB_VERSION_SIGNATURES:
            match = re.search(pattern, code)
            if match:
                self.versions.append({"library": lib, "version": match.group(1)})
                self._version_scanned = True
                return

    

    def _process_sourcemap(self, map_url: str, code: str):
        refs = _SOURCEMAP.findall(code)
        candidates = []
        for ref in refs:
            ref = ref.strip().strip("*/ ")
            resolved = self._resolve(map_url, ref)
            if resolved:
                candidates.append(resolved)
        return candidates

    def _probe_bare_sourcemap(self, js_url: str):
        return self._resolve(js_url, js_url.rsplit("/", 1)[-1] + ".map")

    def _analyze_sourcemap(self, map_url: str):
        raw = self._get_text(map_url, self.max_bytes)
        if not raw or not raw.lstrip().startswith("{"):
            return 0
        try:
            doc = json.loads(raw)
        except Exception:
            head = raw.lstrip()[:1]
            if head == "x":
                try:
                    import base64
                    doc = json.loads(base64.b64decode(raw).decode("utf-8", "ignore"))
                except Exception:
                    return 0
            else:
                return 0

        sources = doc.get("sources", []) or []
        contents = doc.get("sourcesContent", []) or []
        root = doc.get("sourceRoot", "") or ""
        self.sourcemaps.append({
            "map_url": map_url,
            "sources": len(sources),
            "with_content": len(contents),
        })

        for i, source in enumerate(sources[:400]):
            full = f"{root}/{source}" if root and not source.startswith("/") else source
            if self._is_vendor_source(full):
                self.vendor_sources += 1
                continue
            if "://" in full and not self._internal(full):
                continue

            self.original_sources.append(full)

            if i < len(contents) and contents[i]:
                self._harvest_paths(map_url, contents[i])
                self._harvest_config(map_url, contents[i])

        return len(contents)

    @staticmethod
    def _is_vendor_source(name: str) -> bool:
        """Bundled third-party code must not be mined for endpoints.

        A vendor bundle such as swagger-ui ships source maps containing all of
        React, babel-runtime and fbjs. Harvesting those produces hundreds of
        endpoints and parameters that belong to a library, not to the target.
        """
        lowered = name.lower()
        if "/~/" in lowered or "/node_modules/" in lowered:
            return True
        if "/bower_components/" in lowered or "/vendor/" in lowered:
            return True
        if "universalmoduledefinition" in lowered or lowered.startswith("webpack/bootstrap"):
            return True
        if "webpack://" in lowered and "webpack:///./" not in lowered:
            return True
        return False

    @staticmethod
    def _looks_like_internal_source(name: str) -> bool:
        """webpack:///./src/... paths are exactly the leak we want to report.
        Only vendored dependencies are filtered out as uninteresting."""
        lowered = name.lower()
        if not lowered:
            return False
        return not lowered.startswith(("http://", "https://")) and\
            "/node_modules/" not in lowered and not lowered.startswith("node_modules/")

    @staticmethod
    def _looks_like_internal_source(name: str) -> bool:
        lowered = name.lower()
        if not lowered:
            return False
        return not lowered.startswith(("http://", "https://")) and\
            "/node_modules/" not in lowered and not lowered.startswith("node_modules/")

    

    def _queue_bundle(self, url: str):
        if not url or not _JS_BUNDLE.search(url):
            return False
        if not self._internal(url):
            return False
        if url in self.queued or url in self._done:
            return False
        if len(self.analyzed) >= self.max_bundles:
            self._bundle_cap_reached = True
            return False
        if len(self.queued) >= self.max_bundles * 3:
            self._bundle_cap_reached = True
            return False
        self.queued.add(url)
        return True

    def _next_batch(self, limit=12):
        batch = []
        while self.queued and len(batch) < max(0, int(limit)):
            batch.append(self.queued.pop())
        return batch

    def _analyze_bundle(self, js_url: str, budget: int):
        if len(self.analyzed) >= self.max_bundles:
            self._bundle_cap_reached = True
            return False
        code = self._get_text(js_url, budget)
        if not code:
            return False

        self.analyzed.append(js_url)
        self._done.add(js_url)
        self._harvest_versions(code)
        self._harvest_paths(js_url, code)
        self._harvest_config(js_url, code)

        for ref in self._process_sourcemap(js_url, code):
            if self._analyze_sourcemap(ref):
                self._done.add(ref)
                success(self.console, f"Source map recovered with original sources: {ref}")

        if not _SOURCEMAP.search(code):
            bare = self._probe_bare_sourcemap(js_url)
            if self._analyze_sourcemap(bare):
                self._done.add(bare)

        for rel in _IMPORT_REL.findall(code):
            resolved = self._resolve(js_url, rel)
            if resolved:
                self._queue_bundle(resolved)
        return True

    def analyze(self, js_urls=None, inline_scripts=None, page_sources=None):
        new_bundles = 0
        for url in (js_urls or []):
            if self._queue_bundle(url):
                new_bundles += 1

        info(self.console, f"Deep JS analysis (budget: {self.max_bundles} bundles / "
                           f"{self.max_bytes // 1_000_000}MB) - "
                           f"{new_bundles} new bundle(s) queued")

        batches = 0
        while self.queued and len(self.analyzed) < self.max_bundles and batches < 40:
            batches += 1
            remaining = self.max_bundles - len(self.analyzed)
            for js_url in self._next_batch(min(12, remaining)):
                self._analyze_bundle(
                    js_url,
                    self.max_bytes // max(1, batches) + 200_000,
                )

        for chunk in list(dict.fromkeys(self.chunk_files))[:60]:
            for suffix in (".js", ""):
                resolved = self._resolve(self.base, f"{chunk}{suffix}")
                if resolved and _JS_BUNDLE.search(resolved):
                    self._queue_bundle(resolved)
                    break
        while self.queued and len(self.analyzed) < self.max_bundles:
            remaining = self.max_bundles - len(self.analyzed)
            for chunk in self._next_batch(min(12, remaining)):
                self._analyze_bundle(chunk, 400_000)
        if self.queued:
            self._bundle_cap_reached = True

        for code in (inline_scripts or []):
            if not code or not code.strip():
                continue
            signature = hashlib.sha256(code.encode("utf-8", "ignore")).hexdigest()
            if signature in self._inline_done:
                continue
            if self._inline_seen >= self.max_inline:
                self._inline_cap_reached = True
                break
            self._inline_done.add(signature)
            self._inline_seen += 1
            self._harvest_paths("inline:<script>", code)
            self._harvest_config("inline:<script>", code)

        for html in (page_sources or [])[:40]:
            for raw in _NEXT_DATA.findall(html):
                self._harvest_config("__NEXT_DATA__", raw)

        for route in sorted(self.routes | set()):
            self.surface.add_endpoint(f"{self.base}{route}", "js-route")

        found(self.console, f"JS bundles analyzed: {len(self.analyzed)}")
        found(self.console, f"Source maps recovered: {len(self.sourcemaps)} "
                            f"({sum(1 for s in self.sourcemaps if s['with_content'])} with original sources)")
        found(self.console, f"Endpoints mined from JS: {len(self.api_endpoints)}")
        if self.tokens_parsed:
            found(self.console, f"Bundles fully tokenized: {self.tokens_parsed}")
        reachable = [s for s in self.sinks if s.get("has_user_source")]
        if reachable:
            vuln(self.console, f"{len(reachable)} client-side sink(s) receive user-controlled "
                               "input (DOM XSS candidates):")
            for sink in reachable[:10]:
                vuln(self.console, f"  {sink['sink']} <- {', '.join(sink['sources'])}  "
                                   f"[{os.path.basename(sink['file'])}]")
        if self.secret_like:
            for item in self.secret_like[:10]:
                from core.redact import redact_secret
                vuln(self.console, f"Client-side credential literal: {redact_secret(item['value'])} "
                                   f"({os.path.basename(item['file'])})")
        if self.original_sources:
            found(self.console, f"Original source paths leaked: {len(self.original_sources)}")
            for path in self.original_sources[:8]:
                found(self.console, f"  source: {path}")
        if self.versions:
            for v in self.versions:
                found(self.console, f"Library fingerprint: {v['library']} {v['version']}")
        if self.env_vars:
            found(self.console, f"Client-side env vars: {', '.join(sorted(self.env_vars)[:10])}")
        if self.truncated:
            warning(self.console, f"{len(self.truncated)} bundle(s) were truncated at the byte cap - "
                                  "partial results. Raise --deep for full coverage.")

        return {
            "bundles_analyzed": self.analyzed,
            "bundle_count": len(self.analyzed),
            "bytes_read": self.bytes_read,
            "blobs": self.blobs,
            "sourcemaps": self.sourcemaps,
            "source_maps_with_content": sum(1 for s in self.sourcemaps if s["with_content"]),
            "original_sources": sorted(set(self.original_sources))[:500],
            "vendor_sources_skipped": self.vendor_sources,
            "routes": sorted(self.api_endpoints),
            "endpoints_count": len(self.api_endpoints),
            "chunk_files": sorted(set(self.chunk_files))[:200],
            "env_vars": sorted(self.env_vars),
            "config_objects": self.config_objects,
            "versions": self.versions,
            "sinks": self.sinks,
            "sinks_with_user_source": [s for s in self.sinks if s.get("has_user_source")],
            "secret_like": self.secret_like,
            "user_sources": sorted(self.user_sources),
            "http_calls": self.http_calls,
            "bundles_tokenized": self.tokens_parsed,
            "inferred_routes": sorted(self.inferred_routes)[:200],
            "truncated": self.truncated[:50],
            "analysis_limits": list(dict.fromkeys(self.analysis_limits)),
            "reached_bundle_cap": self._bundle_cap_reached or
                                  len(self.analyzed) >= self.max_bundles,
            "inline_count": self._inline_seen,
            "reached_inline_cap": self._inline_cap_reached or
                                  self._inline_seen >= self.max_inline,
        }
