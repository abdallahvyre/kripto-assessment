import fnmatch
import re
import warnings
from collections import deque
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

from config import STAGE_LIMITS, TIMEOUT
from core.banner import found, info, success, warning
from core.http import RateLimitedSession
from core.policy import _normalise_path

_SKIP_CTYPE = ("image/", "font/", "video/", "audio/")

_ROUTE_PATTERNS = [
    re.compile(r"""\bpath\s*[:=]\s*["'](/[^"'\\\s]{0,80})["']"""),
    re.compile(r"""\bto\s*[:=]\s*["'](/[^"'\\\s]{0,80})["']"""),
    re.compile(r"""\bhref\s*[:=]\s*["'](/[^"'\\\s]{0,80})["']"""),
    re.compile(r"""\b(?:navigate|redirect|push)\s*\(\s*["'](/[^"'\\\s]{0,80})["']"""),
    re.compile(r"""["'](/[a-z0-9][a-z0-9\-_/]{0,78})["']""", re.IGNORECASE),
]

_META_REFRESH = re.compile(r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']([^"']+)""", re.I)
_LINK_HREF = re.compile(r"""["']((?:https?:)?//[^"'\\\s<>]{4,200})["']""")
_ATTR_INTO = re.compile(r"""\b(?:location(?:\.href|\.replace\(|\.assign\()?\s*[=(]|window\.open\s*\()\s*["']([^"']{4,200})["']""", re.I)
_ROUTE_PLACEHOLDER = re.compile(r"\{[^{}]{1,40}\}|:[A-Za-z_$][\w$]{1,40}|@[A-Za-z_$][\w$]{1,40}|\[[^\[\]]{1,40}\]")


def concrete_route(path: str, value: str = "1") -> str:
    """Turn /users/{id} or /users/:id into a requestable URL."""
    if not path:
        return path
    return _ROUTE_PLACEHOLDER.sub(value, path)


def looks_like_route(path: str) -> bool:
    if not path.startswith("/") or len(path) < 2:
        return False
    if "?" in path or "#" in path:
        return False
    lowered = path.lower()
    if lowered.count("/") > 6 or " " in path or "\\" in path:
        return False
    if lowered.startswith(("//", "/_", "/node_modules/")):
        return False
    tail = lowered.rsplit("/", 1)[-1]
    if "." in tail:
        return False
    return True


class CrawlerModule:
    """Breadth-first crawler that runs in several passes.

    The first pass sees only what the homepage links to. Later passes are
    fed with whatever the previous stages turned up - bruteforced paths,
    routes mined from JavaScript, endpoints listed in an OpenAPI document -
    and the crawler keeps descending from there. That is what turns a
    one-page SPA into a real attack surface map.
    """

    def __init__(self, target: str, console, surface=None, max_depth=None,
                 max_pages=None, profile: str = "default", scope: str = None,
                 exclude: list = None):
        self.target = target
        self.console = console
        self.surface = surface
        self.scope = scope or urlparse(target).hostname
        self.exclude = exclude or []

        limits = dict(STAGE_LIMITS["default"])
        limits.update(STAGE_LIMITS.get(profile, {}))
        self.max_depth = max_depth if max_depth is not None else limits["crawl_depth"]
        self.max_pages = max_pages if max_pages is not None else limits["crawl_pages"]
        self.blob_budget = limits["js_bytes"]

        parsed = urlparse(target)
        self.domain = parsed.hostname
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.session = RateLimitedSession()

        self.visited = set()
        self.internal_links = set()
        self.external_links = set()
        self.forms = []
        self.params = set()
        self.js_files = set()
        self.css_files = set()
        self.image_files = set()
        self.inline_scripts = []
        self.hash_routes = set()
        self.emails_found = set()
        self.robots_info = {}
        self.sitemap_urls = set()
        self.spotted_routes = set()
        self.outbound_hosts = set()

        self.pages = 0
        self.blobs = []
        self.blob_bytes = 0
        self.truncated_crawl = False
        self.passes = 0

    def _is_internal(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.hostname is None:
            return True
        host = parsed.hostname
        if host == self.domain:
            return True
        scope = self.scope or self.domain
        if scope and scope.startswith("*."):
            suffix = scope[1:]
            if host.endswith(suffix):
                return True
        if scope and fnmatch.fnmatch(host, scope):
            return True
        return False

    def _normalize(self, url: str) -> str:
        parsed = urlparse(url)
        query = ("&".join(sorted(f"{k}={v[0]}" for k, v in parse_qs(parsed.query).items()))
                 if parsed.query else "")
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

    def _excluded(self, url: str) -> bool:
        candidate = _normalise_path(urlparse(url).path)
        for raw in self.exclude:
            value = str(raw).strip()
            if not value:
                continue
            if "://" in value:
                value = urlparse(value).path
            excluded = _normalise_path(value)
            if any(char in excluded for char in "*?["):
                if fnmatch.fnmatchcase(candidate, excluded):
                    return True
                continue
            prefix = excluded.rstrip("/") or "/"
            if candidate == prefix or candidate.startswith(prefix + "/"):
                return True
        return False

    def _fetch(self, url: str):
        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
            return resp.text, resp.status_code, resp.url, resp.headers.get("Content-Type", "")
        except Exception:
            return None, 0, url, ""

    def _keep_blob(self, label: str, text: str):
        if not text or self.blob_bytes >= self.blob_budget:
            return
        self.blob_bytes += len(text)
        self.blobs.append((label, text))

    def _record(self, url: str, source: str):
        if not self.surface:
            return
        self.surface.add_endpoint(url, source)
        self.surface.add_params_from_url(url, source)

    def parse_robots(self):
        try:
            resp = self.session.get(f"{self.base}/robots.txt", timeout=TIMEOUT)
        except Exception:
            return
        if resp.status_code != 200:
            return
        try:
            disallowed, sitemaps = [], []
            for line in resp.text.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                        self.internal_links.add(urljoin(self.base, path))
                elif low.startswith("sitemap:"):
                    sitemaps.append(line.split(":", 1)[1].strip())
            self.robots_info = {"disallowed": disallowed, "sitemaps": sitemaps}
            self._keep_blob("robots.txt", resp.text)
            info(self.console, f"robots.txt: {len(disallowed)} disallowed, {len(sitemaps)} sitemaps")
            for sm in sitemaps:
                self._parse_sitemap(sm)
        except Exception:
            pass

    def discover_sitemaps(self):
        known = set(self.robots_info.get("sitemaps", []))
        for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.xml.gz",
                     "/sitemap-index.xml", "/wp-sitemap.xml"]:
            url = self.base + path
            if url in known:
                continue
            try:
                resp = self.session.get(url, timeout=TIMEOUT)
            except Exception:
                continue
            if resp.status_code == 200 and "<" in resp.text[:2000]:
                known.add(url)
                self._parse_sitemap(url)
        if known:
            info(self.console, f"Sitemaps discovered: {len(known)}")

    def _parse_sitemap(self, url: str, depth: int = 0):
        if depth > 3:
            return
        try:
            resp = self.session.get(url, timeout=TIMEOUT)
        except Exception:
            return
        if resp.status_code != 200:
            return
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            locs = [loc.text.strip() for loc in soup.find_all("loc") if loc.text.strip()]
            for u in locs:
                self.sitemap_urls.add(u)
                if self._is_internal(u):
                    self.internal_links.add(u)
                    self._record(u, "sitemap")
            for child in locs:
                if child.endswith((".xml", ".xml.gz")) and child != url:
                    self._parse_sitemap(child, depth + 1)
            if locs:
                info(self.console, f"Sitemap {url}: {len(locs)} URLs")
        except Exception:
            pass

    def _extract_page(self, url: str, html: str):
        soup = BeautifulSoup(html, "html.parser")

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("mailto:"):
                self.emails_found.add(href.replace("mailto:", "").split("?")[0].strip())
                continue
            if href.startswith(("javascript:", "tel:", "data:")):
                for match in _ATTR_INTO.findall(href):
                    if match.startswith("/"):
                        self.spotted_routes.add(match)
                continue
            if href.startswith("#"):
                fragment = href[1:]
                if fragment and looks_like_route("/" + fragment.lstrip("/")):
                    self.hash_routes.add("/" + fragment.lstrip("/"))
                continue
            full = urljoin(url, href)
            if self._is_internal(full):
                if self._excluded(full):
                    continue
                self.internal_links.add(full)
                self._record(full, "link")
            else:
                self.external_links.add(full)
                host = urlparse(full).hostname
                if host and host != self.domain:
                    self.outbound_hosts.add(host)

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            full_action = urljoin(url, action) if action else url
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                data = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                    "id": inp.get("id", ""),
                }
                if data["name"]:
                    inputs.append(data)
            self.forms.append({
                "action": full_action, "method": method,
                "inputs": inputs, "page": url,
            })
            self._record(full_action, "form")

        parsed = urlparse(url)
        if parsed.query:
            for param in parse_qs(parsed.query).keys():
                self.params.add((url.split("?")[0], param))

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                self.js_files.add(urljoin(url, src))
            elif script.string and script.string.strip():
                self.inline_scripts.append(script.string)

        for link in soup.find_all("link", rel=True):
            rel = link.get("rel", [])
            if isinstance(rel, str):
                rel = [rel]
            if "stylesheet" in rel and link.get("href"):
                self.css_files.add(urljoin(url, link["href"]))

        for img in soup.find_all("img", src=True):
            self.image_files.add(urljoin(url, img["src"]))

        for refresh in _META_REFRESH.findall(html):
            target = refresh.split("url=", 1)[-1].strip().strip("'\"")
            if target and self._is_internal(target):
                self.internal_links.add(urljoin(url, target))

        for host in _LINK_HREF.findall(html):
            name = urlparse(host if "://" in host else f"//{host}").hostname
            if name and name != self.domain and not name.endswith((".js", ".css", ".png", ".jpg")):
                self.outbound_hosts.add(name)

    def _extract_routes_from_js(self, js_url: str):
        text, status, _, _ = self._fetch(js_url)
        if not text or status != 200:
            return set()
        routes = set()
        for pattern in _ROUTE_PATTERNS:
            for match in pattern.findall(text):
                if looks_like_route(match):
                    routes.add(match)
        return routes

    def crawl(self, seeds=None, label="pass-1"):
        self.passes += 1
        seed_list = [s for s in (seeds or [self.target]) if s]
        queue = deque((s, 0) for s in seed_list)
        for seed in seed_list:
            self.visited.add(self._normalize(seed))
        before = self.pages

        while queue:
            url, depth = queue.popleft()
            if depth > self.max_depth or self.pages >= self.max_pages:
                self.truncated_crawl = True
                continue

            html, status, final_url, content_type = self._fetch(url)
            self.pages += 1
            if not html or status >= 400:
                continue

            ctype = content_type.split(";")[0].strip().lower()
            if ctype.startswith(_SKIP_CTYPE):
                continue

            self._extract_page(final_url, html)
            self._keep_blob(final_url, html)

            if depth < self.max_depth:
                for link in list(self.internal_links):
                    normalized = self._normalize(link)
                    if normalized not in self.visited:
                        self.visited.add(normalized)
                        queue.append((link, depth + 1))

        added = self.pages - before
        info(self.console, f"Crawl {label}: +{added} pages (total {self.pages}, depth {self.max_depth})")
        return added

    def crawl_spa_routes(self, limit=60):
        if not self.js_files:
            warning(self.console, "No external JS bundles found - client-side routes cannot be discovered.")
            return set()

        discovered = set()
        for js_url in list(self.js_files)[:limit]:
            discovered |= self._extract_routes_from_js(js_url)

        for route in discovered:
            self.spotted_routes.add(route)
            self.internal_links.add(self.base + route)
            self._record(self.base + route, "spa-route")

        if discovered:
            info(self.console, f"SPA routes found in JS bundles: {len(discovered)}")
        else:
            warning(self.console, "No client-side routes could be extracted from JS bundles.")
        return discovered

    def crawl_route_seeds(self, routes, label="routes"):
        seeds = []
        for route in routes:
            path = route.split("?")[0]
            if not path.startswith("/"):
                continue
            if not self._is_internal(self.base + path):
                continue
            if not (path.startswith("/api/") or looks_like_route(concrete_route(path))):
                continue
            concrete = concrete_route(path)
            if self._normalize(self.base + concrete) in self.visited:
                continue
            seeds.append(self.base + concrete)
        if seeds:
            self.crawl(seeds[:200], label=label)
        return len(seeds)

    def run(self) -> dict:
        self._record(self.target, "root")
        info(self.console, "Parsing robots.txt and sitemaps...")
        self.parse_robots()
        self.discover_sitemaps()

        info(self.console, f"Starting crawler (depth={self.max_depth}, cap={self.max_pages} pages)...")
        self.crawl()

        self.crawl_spa_routes()

        success(self.console, f"Crawl complete: {len(self.visited)} URLs, {self.pages} pages fetched")
        found(self.console, f"Internal links: {len(self.internal_links)}")
        found(self.console, f"External links: {len(self.external_links)}")
        found(self.console, f"Forms found: {len(self.forms)}")
        found(self.console, f"URL parameters: {len(self.params)}")
        found(self.console, f"JS files: {len(self.js_files)}")
        if self.spotted_routes:
            found(self.console, f"Client-side routes: {len(self.spotted_routes)}")
        if self.hash_routes:
            found(self.console, f"Hash routes: {len(self.hash_routes)}")
        if self.outbound_hosts:
            found(self.console, f"Third-party hosts referenced: {len(self.outbound_hosts)}")
        if self.emails_found:
            found(self.console, f"Emails (mailto): {', '.join(list(self.emails_found)[:5])}")

        if self.truncated_crawl:
            warning(self.console, f"Crawl stopped at the {self.max_pages}-page cap - the surface "
                                   "map is INCOMPLETE. Raise --pages or use --deep.")

        surface_stats = self.surface.stats() if self.surface else {}
        if surface_stats and not (surface_stats.get("params") or surface_stats.get("forms")):
            warning(
                self.console,
                "No attack surfaces (forms/params) discovered - injection tests will have nothing to test.",
            )

        return {
            "internal_links": list(self.internal_links),
            "external_links": list(self.external_links),
            "outbound_hosts": sorted(self.outbound_hosts),
            "forms": self.forms,
            "params": [{"url": u, "param": p} for u, p in self.params],
            "js_files": list(self.js_files),
            "css_files": list(self.css_files),
            "images": list(self.image_files),
            "inline_scripts": len(self.inline_scripts),
            "inline_script_sources": list(self.inline_scripts),
            "spa_routes": sorted(self.spotted_routes),
            "hash_routes": sorted(self.hash_routes),
            "emails": list(self.emails_found),
            "robots": self.robots_info,
            "sitemap_urls": list(self.sitemap_urls),
            "pages_crawled": self.pages,
            "urls_queued": len(self.visited),
            "passes": self.passes,
            "page_cap_reached": self.truncated_crawl,
            "depth_used": self.max_depth,
        }
