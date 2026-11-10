import hashlib
import os
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from config import *
from core.banner import found, info, success, warning, make_table
from core.http import RateLimitedSession
from core.redact import redact_secret, redact_text

_PLACEHOLDER = re.compile(
    r"(your|example|placeholder|changeme|change_me|xxxx|xxxxx|todo|tbd|dummy|"
    r"sample|test_?key|insert|redacted|<|\.\.\.|secret_here|my_?key)",
    re.IGNORECASE,
)

_TOKEN_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?:aws_secret|secret_key|secretkey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth Client": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
    "Slack Token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9\-]*',
    "Slack Webhook": r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+',
    "JWT": r'eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}',
    "Private Key": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "Stripe Key": r'(?:sk|pk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}',
    "SendGrid": r'SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}',
    "Mailgun Key": r'key-[0-9a-zA-Z]{32}',
    "Firebase": r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}',
    "Bearer Token": r'\b[Bb]earer\s+([A-Za-z0-9\-_.~+/]{20,}={0,2})',
    "Basic Auth Header": r'\b[Bb]asic\s+([A-Za-z0-9+/]{20,}={1,2})',
    "Generic Secret": r'(?:secret|password|passwd|pwd|api_?key|access_?key|client_?secret|private_?key)'
                        r'["\']?\s*[:=]\s*["\']([^"\'\s]{12,200})["\']',
}

_EMAIL = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

_PHONE = re.compile(
    r'(?<![\w.])'
    r'(?:\+\d{1,3}[\s.\-]?)?'
    r'(?:\(\d{2,4}\)[\s.\-]?)?'
    r'\d{3,4}(?:[\s.\-]\d{3,4}){1,3}'
    r'(?![\w.])'
)

_JS_ENDPOINT_PATTERNS = [
    r'["\'](/api/v[0-9]+/[a-zA-Z0-9_\-/]*)["\']',
    r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/graphql)["\']',
    r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]',
    r'\.(?:get|post|put|delete|patch)\s*\(\s*["\'`]([^"\'`]+)["\'`]',
    r'axios\s*(?:\.\w+)?\s*\(\s*["\'`]([^"\'`]+)["\'`]',
    r'XMLHttpRequest[\s\S]{0,200}?\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\'`]([^"\'`]+)["\'`]',
]

_IGNORED_ENDPOINT_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".html", ".htm", ".json",
)


def _looks_like_phone(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    if not 7 <= len(digits) <= 15:
        return False
    if re.search(r"\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}", match):
        return False
    has_separator = bool(re.search(r"[()\s.\-]", match.strip()))
    if not has_separator and not match.strip().startswith("+"):
        return False
    if len(set(digits)) <= 2:
        return False
    return True


def _plausible_token(value: str) -> bool:
    if not value or _PLACEHOLDER.search(value):
        return False
    if len(set(value)) <= 3:
        return False
    if value.lower() in ("password", "null", "undefined", "true", "false"):
        return False
    return True


class ExtractorModule:
    def __init__(self, target: str, console, pages=None, surface=None, profile: str = "default"):
        self.target = target
        self.console = console
        seen, ordered = set(), []
        for page in (pages or []):
            if page and page not in seen:
                seen.add(page)
                ordered.append(page)
        if target not in seen:
            ordered.insert(0, target)
        self.pages = ordered or [target]
        self.surface = surface

        limits = dict(STAGE_LIMITS["default"])
        limits.update(STAGE_LIMITS.get(profile, {}))
        self.max_pages = limits["extraction_pages"]
        self.max_bundles = limits["js_bundles"]
        self.max_inline = limits["inline_scripts"]
        self.cap_reached = False

        self.session = RateLimitedSession()
        self.results = {
            "emails": set(), "phones": set(), "social_links": set(),
            "comments": [], "hidden_fields": [], "metadata": {},
            "js_endpoints": set(), "tokens_keys": [], "form_actions": [],
            "data_attrs": [], "iframes": [], "csp_urls": [], "link_rel": [],
        }

    def _fetch(self, url: str) -> str:
        try:
            return self.session.get(url, timeout=TIMEOUT).text
        except Exception:
            return ""

    def download_exposed_file(self, url: str, category: str):
        try:
            filename = os.path.basename(urlparse(url).path)
            if not filename or len(filename) > 100:
                filename = "file_" + hashlib.sha256(url.encode()).hexdigest()[:16] + ".bin"

            dest_dir = os.path.join("output", "downloaded_files", category)
            os.makedirs(dest_dir, exist_ok=True)
            filepath = os.path.join(dest_dir, os.path.basename(filename))

            resp = self.session.get(url, timeout=TIMEOUT, stream=True)
            if resp.status_code == 200:
                with open(filepath, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                found(self.console, f"Downloaded exposed file: {os.path.basename(filepath)} -> {filepath}")
                return filepath
        except Exception:
            pass
        return None

    def extract_emails(self, html: str):
        for match in _EMAIL.findall(html):
            local = match.lower()
            if local.endswith((".png", ".jpg", ".gif", ".css", ".js", ".webp")):
                continue
            if re.match(r"^[0-9a-f]{16,}@", local):
                continue
            self.results["emails"].add(local)

    def extract_phones(self, html: str):
        for match in _PHONE.findall(html):
            cleaned = match.strip()
            if _looks_like_phone(cleaned):
                self.results["phones"].add(cleaned)

    def extract_social(self, html: str):
        social_patterns = {
            "Facebook": r'(?:https?://)?(?:www\.)?facebook\.com/[\w.\-]+',
            "Twitter/X": r'(?:https?://)?(?:www\.)?(?:twitter|x)\.com/[\w]+',
            "LinkedIn": r'(?:https?://)?(?:www\.)?linkedin\.com/(?:in|company)/[\w\-]+',
            "Instagram": r'(?:https?://)?(?:www\.)?instagram\.com/[\w.]+',
            "YouTube": r'(?:https?://)?(?:www\.)?youtube\.com/(?:@|channel/|user/)[\w\-]+',
            "GitHub": r'(?:https?://)?(?:www\.)?github\.com/[\w\-]+',
            "Telegram": r'(?:https?://)?(?:t\.me|telegram\.me)/[\w]+',
            "TikTok": r'(?:https?://)?(?:www\.)?tiktok\.com/@[\w.]+',
            "Discord": r'(?:https?://)?(?:discord\.gg|discord\.com/invite)/[\w]+',
        }
        for platform, pattern in social_patterns.items():
            for match in re.findall(pattern, html, re.IGNORECASE):
                self.results["social_links"].add(f"[{platform}] {match}")

    def extract_comments(self, html: str, url: str):
        keywords = [
            "password", "pwd", "pass", "secret", "key", "token", "api",
            "todo", "fixme", "hack", "debug", "admin", "root", "internal",
            "private", "credential", "database", "db", "sql", "config",
        ]
        for c in re.findall(r'<!--(.*?)-->', html, re.DOTALL):
            c = c.strip()
            if len(c) > 5 and not c.startswith("[if"):
                self.results["comments"].append({
                    "content": c[:500],
                    "page": url,
                    "sensitive": any(kw in c.lower() for kw in keywords),
                })

    def extract_hidden_fields(self, html: str, url: str):
        soup = BeautifulSoup(html, "html.parser")
        for inp in soup.find_all("input", type="hidden"):
            name = inp.get("name", "")
            value = inp.get("value", "")
            if name and value:
                self.results["hidden_fields"].append({
                    "name": name, "value": value[:200], "page": url,
                })

    def extract_metadata(self, html: str):
        soup = BeautifulSoup(html, "html.parser")
        for name in ["author", "generator", "description", "keywords",
                     "robots", "viewport", "theme-color", "application-name"]:
            tag = soup.find("meta", attrs={"name": name})
            if tag and tag.get("content"):
                self.results["metadata"][name] = tag["content"]

        for og in soup.find_all("meta", property=True):
            prop = og.get("property", "")
            if prop.startswith(("og:", "twitter:")):
                self.results["metadata"][prop] = og.get("content", "")

        title = soup.find("title")
        if title:
            self.results["metadata"]["title"] = title.text.strip()

    def extract_page_signals(self, html: str, url: str):
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                self.results["form_actions"].append({
                    "action": urljoin(url, action),
                    "method": form.get("method", "GET").upper(),
                    "page": url,
                })

        for tag in soup.find_all(True):
            for attr, value in (tag.attrs or {}).items():
                if not isinstance(value, (str, list)):
                    continue
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if attr.startswith("data-") and isinstance(item, str) and (
                            "/" in item or "http" in item):
                        self.results["data_attrs"].append(
                            {"attr": attr, "value": item[:200], "page": url}
                        )

        for frame in soup.find_all(["iframe", "frame", "embed", "object"]):
            src = frame.get("src") or frame.get("data")
            if src:
                self.results["iframes"].append({
                    "url": urljoin(url, src), "tag": frame.name, "page": url,
                    "sandbox": frame.get("sandbox") is not None,
                })

        for meta in soup.find_all("meta", attrs={"http-equiv": True}):
            if meta["http-equiv"].lower() == "content-security-policy":
                for part in (meta.get("content") or "").split():
                    if part.endswith(":"):
                        continue
                    self.results["csp_urls"].append(part.strip("'\""))

        for link in soup.find_all("link", href=True):
            rel = link.get("rel") or []
            rel = [rel] if isinstance(rel, str) else list(rel)
            if any(r in ("preload", "prefetch", "preconnect", "dns-prefetch", "modulepreload")
                   for r in rel):
                self.results["link_rel"].append({
                    "rel": ",".join(rel), "href": urljoin(url, link["href"]), "page": url,
                })

    def _scan_source_for_endpoints(self, content: str):
        for pattern in _JS_ENDPOINT_PATTERNS:
            for match in re.findall(pattern, content):
                candidate = match.strip().rstrip("\\")
                if (
                    len(candidate) > 4
                    and "/" in candidate
                    and not candidate.startswith(("http://", "https://", "//", "{{", "${", "data:"))
                    and not candidate.endswith(_IGNORED_ENDPOINT_EXT)
                    and not candidate.startswith(("http", "ws:", "wss:"))
                ):
                    self.results["js_endpoints"].add(candidate)

    def extract_js_endpoints(self, js_urls: list, inline_scripts=None):
        sources = []
        for code in (inline_scripts or [])[: self.max_inline]:
            sources.append(("inline:<script>", code))
        for js_url in js_urls[: self.max_bundles]:
            content = self._fetch(js_url)
            if content:
                sources.append((js_url, content))

        for origin, content in sources:
            self._scan_source_for_endpoints(content)
            self.extract_emails(content)
            self.extract_phones(content)
            self.extract_social(content)
            self.extract_tokens_keys(content, origin)
        return len(sources)

    def extract_tokens_keys(self, html: str, url: str):
        for key_type, pattern in _TOKEN_PATTERNS.items():
            for match in re.findall(pattern, html):
                value = match if isinstance(match, str) else (match[0] if match else "")
                if not _plausible_token(value):
                    continue
                self.results["tokens_keys"].append({
                    "type": key_type,
                    "value": value[:100] + ("..." if len(value) > 100 else ""),
                    "page": url,
                })

    def run(self, js_files=None, inline_scripts=None) -> dict:
        page_budget = self.pages[: self.max_pages]
        if len(self.pages) > self.max_pages:
            self.cap_reached = True
        info(self.console, f"Extracting data from {len(page_budget)} pages...")

        for i, page in enumerate(page_budget):
            html = self._fetch(page)
            if not html:
                continue

            self.extract_emails(html)
            self.extract_phones(html)
            self.extract_social(html)
            self.extract_comments(html, page)
            self.extract_hidden_fields(html, page)
            self.extract_tokens_keys(html, page)
            self.extract_page_signals(html, page)

            if self.surface:
                for form in self.results["form_actions"]:
                    if form["page"] == page:
                        self.surface.add_endpoint(form["action"], "form-extraction",
                                                  methods=[form["method"]])

            if i == 0:
                self.extract_metadata(html)

            if (i + 1) % 50 == 0:
                info(self.console, f"Processed {i + 1}/{len(page_budget)} pages")

        if self.cap_reached:
            warning(self.console, f"Extraction stopped at the {self.max_pages}-page cap out of "
                                  f"{len(self.pages)} discovered pages - results are INCOMPLETE.")

        if js_files or inline_scripts:
            info(self.console, f"Analyzing {min(len(js_files or []), self.max_bundles)} JS bundles "
                               "for endpoints/secrets...")
            count = self.extract_js_endpoints(js_files or [], inline_scripts)
            info(self.console, f"Scanned {count} script source(s) for endpoints, emails and secrets.")

        if self.results["emails"]:
            found(self.console, f"Emails: {', '.join(list(self.results['emails'])[:10])}")
        if self.results["phones"]:
            found(self.console, f"Phones: {', '.join(list(self.results['phones'])[:10])}")
        for s in list(self.results["social_links"])[:10]:
            found(self.console, f"Social: {s}")
        for tk in self.results["tokens_keys"][:10]:
            masked = redact_secret(tk["value"], "credential")
            found(self.console, f"[bright_red]KEY FOUND[/bright_red] [{tk['type']}] {masked}")

        sensitive = [c for c in self.results["comments"] if c.get("sensitive")]
        if sensitive:
            warning(self.console, f"Sensitive HTML comments found: {len(sensitive)}")
            for sc in sensitive[:5]:
                found(self.console, f"Comment: {redact_text(sc['content'])[:160]}")

        if self.results["js_endpoints"]:
            found(self.console, f"JS endpoints discovered: {len(self.results['js_endpoints'])}")
        if self.results["iframes"]:
            for f in self.results["iframes"][:6]:
                found(self.console, f"Framed content: {f['url']}"
                                    f"{' [sandboxed]' if f['sandbox'] else ' [UNSANDBOXED]'}")
        if self.results["csp_urls"]:
            found(self.console, f"CSP listed origins: {', '.join(sorted(set(self.results['csp_urls']))[:8])}")

        rows = [
            ("Emails", str(len(self.results["emails"]))),
            ("Phone Numbers", str(len(self.results["phones"]))),
            ("Social Links", str(len(self.results["social_links"]))),
            ("HTML Comments", str(len(self.results["comments"]))),
            ("Hidden Fields", str(len(self.results["hidden_fields"]))),
            ("Tokens/Keys", str(len(self.results["tokens_keys"]))),
            ("JS Endpoints", str(len(self.results["js_endpoints"]))),
            ("Metadata Tags", str(len(self.results["metadata"]))),
            ("Form Actions", str(len(self.results["form_actions"]))),
            ("Iframes/Embeds", str(len(self.results["iframes"]))),
            ("Preload/Preconnect", str(len(self.results["link_rel"]))),
            ("data-* URL attrs", str(len(self.results["data_attrs"]))),
        ]
        self.console.print(make_table("Extraction Summary", ["Type", "Count"], rows))

        if not any(len(v) for v in self.results.values() if isinstance(v, (set, list, dict))):
            warning(self.console, "Nothing extracted - pages may be client-rendered with data loaded via XHR.")

        return {
            "emails": sorted(self.results["emails"]),
            "phones": sorted(self.results["phones"]),
            "social_links": sorted(self.results["social_links"]),
            "comments": self.results["comments"],
            "hidden_fields": self.results["hidden_fields"],
            "metadata": self.results["metadata"],
            "js_endpoints": sorted(self.results["js_endpoints"]),
            "tokens_keys": self.results["tokens_keys"],
            "form_actions": self.results["form_actions"],
            "iframes": self.results["iframes"],
            "csp_urls": sorted(set(self.results["csp_urls"])),
            "link_rel": self.results["link_rel"],
            "data_attrs": self.results["data_attrs"][:500],
            "page_cap_reached": self.cap_reached,
        }
