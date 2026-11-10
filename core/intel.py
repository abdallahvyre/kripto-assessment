import base64
import json
import re
from urllib.parse import urljoin, urlparse

import dns.resolver

from config import (
    API_SPEC_PATHS,
    EOL_LIBRARIES,
    GIT_PATHS,
    INFO_HEADERS,
    METHOD_PROBE,
    STAGE_LIMITS,
    TIMEOUT,
    WELL_KNOWN_PATHS,
)
from core.banner import error, found, info, make_table, success, vuln, warning
from core.http import RateLimitedSession, get_capped
from core.policy import ScopePolicy
from core.pool import WorkerPool
from core.redact import redact_secret

WELL_KNOWN_BODY_CAP = 2_000_000

_PASSIVE_SOURCES = [
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json"),
    ("crt.sh (direct)", "https://crt.sh/?q={domain}&output=json"),
    ("hackertarget", "https://api.hackertarget.com/hostsearch/?q={domain}"),
]

_TAKEOVER_FINGERPRINTS = {
    "heroku": (r"\.herokuapp\.com$", "Heroku"),
    "aws": (r"\.s3[-.]?website[-.]?amazonaws\.com$|\.elasticbeanstalk\.com$", "AWS"),
    "cloudfront": (r"\.cloudfront\.net$", "CloudFront"),
    "github-pages": (r"\.github\.io$", "GitHub Pages"),
    "shopify": (r"\.myshopify\.com$", "Shopify"),
    "surge": (r"\.surge\.sh$", "Surge"),
    "netlify": (r"\.netlify\.app$", "Netlify"),
    "vercel": (r"\.vercel\.app$", "Vercel"),
    "azure": (r"\.azurewebsites\.net$|\.cloudapp\.net$|\.trafficmanager\.net$", "Azure"),
    "firebase": (r"\.firebaseapp\.com$|\.web\.app$|\.firebaseio\.com$", "Firebase"),
    "readthedocs": (r"\.readthedocs\.io$", "ReadTheDocs"),
    "bitbucket": (r"\.bitbucket\.io$", "Bitbucket Pages"),
    "fastly": (r"\.fastly-app\.net$", "Fastly"),
    "cloudapp": (r"\.cloudapp\.azure\.com$", "Azure CloudApp"),
}

_SECRET_PATTERNS = {
    "AWS Access Key ID": r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
    "AWS Secret Key": r"(?i)aws_?secret_?(?:access_?)?key\W{0,4}(\"?[A-Za-z0-9/+=]{40}\"?)",
    "Google API Key": r"\b(AIza[0-9A-Za-z\-_]{35})\b",
    "Google OAuth Client": r"\b([0-9]{6,12}-[0-9A-Za-z_]{28,40}\.apps\.googleusercontent\.com)\b",
    "Google Service Account": r"\"type\"\s*:\s*\"service_account\"",
    "Firebase Cloud Messaging Key": r"\b(AAAA[A-Za-z0-9_\-]{7}:APA91b[A-Za-z0-9_\-]{60,})\b",
    "GitHub Token": r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b",
    "GitLab Token": r"\b(glpat-[A-Za-z0-9_\-]{20,})\b",
    "Slack Token": r"\b(xox[abposr]-[0-9A-Za-z\-]{10,})\b",
    "Slack Webhook": r"(https://hooks\.slack\.com/services/[A-Za-z0-9_/]+)",
    "Discord Webhook": r"(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+)",
    "Telegram Bot Token": r"\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{32,})\b",
    "Stripe Secret Key": r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b",
    "Stripe Publishable": r"\b(pk_(?:test|live)_[0-9A-Za-z]{20,})\b",
    "SendGrid Key": r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,})\b",
    "Mailgun Key": r"\b(key-[0-9a-hjkmnp-tv-zA-Z]{32})\b",
    "Twilio SID": r"\b(AC[a-f0-9]{32})\b",
    "Twilio Key": r"(?i)twilio.{0,20}([a-f0-9]{32})",
    "Shopify Token": r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
    "NPM Token": r"\b(npm_[A-Za-z0-9]{36})\b",
    "PyPI Token": r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
    "Heroku API Key": r"(?i)heroku.{0,20}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "JWT": r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b",
    "Private Key Block": r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)",
    "Connection String": r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s\"'<>]{8,160})",
    "S3 Bucket URL": r"\b([a-z0-9.\-]{3,63}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com)\b",
    "Azure Storage Blob": r"\b(https?://[a-z0-9]+\.blob\.core\.windows\.net/[a-z0-9\-_/]+)",
    "Basic Auth in URL": r"\b([a-z][a-z0-9+.\-]*://[^/\s:@]{1,40}:[^/\s:@]{1,80}@[^\s/\"']+)",
    "Hardcoded Credential": (
        r"(?i)\b(?:password|passwd|pwd|secret|api_?key|apikey|access_?key|client_?secret|"
        r"private_?key|auth_?token|token|refresh_?token|encryption_?key|signing_?key)\b"
        r"\s*[:=]\s*[\"']([^\"'\s$<>{}]{8,120})[\"']"
    ),
    "DB DSN": r"(?i)\b(?:jdbc|mongodb|postgres|mysql|redis)://[^\s\"'<>]{8,180}",
}

_PLACEHOLDER = re.compile(
    r"(your|example|placeholder|changeme|change_me|xxxx|todo|tbd|dummy|sample|"
    r"test_?key|redacted|secret_here|my_?key|insert_?|replace_?|some_?password|"
    r"lorem|\.\.\.|<|\$\{|process\.env|import\.meta|window\.|undefined|null)",
    re.I,
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_OBFUSCATED_EMAIL = re.compile(
    r"\b([A-Za-z0-9._%+\-]{2,40})\b\s*(?:\[|\(|\{)?\s*(?:\[at\]|@|\(at\)|\bat\b)\s*"
    r"(?:\]|\)|\})?\s*\b([A-Za-z0-9\-]{2,40})\b\s*(?:\[|\(|\{)?\s*"
    r"(?:\[dot\]|\.|\(dot\)|\bdot\b)\s*(?:\]|\)|\})?\s*\b([A-Za-z]{2,8})\b"
)
_INTERNAL_IP = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)
_SPECIAL_IP = re.compile(r"\b(?:0\.0\.0\.0|::1|0x7f000001)\b")
_INTERNAL_SUFFIX = re.compile(
    r"\b([a-z0-9][a-z0-9\-]{1,60}\.(?:internal|intranet|corp|lan|home|localdomain|svc|"
    r"cluster\.local|pvt\.local|internal\.local))\b",
    re.I,
)
_ENV_SUFFIX = re.compile(
    r"\b([a-z0-9][a-z0-9\-]{0,40}\.(?:dev|test|qa|uat|stage|staging|preprod|sandbox|"
    r"demo|beta|alpha|canary|preview))\b",
    re.I,
)
_AUTHOR_EMAIL = re.compile(r"[\w.\-]+@[\w.\-]+\.\w{2,}")
_BASE64_BLOB = re.compile(r"\b([A-Za-z0-9+/]{40,}={0,2})\b")



ENV_TLDS = {"com", "net", "org", "io", "co", "app", "dev", "cloud", "saas", "ai"}

_GRAPHQL_QUERY = "{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}}}}} directives{name locations args{name}}}}"
_GRAPHQL_INTROSPECTION = json.dumps({"query": _GRAPHQL_QUERY})


class IntelModule:
    """The layer that finds what everybody misses.

    Everything here targets information that is trivially exposed but routinely
    overlooked: published certificate-transparency names, a readable .git
    directory, an OpenAPI document, a JavaScript source map, an OPTIONS
    response, or a database hostname left in a config comment.
    """

    def __init__(self, target: str, console, surface, max_spec_endpoints=None):
        self.target = target
        parsed = urlparse(target)
        self.domain = parsed.hostname
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.console = console
        self.surface = surface
        self.max_spec_endpoints = max(
            0,
            int(max_spec_endpoints if max_spec_endpoints is not None
                else STAGE_LIMITS["default"]["spec_endpoints"]),
        )

        self.session = RateLimitedSession()

        self.well_known = []
        self.git_exposed = []
        self.git_details = {}
        self.specs = []
        self.spec_endpoints = []
        self._spec_endpoint_keys = set()
        self.spec_endpoint_cap_reached = False
        self.security_txt = {}
        self.methods = {}
        self.subdomains = {}
        self.takeover_candidates = []
        self.graphql = {}
        self.version_inventory = []

    

    def _get(self, url, timeout=TIMEOUT, headers=None, **kw):
        try:
            return self.session.get(url, timeout=timeout, headers=headers, **kw)
        except Exception:
            return None

    def _path(self, rel):
        return urljoin(self.base + "/", rel.lstrip("/"))

    

    def passive_subdomains(self):
        info(self.console, "Passive subdomain sources (certificate transparency)...")
        names = set()
        errors = []

        for label, template in _PASSIVE_SOURCES:
            if not self.domain:
                continue
            url = template.format(domain=self.domain)
            resp = None
            try:
                
                provider_session = RateLimitedSession(
                    pool=self.session.pool,
                    policy=ScopePolicy(url),
                    inherit_headers=False,
                )
                resp = provider_session.get(url, timeout=30, allow_redirects=True)
            except Exception as e:
                errors.append(f"{label}: {type(e).__name__}")
                continue
            finally:
                if "provider_session" in locals():
                    provider_session.close()

            if resp is None or resp.status_code != 200 or not resp.text.strip():
                errors.append(f"{label}: no usable response")
                continue

            text = resp.text
            if label.startswith("crt.sh"):
                try:
                    for entry in json.loads(text):
                        for field in ("name_value", "common_name"):
                            for raw in (entry.get(field) or "").split("\n"):
                                name = raw.strip().lstrip("*.").lower()
                                if name == self.domain or name.endswith("." + self.domain):
                                    names.add(name)
                except Exception:
                    errors.append("crt.sh: response was not valid JSON")
            else:
                for line in text.splitlines():
                    parts = line.strip().split(",")
                    if parts and (parts[0].strip().lower() == self.domain or parts[0].strip().lower().endswith("." + self.domain)):
                        names.add(parts[0].strip().lower())

            if names:
                break

        names.discard(self.domain.lower() if self.domain else "")
        names = {n for n in names if n and n.endswith("." + self.domain)}

        resolved = {}
        for name in sorted(names):
            try:
                from core.network import authorize
                _, allowed_host, _ = authorize("https://" + name, "passive subdomain DNS", policy=self.surface.policy if self.surface else None)
                ips = sorted({str(r) for r in dns.resolver.resolve(allowed_host, "A")})
            except Exception as exc:
                errors.append(f"DNS {name}: {type(exc).__name__}")
                continue
            if not ips:
                continue
            try:
                _, allowed_host, _ = authorize("https://" + name, "passive subdomain CNAME", policy=self.surface.policy if self.surface else None)
                cnames = [str(r) for r in dns.resolver.resolve(allowed_host, "CNAME")]
            except Exception:
                cnames = []
            resolved[name] = {"ips": ips, "cnames": cnames}
            found(self.console, f"[passive] {name} -> {', '.join(ips)}")

        self.subdomains = resolved
        self._takeover_scan(resolved)

        if not resolved:
            warning(self.console, "No passive subdomains were confirmed (sources may be unreachable "
                                  "or the domain has no CT history).")
        if errors:
            info(self.console, "Passive source notes: " + "; ".join(dict.fromkeys(errors))[:200])
        return resolved

    def _takeover_scan(self, resolved: dict):
        for name, data in resolved.items():
            for cname in data.get("cnames", []):
                for pattern, provider in _TAKEOVER_FINGERPRINTS.items():
                    if re.search(pattern, cname, re.I):
                        self.takeover_candidates.append(
                            {"subdomain": name, "cname": cname, "provider": provider}
                        )
                        warning(
                            self.console,
                            f"Possible dangling CNAME -> {provider}: {name} -> {cname}. "
                            "Verify manually that the target no longer claims this name.",
                        )

    

    def wellknown_sweep(self):
        info(self.console, f"Sweeping {len(WELL_KNOWN_PATHS)} well-known / low-hanging paths...")
        try:
            baseline = self._get(self._path("this-should-not-exist-9f3a2c.html"))
        except Exception:
            baseline = None

        for rel in WELL_KNOWN_PATHS:
            url = self._path(rel)
            resp = get_capped(url, cap=WELL_KNOWN_BODY_CAP, allow_redirects=True)
            if resp is None or resp.status_code >= 400:
                continue
            if len(resp.content) < 8:
                continue
            if baseline is not None and self._same_page(resp, baseline):
                continue

            ctype = resp.headers.get("Content-Type", "").lower()
            entry = {
                "path": rel,
                "url": url,
                "status": resp.status_code,
                "size": len(resp.content),
                "content_type": ctype,
                "truncated": bool(getattr(resp, "kripto_truncated", False)),
                "preview": resp.text[:180].strip() if "text" in ctype or "json" in ctype
                           or "xml" in ctype or not ctype else "",
            }
            self.well_known.append(entry)
            note = " (body capped)" if entry["truncated"] else ""
            found(self.console, f"[easy] {rel} ({resp.status_code}, {entry['size']}B{note})")

            if rel.endswith("security.txt"):
                self._parse_security_txt(resp.text)

        return self.well_known

    @staticmethod
    def _same_page(a, b) -> bool:
        return (a.status_code == b.status_code
                and abs(len(a.content) - len(b.content)) < 8
                and a.text.strip() == b.text.strip())

    def _parse_security_txt(self, text: str):
        info = {}
        current = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line and not line.startswith("http"):
                key, _, value = line.partition(":")
                key = key.strip().lower()
                if key == "contact":
                    info.setdefault("contacts", []).append(value.strip())
                    current = "contacts"
                else:
                    info[key] = value.strip()
                    current = key
            elif current == "contacts":
                info.setdefault("contacts", []).append(line)
        self.security_txt = info
        if info:
            found(self.console, f"security.txt published: contacts={info.get('contacts')} "
                                f"expires={info.get('expires')}")
            if not info.get("expires"):
                vuln(self.console, "security.txt has no Expires field (RFC 9116 violation)")
        return info

    

    def git_exposure(self):
        info(self.console, "Checking for exposed version-control metadata...")
        for rel in GIT_PATHS:
            url = self._path(rel)
            resp = self._get(url, allow_redirects=False)
            if resp is None or resp.status_code >= 400 or len(resp.content) < 8:
                continue

            self.git_exposed.append({"path": rel, "status": resp.status_code,
                                     "size": len(resp.content), "url": url})
            found(self.console, f"[easy] VCS file exposed: {rel} ({len(resp.content)}B)")

            if rel == ".git/config":
                remotes = re.findall(r"url\s*=\s*(.+)", resp.text)
                self.git_details["remotes"] = [r.strip() for r in remotes]
                for r in self.git_details["remotes"]:
                    found(self.console, f"  Git remote: {r}")
            elif rel == ".git/logs/HEAD":
                entries = re.findall(r"^([0-9a-f]{40})\s+(.*?)\s+([^\s<]+)\s+([^\]]*)$",
                                     resp.text, re.M)
                self.git_details["commits"] = len(entries)
                authors = {_AUTHOR_EMAIL.findall(e[3])[0] for e in entries
                           if _AUTHOR_EMAIL.findall(e[3])}
                self.git_details["authors"] = sorted(authors)
                self.git_details["recent"] = [
                    {"sha": e[0][:12], "author": e[2], "when": e[1], "msg": e[3][:120]}
                    for e in entries[-15:]
                ]
                found(self.console, f"  Git history: {len(entries)} commits, "
                                    f"{len(authors)} contributor address(es)")
                for a in sorted(authors)[:10]:
                    found(self.console, f"  Contributor: {a}")
            elif rel == ".git/HEAD":
                self.git_details["head"] = resp.text.strip()

        if self.git_exposed and not any(e["path"] == ".git/config" for e in self.git_exposed):
            warning(self.console, "Partial VCS exposure - the directory exists but the config was "
                                  "not readable. Treat source disclosure as unconfirmed.")
        return self.git_exposed

    

    def api_specs(self):
        info(self.console, f"Probing {len(API_SPEC_PATHS)} API-description locations...")
        for rel in API_SPEC_PATHS:
            url = self._path(rel)
            resp = self._get(url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text.strip()
            if not body:
                continue
            if not re.search(r"(paths\s*[:{]|openapi\s*[:\"']|swagger\s*[:\"']|definitions\s*[:{])", body):
                continue
            endpoints = self._parse_spec(body, url)
            if endpoints:
                self.specs.append({"path": rel, "url": url, "endpoints": len(endpoints)})
                found(self.console, f"[easy] API spec found: {rel} -> {len(endpoints)} endpoints")
        self.graphql = self._graphql_introspection()
        return self.specs

    def _parse_spec(self, body: str, url: str) -> list:
        doc = None
        try:
            doc = json.loads(body)
        except Exception:
            doc = self._parse_spec_yaml(body)

        if not isinstance(doc, dict):
            return []

        base = ""
        for server in doc.get("servers", []) or []:
            if isinstance(server, dict) and server.get("url"):
                base = str(server["url"]).rstrip("/")
                break
        if not base:
            host = doc.get("host")
            if host:
                base = f"{'https' if doc.get('schemes', ['https'])[0] == 'https' else 'http'}://{host}"
                base += (doc.get("basePath") or "").rstrip("/")

        pool = dict(doc.get("components", {}).get("parameters", {}) or {})
        pool.update(doc.get("parameters", {}) or {})

        endpoints = []
        for path, operations in (doc.get("paths") or {}).items():
            if len(self.spec_endpoints) + len(endpoints) >= self.max_spec_endpoints:
                self.spec_endpoint_cap_reached = True
                break
            if not isinstance(operations, dict):
                continue
            if not str(path).startswith("/"):
                continue

            common = operations.get("parameters", []) or []
            for method, operation in operations.items():
                if len(self.spec_endpoints) + len(endpoints) >= self.max_spec_endpoints:
                    self.spec_endpoint_cap_reached = True
                    break
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                if not isinstance(operation, dict):
                    continue

                params = set()
                for param in list(common) + list(operation.get("parameters", []) or []):
                    if not isinstance(param, dict):
                        continue
                    resolved = param
                    ref = param.get("$ref")
                    if ref:
                        resolved = pool.get(ref.split("/")[-1], {})
                    name = resolved.get("name") or param.get("name")
                    if name:
                        params.add(name)

                for a, b, c in re.findall(
                        r"\{([^}]+)\}|:([A-Za-z_]\w*)|\[([A-Za-z_]\w*)\]", str(path)):
                    token = a or b or c
                    if token:
                        params.add(token)

                body_schema = (operation.get("requestBody") or {}).get("content", {})\
                    if isinstance(operation.get("requestBody"), dict) else {}
                for media in body_schema.values():
                    schema = (media or {}).get("schema", {}) if isinstance(media, dict) else {}
                    if isinstance(schema, dict) and schema.get("properties"):
                        params.update(schema["properties"].keys())

                if base.startswith("http"):
                    absolute = f"{base}{path}"
                elif base:
                    absolute = f"{self.base}/{base.strip('/')}{path}"
                else:
                    absolute = f"{self.base}{path}"
                endpoint_key = (method.upper(), absolute)
                if endpoint_key in self._spec_endpoint_keys:
                    continue
                self._spec_endpoint_keys.add(endpoint_key)
                endpoints.append({"method": method.upper(), "path": path,
                                  "url": absolute, "params": sorted(params)})

                self.surface.add_endpoint(absolute, "api-spec", methods=[method.upper()], note=url)
                for name in params:
                    self.surface.add_param(absolute, name, "api-spec")

        if endpoints:
            self.spec_endpoints.extend(endpoints)
            vuln(self.console, f"Public API specification: {len(endpoints)} documented operations "
                               "exposed without authentication")
        if self.spec_endpoint_cap_reached:
            warning(self.console, f"OpenAPI endpoint inventory stopped at the "
                                  f"{self.max_spec_endpoints}-operation cap.")
        return endpoints

    def _parse_spec_yaml(self, body: str):
        """Minimal YAML path extraction - enough to list endpoints from a spec
        served as openapi.yaml without pulling in a parser dependency."""
        paths = {}
        current = None
        for raw in body.splitlines():
            if not raw.strip() or raw.strip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            stripped = raw.strip()
            if indent == 2 and stripped.startswith("/"):
                current = stripped.rstrip(":").strip().strip("'\"").rstrip(":").strip()
                if current:
                    paths.setdefault(current, {})
            elif indent >= 4 and current and re.match(r"^(get|post|put|patch|delete|head):",
                                                       stripped, re.I):
                paths[current][stripped.split(":")[0].lower()] = {}
        return {"paths": paths}

    def _graphql_introspection(self):
        for rel in ("graphql", "api/graphql", "v1/graphql", "query"):
            url = self._path(rel)
            resp = self.session.post(
                url,
                data=_GRAPHQL_INTROSPECTION,
                headers={}, allow_redirects=False,
                request_headers={"Content-Type": "application/json"},
                timeout=TIMEOUT,
            ) if hasattr(self.session, "post") else None
            if resp is None or resp.status_code != 200:
                continue
            try:
                doc = resp.json()
            except Exception:
                continue
            if "data" in doc and doc.get("data", {}).get("__schema"):
                schema = doc["data"]["__schema"]
                types = [t.get("name") for t in schema.get("types", []) or []]
                queries = [t.get("name") for t in schema.get("types", []) or []]
                self.graphql = {
                    "endpoint": url,
                    "open": True,
                    "types": [t for t in types if t][:200],
                    "queries": [q for q in queries if q][:100],
                }
                vuln(self.console, f"GraphQL introspection enabled without auth at {url} "
                                   f"({len(types)} types exposed)")
                return self.graphql
        return {}

    

    def http_methods(self, url=None):
        url = url or self.target
        try:
            resp = self.session.request("OPTIONS", url, timeout=TIMEOUT, allow_redirects=False)
        except Exception as e:
            error(self.console, f"OPTIONS probe failed: {e}")
            return self.methods

        allowed = set()
        header = resp.headers.get("Allow", "")
        if header:
            allowed.update(m.strip().upper() for m in header.split(","))
        for method in METHOD_PROBE:
            if method in header.upper():
                allowed.add(method)
        allowed.add("OPTIONS")

        for method in ("TRACE", "PUT", "DELETE"):
            if method in allowed:
                continue
            try:
                probe = self.session.request(method, url, timeout=8, allow_redirects=False)
                if probe is not None and probe.status_code not in (405, 501, 403):
                    allowed.add(method)
            except Exception:
                continue

        self.methods = {"url": url, "allow_header": header, "accepted": sorted(allowed)}
        for method in sorted(allowed - {"GET", "HEAD", "OPTIONS"}):
            warning(self.console, f"Uncommon HTTP method accepted on {url}: {method}")
        found(self.console, f"Allowed methods on {url}: {', '.join(sorted(allowed))}")
        return self.methods

    

    def header_inventory(self, url=None):
        url = url or self.target
        resp = self._get(url)
        if resp is None:
            return {}
        found_headers = {
            k: v for k, v in resp.headers.items()
            if k in INFO_HEADERS or k.lower().startswith("x-")
        }
        for key, value in found_headers.items():
            self.version_inventory.append({"header": key, "value": value[:120]})
        return found_headers

    

    def leak_scan(self, blobs, domain=None):
        """blobs: iterable of (source_label, text)."""
        domain = domain or self.domain
        secrets, emails, internal_ips, internal_hosts, buckets, authors = (
            set(), set(), set(), set(), set(), set()
        )
        env_hosts = set()
        scanned = 0

        for label, text in blobs:
            if not text:
                continue
            scanned += 1

            for name, pattern in _SECRET_PATTERNS.items():
                for match in re.findall(pattern, text):
                    value = match if isinstance(match, str) else next(
                        (m for m in match if isinstance(m, str) and m), ""
                    )
                    value = value.strip().strip('"')
                    if not value or _PLACEHOLDER.search(value):
                        continue
                    if len(set(value)) <= 4:
                        continue
                    secrets.add((name, value[:120], label))

            for match in _EMAIL.findall(text):
                lowered = match.lower()
                if lowered.endswith((".png", ".jpg", ".gif", ".svg", ".woff", ".webp", ".js", ".css")):
                    continue
                if re.match(r"^[0-9a-f]{16,}@", lowered):
                    continue
                emails.add(lowered)

            for local, host, tld in _OBFUSCATED_EMAIL.findall(text):
                candidate = f"{local}@{host}.{tld}".lower()
                if "@" in local:
                    continue
                emails.add(candidate)

            for match in _INTERNAL_IP.findall(text):
                internal_ips.add(match)
            for match in _SPECIAL_IP.findall(text):
                internal_ips.add(match)

            for match in _INTERNAL_SUFFIX.findall(text):
                if not domain or match.lower() != domain.lower():
                    internal_hosts.add(match.lower())

            for match in _ENV_SUFFIX.findall(text):
                host = match.lower()
                if domain and host.endswith(domain.lower()) and host != domain.lower():
                    env_hosts.add(host)
                elif domain and host.count(".") >= 2 and host.split(".")[-1] in ENV_TLDS:
                    env_hosts.add(host)

            for candidate in list(emails):
                if _INTERNAL_SUFFIX.fullmatch(candidate.split("@")[-1]):
                    emails.discard(candidate)

            for match in re.findall(r"\b([a-z0-9][a-z0-9\-]{3,50}\.(?:s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com|blob\.core\.windows\.net|digitaloceanspaces\.com|storage\.googleapis\.com|r2\.cloudflarestorage\.com|supabase\.co))\b", text, re.I):
                buckets.add(match.lower())

            if label == ".git/logs/HEAD":
                authors.update(a.lower() for a in _AUTHOR_EMAIL.findall(text))

        result = {
            "scanned_blobs": scanned,
            "secrets": [{"type": t, "value": v, "source": s} for t, v, s in sorted(secrets)],
            "emails": sorted(emails),
            "internal_ips": sorted(internal_ips),
            "internal_hosts": sorted(internal_hosts),
            "environment_hosts": sorted(env_hosts),
            "buckets": sorted(buckets),
            "git_authors": sorted(authors),
        }

        for secret in result["secrets"]:
            masked = redact_secret(secret["value"], "credential")
            vuln(self.console, f"[LEAK] {secret['type']}: {masked} ({secret['source']})")
        if result["emails"]:
            found(self.console, f"Emails harvested: {len(result['emails'])} "
                                f"({', '.join(result['emails'][:8])})")
        if result["internal_ips"]:
            vuln(self.console, f"Internal IPs referenced in content: "
                               f"{', '.join(result['internal_ips'][:8])}")
        if result["internal_hosts"]:
            vuln(self.console, f"Internal hostnames referenced in content: "
                               f"{', '.join(result['internal_hosts'][:8])}")
        if result["environment_hosts"]:
            found(self.console, f"Non-production environments referenced: "
                                f"{', '.join(result['environment_hosts'][:8])}")
        if result["buckets"]:
            vuln(self.console, f"Cloud storage buckets referenced: "
                               f"{', '.join(result['buckets'][:8])}")

        return result

    @staticmethod
    def _decode_base64_blobs(text):
        for blob in _BASE64_BLOB.findall(text):
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "ignore")
            except Exception:
                continue
            if sum(1 for c in decoded if c.isprintable()) / max(1, len(decoded)) > 0.85:
                yield decoded

    

    def run(self, blobs=None):
        results = {}
        results["passive_subdomains"] = self.passive_subdomains()
        results["well_known"] = self.wellknown_sweep()
        results["git_exposure"] = self.git_exposure()
        results["git_details"] = self.git_details
        results["api_specs"] = self.api_specs()
        results["spec_endpoints"] = self.spec_endpoints
        results["spec_endpoint_cap_reached"] = self.spec_endpoint_cap_reached
        results["graphql"] = self.graphql
        results["security_txt"] = self.security_txt
        results["http_methods"] = self.http_methods()
        results["header_inventory"] = self.header_inventory()
        results["leaks"] = self.leak_scan(blobs or [])

        rows = [
            ("Passive subdomains", str(len(results["passive_subdomains"]))),
            ("Well-known files", str(len(results["well_known"]))),
            ("VCS files exposed", str(len(results["git_exposure"]))),
            ("API specs", str(len(results["api_specs"]))),
            ("Spec endpoints", str(len(results["spec_endpoints"]))),
            ("GraphQL introspection", "open" if results["graphql"].get("open") else "closed/absent"),
            ("security.txt", "yes" if results["security_txt"] else "no"),
            ("Accepted HTTP methods", ", ".join(results["http_methods"].get("accepted", []) or ["-"])),
            ("Secrets found", str(len(results["leaks"]["secrets"]))),
            ("Emails", str(len(results["leaks"]["emails"]))),
            ("Internal IPs", str(len(results["leaks"]["internal_ips"]))),
            ("Internal hosts", str(len(results["leaks"]["internal_hosts"]))),
            ("Cloud buckets", str(len(results["leaks"]["buckets"]))),
            ("Takeover candidates", str(len(self.takeover_candidates))),
        ]
        self.console.print(make_table("Discovery Layer Summary", ["Signal", "Value"], rows))

        if rows[0][1] == "0" and rows[1][1] == "0" and rows[2][1] == "0":
            warning(self.console, "The easy-discovery layer returned nothing at all. Either the "
                                  "target is locked down, or the requests are being filtered. "
                                  "Re-run with a lower --rate if a WAF is in front.")

        return results


def eol_check(versions):
    notes = []
    for item in versions or []:
        lib = item.get("library")
        version = str(item.get("version", ""))
        if lib in EOL_LIBRARIES and (version.startswith("1.") or version.startswith("2.")
                                     or lib == "AngularJS"):
            notes.append({"library": lib, "version": version, "note": EOL_LIBRARIES[lib]})
    return notes
