import json
import re
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

from config import TIMEOUT
from core.banner import error, found, info, vuln, warning

_SMUGGLE_MARKER = "kripto-desync-probe-4d2f"
_GRAPHQL_QUERY = "{__schema{types{name kind}}}"
_GRAPHQL_BATCH = json.dumps([{"query": _GRAPHQL_QUERY}, {"query": _GRAPHQL_QUERY}])
_GRAPHQL_BROKEN = json.dumps({"query": "{__schema{types{name}"})
_HTTP_STATUS_LINE = re.compile(r"(?:^|\r?\n)(HTTP/1\.[01]\s+\d{3}[^\r\n]*)")
_SMUGGLE_ATTEMPTS = 2


def _framed_status_lines(raw: str):
    """Parse consecutive HTTP/1 responses using framing, not body text regexes."""
    statuses = []
    pos = 0
    length = len(raw)
    while pos < length:
        while raw.startswith("\r\n", pos):
            pos += 2
        if not raw.startswith(("HTTP/1.0 ", "HTTP/1.1 "), pos):
            break
        header_end = raw.find("\r\n\r\n", pos)
        if header_end < 0:
            break
        header_lines = raw[pos:header_end].split("\r\n")
        statuses.append(header_lines[0])
        headers = {}
        for line in header_lines[1:]:
            key, sep, value = line.partition(":")
            if sep:
                headers[key.strip().lower()] = value.strip().lower()
        body_start = header_end + 4
        if "chunked" in headers.get("transfer-encoding", ""):
            cursor = body_start
            while True:
                line_end = raw.find("\r\n", cursor)
                if line_end < 0:
                    return statuses
                try:
                    chunk_size = int(raw[cursor:line_end].split(";", 1)[0], 16)
                except ValueError:
                    return statuses
                cursor = line_end + 2
                if chunk_size == 0:
                    trailer_end = raw.find("\r\n\r\n", cursor)
                    pos = trailer_end + 4 if trailer_end >= 0 else cursor + 2
                    break
                cursor += chunk_size
                if raw[cursor:cursor + 2] != "\r\n":
                    return statuses
                cursor += 2
        elif "content-length" in headers:
            try:
                body_length = int(headers["content-length"])
            except ValueError:
                break
            pos = body_start + max(0, body_length)
        else:
            
            
            break
    return statuses


METHOD_PROBE = [
    
    "OPTIONS", "PROPFIND", "TRACE",
]


WRITE_VERBS = set()


class ProtoModule:
    """Protocol-level analysis: request smuggling, WebSocket, GraphQL, verbs.

    All probes are read-only and low volume. A smuggling probe sends one
    malformed request and observes how the server frames its own response; it
    never poisons a cache, never splits a response to a third party, and never
    issues more than two requests per class.
    """

    def __init__(self, target: str, console, baseline=None, mode: str = "active"):
        self.target = target
        self.console = console
        self.baseline = baseline
        self.mode = mode
        parsed = urlparse(target)
        self.scheme = parsed.scheme
        from core.policy import ScopePolicy
        self.host = urlparse(ScopePolicy._absolute_http_url(target)).hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.path = parsed.path or "/"

        from core.http import RateLimitedSession
        self.session = RateLimitedSession()

        self.smuggling = []
        self.websocket = {}
        self.graphql = {}
        self.verb_tampering = []
        self.alpn = []
        self.errors = []

    

    def _raw(self, payload: str, timeout=6, follow_up=None):
        return self.session.raw_diagnostic(self.target, payload, timeout, follow_up)

    def _build(self, path, headers, body=""):
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {self.host}",
            "Connection: close",
        ]
        lines.extend(headers)
        if body:
            lines.append(f"Content-Length: {len(body)}")
        return "\r\n".join(lines) + "\r\n\r\n" + body

    

    def _baseline_raw(self):
        response, err = self._raw(self._build(self.path, ["User-Agent: Mozilla/5.0"]))
        if not response:
            return None
        head, _, body = response.partition("\r\n\r\n")
        status = head.splitlines()[0] if head else ""
        return {"status": status, "length": len(body), "raw": response}

    def check_smuggling(self):
        """Look for repeatable, direct evidence of HTTP framing desynchronisation.

        A malformed request being rejected with 400/403/501 is normal protocol
        hardening, not request smuggling. Findings require multiple HTTP responses
        on the same connection on every attempt; status changes and timeouts remain
        diagnostic-only signals.
        """
        self.smuggling = []
        info(self.console, "Checking HTTP request framing (smuggling desync)...")
        baseline = self._baseline_raw()
        if not baseline:
            warning(self.console, "Could not obtain a raw HTTP baseline - smuggling check "
                                  "is INCONCLUSIVE.")
            return self.smuggling

        body = f"{_SMUGGLE_MARKER}\r\n"

        vectors = {
            "CL.TE": [
                ("GET" if self.path == "/" else "POST"),
                self.path,
                [f"Content-Length: {len(body) + 5}",
                 "Transfer-Encoding: chunked",
                 "Content-Type: application/x-www-form-urlencoded"],
                body,
            ],
            "TE.CL": [
                ("GET" if self.path == "/" else "POST"),
                self.path,
                ["Transfer-Encoding: chunked",
                 f"Content-Length: {len(body)}",
                 "Content-Type: application/x-www-form-urlencoded"],
                "0\r\n\r\n" + body,
            ],
            "TE.TE": [
                ("GET" if self.path == "/" else "POST"),
                self.path,
                ["Transfer-Encoding: chunked",
                 "Transfer-Encoding: identity",
                 f"Content-Length: {len(body)}"],
                body,
            ],
        }

        for name, (method, path, headers, payload_body) in vectors.items():
            raw = "\r\n".join([
                f"{method} {path} HTTP/1.1",
                f"Host: {self.host}",
                *headers,
                "Connection: close",
                "",
                payload_body,
            ])
            raw = raw.replace("\r\n\r\n\r\n", "\r\n\r\n")
            if payload_body and "chunked" in " ".join(headers).lower() and\
                    name == "CL.TE":
                raw = raw.replace(f"Content-Length: {len(body) + 5}", "Content-Length: 6")

            attempts = []
            for _ in range(_SMUGGLE_ATTEMPTS):
                response, err = self._raw(raw, timeout=6)
                if response is None:
                    attempts.append({"status": "", "status_lines": [], "error": err})
                    continue
                status_lines = _framed_status_lines(response)
                attempts.append({
                    "status": status_lines[0] if status_lines else "",
                    "status_lines": status_lines,
                    "error": err,
                })

            repeated_desync = (len(attempts) == _SMUGGLE_ATTEMPTS and
                               all(len(item["status_lines"]) > 1 for item in attempts))
            if repeated_desync:
                verdict = (f"multiple HTTP responses were observed on the same connection "
                           f"in {_SMUGGLE_ATTEMPTS}/{_SMUGGLE_ATTEMPTS} attempts")
                finding = {"vector": name, "verdict": verdict,
                           "baseline_status": baseline["status"],
                           "probe_status": attempts[0]["status"],
                           "attempts": attempts, "confirmed": True}
                self.smuggling.append(finding)
                vuln(self.console, f"HTTP request framing anomaly ({name}): {verdict}")

        if not self.smuggling:
            found(self.console, "No request-smuggling desync observed on the standard vectors.")
        return self.smuggling

    

    def check_websocket(self):
        from core.assessments import websocket_assessment
        self.websocket = websocket_assessment(self.target, self.session, active=self.mode != "safe")
        return self.websocket
    
    

    def check_graphql(self, candidates=None):
        candidates = candidates or ["graphql", "api/graphql", "v1/graphql", "query", "gql"]
        for rel in candidates:
            url = urljoin(self.target.rstrip("/") + "/", rel.lstrip("/"))
            entry = self._probe_graphql(url)
            if entry:
                entry["url"] = url
                self.graphql = entry
                if entry.get("open"):
                    vuln(self.console, f"GraphQL introspection is open at {url}")
                    break
        if not self.graphql:
            self.graphql = {"open": False, "note": "no GraphQL endpoint responded to introspection"}
        return self.graphql

    def _post(self, url, payload, content_type="application/json", origin=None):
        headers = {"Content-Type": content_type}
        if origin:
            headers["Origin"] = origin
        try:
            return self.session.post(url, data=payload, headers={}, request_headers=headers,
                                     allow_redirects=False, timeout=TIMEOUT)
        except Exception:
            return None

    def _probe_graphql(self, url):
        entry = {"open": False, "batching": False, "verbose_errors": False,
                 "introspectable_via_text_plain": False, "types": 0, "notes": []}

        resp = self._post(url, json.dumps({"query": _GRAPHQL_QUERY}))
        if resp is None or resp.status_code != 200:
            return None
        try:
            doc = resp.json()
        except Exception:
            return None
        if not doc.get("data", {}).get("__schema"):
            return None

        entry["open"] = True
        entry["types"] = len(doc["data"]["__schema"].get("types", []) or [])

        broken = self._post(url, _GRAPHQL_BROKEN)
        if broken is not None:
            body = broken.text.lower()
            if any(marker in body for marker in ("traceback", "at ", ".java:", ".py\"", ".rb:",
                                                 "exception", "line ", "stack")):
                entry["verbose_errors"] = True
                entry["notes"].append("malformed query returns stack-level error detail")

        batch = self._post(url, _GRAPHQL_BATCH)
        if batch is not None:
            try:
                if isinstance(batch.json(), list):
                    entry["batching"] = True
                    entry["notes"].append("batched queries accepted - request amplification")
            except Exception:
                pass

        plain = self._post(url, json.dumps({"query": _GRAPHQL_QUERY}),
                           content_type="text/plain", origin="https://evil-origin.example")
        if plain is not None and plain.status_code == 200 and "data" in plain.text:
            entry["introspectable_via_text_plain"] = True
            entry["notes"].append("introspection works with Content-Type: text/plain - "
                                  "simple cross-site request vector")

        return entry

    

    def check_verbs(self, paths=None):
        """Non-standard verbs on endpoints that should only accept GET/POST."""
        paths = paths or [self.path]
        info(self.console, "Checking non-standard HTTP verbs on live endpoints...")
        interesting = METHOD_PROBE

        for path in paths[:12]:
            for verb in interesting:
                marker = "kripto-trace-4d2f"
                try:
                    resp = self.session.request(verb, urljoin(self.target.rstrip("/") + "/",
                                                              path.lstrip("/")),
                                                timeout=8, allow_redirects=False,
                                                request_headers={"X-Kripto-Trace": marker})
                except Exception:
                    continue
                if resp is None:
                    continue
                if resp.status_code in (405, 501, 403, 400):
                    continue
                if verb == "OPTIONS":
                    
                    continue
                if verb == "TRACE" and marker not in resp.text:
                    continue
                if verb == "PROPFIND":
                    content_type = resp.headers.get("Content-Type", "").lower()
                    dav = resp.headers.get("DAV", "")
                    if not (resp.status_code == 207 and
                            ("multistatus" in resp.text.lower() or dav or
                             "xml" in content_type)):
                        continue
                entry = {"path": path, "verb": verb, "status": resp.status_code,
                         "length": len(resp.content),
                         "allow": resp.headers.get("Allow", "")}
                self.verb_tampering.append(entry)
                if verb == "TRACE":
                    vuln(self.console, f"TRACE is reflected on {path} "
                                       f"({resp.status_code}, {len(resp.content)} bytes) - "
                                       "cross-site tracing can recover HttpOnly headers")
                elif verb in WRITE_VERBS:
                    vuln(self.console, f"{verb} accepted on {path} "
                                       f"({resp.status_code}, {len(resp.content)} bytes)")
                else:
                    found(self.console, f"{verb} accepted on {path} "
                                        f"({resp.status_code}, {len(resp.content)} bytes)")

        if not self.verb_tampering:
            found(self.console, "No non-standard verb was accepted on the tested endpoints.")
        return self.verb_tampering

    

    def run(self, graphql_candidates=None, verb_paths=None):
        results = {}
        checks = [
            ("websocket", self.check_websocket, {}),
            ("graphql", self.check_graphql, {"candidates": graphql_candidates}),
            ("verb_tampering", self.check_verbs, {"paths": verb_paths}),
        ]
        if self.mode == "intrusive":
            checks.insert(0, ("smuggling", self.check_smuggling, {}))
        else:
            results["smuggling"] = []

        for name, fn, kwargs in checks:
            try:
                results[name] = fn(**kwargs)
            except Exception as e:
                error(self.console, f"Protocol check '{name}' failed: {type(e).__name__}: {e}")
                results[name] = {"error": f"{type(e).__name__}: {e}"}

        results["errors"] = self.errors
        results["smuggling_vectors_tried"] = (
            ["CL.TE", "TE.CL", "TE.TE"] if self.mode == "intrusive" else []
        )
        return results
