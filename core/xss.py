import os
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

from config import *
from core.banner import info, success, warning, vuln, found, make_table
from core.http import RateLimitedSession

URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster",
             "srcset", "background", "codebase", "cite", "xlink:href"}


class XSSModule:
    def __init__(self, target: str, console, params=None, forms=None, baseline=None,
                 surface=None, intrusive: bool = False):
        self.target = target
        self.console = console
        self.params = params or []
        self.forms = forms or []
        self.baseline = baseline
        self.surface = surface
        self.intrusive = intrusive
        self.session = RateLimitedSession()
        self.reflected = []
        self.dom_based = []
        self.tested = 0
        self._baseline_cache = {}

    def _record_injection(self, count=1):
        if self.surface and hasattr(self.surface, "record_injection"):
            self.surface.record_injection("xss", count)

    def _baseline_body(self, url: str) -> str:
        if url not in self._baseline_cache:
            try:
                self._baseline_cache[url] = self.session.get(url, timeout=TIMEOUT).text
            except Exception:
                self._baseline_cache[url] = ""
        return self._baseline_cache[url]

    def _decoded(self, text: str) -> str:
        import html as html_mod
        import urllib.parse as urlparse_mod
        text = html_mod.unescape(text)
        return urlparse_mod.unquote_plus(text)

    def _reflection_context(self, html: str, payload: str):
        """Where did the payload land? text node / tag attribute / script block."""
        idx = html.find(payload)
        if idx == -1:
            return "unknown", None
        head = html[:idx]

        last_open = head.rfind("<")
        last_close = head.rfind(">")
        if last_open > last_close:
            tag_match = re.search(r"<\s*([a-zA-Z][\w:-]*)", head[last_open:])
            attr_match = re.search(r"([\w:-]+)\s*=\s*[\"']?[^\"'>]*$", head[last_open:])
            return "attribute", (attr_match.group(1).lower() if attr_match else None)

        if re.search(r"<(script|style)\b[^>]*>(?:(?!</\1>).)*$", head, re.DOTALL | re.IGNORECASE):
            return "script", None
        return "text", None

    def _exploitable(self, payload: str, context: str, attr) -> bool:
        """Unescaped reflection is only exploitable depending on where it landed."""
        if context == "unknown":
            return True
        if context == "script":
            return bool(re.search(r"[\"'`]|</script|<", payload, re.IGNORECASE))
        if context == "attribute":
            if re.search(r"[<>\"'`]", payload):
                return True
            return attr in URL_ATTRS and "javascript:" in payload.lower()
        return "<" in payload or ">" in payload

    @staticmethod
    def _is_html_response(resp) -> bool:
        content_type = str(getattr(resp, "headers", {}).get("Content-Type", ""))\
            .split(";", 1)[0].strip().lower()
        if content_type:
            return content_type in ("text/html", "application/xhtml+xml")
        sample = str(getattr(resp, "text", ""))[:512].lstrip().lower()
        return sample.startswith(("<!doctype html", "<html", "<head", "<body"))

    def test_reflected(self, url: str, param: str):
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        base_body = self._baseline_body(url)
        base_decoded = self._decoded(base_body)

        for payload in XSS_PAYLOADS:
            try:
                test_params = dict(base_params)
                test_params[param] = payload
                query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

                self._record_injection()
                resp = self.session.get(test_url, timeout=TIMEOUT)
                self.tested += 1

                if not self._is_html_response(resp):
                    continue

                if self.baseline is not None and self.baseline.classify(resp) == "catchall":
                    continue

                if payload in base_body:
                    continue

                if payload in resp.text:
                    context, attr = self._reflection_context(resp.text, payload)
                    if not self._exploitable(payload, context, attr):
                        continue
                    self.reflected.append({
                        "url": url, "param": param, "payload": payload,
                        "context": f"{context}" + (f"[{attr}]" if attr else ""),
                        "context_snippet": self._get_context(resp.text, payload),
                        "encoding": "none",
                    })
                    vuln(self.console, f"XSS (Reflected, unencoded) @ {param} | {payload[:50]}")
                    return True

                if "<" in payload and ">" in payload:
                    tag_part = payload.split(">")[0] + ">"
                    if tag_part in base_body or tag_part in base_decoded:
                        continue
                    if tag_part in resp.text:
                        context, attr = self._reflection_context(resp.text, tag_part)
                        if not self._exploitable(tag_part, context, attr):
                            continue
                        self.reflected.append({
                            "url": url, "param": param, "payload": payload,
                            "context": f"{context}" + (f"[{attr}]" if attr else ""),
                            "context_snippet": self._get_context(resp.text, tag_part),
                            "encoding": "partial",
                        })
                        vuln(self.console, f"XSS (Partial Reflect) @ {param}")
                        return True

            except Exception:
                continue
        return False

    def test_form_xss(self, form: dict):
        action = form.get("action", self.target)
        method = form.get("method", "GET").upper()
        if method != "GET" and not self.intrusive:
            return False
        inputs = form.get("inputs", [])
        base_body = self._baseline_body(action)

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            if itype in ("hidden", "submit", "button", "image", "file"):
                continue

            for payload in XSS_PAYLOADS[:8]:
                try:
                    data = {}
                    for i in inputs:
                        if i["name"] == name:
                            data[i["name"]] = payload
                        else:
                            data[i["name"]] = i.get("value", "test")

                    if method == "POST":
                        self._record_injection()
                        resp = self.session.post(action, data=data, timeout=TIMEOUT)
                    else:
                        self._record_injection()
                        resp = self.session.get(action, params=data, timeout=TIMEOUT)
                    self.tested += 1

                    if not self._is_html_response(resp):
                        continue

                    if payload in resp.text and payload not in base_body:
                        context, attr = self._reflection_context(resp.text, payload)
                        if not self._exploitable(payload, context, attr):
                            continue
                        self.reflected.append({
                            "url": action, "param": f"form:{name}", "payload": payload,
                            "method": method,
                            "request_context": {"location": "form", "field": name},
                            "context": f"{context}" + (f"[{attr}]" if attr else ""),
                            "context_snippet": self._get_context(resp.text, payload),
                            "encoding": "none",
                        })
                        vuln(self.console, f"XSS (Form) @ {name} | {payload[:40]}")
                        return True
                except Exception:
                    continue
        return False

    def check_dom_sources(self, url: str, html: str):
        dangerous_sinks = [
            (r'document\.write\s*\(', "document.write"),
            (r'\.innerHTML\s*=', "innerHTML"),
            (r'\.outerHTML\s*=', "outerHTML"),
            (r'eval\s*\(', "eval"),
            (r'setTimeout\s*\(\s*["\']', "setTimeout with string"),
            (r'setInterval\s*\(\s*["\']', "setInterval with string"),
            (r'location\s*=', "location assignment"),
            (r'location\.href\s*=', "location.href"),
            (r'location\.replace\s*\(', "location.replace"),
            (r'location\.assign\s*\(', "location.assign"),
            (r'document\.cookie', "document.cookie access"),
            (r'\.insertAdjacentHTML\s*\(', "insertAdjacentHTML"),
            (r'document\.URL', "document.URL"),
            (r'document\.referrer', "document.referrer"),
            (r'window\.name', "window.name"),
            (r'document\.domain', "document.domain"),
        ]

        dangerous_sources = [
            r'location\.search', r'location\.hash', r'location\.href',
            r'document\.URL', r'document\.documentURI', r'document\.referrer',
            r'window\.name', r'document\.cookie',
        ]

        def linked_source(code, sink_match):
            
            
            
            prefix = code[:sink_match.start()]
            markers = [prefix.rfind("function "), prefix.rfind("=>"), prefix.rfind("{")]
            region_start = max(markers)
            region = code[max(0, region_start): min(len(code), sink_match.end() + 300)]
            sink_line = code[sink_match.start(): code.find(";", sink_match.start())]
            if any(re.search(source, sink_line) for source in dangerous_sources):
                return True

            before = region[: max(0, sink_match.start() - max(0, region_start))]
            for source in dangerous_sources:
                for assignment in re.finditer(
                        rf"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;]*{source}[^;]*;",
                        before):
                    variable = assignment.group(1)
                    if re.search(rf"\b{re.escape(variable)}\b", sink_line):
                        return True
            return False

        scripts = BeautifulSoup(html, "html.parser").find_all("script")
        for script in scripts:
            code = script.string or ""
            if not code.strip():
                continue

            for pattern, sink_name in dangerous_sinks:
                for context_match in re.finditer(pattern, code):
                    start = max(0, context_match.start() - 50)
                    end = min(len(code), context_match.end() + 50)
                    snippet = code[start:end].strip()
                    if not linked_source(code, context_match):
                        continue
                    self.dom_based.append({
                        "url": url, "sink": sink_name,
                        "context": snippet[:200],
                        "has_source": True,
                    })
                    vuln(self.console, f"DOM XSS: {sink_name} with user-controllable source")

    def _get_context(self, html: str, payload: str) -> str:
        idx = html.find(payload)
        if idx == -1:
            return "reflected"
        start = max(0, idx - 50)
        end = min(len(html), idx + len(payload) + 50)
        return html[start:end]

    def run(self, js_files=None, js_sinks=None) -> dict:
        targets = self.surface.injection_targets() if self.surface else self.params
        info(self.console, f"Testing XSS: {len(targets)} params, {len(self.forms)} forms...")

        if not targets and not self.forms:
            warning(
                self.console,
                "No URL parameters or forms were discovered - reflected XSS testing was NOT performed.",
            )

        for p in targets:
            url = p.get("url", self.target)
            param = p.get("param", "")
            if not param:
                continue
            if "?" not in url:
                url = f"{url}?{param}=test"
            info(self.console, f"Testing param: {param} (source: {p.get('source', 'crawl')})")
            self.test_reflected(url, param)

        for form in self.forms[:50]:
            self.test_form_xss(form)

        if js_sinks is not None:
            for sink in js_sinks:
                self.dom_based.append({
                    "url": sink.get("file", ""),
                    "sink": sink.get("sink"),
                    "context": sink.get("context", "")[:200],
                    "has_source": bool(sink.get("has_user_source")),
                    "sources": sink.get("sources", []),
                    "analyser": "tokenized",
                })
            reachable = [d for d in self.dom_based if d.get("has_source")]
            for item in reachable:
                vuln(self.console, f"DOM XSS (tokenized analysis): {item['sink']} <- "
                                   f"{', '.join(item.get('sources', []))} in "
                                   f"{os.path.basename(item['url'])}")
        else:
            for script_url, script_body in self._collect_scripts(js_files):
                self.check_dom_sources(script_url, script_body)

        success(self.console, f"XSS scan complete: {len(self.reflected)} reflected, {len(self.dom_based)} DOM-based")

        if self.reflected:
            rows = [(r["param"], r["payload"][:36], r.get("context", "-"), r.get("encoding", "-"))
                    for r in self.reflected]
            self.console.print(make_table("Reflected XSS", ["Param", "Payload", "Context", "Encoding"], rows))

        if self.dom_based:
            rows = [(d["sink"], "Yes" if d["has_source"] else "No", d["context"][:50]) for d in self.dom_based]
            self.console.print(make_table("DOM-Based XSS Sinks", ["Sink", "User Source?", "Context"], rows))

        total_known = len(self.surface.params()) if self.surface else len(self.params)
        return {
            "reflected": self.reflected,
            "dom_based": self.dom_based,
            "tested_count": self.tested,
            "params_considered": len(targets),
            "uncovered_params": max(0, total_known - len(targets)),
        }

    def _collect_scripts(self, js_files):
        scripts = []
        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            if resp is not None:
                for script in BeautifulSoup(resp.text, "html.parser").find_all("script"):
                    if script.string and script.string.strip():
                        scripts.append((self.target, script.string))
        except Exception:
            pass

        for js_url in (js_files or [])[:40]:
            try:
                resp = self.session.get(js_url, timeout=TIMEOUT)
                if resp is not None and resp.text:
                    scripts.append((js_url, resp.text))
            except Exception:
                continue

        if scripts:
            info(self.console, f"Scanning {len(scripts)} script(s) for DOM XSS sinks...")
        return scripts
