"""Optional browser-assisted rendering.

A single-page application can only be mapped completely by running it, but a
browser is a heavy dependency and an optional capability, not a requirement.  So
this module never imports a browser driver unless one is already installed and the
operator has explicitly asked for it: without ``--browser`` nothing here is
called, and without the driver the caller is told why in one line instead of
receiving a stack trace.

The rendered DOM is used for discovery only.  Nothing is submitted, no form is
filled in, and no script is injected: the page is loaded, its final DOM and the
requests it made are recorded, and that is all.
"""

from __future__ import annotations

import re

_ENGINES = ("playwright", "selenium")


_STATIC_SUFFIXES = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".woff", ".woff2", ".ttf", ".ico", ".map")

_TIMEOUT_SECONDS = 20
_MAX_HTML = 4_000_000
_MAX_REQUESTS = 512
_MAX_LINKS = 512
_MAX_URL = 8192


def availability() -> dict:
    """Report which driver is usable, without importing one that is not there."""
    try:
        import playwright.sync_api  
        return {"available": True, "engine": "playwright",
                "reason": "playwright is installed"}
    except Exception:
        pass
    try:
        import selenium  
        return {"available": True, "engine": "selenium",
                "reason": "selenium is installed"}
    except Exception:
        pass
    return {
        "available": False,
        "engine": "",
        "reason": ("no browser driver is installed; install playwright "
                   "(`python -m pip install playwright` then "
                   "`python -m playwright install chromium`) to enable rendering"),
    }


def _is_document(url: str) -> bool:
    path = str(url or "").split("?")[0].lower()
    return not path.endswith(_STATIC_SUFFIXES)


def _render_with_playwright(url: str, timeout: int) -> dict:
    from playwright.sync_api import sync_playwright

    requests, documents, limitations = [], [], []
    request_count = 0
    with sync_playwright() as play:
        
        
        
        browser = play.chromium.launch(headless=True,
            proxy={"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
            args=["--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                  "--disable-background-networking", "--disable-quic",
                  "--js-flags=--max-old-space-size=128"])
        try:
            context = browser.new_context(service_workers="block")
            context.add_init_script("""(() => {
                for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection']) {
                    Object.defineProperty(globalThis, name, {value: undefined, writable: false, configurable: false});
                }
            })();""")
            from core.http import RateLimitedSession
            session = RateLimitedSession()
            def fulfill(route):
                nonlocal request_count
                request = route.request
                request_count += 1
                if request_count > _MAX_REQUESTS:
                    if "browser request limit reached" not in limitations:
                        limitations.append("browser request limit reached")
                    route.abort()
                    return
                if request.method not in {"GET", "HEAD", "OPTIONS"}:
                    route.abort()
                    return
                response = None
                try:
                    response = session.request(request.method, request.url,
                                               allow_redirects=False, stream=True, timeout=timeout)
                    body = bytearray()
                    for chunk in response.iter_content(65536):
                        body.extend(chunk[:max(0, _MAX_HTML - len(body))])
                        if len(body) >= _MAX_HTML:
                            break
                    route.fulfill(status=response.status_code, body=bytes(body), headers={
                        key: value for key, value in response.headers.items()
                        if key.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection"}})
                except Exception:
                    route.abort()
                finally:
                    if response is not None:
                        response.close()
            context.route("**/*", fulfill)
            if not hasattr(context, "route_web_socket"):
                raise RuntimeError("installed Playwright cannot block WebSockets; upgrade the optional adapter")
            context.route_web_socket("**/*", lambda route: route.close())
            page = context.new_page()
            page.set_default_timeout(timeout * 1000)
            page.on("request", lambda request: requests.append(request.url[:_MAX_URL])
                    if len(requests) < _MAX_REQUESTS else None)
            page.goto(url, wait_until="load", timeout=timeout * 1000)
            
            
            
            html = page.evaluate("limit => document.documentElement.outerHTML.slice(0, limit)", _MAX_HTML)
            if not isinstance(html, str):
                raise ValueError("invalid browser HTML inventory")
            final_url = page.url
            try:
                links = page.evaluate("""limits => {
                    const result = [], els = document.links;
                    for (let index = 0; index < Math.min(els.length, limits[0]); index++) {
                        result.push((els[index].getAttribute('href') || '').slice(0, limits[1]));
                    }
                    return result;
                }""", [_MAX_LINKS, _MAX_URL])
            except Exception:
                links = []
                limitations.append("browser link inventory could not be extracted")
            if not isinstance(links, list) or any(not isinstance(link, str) for link in links[:_MAX_LINKS]):
                raise ValueError("invalid browser link inventory")
            if not isinstance(final_url, str):
                raise ValueError("invalid browser URL inventory")
            if (len(html) > _MAX_HTML or len(links) > _MAX_LINKS
                    or len(final_url) > _MAX_URL
                    or any(len(link) > _MAX_URL for link in links[:_MAX_LINKS])):
                limitations.append("browser output truncated by trusted retention limits")
            html = html[:_MAX_HTML]
            links = [link[:_MAX_URL] for link in links[:_MAX_LINKS] if link]
            final_url = final_url[:_MAX_URL]
        finally:
            try:
                browser.close()
            finally:
                if "session" in locals():
                    session.close()

    for item in requests:
        if item not in documents and _is_document(item):
            documents.append(item)
    return {
        "available": True,
        "engine": "playwright",
        "url": final_url or url,
        "html": html,
        "documents": documents,
        "links": links,
        "limitations": limitations + ["Chromium CPU, native memory and DOM execution are not OS bounded"],
    }


def render(url: str, timeout: int = _TIMEOUT_SECONDS) -> dict:
    """Load a page in a real browser and return what it produced.

    The return value always has an ``available`` key; when it is ``False`` the
    caller should treat the DOM as unobserved rather than as empty.
    """
    status = availability()
    if not status["available"]:
        return status
    try:
        if status["engine"] == "playwright":
            return _render_with_playwright(url, timeout)
        return {"available": False, "engine": status["engine"],
                "reason": "Selenium adapter cannot enforce centralized HTTP policy; use Playwright"}
    except Exception as exc:
        return {
            "available": False,
            "engine": status["engine"],
            "reason": f"{type(exc).__name__}: {exc}"[:300],
        }


def inline_scripts(html: str) -> tuple:
    """Inline script bodies from rendered HTML, for the existing analyser."""
    bodies = []
    for match in re.finditer(
            r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", str(html or ""),
            re.DOTALL | re.IGNORECASE):
        body = match.group(1).strip()
        if body:
            bodies.append(body)
    return tuple(bodies)


def script_sources(html: str) -> tuple:
    """External script URLs referenced by rendered HTML."""
    return tuple(
        match.group(1) for match in re.finditer(
            r"""<script[^>]*\bsrc=["']([^"']+)["']""", str(html or ""),
            re.IGNORECASE))
