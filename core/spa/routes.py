"""Client-side route extraction from framework router configurations.

``core.jparse`` already mines paths from JavaScript using a small tokenizer, and
``core.jscan`` normalises them.  What neither does is understand the *shape* of a
router declaration, where the useful route is a value in an object next to a
``component`` key and the same string literal appears nowhere near a URL.  That
is what this module reads: React Router, Vue Router, Angular routing modules and
Next.js page paths, in both the ``{path: "/x"}`` and ``path: 'x'`` spellings.
"""

from __future__ import annotations

import re



_BRACE_ROUTE = re.compile(
    r"""\{\s*["']?path["']?\s*:\s*(["'`])([^"'`]{1,200}?)\1""", re.IGNORECASE)


_BARE_ROUTE = re.compile(
    r"""["']?\bpath["']?\s*:\s*(["'`])([^"'`]{1,200}?)\1""", re.IGNORECASE)


_ROUTES_KEY = re.compile(r"\broutes\s*[:=]", re.IGNORECASE)


_ROUTE_CONSTANT = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(\[|\{)""")


_NEXT_DYNAMIC = re.compile(r"\[(\.\.\.)?([A-Za-z0-9_-]+)\]")


_PARAM_SEGMENT = re.compile(r"^(?::[A-Za-z_][\w]*|\[[^\]]+\]|\{[^}]+\}|\*)$")

_MAX_ROUTES = 400


def _clean(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    
    text = re.sub(r"/{2,}", "/", text)
    return text.rstrip("/") or "/"


def is_dynamic(route: str) -> bool:
    """Whether a route template carries a parameter segment."""
    return any(_PARAM_SEGMENT.match(segment)
               for segment in str(route or "").split("/") if segment)


def normalise(route: str) -> str:
    """One canonical spelling for parameter segments.

    ``/orders/:id``, ``/orders/{id}``, ``/orders/[id]`` and ``/orders/*`` all
    describe the same shape, so they collapse to ``/orders/:id``.
    """
    cleaned = _clean(route)
    segments = []
    for segment in cleaned.split("/"):
        if not segment:
            continue
        if _PARAM_SEGMENT.match(segment):
            segments.append(":id")
        else:
            segments.append(segment)
    return "/" + "/".join(segments) if segments else "/"


def concretise(route: str, value: str = "1") -> str:
    """Turn a template into a requestable path for a read-only probe."""
    segments = []
    for segment in str(route or "").split("/"):
        if not segment:
            continue
        segments.append(value if _PARAM_SEGMENT.match(segment) else segment)
    return "/" + "/".join(segments) if segments else "/"


def next_page_route(path: str) -> str:
    """Infer a route from a Next.js page file path.

    ``pages/orders/[id].tsx`` becomes ``/orders/:id`` so it can be probed like
    any other client route.
    """
    text = str(path or "").replace("\\", "/").strip()
    for prefix in ("pages/", "app/", "./pages/", "./app/"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    text = re.sub(r"\.(?:tsx?|jsx?|vue|svelte)$", "", text)
    text = re.sub(r"/(?:index)$", "", text)
    if text in ("index", ""):
        return "/"
    text = _NEXT_DYNAMIC.sub(lambda match: ":" + match.group(2), text)
    return _clean(text)


def extract(code: str, origin: str = "") -> dict:
    """Every route a chunk of JavaScript declares.

    Returns ``{"routes": [...], "templates": [...], "has_router": bool}`` where
    ``routes`` holds the literal declarations and ``templates`` the normalised,
    de-duplicated forms.
    """
    text = str(code or "")
    found = []

    has_router = bool(_ROUTES_KEY.search(text)) or bool(_ROUTE_CONSTANT.search(text))

    for match in _BRACE_ROUTE.finditer(text):
        found.append(match.group(2))
    for match in _BARE_ROUTE.finditer(text):
        found.append(match.group(2))

    routes, templates, seen_routes, seen_templates = [], [], set(), set()
    for raw in found:
        if len(routes) >= _MAX_ROUTES:
            break
        cleaned = _clean(raw)
        if not cleaned or cleaned == "/":
            continue
        if cleaned not in seen_routes:
            seen_routes.add(cleaned)
            routes.append(cleaned)
        template = normalise(cleaned)
        if template not in seen_templates:
            seen_templates.add(template)
            templates.append(template)

    return {
        "origin": origin,
        "has_router": has_router,
        "routes": routes,
        "templates": templates,
    }


def merge(extractions) -> dict:
    """Combine per-chunk extractions into one route inventory."""
    routes, templates = [], []
    seen_routes, seen_templates = set(), set()
    has_router = False
    for item in extractions or []:
        if not isinstance(item, dict):
            continue
        has_router = has_router or bool(item.get("has_router"))
        for route in item.get("routes") or []:
            if route not in seen_routes:
                seen_routes.add(route)
                routes.append(route)
        for template in item.get("templates") or []:
            if template not in seen_templates:
                seen_templates.add(template)
                templates.append(template)
    return {
        "has_router": has_router,
        "routes": routes,
        "templates": templates,
        "dynamic_templates": [t for t in templates if is_dynamic(t)],
    }
