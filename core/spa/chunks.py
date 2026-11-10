"""Discovery of lazily-loaded JavaScript chunks.

A single-page application usually ships its route components as separate chunks
that the initial HTML never references.  ``core.jscan`` follows bundles it can
see; this module finds the ones it cannot, by reading the three places a bundler
publishes its chunk map:

* the build manifest Next.js serves (``_buildManifest.js``);
* dynamic ``import("...")`` / ``require.ensure`` calls carrying a filename;
* literal chunk paths in the bundler's public path (``static/js/``, ``_nuxt/``).

Every URL returned is absolute and already de-duplicated, so the caller can queue
them straight into the bundle budget.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin


_DYNAMIC_IMPORT = re.compile(
    r"""\bimport\s*\(\s*(?:/\*.*?\*/\s*)?(["'])([^"']{1,300}?\.m?js)\1""",
    re.DOTALL)


_REQUIRE_ENSURE = re.compile(r"""require\.ensure\s*\(""", re.IGNORECASE)


_CHUNK_LITERAL = re.compile(
    r"""["']((?:static|_next|_nuxt|assets|js|chunks)/[A-Za-z0-9._~\-/]{1,200}?\.m?js)["']""")


_MANIFEST_ENTRY = re.compile(
    r"""["'](/[^"']*)["']\s*:\s*\[([^\]]{1,2000})\]""")


_LOAD_CHILDREN = re.compile(
    r"""loadChildren\s*:\s*\(\)\s*=>\s*import\s*\(\s*(["'])([^"']{1,300})\1""")


_QUOTED = re.compile(r"""["']([^"']{1,300})["']""")

_MAX_CHUNKS = 200


def _absolute(base_url: str, candidate: str) -> str:
    text = str(candidate or "").strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text
    if text.startswith("//"):
        return "https:" + text
    if not text.startswith("/"):
        text = "/" + text
    return urljoin(base_url, text)


def chunk_urls(code: str, base_url: str) -> tuple:
    """Absolute URLs of chunks the code references but the page may not load."""
    text = str(code or "")
    seen, urls = set(), []

    def add(candidate: str):
        if len(urls) >= _MAX_CHUNKS:
            return
        absolute = _absolute(base_url, candidate)
        if not absolute or absolute in seen:
            return
        if not absolute.split("?")[0].endswith((".js", ".mjs")):
            return
        seen.add(absolute)
        urls.append(absolute)

    for match in _DYNAMIC_IMPORT.finditer(text):
        add(match.group(2))
    for match in _LOAD_CHILDREN.finditer(text):
        add(match.group(2))
    for match in _CHUNK_LITERAL.finditer(text):
        add(match.group(1))

    return tuple(urls)


def manifest_entries(code: str, base_url: str) -> dict:
    """Route-to-chunk mapping from a Next.js style build manifest.

    Returns ``{route: [absolute chunk urls]}``.  A manifest is the most reliable
    source of *which* chunk belongs to *which* route, which is what makes a
    lazily-loaded admin bundle findable at all.
    """
    mapping = {}
    for match in _MANIFEST_ENTRY.finditer(str(code or "")):
        route = str(match.group(1) or "")
        if not route.startswith("/"):
            continue
        chunks = []
        for quoted in _QUOTED.finditer(match.group(2)):
            absolute = _absolute(base_url, quoted.group(1))
            if absolute and absolute.split("?")[0].endswith((".js", ".mjs")):
                chunks.append(absolute)
        if chunks:
            mapping[route] = chunks
    return mapping


def manifest_routes(code: str) -> tuple:
    """Route paths mentioned by a build manifest, in declaration order."""
    routes = []
    for match in _MANIFEST_ENTRY.finditer(str(code or "")):
        route = str(match.group(1) or "")
        if route.startswith("/") and route not in routes:
            routes.append(route)
    return tuple(routes)


def is_manifest(code: str) -> bool:
    """Whether this text looks like a build manifest rather than application code."""
    text = str(code or "")
    if "BUILD_MANIFEST" in text or "_buildManifest" in text:
        return True
    return bool(re.search(r"""["']/[^"']*["']\s*:\s*\[\s*["']static/""", text))


def looks_like_chunk_loader(code: str) -> bool:
    """Whether a bundle loads further bundles instead of carrying them."""
    text = str(code or "")
    return bool(_REQUIRE_ENSURE.search(text)) or bool(_DYNAMIC_IMPORT.search(text))
