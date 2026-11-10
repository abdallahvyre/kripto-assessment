"""SPA assessment: turn client-side route and chunk knowledge into endpoints.

``core.jscan`` already reads every bundle it can reach.  This module takes what
it produced and answers the two questions the crawler cannot: which routes exist
only in the client-side router, and which bundles load lazily and were therefore
never fetched.

Nothing here issues a request.  It reads text the run already retrieved, writes
endpoints onto the shared surface, and lets the existing crawler and injection
modules do the work - so a client route becomes a normal target with normal
coverage accounting instead of a special case.
"""

from __future__ import annotations

from core.spa import browser, chunks, routes


_PRIVILEGED_HINTS = ("admin", "manage", "internal", "staff", "settings", "account",
                     "billing", "debug", "console", "dashboard")


def _privileged(path: str) -> bool:
    lowered = str(path or "").lower()
    return any(hint in lowered for hint in _PRIVILEGED_HINTS)


class SpaAssessor:
    """Assess a single-page application's client-side structure."""

    def __init__(self, target: str, console, surface=None, max_routes: int = 300,
                 max_chunks: int = 100, use_browser: bool = False):
        self.target = target.rstrip("/")
        self.console = console
        self.surface = surface
        self.max_routes = max(1, int(max_routes))
        self.max_chunks = max(0, int(max_chunks))
        self.use_browser = bool(use_browser)

    

    def _register(self, path: str, source: str) -> str:
        """Register one client route on the surface; return its URL when added.

        The URL is returned rather than the path, so the report lists what was
        actually queued for crawling instead of a relative form the reader has
        to resolve themselves.
        """
        if not path or path == "/" or not path.startswith("/"):
            return ""
        if self.surface is None:
            return ""
        url = self.target + path
        return url if self.surface.add_endpoint(url, source) else ""

    

    def from_blobs(self, blobs) -> dict:
        """Extract routes and chunks from already-retrieved JavaScript."""
        extractions, route_urls, chunk_urls, manifests = [], [], [], {}
        for label, text in blobs or []:
            if not text:
                continue
            source_url = self.target + "/" + str(label).lstrip("/")
            if chunks.is_manifest(text):
                found = chunks.manifest_entries(text, self.target)
                if found:
                    manifests.update(found)
                for route in chunks.manifest_routes(text):
                    extractions.append(routes.extract(
                        '{"path": "%s"}' % route, source_url))
            extraction = routes.extract(text, source_url)
            if extraction["routes"] or extraction["has_router"]:
                extractions.append(extraction)
            chunk_urls.extend(chunks.chunk_urls(text, self.target))
            route_urls.extend(extraction["routes"])

        merged = routes.merge(extractions)
        return {
            "routes": merged["routes"],
            "templates": merged["templates"],
            "dynamic_templates": merged["dynamic_templates"],
            "has_router": merged["has_router"],
            "chunks": list(dict.fromkeys(chunk_urls))[: self.max_chunks],
            "manifest": manifests,
        }

    def from_scanner(self, scanner_result: dict) -> dict:
        """Fold in the routes the existing scanner already mined."""
        known = list((scanner_result or {}).get("routes") or [])
        templates, seen = [], set()
        for route in known:
            template = routes.normalise(route)
            if template not in seen:
                seen.add(template)
                templates.append(template)
        return {
            "scanner_routes": known,
            "scanner_templates": templates,
        }

    

    def register(self, inventory: dict) -> dict:
        """Register client routes and lazy chunks as crawlable endpoints."""
        registered_routes, registered_chunks = [], []
        dynamic = []

        for path in (inventory.get("routes") or [])[: self.max_routes]:
            if routes.is_dynamic(path):
                concrete = routes.concretise(path, "1")
                dynamic.append({"template": path, "probe": concrete,
                                "privileged": _privileged(concrete)})
                url = self._register(concrete, "spa-route")
            else:
                url = self._register(path, "spa-route")
            if url:
                registered_routes.append(url)

        for url in (inventory.get("chunks") or [])[: self.max_chunks]:
            if self.surface is None:
                break
            path = url.split(self.target, 1)[-1] or "/"
            if self.surface.add_endpoint(url, "spa-chunk", note=path):
                registered_chunks.append(url)

        return {
            "registered_routes": registered_routes,
            "registered_chunks": registered_chunks,
            "dynamic_routes": dynamic[:40],
        }

    def render_home(self) -> dict:
        """Render the landing page, when a driver exists and the operator opted in."""
        if not self.use_browser:
            return {"available": False, "reason": "browser rendering was not requested"}
        result = browser.render(self.target)
        if not result.get("available"):
            return result
        inventory = {
            "documents": result.get("documents") or [],
            "links": result.get("links") or [],
            "inline_scripts": list(browser.inline_scripts(result.get("html", ""))),
            "script_sources": list(browser.script_sources(result.get("html", ""))),
        }
        for url in inventory["documents"]:
            self._register(url.split(self.target, 1)[-1], "browser-document")
        return {"available": True, "engine": result.get("engine"),
                "limitations": list(result.get("limitations") or []), **inventory}

    

    def run(self, blobs=None, scanner_result=None) -> dict:
        inventory = self.from_blobs(blobs)
        merged = self.from_scanner(scanner_result)
        if merged["scanner_templates"]:
            seen = set(inventory["templates"])
            for template in merged["scanner_templates"]:
                if template not in seen:
                    seen.add(template)
                    inventory["templates"].append(template)
            inventory["routes"] = list(dict.fromkeys(
                list(inventory["routes"]) + merged["scanner_routes"]))

        registration = self.register(inventory)
        rendered = self.render_home()

        privileged = [item for item in registration["dynamic_routes"] if item["privileged"]]
        privileged += [{"path": path, "privileged": True}
                       for path in inventory["routes"] if _privileged(path)][:20]

        report = {
            "has_client_router": bool(inventory["has_router"]),
            "route_count": len(inventory["routes"]),
            "routes": inventory["routes"][: self.max_routes],
            "templates": inventory["templates"][: self.max_routes],
            "dynamic_routes": registration["dynamic_routes"],
            "privileged_routes": privileged[:40],
            "chunk_count": len(inventory["chunks"]),
            "chunks": inventory["chunks"],
            "manifests": {route: files[:5] for route, files in
                          list(inventory["manifest"].items())[:40]},
            "registered_routes": registration["registered_routes"],
            "registered_chunks": registration["registered_chunks"],
            "browser": rendered,
            "notes": [],
        }

        if not report["has_client_router"] and not report["route_count"]:
            report["notes"].append(
                "No client-side router was identified, so route discovery came only "
                "from literal paths in fetched scripts.")
        if report["privileged_routes"]:
            report["notes"].append(
                f"{len(report['privileged_routes'])} client-side route(s) read as "
                "privileged. Hiding a route in the client bundle does not restrict "
                "access; they were registered for authorization testing.")
        if report["chunk_count"] and self.max_chunks == 0:
            report["notes"].append("Lazy chunks were found but chunk following is disabled.")
        if rendered.get("available") is False and rendered.get("reason"):
            report["notes"].append(f"Browser rendering: {rendered['reason']}")
        report["notes"].extend(f"Browser rendering: {note}" for note in rendered.get("limitations") or [])
        return report
