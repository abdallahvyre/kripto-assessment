"""API authorization selection.

This module deliberately contains no authorization *checks*.  ``core.access``
already decides whether an object answer belongs to the right identity, and a
second implementation of that reasoning would eventually disagree with the
first one.  What the API layer adds is the addresses: a documented
``/orders/{orderId}`` is turned into a concrete ``/orders/1`` and registered on
the shared surface, which is exactly the form ``core.access`` selects as an
object carrier.  The existing checks then cover the API routes for free.
"""

from __future__ import annotations

import re




ID_PLACEHOLDERS = ("1", "2")


UUID_PLACEHOLDER = "00000000-0000-4000-8000-000000000001"

ADMIN_PATH = re.compile(
    r"(admin|manage|manager|internal|staff|superuser|backoffice|console|"
    r"users?|roles?|permissions?|tenants?|audit|config|settings)", re.IGNORECASE)

_BRACE_TOKEN = re.compile(r"\{([^}]+)\}")
_COLON_TOKEN = re.compile(r"(?<=/):([A-Za-z_]\w*)")
_UUID_NAME = re.compile(r"(uuid|guid)", re.IGNORECASE)


def _placeholder(name: str, position: int, placeholders) -> str:
    if _UUID_NAME.search(name):
        return UUID_PLACEHOLDER
    return placeholders[min(position, len(placeholders) - 1)]


def concrete_urls(operation, placeholders=ID_PLACEHOLDERS) -> tuple:
    """Every concrete URL a documented path template stands for."""
    path = operation.path
    brace_names = _BRACE_TOKEN.findall(path)
    colon_names = _COLON_TOKEN.findall(path)
    if not brace_names and not colon_names:
        return (operation.url,)

    rendered = path
    for position, name in enumerate(brace_names):
        rendered = rendered.replace("{" + name + "}",
                                    _placeholder(name, position, placeholders))
    for position, name in enumerate(colon_names):
        rendered = _COLON_TOKEN.sub(
            lambda match: "/" + _placeholder(match.group(1), position, placeholders),
            rendered, count=1)

    if rendered == path:
        return (operation.url,)
    return (operation.url.replace(path, rendered),)


def is_admin_like(operation) -> bool:
    """Whether an operation reads as a privileged or management surface."""
    haystack = f"{operation.path} {operation.operation_id}"
    return bool(ADMIN_PATH.search(haystack))


def materialise(spec, surface, limit: int = 80) -> dict:
    """Register concrete API routes so the access module can select them."""
    report = {
        "concrete_endpoints": 0,
        "object_operations": 0,
        "admin_operations": [],
        "unverified": [],
    }
    if spec is None or surface is None:
        report["unverified"].append(
            "No specification was parsed, so no documented API routes were "
            "registered for authorization testing.")
        return report

    added = 0
    for operation in spec.operations:
        if added >= limit:
            report["unverified"].append(
                f"Authorization selection stopped at the {limit}-operation limit.")
            break
        if operation.method not in ("GET", "HEAD"):
            
            
            continue

        for url in concrete_urls(operation):
            if surface.add_endpoint(url, "api-spec", methods=[operation.method],
                                    note=operation.path):
                added += 1
                report["concrete_endpoints"] += 1

        if operation.path_parameters:
            report["object_operations"] += 1
        if is_admin_like(operation):
            report["admin_operations"].append({
                "method": operation.method,
                "path": operation.path,
                "url": operation.url,
                "requires_auth": operation.requires_auth,
            })

    if report["admin_operations"]:
        report["unverified"].append(
            "Privileged API operations were identified, but Broken Function Level "
            "Authorization cannot be confirmed without a low-privilege identity to "
            "compare against. They are listed for manual verification, not reported "
            "as findings.")
    return report
