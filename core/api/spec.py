"""Structured OpenAPI / Swagger model.

``core.intel`` already extracts the paths and parameter names from a spec it
happens to find, which is all the crawler needs.  The assessment itself needs
what that extraction throws away: whether an operation *declares* that it
requires authentication, where each parameter lives, and what a request body is
shaped like.  Without those, "the API answered without a session" cannot be
told apart from "this operation was documented as public".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


_PARAMETER_POOLS = (("components", "parameters"), ("parameters",))
_SCHEME_POOLS = (("components", "securitySchemes"), ("securityDefinitions",))

_PATH_TOKEN = re.compile(r"\{([^}]+)\}|:([A-Za-z_]\w*)")

_SENSITIVE_BODY_FIELDS = re.compile(
    r"(pass|pwd|secret|token|api[-_]?key|credit|card|cvv|ssn|salary|role|admin|"
    r"is_?admin|permission|balance|owner)", re.IGNORECASE)


def _dig(document: dict, path: tuple):
    """Follow a nested key path, returning None when any step is missing."""
    node = document
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


@dataclass(frozen=True)
class ApiParameter:
    """One documented parameter."""

    name: str
    location: str = "query"
    required: bool = False
    schema_type: str = ""
    enum_values: tuple = ()

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "in": self.location,
            "required": self.required,
            "type": self.schema_type,
            "enum": list(self.enum_values),
        }


@dataclass(frozen=True)
class ApiOperation:
    """One documented method on one documented path."""

    method: str
    path: str
    url: str
    operation_id: str = ""
    parameters: tuple = ()
    body_properties: tuple = ()
    security_declared: bool = False
    security_schemes: tuple = ()
    deprecated: bool = False
    responses: tuple = ()

    @property
    def requires_auth(self) -> bool:
        """True only when the document says this operation needs a credential.

        An operation with no ``security`` key inherits the global requirement,
        which the parser has already folded in, so this is a plain read.
        """
        return bool(self.security_declared and self.security_schemes)

    @property
    def path_parameters(self) -> tuple:
        """Parameters that appear in the path template, in template order."""
        return tuple(p for p in self.parameters if p.location == "path")

    @property
    def sensitive_body_fields(self) -> tuple:
        return tuple(name for name in self.body_properties
                     if _SENSITIVE_BODY_FIELDS.search(name))

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "url": self.url,
            "operation_id": self.operation_id,
            "parameters": [p.as_dict() for p in self.parameters],
            "body_properties": list(self.body_properties),
            "requires_auth": self.requires_auth,
            "deprecated": self.deprecated,
            "responses": list(self.responses),
        }


@dataclass(frozen=True)
class ApiSpec:
    """A parsed specification, normalised across 2.0 and 3.x."""

    source_url: str
    title: str = ""
    version: str = ""
    spec_version: str = ""
    base_url: str = ""
    servers: tuple = ()
    security_schemes: tuple = ()
    global_security: tuple = ()
    operations: tuple = ()
    document: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def is_swagger2(self) -> bool:
        return str(self.spec_version).startswith("2")

    def operations_for(self, method: str = None) -> tuple:
        if not method:
            return self.operations
        wanted = method.upper()
        return tuple(op for op in self.operations if op.method == wanted)

    def object_operations(self) -> tuple:
        """Operations whose path carries an identifier - BOLA candidates."""
        return tuple(op for op in self.operations if op.path_parameters)

    def documented_private_operations(self) -> tuple:
        return tuple(op for op in self.operations if op.requires_auth)

    def summary(self) -> dict:
        by_method = {}
        for op in self.operations:
            by_method[op.method] = by_method.get(op.method, 0) + 1
        return {
            "source": self.source_url,
            "title": self.title,
            "version": self.version,
            "spec_version": self.spec_version,
            "base_url": self.base_url,
            "operations": len(self.operations),
            "by_method": by_method,
            "object_operations": len(self.object_operations()),
            "private_operations": len(self.documented_private_operations()),
            "security_schemes": list(self.security_schemes),
        }


def _origin(url: str) -> str:
    parsed = urlparse(str(url or ""))
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def _join(origin: str, base: str, path: str) -> str:
    """Resolve a documented path against the spec's base and the scan origin."""
    base = str(base or "").rstrip("/")
    path = str(path or "")
    if base.startswith(("http://", "https://")):
        return base + path
    if base:
        candidate = f"{origin}/{base.lstrip('/')}"
        return candidate + path
    return origin + path


def _normalise_type(schema: dict) -> str:
    if not isinstance(schema, dict):
        return ""
    declared = schema.get("type")
    if isinstance(declared, list):
        declared = declared[0] if declared else ""
    if not declared and isinstance(schema.get("properties"), dict):
        return "object"
    return str(declared or "")


def _schema_properties(schema: dict) -> tuple:
    """Property names of an object schema, resolving one level of $ref."""
    if not isinstance(schema, dict):
        return ()
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return tuple(properties.keys())
    for combinator in ("allOf", "anyOf", "oneOf"):
        parts = schema.get(combinator)
        if isinstance(parts, list):
            collected = []
            for part in parts:
                collected.extend(_schema_properties(part))
            if collected:
                return tuple(dict.fromkeys(collected))
    return ()


def _collect_parameters(document: dict, operation: dict,
                        path_level: list, origin: str) -> tuple:
    """Merge path-level and operation-level parameters, resolving $ref."""
    pool = {}
    for candidate in _PARAMETER_POOLS:
        found = _dig(document, candidate)
        if isinstance(found, dict):
            pool.update(found)

    parameters = []
    seen = set()
    for raw in list(path_level or []) + list(operation.get("parameters") or []):
        if not isinstance(raw, dict):
            continue
        resolved = raw
        ref = raw.get("$ref")
        if ref:
            resolved = pool.get(str(ref).split("/")[-1]) or {}
        name = resolved.get("name")
        if not name:
            continue
        location = str(resolved.get("in") or "query")
        if (name, location) in seen:
            continue
        seen.add((name, location))
        schema = resolved.get("schema") if isinstance(resolved.get("schema"), dict) else {}
        schema_type = _normalise_type(schema) or str(resolved.get("type") or "")
        enum_values = schema.get("enum") or resolved.get("enum") or []
        parameters.append(ApiParameter(
            name=str(name),
            location=location,
            required=bool(resolved.get("required")),
            schema_type=schema_type,
            enum_values=tuple(str(v) for v in enum_values if v is not None),
        ))
    return tuple(parameters)


def _body_properties(document: dict, operation: dict) -> tuple:
    """Fields a client may send, across 2.0 form/body and 3.x requestBody."""
    names = []

    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict):
                    names.extend(_schema_properties(media.get("schema")))

    schema = operation.get("schema")
    if isinstance(schema, dict):
        names.extend(_schema_properties(schema))

    for raw in operation.get("parameters") or []:
        if not isinstance(raw, dict):
            continue
        resolved = raw
        ref = raw.get("$ref")
        if ref:
            resolved = _dig(document, ("parameters",)) or {}
            resolved = resolved.get(str(ref).split("/")[-1]) or {}
        if resolved.get("in") != "body":
            continue
        names.extend(_schema_properties(resolved.get("schema")))

    return tuple(dict.fromkeys(name for name in names if name))


def _security_of(document: dict, operation: dict, global_security: tuple):
    """Resolve the security requirement that applies to one operation."""
    if "security" in operation:
        entries = operation.get("security")
        if entries is None:
            return True, ()
        if not isinstance(entries, list):
            return True, ()
        if not entries:
            
            return False, ()
        return True, tuple(_scheme_names(entries))
    return bool(global_security), tuple(global_security)


def _scheme_names(entries) -> list:
    names = []
    for entry in entries or []:
        if isinstance(entry, dict):
            names.extend(str(key) for key in entry.keys())
    return list(dict.fromkeys(names))


def _base_url(document: dict, origin: str) -> str:
    servers = document.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict) and server.get("url"):
                url = str(server["url"])
                if url.startswith(("http://", "https://")):
                    return url.rstrip("/")
                return f"{origin}/{url.strip('/')}".rstrip("/")
    host = document.get("host")
    if host:
        schemes = document.get("schemes") or ["https"]
        scheme = "https" if str(schemes[0]).lower() == "https" else "http"
        base = f"{scheme}://{host}"
        base_path = str(document.get("basePath") or "").rstrip("/")
        return base + base_path
    return ""


def parse_spec(text: str, source_url: str, origin: str = "", limit: int = 500) -> ApiSpec:
    """Parse an OpenAPI 3.x or Swagger 2.0 document.

    ``limit`` bounds how many operations are modelled; a specification is
    attacker-supplied input, so its size never becomes the scan's size.
    """
    document = None
    try:
        document = json.loads(text)
    except (TypeError, ValueError):
        document = _parse_yaml_paths(text)
    if not isinstance(document, dict):
        return ApiSpec(source_url=source_url)

    origin = origin or _origin(source_url)
    spec_version = str(document.get("openapi") or document.get("swagger") or "")

    schemes = []
    for pool in _SCHEME_POOLS:
        found = _dig(document, pool)
        if isinstance(found, dict):
            schemes.extend(found.keys())
    schemes = list(dict.fromkeys(schemes))

    global_requirement = document.get("security")
    global_security = tuple(_scheme_names(global_requirement))\
        if isinstance(global_requirement, list) else ()

    base = _base_url(document, origin)
    info = document.get("info") if isinstance(document.get("info"), dict) else {}

    operations = []
    paths = document.get("paths")
    if isinstance(paths, dict):
        for raw_path, path_item in paths.items():
            if len(operations) >= limit:
                break
            path = str(raw_path)
            if not path.startswith("/") or not isinstance(path_item, dict):
                continue
            path_level = path_item.get("parameters") or []
            for method in path_item.keys():
                if len(operations) >= limit:
                    break
                if str(method).lower() not in HTTP_METHODS:
                    continue
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                declared, required_schemes = _security_of(
                    document, operation, global_security)
                parameters = list(_collect_parameters(
                    document, operation, path_level, origin))
                documented_names = {p.name for p in parameters}
                for token in _PATH_TOKEN.findall(path):
                    name = next((value for value in token if value), "")
                    if name and name not in documented_names:
                        parameters.append(ApiParameter(
                            name=name, location="path", required=True))

                responses = tuple(str(code) for code in
                                  (operation.get("responses") or {}).keys())

                operations.append(ApiOperation(
                    method=str(method).upper(),
                    path=path,
                    url=_join(origin, base, path),
                    operation_id=str(operation.get("operationId") or ""),
                    parameters=tuple(parameters),
                    body_properties=_body_properties(document, operation),
                    security_declared=declared,
                    security_schemes=required_schemes,
                    deprecated=bool(operation.get("deprecated")),
                    responses=responses,
                ))

    return ApiSpec(
        source_url=source_url,
        title=str(info.get("title") or ""),
        version=str(info.get("version") or ""),
        spec_version=spec_version,
        base_url=base,
        servers=tuple(str(s.get("url")) for s in (document.get("servers") or [])
                      if isinstance(s, dict) and s.get("url")),
        security_schemes=tuple(schemes),
        global_security=global_security,
        operations=tuple(operations),
        document=document,
    )


def _parse_yaml_paths(text: str) -> dict:
    """Recover paths and methods from an ``openapi.yaml`` without a dependency.

    Only the two levels the assessment needs are read: a ``/path:`` key at
    indentation 2 and its method keys at indentation 4.  Anything else in the
    document is ignored rather than guessed at.
    """
    paths: dict = {}
    current = None
    for raw in str(text or "").splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if indent == 2 and stripped.startswith("/"):
            current = stripped.split(":")[0].strip().strip("'\"")
            if current:
                paths.setdefault(current, {})
        elif indent == 4 and current and re.match(
                r"^(get|put|post|delete|options|head|patch|trace):", stripped, re.I):
            paths[current][stripped.split(":")[0].lower()] = {}
    if not paths:
        return {}
    return {"paths": paths}
