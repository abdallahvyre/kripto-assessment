"""Additional deterministic assessment functions; passive functions perform no I/O."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from core.redact import redact_secret, redact_text


def finding(kind, title, target, evidence, *, severity="low", variant="", verification="CONFIRMED"):
    return dict(kind=kind, title=title, target=target, evidence=evidence,
                severity=severity, verification=verification, fingerprint_variant=variant)


def header_analysis(headers, target):
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    items = []
    csp = headers.get("content-security-policy", "")
    directives = dict((part.strip().split(None, 1) + [""])[:2]
                      for part in csp.split(";") if part.strip())
    script = directives.get("script-src", directives.get("default-src", ""))
    if script and any(value in script.split() for value in ("*", "'unsafe-eval'")):
        items.append(finding("weak-csp", "Permissive script policy", target, script,
                             variant="script-src"))
    if "'unsafe-inline'" in script.split() and not re.search(r"'(?:nonce-|sha(?:256|384|512)-)", script):
        items.append(finding("weak-csp", "Inline scripts permitted without nonce or hash", target,
                             script, variant="unsafe-inline"))
    if target.startswith("https:") and "strict-transport-security" in headers:
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", headers["strict-transport-security"], re.I)
        if not match or int(match[1]) == 0:
            items.append(finding("weak-hsts", "HSTS is invalid or disabled", target,
                                 headers["strict-transport-security"]))
    return {"findings": items, "frame_protection": bool("frame-ancestors" in directives or
            headers.get("x-frame-options", "").upper() in {"DENY", "SAMEORIGIN"})}


def dns_analysis(records, target):
    txt = [str(value).strip('"') for value in (records or {}).get("TXT", [])]
    spf = [value for value in txt if value.lower().startswith("v=spf1")]
    items = []
    if len(spf) > 1:
        items.append(finding("dns-policy", "Multiple SPF records invalidate SPF", target,
                             f"{len(spf)} SPF policies", variant="multiple-spf"))
    for value in spf:
        if "+all" in value.split():
            items.append(finding("dns-policy", "SPF authorizes every sender", target, value,
                                 variant="spf-all"))
    return {"findings": items, "dnssec": "DS record observed; validation not performed" if
            records.get("DS") else "DNSSEC delegation not established by collected records",
            "limitations": ["No zone transfer, mail delivery or DNSSEC chain validation performed."]}


def technology_analysis(headers, blobs):
    signatures = {"WordPress": r"wp-content/|wp-includes/", "Next.js": r"__NEXT_DATA__|/_next/",
                  "React": r"data-reactroot|react-dom", "Angular": r"ng-version=|angular(?:\.min)?\.js",
                  "Vue": r"vue(?:\.min)?\.js|data-v-[0-9a-f]{6,}"}
    content = "\n".join(str(blob[1] if isinstance(blob, (tuple, list)) else blob)[:256000]
                         for blob in list(blobs or [])[:100])
    technologies = [{"name": name, "confidence": "signature", "version": None}
                    for name, pattern in signatures.items() if re.search(pattern, content, re.I)]
    for key in ("Server", "X-Powered-By"):
        value = next((v for k, v in (headers or {}).items() if k.lower() == key.lower()), None)
        if value:
            technologies.append({"name": redact_text(value), "confidence": "declared header",
                                 "version": None})
    return {"technologies": technologies, "limitations": ["Signatures are inventory, not proof of vulnerable versions."]}


def passive_secrets(blobs, target):
    patterns = [("private-key", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----"),
                ("aws-key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
                ("github-token", r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")]
    items, seen = [], set()
    for blob in list(blobs or [])[:100]:
        source, text = blob if isinstance(blob, (tuple, list)) and len(blob) == 2 else (target, blob)
        for label, pattern in patterns:
            for match in re.finditer(pattern, str(text)[:256000]):
                digest = hashlib.sha256(match[0].encode()).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                items.append(finding("secret-leak", f"{label} in collected content", target,
                                     redact_secret(match[0], label), variant=digest,
                                     severity="high", verification="POTENTIAL"))
    return {"findings": items, "limitations": ["Secret validity is not tested; no credential use or external calls."]}


def websocket_assessment(target, session, active=False):
    if not active:
        return {"skipped": True, "reason": "WebSocket handshake requires active authorization", "findings": []}
    key = base64.b64encode(b"kripto-ws-check!").decode()
    expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    response = session.get(target, allow_redirects=False, request_headers={"Connection": "Upgrade",
            "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key,
            "Origin": "https://kripto-origin.invalid"}, stream=True)
    try:
        supported = response.status_code == 101
        accept = response.headers.get("Sec-WebSocket-Accept", "") == expected
        items = [finding("websocket-protocol", "Invalid WebSocket handshake accepted", target,
                         "HTTP 101 without the expected accept hash")] if supported and not accept else []
        return {"supported": supported, "status": response.status_code, "accept_valid": accept,
                "cross_origin_upgrade": supported, "findings": items,
                "limitations": ["Upgrade acceptance alone does not establish cross-site WebSocket hijacking.",
                                "No frames, data extraction or exhaustion probes sent."]}
    finally:
        response.close()


_ADVISORIES = {"jquery": [("3.5.0", "CVE-2020-11022")],
               "lodash": [("4.17.21", "CVE-2021-23337")]}


def _version(value):
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", str(value)):
        return None
    return tuple((list(map(int, value.split("."))) + [0] * 4)[:4])


def dependency_audit(path, target):
    path = Path(path)
    if path.stat().st_size > 2_000_000:
        raise ValueError("dependency manifest exceeds 2 MB")
    data = json.loads(path.read_text(encoding="utf-8"))
    dependencies = []
    for location, item in data.get("packages", {}).items():
        if location and isinstance(item, dict) and "node_modules/" in location:
            dependencies.append((item.get("name") or location.rsplit("node_modules/", 1)[-1], item.get("version")))
    def visit(items, depth=0):
        if depth > 20:
            raise ValueError("dependency tree nesting limit reached")
        for name, item in items.items():
            if isinstance(item, dict):
                dependencies.append((name, item.get("version")))
                visit(item.get("dependencies", {}), depth + 1)
    if not data.get("packages"):
        visit(data.get("dependencies", {}))
    items = []
    for name, version in sorted(set(dependencies)):
        actual = _version(version)
        for fixed, cve in _ADVISORIES.get(name.lower(), []):
            if actual is not None and actual < _version(fixed):
                items.append(finding("dependency-advisory", f"{name} {version}: {cve}", target,
                                     f"Exact lock version matches advisory; fixed in {fixed}. Runtime reachability untested.",
                                     variant=f"{name}:{cve}", severity="medium", verification="POTENTIAL"))
    return {"findings": items, "dependencies": len(set(dependencies)),
            "limitations": ["Offline npm lockfile review with a small curated advisory set, not comprehensive CVE coverage."]}


def cloud_audit(path, target):
    path = Path(path)
    if path.stat().st_size > 2_000_000:
        raise ValueError("cloud configuration exceeds 2 MB")
    data = json.loads(path.read_text(encoding="utf-8"))
    items = []
    for name, resource in data.get("Resources", {}).items():
        if resource.get("Type") != "AWS::S3::Bucket":
            continue
        properties = resource.get("Properties", {})
        if properties.get("AccessControl") in {"PublicRead", "PublicReadWrite"}:
            items.append(finding("cloud-config", f"S3 bucket {name} declares a public ACL", target,
                                 f"AccessControl={properties['AccessControl']}; effective account policy unverified",
                                 variant=name, verification="POTENTIAL"))
    return {"findings": items, "limitations": ["Supplied CloudFormation JSON only; effective provider policy and intent require owner validation.",
            "No cloud API, metadata endpoint or remote bucket probing."]}
