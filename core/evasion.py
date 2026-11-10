"""Request-level evasion helpers used by the deep audit.

Nothing here changes the target: it only rotates client fingerprints and
produces alternate encodings of the same probe so a naive signature match
does not hide a vulnerability from the scanner.
"""

from __future__ import annotations

import random
from urllib.parse import quote

from config import USER_AGENT

_AGENTS = [
    USER_AGENT,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def headers(extra: dict | None = None, rotate_agent: bool = True,
            spoof_ip: bool = False) -> dict:
    """A plausible browser header set, optionally with a rotated source IP."""
    result = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }
    if rotate_agent:
        result["User-Agent"] = random.choice(_AGENTS)
    if spoof_ip:
        result.update({
            "X-Forwarded-For": random_ip(),
            "X-Real-IP": random_ip(),
            "X-Client-IP": random_ip(),
            "X-Originating-IP": random_ip(),
        })
    if extra:
        result.update(extra)
    return result


def variants(payload: str) -> list[str]:
    """The probe plus encoding variants that commonly bypass filters."""
    encoded = quote(payload, safe="")
    double = quote(encoded, safe="")
    return list(dict.fromkeys([
        payload,
        encoded,
        double,
        payload.replace("://", ":%2f%2f"),
        payload.replace(".", "%2e"),
        payload.replace("/", "\\/"),
    ]))
