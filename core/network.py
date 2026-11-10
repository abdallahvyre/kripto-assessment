"""Explicit gate for DNS, TLS and non-HTTP diagnostic connections.

These protocols have no proxy adapter; selected proxies fail closed, never direct.
HTTP probes use core.http, including its raw diagnostic entry point.
"""
import config
from core.http import RateLimitedSession
from core.transport import TransportError


def authorize(target, source="network-diagnostic", policy=None):
    if getattr(config, "TRANSPORT_MODE", "direct") != "direct":
        raise TransportError(f"{source} unavailable through selected transport; no direct fallback")
    session = RateLimitedSession(policy=policy)
    try:
        return session._pre(target, "GET", source=source)
    finally:
        session.close()
