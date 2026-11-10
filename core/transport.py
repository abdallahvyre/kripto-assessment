"""Select the network route every outbound request takes.

Kripto can talk to a target directly, through the bundled Tor SOCKS5 listener,
or through an operator-supplied SOCKS proxy.  The choice is made once, before
any scan traffic is generated, and then bound to the HTTP session itself.

The single most important rule here is that a proxy mode is *never* downgraded
to a direct connection.  If the operator asked for Tor and Tor cannot be used,
:class:`TransportError` is raised and the caller must abort.  Silently sending
a scan over the operator's real IP when they asked for a proxy would be both
surprising and, on an assessment, potentially harmful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core import tor_manager

DIRECT = "direct"
TOR = "tor"
SOCKS = "socks"
HTTP_PROXY = "http"

SUPPORTED_SCHEMES = ("socks5h", "socks5", "socks4a", "socks4", "http", "https")
DEFAULT_PORTS = {
    "socks5h": 1080, "socks5": 1080, "socks4a": 1080, "socks4": 1080,
    "http": 8080, "https": 8080,
}


class TransportError(RuntimeError):
    """Raised when the requested transport cannot be established."""


@dataclass
class TransportResolution:
    """The outcome of resolving a `--proxy` request."""

    mode: str = DIRECT
    proxy_url: str = ""
    proxies: dict = field(default_factory=dict)
    label: str = "DIRECT"
    notes: list = field(default_factory=list)
    tor_status: dict = field(default_factory=dict)

    @property
    def uses_proxy(self) -> bool:
        return bool(self.proxies)

    def report(self) -> dict:
        """Reportable summary.  Never includes proxy credentials."""
        return {
            "mode": self.mode,
            "proxy": _redact_proxy(self.proxy_url),
            "label": self.label,
            "notes": list(self.notes),
            "tor": dict(self.tor_status) if self.tor_status else {},
        }


def _redact_proxy(proxy_url: str) -> str:
    """Strip any userinfo (user:password) from a proxy URL before logging."""
    if not proxy_url:
        return ""
    try:
        parsed = urlsplit(proxy_url)
    except ValueError:
        return "<invalid proxy url>"
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    if parsed.username or parsed.password:
        return f"{parsed.scheme}://<credentials>@{host}{port}"
    return f"{parsed.scheme}://{host}{port}"


def parse_proxy(value: str) -> tuple:
    """Parse a proxy string into (scheme, host, port, url).

    ``socks5://host:9050`` and a bare ``host:9050`` are both accepted; a bare
    host defaults to SOCKS5 because that is what Tor serves.
    """
    text = str(value or "").strip()
    if not text:
        raise TransportError("an empty --proxy value was given")

    if "://" not in text:
        text = f"socks5h://{text}"

    parsed = urlsplit(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise TransportError(
            f"unsupported proxy scheme {scheme!r}; "
            f"supported: {', '.join(SUPPORTED_SCHEMES)}"
        )
    if not parsed.hostname:
        raise TransportError(f"proxy {text!r} has no hostname")

    port = parsed.port or DEFAULT_PORTS.get(scheme, 1080)
    if not (0 < int(port) < 65536):
        raise TransportError(f"proxy port {port} is out of range")

    netloc = f"{parsed.hostname}:{port}"
    if parsed.username or parsed.password:
        
        userinfo = parsed.username or ""
        if parsed.password:
            userinfo = f"{userinfo}:{parsed.password}"
        netloc = f"{userinfo}@{netloc}"
    return scheme, parsed.hostname, int(port), f"{scheme}://{netloc}"


def _require_socks_support(scheme: str) -> None:
    if not scheme.startswith("socks"):
        return
    try:
        import socks  
    except ImportError as exc:
        raise TransportError(
            "SOCKS proxying requires PySocks. Install it with "
            "`python -m pip install PySocks` (or `pip install requests[socks]`)."
        ) from exc


def _proxies_for(proxy_url: str) -> dict:
    return {"http": proxy_url, "https": proxy_url}


def verify_proxy_reachable(proxy_url: str, timeout: float = 3.0) -> tuple:
    """Confirm something SOCKS-shaped is answering before a scan starts."""
    scheme, host, port, _ = parse_proxy(proxy_url)
    if scheme.startswith("socks"):
        return tor_manager.socks_greeting(host, port, timeout=max(2.0, timeout))
    if tor_manager.port_open(host, port, timeout=timeout):
        return True, f"{scheme} listener accepted a TCP connection"
    return False, f"nothing is listening on {host}:{port}"







def resolve(proxy: str = None, *, start_tor: bool = False,
            tor_root: str = None, tor_data_dir: str = None,
            tor_timeout: float = None,
            tor_host: str = tor_manager.DEFAULT_SOCKS_HOST,
            tor_port: int = tor_manager.DEFAULT_SOCKS_PORT) -> TransportResolution:
    """Turn a `--proxy` request into a bound transport, or raise.

    ``proxy`` accepts:

    * ``None`` or ``"direct"`` - no proxy at all;
    * ``"tor"`` - use the local Tor SOCKS listener, starting it if asked;
    * any ``scheme://host:port`` string - use that proxy as given.
    """
    value = (str(proxy).strip().lower() if proxy is not None else "")
    if value in ("", "direct", "none", "off"):
        return TransportResolution(mode=DIRECT, label="DIRECT")

    if value == "tor":
        return _resolve_tor(
            start_tor=start_tor, tor_root=tor_root, tor_data_dir=tor_data_dir,
            tor_timeout=tor_timeout, tor_host=tor_host, tor_port=tor_port,
        )

    return _resolve_explicit(proxy)


def _resolve_tor(*, start_tor, tor_root, tor_data_dir, tor_timeout,
                 tor_host, tor_port) -> TransportResolution:
    manager = tor_manager.get_manager(
        root=tor_root, socks_host=tor_host, socks_port=tor_port,
        data_dir=tor_data_dir,
        **({"start_timeout": tor_timeout} if tor_timeout else {}),
    )
    notes = []
    try:
        if start_tor:
            notes.append("started a managed Tor process for this run")
            manager.start(timeout=tor_timeout)
        else:
            running, detail = manager.socks_ready()
            if not running:
                notes.append(
                    "nothing was listening on the Tor SOCKS port and --tor-start "
                    "was not given"
                )
                manager.start(timeout=tor_timeout)
                notes.append("started a managed Tor process for this run")
    except tor_manager.TorError as exc:
        raise TransportError(str(exc)) from exc

    ready, detail = manager.socks_ready()
    if not ready:
        raise TransportError(
            f"Tor SOCKS5 endpoint {tor_host}:{tor_port} is not usable: {detail}"
        )

    proxy_url = f"socks5h://{tor_host}:{tor_port}"
    _require_socks_support("socks5h")
    return TransportResolution(
        mode=TOR,
        proxy_url=proxy_url,
        proxies=_proxies_for(proxy_url),
        label=f"TOR ({tor_host}:{tor_port})",
        notes=notes + [detail, "DNS resolution is delegated to the SOCKS5 proxy"],
        tor_status=manager.status(transport=TOR).report(),
    )


def _resolve_explicit(proxy: str) -> TransportResolution:
    scheme, host, port, proxy_url = parse_proxy(proxy)
    _require_socks_support(scheme)

    reachable, detail = verify_proxy_reachable(proxy_url)
    if not reachable:
        raise TransportError(
            f"proxy {_redact_proxy(proxy_url)} is not answering: {detail}"
        )
    mode = SOCKS if scheme.startswith("socks") else HTTP_PROXY
    return TransportResolution(
        mode=mode,
        proxy_url=proxy_url,
        proxies=_proxies_for(proxy_url),
        label=f"{scheme.upper()} ({host}:{port})",
        notes=[detail],
    )







def apply(resolution: TransportResolution, config_module=None) -> TransportResolution:
    """Bind *resolution* to the shared config used by every HTTP session.

    ``core.http.build_session`` reads these values, so there is no code path
    that reaches the network without them.
    """
    if config_module is None:
        import config as config_module  

    config_module.TRANSPORT_MODE = resolution.mode
    config_module.TRANSPORT_PROXIES = dict(resolution.proxies)
    config_module.TRANSPORT_PROXY_URL = resolution.proxy_url
    config_module.TRANSPORT_LABEL = resolution.label
    return resolution


def reset(config_module=None) -> None:
    """Return the HTTP layer to a direct connection (test teardown)."""
    if config_module is None:
        import config as config_module
    config_module.TRANSPORT_MODE = DIRECT
    config_module.TRANSPORT_PROXIES = {}
    config_module.TRANSPORT_PROXY_URL = ""
    config_module.TRANSPORT_LABEL = "DIRECT"


def current_label(config_module=None) -> str:
    if config_module is None:
        import config as config_module
    return getattr(config_module, "TRANSPORT_LABEL", "DIRECT")
