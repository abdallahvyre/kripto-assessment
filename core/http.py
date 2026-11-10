import threading
import weakref
import socket
import time
import copy
from http.cookiejar import Cookie
from contextlib import nullcontext
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config
from config import USER_AGENT, REQUEST_TIMEOUT, REQUEST_RETRIES
from core.policy import ScopePolicy, ScopeViolation, _normalise_host
from core.pool import SessionPool
from core.transport import TransportError


DEFAULT_BODY_CAP = 4_000_000
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
IDEMPOTENT_RETRY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SENSITIVE_REDIRECT_HEADERS = frozenset(
    {"authorization", "cookie", "host", "proxy-authorization", "x-api-key", "x-auth-token"}
)


def origin(url):
    parsed = urlsplit(str(url))
    return (parsed.scheme.lower(), _normalise_host(parsed.hostname or ""),
            parsed.port or (443 if parsed.scheme.lower() == "https" else 80))


class IdentityHeaders(dict):
    """Portable identity retaining cookie destination rules across sessions."""

    def __init__(self, headers, destination, cookies=None):
        self.destination = destination
        self.credential_origin = origin(destination) if destination else None
        self.static_headers = dict(headers)
        self.cookie_jar = requests.cookies.RequestsCookieJar()
        for cookie in cookies or ():
            if isinstance(cookie, Cookie):
                self.cookie_jar.set_cookie(copy.copy(cookie))
            else:
                
                self.cookie_jar.set(cookie.name, cookie.value,
                                    domain=urlsplit(destination).hostname or "", path="/")
        super().__init__(self.resolve(destination))

    def resolve(self, url):
        if self.credential_origin is not None and origin(url) != self.credential_origin:
            return {}
        headers = dict(self.static_headers)
        if self.cookie_jar:
            request = requests.Request("GET", url).prepare()
            value = requests.cookies.get_cookie_header(self.cookie_jar, request)
            headers["Cookie"] = value or ""
        return headers

    def copy(self):
        return type(self)(self.static_headers, self.destination, self.cookie_jar)


def _guard_response(response, control, seconds, release):
    """Bound blocked body reads and keep the request slot until response cleanup."""
    stopped, lock = threading.Event(), threading.Lock()
    original_close = response.close
    closed = False
    deadline = time.monotonic() + seconds
    
    raw = response.raw
    fp = getattr(getattr(raw, "_fp", None), "fp", None)
    sock = getattr(getattr(fp, "raw", None), "_sock", None)

    def close():
        nonlocal closed
        with lock:
            if closed:
                return
            closed = True
        stopped.set()
        release()
        original_close()

    response.close = close

    def watch():
        while not stopped.wait(0.05):
            cancelled = control is not None and control.cancelled.is_set()
            if not cancelled and time.monotonic() < deadline:
                continue
            from core.runtime import Cancelled
            response.kripto_body_error = Cancelled("scan cancelled") if cancelled else requests.Timeout("response body deadline exceeded")
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            close()
            return

    threading.Thread(target=watch, daemon=True, name="kripto-response-deadline").start()


def build_session(verify: bool = None, retries: int = REQUEST_RETRIES) -> requests.Session:
    if retries is None or int(retries) < 0:
        raise ValueError("retries must be zero or greater")
    session = requests.Session()
    retry = Retry(
        total=int(retries),
        connect=int(retries),
        read=int(retries),
        status=int(retries),
        redirect=0,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=IDEMPOTENT_RETRY_METHODS,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=64, pool_maxsize=64)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    session.verify = config.TLS_VERIFY if verify is None else bool(verify)
    _bind_transport(session)
    return session


def _bind_transport(session: requests.Session) -> None:
    """Attach the resolved transport (direct / Tor / SOCKS) to a session.

    Every session in the process is built here, so binding the proxy at this
    point means no discovery or testing module can accidentally reach the
    target over a different route.  A non-direct mode with no proxy configured
    is a hard error: silently sending the scan directly would contradict what
    the operator asked for.
    """
    mode = getattr(config, "TRANSPORT_MODE", "direct")
    proxies = getattr(config, "TRANSPORT_PROXIES", None) or {}

    if mode == "direct":
        session.trust_env = False
        return

    if not proxies:
        raise TransportError(
            f"transport mode {mode!r} was selected but no proxy is configured; "
            "refusing to fall back to a direct connection"
        )

    session.proxies.update(proxies)
    
    session.trust_env = False


def get_capped(url: str, cap: int = DEFAULT_BODY_CAP, headers=None, **kwargs):
    """Fetch a URL but stop reading past `cap` bytes.

    Discovery sweeps walk paths like /llms-full.txt that can be tens of
    megabytes. Buffering them whole costs memory and time for content that is
    only being identified, never analysed.
    """
    if cap <= 0:
        raise ValueError("cap must be greater than zero")
    session = RateLimitedSession(pool=RateLimitedSession.shared())
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT, stream=True,
                               headers=headers, **kwargs)
    except Exception:
        session.close()
        return None

    try:
        buffer = bytearray()
        for chunk in response.raw.stream(65536, decode_content=True):
            if session._control:
                session._control.check()
            if getattr(response, "kripto_body_error", None):
                raise response.kripto_body_error
            remaining = cap - len(buffer)
            if remaining <= 0:
                break
            buffer.extend(chunk[:remaining])
            if len(chunk) > remaining or len(buffer) >= cap:
                break
        truncated = len(buffer) >= cap
        response._content = bytes(buffer)
        response._content_consumed = True
        response.encoding = response.encoding or "utf-8"
        response.kripto_truncated = truncated
        if getattr(response, "kripto_body_error", None):
            raise response.kripto_body_error
        response.close()
        return response
    except Exception:
        try:
            response.close()
        except Exception:
            pass
        return None
    finally:
        session.close()


class RateLimitedSession:
    """Scope-checked session using one shared global request budget.

    The first request in a process pins the default policy to that host.  The
    application can call :meth:`configure_policy` before scanning to add an
    authorized wildcard scope and excluded paths.  Redirects are followed here,
    one hop at a time, so no hop can bypass scope or rate limiting.
    """

    _shared_pool = None
    _shared_rate = None
    _shared_policy = None
    _shared_lock = threading.Lock()
    _control = None
    _credential_origin = None
    _sessions = weakref.WeakSet()

    def __init__(self, rate_per_second: float = None, pool: SessionPool = None,
                 policy: ScopePolicy = None, target: str = None, scope=None,
                 excludes=None, inherit_headers=True):
        
        
        self._session = build_session(retries=0)
        self._sessions.add(self)
        if policy is not None and target is not None:
            raise ValueError("pass either policy or target, not both")
        self._policy = policy or (ScopePolicy(target, scope=scope, excludes=excludes)
                                  if target is not None else None)
        self._inherit_headers = bool(inherit_headers)
        self._identity_origin = origin(self._policy.target) if target else None
        if pool is not None:
            self._pool = pool
        elif rate_per_second is not None:
            self._pool = SessionPool(rate_per_second)
        else:
            self._pool = self.shared()

    @classmethod
    def shared(cls, rate: float = None) -> SessionPool:
        with cls._shared_lock:
            target_rate = rate if rate is not None else config.REQUESTS_PER_SECOND
            target_rate = float(target_rate)
            if target_rate <= 0:
                raise ValueError("request rate must be greater than zero")
            if cls._shared_pool is None or cls._shared_rate != target_rate:
                cls._shared_pool = SessionPool(target_rate)
                cls._shared_rate = target_rate
            return cls._shared_pool

    @classmethod
    def configure_policy(cls, target: str, scope=None, excludes=None,
                         max_redirects: int = 8) -> ScopePolicy:
        policy = ScopePolicy(target, scope=scope, excludes=excludes,
                             max_redirects=max_redirects)
        with cls._shared_lock:
            cls._shared_policy = policy
            cls._credential_origin = origin(policy.target)
        return policy

    @classmethod
    def get_shared_policy(cls) -> ScopePolicy | None:
        with cls._shared_lock:
            return cls._shared_policy

    @classmethod
    def reset_shared(cls):
        cls.close_all()
        with cls._shared_lock:
            cls._shared_pool = None
            cls._shared_rate = None
            cls._shared_policy = None
            cls._control = None
            cls._credential_origin = None

    @classmethod
    def configure_runtime(cls, control):
        cls._control = control

    def close(self):
        self._session.close()

    @classmethod
    def close_all(cls):
        for session in list(cls._sessions):
            session.close()
        cls._sessions.clear()

    def __getattr__(self, item):
        if item.lower() in {"options", "put", "patch", "delete"}:
            return lambda url, **kwargs: self.request(item.upper(), url, **kwargs)
        return getattr(self._session, item)

    def _policy_for(self, url: str) -> ScopePolicy:
        if self._policy is not None:
            return self._policy
        with self.__class__._shared_lock:
            if self.__class__._shared_policy is None:
                self.__class__._shared_policy = ScopePolicy(url)
                self.__class__._credential_origin = origin(url)
            return self.__class__._shared_policy

    def _pre(self, url: str, method: str, source: str = "request"):
        policy = self._policy_for(url)
        allowed_url = policy.authorize(url, method=method, source=source)
        host = urlsplit(allowed_url).hostname
        if self._control is not None:
            self._control.reserve()
        self._pool.acquire(host)
        if self._control is not None:
            self._control.check()
        delay = self._pool.backoff.delay(host)
        if delay > 0:
            
            
            if self._control:
                self._control.cancelled.wait(delay)
                self._control.check()
            else:
                threading.Event().wait(delay)
        return allowed_url, host, policy

    def _post(self, host, response):
        if response is not None:
            self._pool.observe(host, response)
        return response

    @staticmethod
    def _redirect_method(method: str, status: int) -> str:
        method = method.upper()
        if status == 303 and method != "HEAD":
            return "GET"
        if status == 302 and method != "HEAD":
            return "GET"
        if status == 301 and method == "POST":
            return "GET"
        return method

    @staticmethod
    def _drop_sensitive_headers(kwargs: dict) -> None:
        kwargs.pop("auth", None)
        kwargs.pop("cookies", None)
        headers = kwargs.get("headers")
        if not headers:
            return
        kwargs["headers"] = {
            key: value for key, value in dict(headers).items()
            if key.lower() not in SENSITIVE_REDIRECT_HEADERS
        }

    @staticmethod
    def _drop_request_body(kwargs: dict) -> None:
        for key in ("data", "json", "files"):
            kwargs.pop(key, None)
        headers = kwargs.get("headers")
        if headers:
            stripped = {
                key: value for key, value in (headers.static_headers if isinstance(headers, IdentityHeaders)
                                             else dict(headers)).items()
                if key.lower() not in {"content-length", "content-type", "transfer-encoding"}
            }
            kwargs["headers"] = (IdentityHeaders(stripped, headers.destination, headers.cookie_jar)
                                 if isinstance(headers, IdentityHeaders) else stripped)

    def get(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def request(self, method, url, **kwargs):
        method = str(method).upper()
        allow_redirects = kwargs.pop("allow_redirects", True)
        request_headers = kwargs.pop("request_headers", None)
        current_url = str(url)
        current_method = method
        current_kwargs = dict(kwargs)
        explicit_identity = "headers" in kwargs and kwargs["headers"] is not None
        identity_origin = self._identity_origin or self._credential_origin
        
        if identity_origin is None and self._policy is None:
            identity_origin = origin(self._policy_for(current_url).target)
        origin_changed = False
        eager = not current_kwargs.get("stream", False)
        if eager:
            current_kwargs["stream"] = True
        history = []

        while True:
            allowed_url, host, policy = self._pre(current_url, current_method,
                                                  source="redirect" if history else "request")
            send_kwargs = dict(current_kwargs)
            
            
            custom_headers = getattr(config, "REQUEST_HEADERS", {}) or {}
            same_identity_origin = identity_origin == origin(allowed_url) and not origin_changed
            if self._inherit_headers and not explicit_identity and same_identity_origin and custom_headers:
                send_kwargs["headers"] = (custom_headers.resolve(allowed_url)
                    if isinstance(custom_headers, IdentityHeaders) else dict(custom_headers))
            selected_headers = send_kwargs.get("headers")
            if isinstance(selected_headers, IdentityHeaders):
                send_kwargs["headers"] = selected_headers.resolve(allowed_url)
            if explicit_identity:
                
                
                selected = requests.structures.CaseInsensitiveDict(send_kwargs.get("headers") or {})
                selected.setdefault("Cookie", "")
                selected.setdefault("Authorization", None)
                send_kwargs["headers"] = dict(selected)
                send_kwargs.setdefault("auth", ())
                send_kwargs.setdefault("cookies", {})
            if not same_identity_origin:
                
                
                send_kwargs["headers"] = {"Cookie": "", "Authorization": None}
                send_kwargs["cookies"] = {}
                send_kwargs["auth"] = ()
            elif request_headers:
                
                
                selected = requests.structures.CaseInsensitiveDict(send_kwargs.get("headers") or {})
                selected.update(request_headers)
                send_kwargs["headers"] = dict(selected)
            send_kwargs["allow_redirects"] = False
            send_kwargs.setdefault("timeout", config.REQUEST_TIMEOUT)
            slot = self._control.slot() if self._control else nullcontext()
            slot.__enter__()
            try:
                response = self._post(host, self._session.request(current_method, allowed_url, **send_kwargs))
            except BaseException:
                slot.__exit__(None, None, None)
                raise
            if isinstance(response, requests.Response) and response.raw is not None:
                timeout = send_kwargs["timeout"]
                seconds = sum(float(value or config.REQUEST_TIMEOUT) for value in timeout) if isinstance(timeout, tuple) else float(timeout or config.REQUEST_TIMEOUT)
                _guard_response(response, self._control, min(seconds, config.REQUEST_TIMEOUT),
                                lambda owner=slot: owner.__exit__(None, None, None))
            else:
                slot.__exit__(None, None, None)
            if eager and isinstance(response, requests.Response) and response.raw is not None:
                import time
                body, started = bytearray(), time.monotonic()
                try:
                    for chunk in response.iter_content(8192):
                        if self._control:
                            self._control.check()
                        body.extend(chunk[:max(0, DEFAULT_BODY_CAP - len(body))])
                        if len(body) >= DEFAULT_BODY_CAP or time.monotonic() - started > config.REQUEST_TIMEOUT:
                            response.kripto_truncated = True
                            break
                    response._content = bytes(body)
                    response._content_consumed = True
                    if getattr(response, "kripto_body_error", None):
                        raise response.kripto_body_error
                except BaseException as exc:
                    if getattr(response, "kripto_body_error", None):
                        raise response.kripto_body_error from exc
                    raise
                finally:
                    response.close()
            response.history = list(history)

            location = response.headers.get("Location")
            if (not allow_redirects or response.status_code not in REDIRECT_STATUSES
                    or not location):
                return response
            if len(history) >= policy.max_redirects:
                response.close()
                raise requests.TooManyRedirects(
                    f"exceeded {policy.max_redirects} safe redirects", response=response
                )

            next_method = self._redirect_method(current_method, response.status_code)
            try:
                next_url = policy.redirect_target(response.url, location, method=next_method)
            except ScopeViolation as exc:
                response.scope_redirect_blocked = {
                    "url": exc.url,
                    "reason": exc.reason,
                }
                return response

            if origin(response.url) != origin(next_url):
                if any(key in current_kwargs for key in ("data", "json", "files")) and next_method == current_method:
                    response.scope_redirect_blocked = {"url": next_url,
                        "reason": "cross-origin redirect cannot replay a request body"}
                    return response
                origin_changed = True
                self._drop_sensitive_headers(current_kwargs)

            if next_method != current_method:
                self._drop_request_body(current_kwargs)
            
            
            current_kwargs.pop("params", None)

            history.append(response)
            response.close()
            current_url = next_url
            current_method = next_method

    @property
    def pool(self) -> SessionPool:
        return self._pool

    def raw_diagnostic(self, url, payload, timeout=6, follow_up=None):
        """Bounded framing probe through the same scope/rate/transport gate."""
        import socket
        import ssl
        import time
        from core.network import authorize
        allowed_url, _, _ = authorize(url, "raw HTTP diagnostic", policy=self._policy)
        parsed = urlsplit(allowed_url)
        sock = None
        try:
            sock = socket.create_connection((parsed.hostname, parsed.port or
                                             (443 if parsed.scheme == "https" else 80)), timeout=timeout)
            if parsed.scheme == "https":
                context = ssl.create_default_context()
                if not config.TLS_VERIFY:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
            sock.sendall(payload.encode("latin-1", "ignore"))
            if follow_up:
                sock.sendall(follow_up.encode("latin-1", "ignore"))
            data, deadline = bytearray(), time.monotonic() + timeout
            while time.monotonic() < deadline and len(data) < 256000:
                if self._control:
                    self._control.check()
                sock.settimeout(max(0.01, deadline - time.monotonic()))
                try:
                    chunk = sock.recv(min(8192, 256000 - len(data)))
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)
            return data.decode("latin-1", "ignore"), None
        except (OSError, ssl.SSLError) as exc:
            return None, str(exc)
        finally:
            if sock is not None:
                sock.close()

    @property
    def policy(self) -> ScopePolicy:
        if self._policy is not None:
            return self._policy
        return self.get_shared_policy()

    @property
    def raw(self):
        """Compatibility alias that still routes requests through safeguards."""
        return self
