"""Executing a login and tracking whether the resulting session still works.

Two rules shape this module.  First, nothing here bypasses the central HTTP
layer: every request goes through :class:`core.http.RateLimitedSession`, so the
login flow inherits scope checks, transport binding and the request budget.
Second, an authentication state is only ever *claimed* when the target itself
demonstrated it - a 200 response is not proof that a login succeeded.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin

from config import TIMEOUT
from core.auth.sources import CredentialSource

_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR = re.compile(r"""([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)


_LOGIN_WALL = (
    "type=\"password\"", "type='password'", "name=\"password\"",
    "name='password'", "sign in", "log in", "login", "unauthorized",
    "authentication required", "access denied", "forbidden",
)
_DENIED_STATUSES = frozenset({401, 403, 407})


class AuthState(str, Enum):
    """What is actually known about one identity right now."""

    AUTHENTICATED = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"

    @property
    def usable(self) -> bool:
        return self is AuthState.AUTHENTICATED

    @property
    def label(self) -> str:
        return self.value


@dataclass
class LoginOutcome:
    """The result of one login attempt, with the evidence behind it."""

    ok: bool
    state: AuthState
    reason: str = ""
    evidence: str = ""
    status: int = 0
    elapsed: float = 0.0


@dataclass
class AuthStatus:
    """Reportable snapshot of an identity."""

    name: str
    role: str
    method: str
    state: AuthState = AuthState.UNKNOWN
    reason: str = ""
    logins: int = 0
    failures: int = 0
    authenticated_at: float = 0.0
    validated_at: float = 0.0

    def report(self) -> dict:
        return {
            "name": self.name,
            "role": self.role,
            "method": self.method,
            "state": self.state.value,
            "reason": self.reason,
            "logins": self.logins,
            "failures": self.failures,
            "authenticated_at": self.authenticated_at,
            "validated_at": self.validated_at,
        }





_BARE_ATTR = re.compile(r"(?:^|\s)([A-Za-z_:][\w:.-]*)(?=\s|/?>|$)")


def _attributes(tag: str) -> dict:
    found = {}
    for match in _ATTR.finditer(tag):
        name = match.group(1).lower()
        value = match.group(3)
        if value is None:
            value = match.group(4)
        if value is None:
            value = match.group(5) or ""
        found[name] = value
    
    
    body = tag[1:]
    for match in _BARE_ATTR.finditer(body):
        name = match.group(1).lower()
        if name in ("input", "br", "hr", "img", "meta", "link"):
            continue
        found.setdefault(name, "")
    return found


def form_fields(html: str) -> dict:
    """Every pre-populated input value a login form expects to be echoed back.

    CSRF tokens, "return to" targets and hidden tenant identifiers all live
    here.  Re-posting them is what makes the login indistinguishable from the
    one a real browser sends.
    """
    fields = {}
    for match in _INPUT_TAG.finditer(str(html or "")):
        attributes = _attributes(match.group(0))
        name = attributes.get("name")
        if not name:
            continue
        kind = (attributes.get("type") or "text").lower()
        if kind in ("submit", "button", "image", "reset", "file"):
            continue
        if kind in ("checkbox", "radio") and "checked" not in attributes:
            continue
        fields[name] = attributes.get("value", "")
    return fields


def looks_like_login_wall(text: str) -> bool:
    lowered = str(text or "").lower()[:8000]
    return any(marker in lowered for marker in _LOGIN_WALL)


class AuthSession:
    """One identity's HTTP session, from login through expiry to re-login."""

    def __init__(self, source: CredentialSource, session, console=None,
                 reauthenticate: bool = True):
        self.source = source
        self._session = session
        if source.login_url:
            from core.http import origin
            self._session._identity_origin = origin(source.login_url)
        self.console = console
        self.reauthenticate = bool(reauthenticate)

        self.state = (AuthState.AUTHENTICATED if source.authenticated
                      and not source.needs_login else AuthState.UNKNOWN)
        self.reason = ""
        self.logins = 0
        self.failures = 0
        self.authenticated_at = 0.0
        self.validated_at = 0.0
        self._flow_headers: dict = dict(source.headers)
        self._cookies: dict = {}
        self._csrf_cached: str = ""
        self._history: list = []

    

    def status(self) -> AuthStatus:
        return AuthStatus(
            name=self.source.name,
            role=self.source.role,
            method=self.source.method,
            state=self.state,
            reason=self.reason,
            logins=self.logins,
            failures=self.failures,
            authenticated_at=self.authenticated_at,
            validated_at=self.validated_at,
        )

    def headers(self, url=None) -> dict:
        """Request headers that reproduce this identity on another session.

        The cookie header is materialised explicitly so a *different* session -
        the access-control module comparing two identities, for example - can
        act as this identity without sharing a cookie jar.
        """
        from core.http import IdentityHeaders
        policy = getattr(self._session, "_policy", None)
        destination = self.source.login_url or getattr(policy, "target", "")
        headers = IdentityHeaders(self._flow_headers, destination,
                                  getattr(self._session, "cookies", ()))
        return headers.resolve(url) if url else headers

    @property
    def authenticated(self) -> bool:
        return self.source.authenticated and self.state is AuthState.AUTHENTICATED

    def _expired_by_time(self) -> bool:
        if not self.source.expires_after or not self.authenticated_at:
            return False
        return (time.time() - self.authenticated_at) >= self.source.expires_after

    

    def _get(self, url, **kwargs):
        try:
            kwargs.setdefault("headers", self.headers())
            return self._session.get(url, timeout=TIMEOUT, **kwargs)
        except Exception:
            return None

    def _csrf_from(self, html: str, cookies) -> str:
        if self.source.csrf_field:
            value = form_fields(html).get(self.source.csrf_field, "")
            if value:
                return value
        if self.source.csrf_cookie:
            try:
                return cookies.get(self.source.csrf_cookie, "") or ""
            except Exception:
                return ""
        return self._csrf_cached

    def login(self) -> LoginOutcome:
        """Perform the configured login flow and record the outcome."""
        source = self.source
        started = time.monotonic()

        if not source.needs_login:
            self.state = AuthState.AUTHENTICATED if source.headers else AuthState.UNAUTHENTICATED
            self.reason = ("static credentials accepted without a login flow"
                           if source.headers else "no credentials")
            self.authenticated_at = time.time()
            return LoginOutcome(ok=source.authenticated, state=self.state,
                                reason=self.reason, elapsed=time.monotonic() - started)

        page = self._get(source.login_url, allow_redirects=True)
        if page is None:
            return self._reject(AuthState.UNKNOWN,
                                "the login page could not be retrieved", started)
        if getattr(page, "scope_redirect_blocked", None):
            return self._reject(AuthState.REJECTED, "login page redirect was blocked by policy", started)
        from core.http import origin
        if origin(getattr(page, "url", None) or source.login_url) != origin(source.login_url):
            return self._reject(AuthState.REJECTED, "login page redirected outside its configured credential origin", started)

        payload = form_fields(page.text)
        self._csrf_cached = self._csrf_from(page.text, self._session.cookies)
        
        
        if source.csrf_field and self._csrf_cached and source.csrf_field not in payload:
            payload[source.csrf_field] = self._csrf_cached
        payload[source.username_field] = source.username
        payload[source.password_field] = source.password
        for key, value in (source.extra_fields or {}).items():
            payload[key] = value

        submit_url = source.login_url
        try:
            submit_url = urljoin(page.url or source.login_url, "")
        except Exception:
            pass

        response = self._post_login(submit_url, payload)
        if response is None:
            return self._reject(AuthState.UNKNOWN, "the login request failed", started)
        if getattr(response, "scope_redirect_blocked", None):
            return self._reject(AuthState.REJECTED, "login response redirect was blocked by policy", started)
        if origin(getattr(response, "url", None) or source.login_url) != origin(source.login_url):
            return self._reject(AuthState.REJECTED, "login response is outside its configured credential origin", started)

        outcome = self._classify_login(response)
        outcome.elapsed = time.monotonic() - started
        self._history.append({"at": time.time(), "state": outcome.state.value,
                              "reason": outcome.reason, "status": outcome.status})
        if outcome.ok:
            self.logins += 1
            self.authenticated_at = time.time()
            self.state = AuthState.AUTHENTICATED
            self._cookies = self._cookie_snapshot()
        else:
            self.failures += 1
            self.state = outcome.state
        self.reason = outcome.reason
        return outcome

    def _post_login(self, url, payload):
        from core.http import origin
        if origin(url) != origin(self.source.login_url):
            return None
        try:
            return self._session.post(
                url, data=payload, timeout=TIMEOUT,
                headers=self.headers(),
                allow_redirects=True,
            )
        except Exception:
            return None

    def _cookie_snapshot(self) -> dict:
        try:
            return {cookie.name: cookie.value for cookie in self._session.cookies}
        except Exception:
            return {}

    def _classify_login(self, response) -> LoginOutcome:
        source = self.source
        status = getattr(response, "status_code", 0) or 0
        body = getattr(response, "text", "") or ""

        if status in _DENIED_STATUSES:
            return LoginOutcome(False, AuthState.REJECTED,
                                f"the login endpoint answered HTTP {status}",
                                evidence=f"HTTP {status}", status=status)

        if source.failure_marker and source.failure_marker in body:
            return LoginOutcome(False, AuthState.REJECTED,
                                "the login page returned its failure marker",
                                evidence=f"failure marker {source.failure_marker!r}",
                                status=status)

        if source.success_marker:
            if source.success_marker in body:
                return LoginOutcome(True, AuthState.AUTHENTICATED,
                                    "the success marker appeared after login",
                                    evidence=f"success marker {source.success_marker!r}",
                                    status=status)
            return LoginOutcome(False, AuthState.REJECTED,
                                "the success marker never appeared",
                                evidence=f"success marker {source.success_marker!r} missing",
                                status=status)

        
        cookies = self._cookie_snapshot()
        if cookies and not looks_like_login_wall(body):
            return LoginOutcome(True, AuthState.AUTHENTICATED,
                                "the target issued a session cookie",
                                evidence=f"{len(cookies)} cookie(s) set", status=status)
        if status in (301, 302, 303, 307, 308) and cookies:
            return LoginOutcome(True, AuthState.AUTHENTICATED,
                                "the login redirect set a session cookie",
                                evidence=f"{len(cookies)} cookie(s) set", status=status)
        if looks_like_login_wall(body):
            return LoginOutcome(False, AuthState.REJECTED,
                                "the response is still a login wall",
                                evidence="login markers present after the POST",
                                status=status)
        return LoginOutcome(False, AuthState.UNKNOWN,
                            "login could not be confirmed either way; supply "
                            "success_marker or validation_url to make it decisive",
                            evidence=f"HTTP {status}, no marker configured", status=status)

    def _reject(self, state, reason, started) -> LoginOutcome:
        self.state = state
        self.reason = reason
        self.failures += 1
        return LoginOutcome(False, state, reason, elapsed=time.monotonic() - started)

    

    def validate(self) -> AuthState:
        """Ask the target whether this session is still usable."""
        source = self.source
        if not source.authenticated:
            self.state = AuthState.UNAUTHENTICATED
            return self.state

        self.validated_at = time.time()
        if self._expired_by_time():
            self.state = AuthState.EXPIRED
            self.reason = (f"the declared lifetime of {source.expires_after:.0f}s elapsed")
            return self.state

        if not source.validation_url:
            
            if self.state is AuthState.UNKNOWN:
                self.state = AuthState.AUTHENTICATED if self._cookies or self._flow_headers\
                    else AuthState.UNKNOWN
            return self.state

        response = self._get(source.validation_url, allow_redirects=False)
        if response is None:
            self.state = AuthState.UNKNOWN
            self.reason = "the validation endpoint did not answer"
            return self.state

        status = response.status_code
        if status in _DENIED_STATUSES:
            self.state = AuthState.EXPIRED
            self.reason = f"the validation endpoint answered HTTP {status}"
            return self.state
        if status in (301, 302, 303, 307, 308):
            location = str(response.headers.get("Location", "")).lower()
            if any(word in location for word in ("login", "signin", "auth", "sso")):
                self.state = AuthState.EXPIRED
                self.reason = "the validation endpoint redirected to a login page"
                return self.state
        if source.validation_marker and source.validation_marker not in (response.text or ""):
            self.state = AuthState.EXPIRED
            self.reason = "the validation marker is no longer present"
            return self.state
        if status == 200:
            self.state = AuthState.AUTHENTICATED
            self.reason = "the validation endpoint returned authenticated content"
        else:
            self.state = AuthState.UNKNOWN
            self.reason = f"the validation endpoint answered HTTP {status}"
        return self.state

    def ensure(self) -> AuthState:
        """Validate, and re-authenticate once when the session has expired."""
        state = self.validate()
        if state is AuthState.AUTHENTICATED:
            return state
        if not self.reauthenticate or not self.source.needs_login:
            return state
        if state in (AuthState.EXPIRED, AuthState.UNKNOWN):
            outcome = self.login()
            if outcome.ok:
                return self.validate()
        return self.state

    def history(self) -> list:
        return list(self._history)
