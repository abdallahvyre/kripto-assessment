"""The role-aware identity registry the pipeline reads.

The pipeline should never hold raw credentials.  It asks this context for "the
first authenticated user identity" and "a second, different identity" and gets
back request headers, so access-control comparison can run without any module
knowing how a session was obtained.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.auth.session import AuthSession, AuthState
from core.auth.sources import CredentialSource


ROLE_ANONYMOUS = "anonymous"
ROLE_USER = "user"
ROLE_ADMIN = "admin"


@dataclass
class Role:
    """One authorization level, with the identities that claim it."""

    name: str
    identities: list = field(default_factory=list)

    def authenticated(self) -> list:
        return [item for item in self.identities if item.authenticated]

    def report(self) -> dict:
        return {
            "role": self.name,
            "identities": [item.source.name for item in self.identities],
            "authenticated": [item.source.name for item in self.authenticated()],
        }


class AuthContext:
    """Every configured identity, their live state, and the roles they occupy."""

    def __init__(self, target: str, console=None, identities=None,
                 reauthenticate: bool = True, session_factory=None):
        self.target = target
        self.console = console
        self.reauthenticate = bool(reauthenticate)
        self._session_factory = session_factory
        self._sessions: dict = {}
        self._order: list = []
        self.prepared = False
        self.errors: list = []

        for source in identities or []:
            self.register(source)

    

    def register(self, source: CredentialSource) -> AuthSession:
        session = AuthSession(source, self._new_session(), console=self.console,
                              reauthenticate=self.reauthenticate)
        self._sessions[source.name] = session
        self._order.append(source.name)
        return session

    def _new_session(self):
        if self._session_factory is not None:
            return self._session_factory()
        from core.http import RateLimitedSession
        from core.policy import ScopePolicy
        policy = RateLimitedSession.get_shared_policy() or ScopePolicy(self.target)
        policy.authorize(self.target, source="authentication context")
        return RateLimitedSession(policy=policy, inherit_headers=False)

    def identity(self, name: str) -> AuthSession | None:
        return self._sessions.get(name)

    def all(self) -> list:
        return [self._sessions[name] for name in self._order]

    def names(self) -> list:
        return list(self._order)

    

    def _first(self, predicate, exclude=()):
        for name in self._order:
            session = self._sessions[name]
            if session.source.name in exclude:
                continue
            if predicate(session):
                return session
        return None

    @property
    def anonymous(self) -> AuthSession | None:
        return self._first(lambda s: not s.source.authenticated)

    @property
    def primary(self) -> AuthSession | None:
        """The first authenticated non-anonymous identity."""
        return self._first(lambda s: s.source.authenticated
                           and s.state is AuthState.AUTHENTICATED)

    @property
    def secondary(self) -> AuthSession | None:
        """A second, *different* authenticated identity.

        Access-control comparison is only meaningful between two distinct
        subjects; returning the same session twice would silently turn every
        check into a self-comparison.
        """
        first = self.primary
        if first is None:
            return None
        return self._first(
            lambda s: s.source.authenticated and s.state is AuthState.AUTHENTICATED,
            exclude={first.source.name},
        )

    @property
    def admin(self) -> AuthSession | None:
        return self._first(lambda s: s.source.role == ROLE_ADMIN
                           and s.source.authenticated
                           and s.state is AuthState.AUTHENTICATED)

    def by_role(self, role: str) -> list:
        return [s for s in self.all() if s.source.role == role]

    def roles(self) -> list:
        grouped: dict = {}
        for session in self.all():
            grouped.setdefault(session.source.role, Role(session.source.role))
            grouped[session.source.role].identities.append(session)
        return [grouped[name] for name in sorted(grouped)]

    

    def prepare(self) -> dict:
        """Log in every dynamic identity, then validate what we have.

        A login that fails is not fatal: the scan continues with the identities
        that did work and the report states plainly which ones did not.
        """
        for session in self.all():
            try:
                if session.source.needs_login:
                    session.login()
                else:
                    session.validate()
            except Exception as exc:  
                self.errors.append(f"{session.source.name}: {type(exc).__name__}: {exc}")
                session.state = AuthState.UNKNOWN
                session.reason = f"preparation failed: {type(exc).__name__}"
        self.prepared = True
        return self.report()

    def refresh(self) -> dict:
        """Re-validate, re-authenticating anything the target expired."""
        for session in self.all():
            try:
                session.ensure()
            except Exception as exc:
                self.errors.append(f"{session.source.name}: {type(exc).__name__}: {exc}")
        return self.report()

    

    def headers_for(self, name: str) -> dict:
        session = self.identity(name)
        return session.headers() if session else {}

    def primary_headers(self) -> dict:
        session = self.primary
        return session.headers() if session else {}

    def secondary_headers(self) -> dict:
        session = self.secondary
        return session.headers() if session else {}

    def has_two_identities(self) -> bool:
        return self.primary is not None and self.secondary is not None

    def has_identity(self) -> bool:
        return self.primary is not None

    def secret_values(self) -> list:
        """Every secret held by every identity, for redaction registration."""
        from core.redact import credential_values
        values = []
        for session in self.all():
            values.extend(session.source.secret_values())
            values.extend(credential_values(session.headers()))
            values.extend(str(cookie.value) for cookie in session._session.cookies)
        return [value for value in values if value]

    

    def report(self) -> dict:
        sessions = self.all()
        return {
            "configured": len(sessions),
            "authenticated": sum(1 for s in sessions if s.authenticated),
            "two_distinct_identities": self.has_two_identities(),
            "identities": [s.status().report() for s in sessions],
            "roles": [role.report() for role in self.roles()],
            "errors": list(self.errors),
        }

    def summary_line(self) -> str:
        report = self.report()
        if not report["configured"]:
            return "no identities configured (unauthenticated scan)"
        parts = [f"{item['name']}={item['state']}" for item in report["identities"]]
        return f"{report['authenticated']}/{report['configured']} authenticated: " +\
               ", ".join(parts)
