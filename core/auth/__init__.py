"""Authenticated scanning: credential sources, sessions and identity roles.

The scanner never invents credentials.  Every identity comes from an operator
supplied source - environment variables, a protected JSON file, or a login flow
performed against the target with credentials the engagement provided.  The
package keeps three concerns apart so each can be tested in isolation:

* :mod:`core.auth.sources`   - where credentials come from and how they load.
* :mod:`core.auth.session`   - performing login and tracking session validity.
* :mod:`core.auth.context`   - the role-aware registry the pipeline reads.
"""

from core.auth.context import AuthContext, Role
from core.auth.session import AuthSession, AuthState, LoginOutcome
from core.auth.sources import (
    AuthConfigError,
    CredentialSource,
    load_credentials,
)

__all__ = [
    "AuthConfigError",
    "AuthContext",
    "AuthSession",
    "AuthState",
    "CredentialSource",
    "LoginOutcome",
    "Role",
    "load_credentials",
]
