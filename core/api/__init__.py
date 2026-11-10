"""API security assessment: specification modelling and API-specific checks.

The package is deliberately small and layered:

* ``spec``      - parse and normalise an OpenAPI 3.x / Swagger 2.0 document;
* ``rest``      - assess documented operations against what the server allows;
* ``graphql``   - schema analysis and bounded resolver-abuse checks;
* ``authz``     - select object-level operations for the existing access module;
* ``validation``- input validation and mass-assignment candidates;
* ``report``    - the API section every report and JSON document carries.

Nothing here opens its own network route: every request goes through the
caller's ``RateLimitedSession`` so scope, rate limiting and transport remain
centrally enforced.
"""

from core.api.spec import ApiOperation, ApiParameter, ApiSpec, parse_spec

__all__ = ["ApiOperation", "ApiParameter", "ApiSpec", "parse_spec"]
