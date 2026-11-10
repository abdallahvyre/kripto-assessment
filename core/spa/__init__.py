"""Single-page application analysis.

The pipeline already had a bundler reader (``core.jscan``) and a tokenizer
(``core.jparse``).  This package adds the pieces they do not cover:

* ``routes``  - framework router declarations, normalised to one template form;
* ``chunks``  - lazily-loaded bundles the initial HTML never references;
* ``browser`` - optional rendering, only when a driver is installed and asked for;
* ``assess``  - folds all of it onto the shared attack surface.

Nothing here opens a network connection of its own; ``browser`` is the single
exception, and it only runs when an operator passes ``--browser``.
"""

from core.spa.assess import SpaAssessor
from core.spa.routes import concretise, is_dynamic, normalise

__all__ = ["SpaAssessor", "concretise", "is_dynamic", "normalise"]
