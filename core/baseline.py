import difflib
import hashlib
import math
import random
import re
import string

from core.banner import info, success, warning
from config import REQUEST_TIMEOUT

_SCRIPT_STYLE = re.compile(r"<(script|style)\b.*?</\1>", re.DOTALL | re.IGNORECASE)
_NONCE = re.compile(r"""(?:nonce|token|csrf|build|v|rev|hash|_)\s*[=:]\s*["'][^"']{4,}["']""", re.IGNORECASE)
_LONG_HEX = re.compile(r"\b[0-9a-f]{12,}\b", re.IGNORECASE)
_LONG_NUM = re.compile(r"\b\d{5,}\b")
_TAIL = re.compile(r"[A-Za-z0-9_\-]{8,}\.(?:js|css|png|jpg|jpeg|svg|woff2?|ico|webp)")


def normalize_body(text: str, limit: int = 40000) -> str:
    if not text:
        return ""
    text = _SCRIPT_STYLE.sub(" ", text)
    text = _NONCE.sub("X", text)
    text = _LONG_HEX.sub("HEX", text)
    text = _LONG_NUM.sub("NUM", text)
    text = _TAIL.sub("ASSET", text)
    return re.sub(r"\s+", " ", text[:limit]).strip()


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


class Baseline:
    """Detects catch-all / soft-404 responses so probing modules stop reporting
    the same shell page as hundreds of 'discovered' paths."""

    SIMILARITY = 0.90
    SIZE_TOLERANCE = 0.03
    MISSING_STATUSES = {404, 410}
    SAMPLE_STATUSES = {200, 401, 403, 404, 410}

    def __init__(self, session, base_url: str, console=None, samples: int = 4):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.console = console
        self.samples = samples

        self.reliable = False
        self.root_response = None
        self.responses = []
        self.hashes = set()
        self.statuses = set()
        self.catchall_hashes = set()
        self.catchall_norms = []
        self.catchall_sizes = []
        self.content_type = None

    def _rand_path(self) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=18))

    def _absorb(self, resp):
        self.responses.append(resp)
        body = resp.content
        self.catchall_hashes.add(hashlib.sha256(body).hexdigest())
        norm = normalize_body(resp.text)
        if norm:
            self.catchall_norms.append(norm)
        self.catchall_sizes.append(len(body))
        self.statuses.add(resp.status_code)
        ct = resp.headers.get("Content-Type", "")
        if ct and self.content_type is None:
            self.content_type = ct.split(";")[0].strip()

    @classmethod
    def _same_missing_page(cls, left, right) -> bool:
        """Whether two random-path responses represent one stable miss page."""
        if left.status_code != right.status_code:
            return False

        left_body = left.content or b""
        right_body = right.content or b""
        if hashlib.sha256(left_body).digest() == hashlib.sha256(right_body).digest():
            return True

        larger = max(len(left_body), len(right_body), 1)
        if abs(len(left_body) - len(right_body)) / larger > cls.SIZE_TOLERANCE:
            return False

        left_norm = normalize_body(left.text)
        right_norm = normalize_body(right.text)
        return bool(left_norm and right_norm and
                    similarity(left_norm, right_norm) >= cls.SIMILARITY)

    def _stable_cluster(self, responses):
        """Return the largest mutually consistent random-path response cluster."""
        best = []
        for anchor in responses:
            cluster = []
            for candidate in responses:
                if not self._same_missing_page(anchor, candidate):
                    continue
                if all(self._same_missing_page(candidate, member) for member in cluster):
                    cluster.append(candidate)
            if len(cluster) > len(best):
                best = cluster
        return best

    def collect(self):
        try:
            root = self.session.get(self.base_url + "/", timeout=REQUEST_TIMEOUT,
                                    allow_redirects=True)
            if root.status_code in self.SAMPLE_STATUSES:
                self.root_response = root
        except Exception:
            pass

        urls = [f"{self.base_url}/{self._rand_path()}" for _ in range(self.samples)]
        sampled = []
        for url in urls:
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            except Exception:
                continue
            if resp.status_code in self.SAMPLE_STATUSES:
                sampled.append(resp)

        cluster = self._stable_cluster(sampled)
        required = max(2, math.ceil(len(sampled) * 0.75)) if sampled else 2
        if len(cluster) < required:
            self.reliable = False
            if self.console:
                warning(
                    self.console,
                    "Baseline unavailable: random paths did not return one stable miss page. "
                    "Positive results will be marked UNVERIFIED.",
                )
            return self

        for resp in cluster:
            self._absorb(resp)
        self.reliable = True
        self.catchall_norms.sort(key=len)
        self.catchall_sizes.sort()
        if self.console:
            info(
                self.console,
                f"Baseline sampled ({len(self.responses)}/{len(urls)} random paths): "
                f"statuses={sorted(self.statuses)} size={self.catchall_sizes[0]}-{self.catchall_sizes[-1]}B",
            )
        return self

    @property
    def catch_all(self) -> bool:
        return self.reliable and any(status not in self.MISSING_STATUSES
                                     for status in self.statuses)

    def _similar_to_baseline(self, text: str) -> bool:
        norm = normalize_body(text)
        if not norm:
            return False
        if any(similarity(norm, base) >= self.SIMILARITY for base in self.catchall_norms):
            return True
        return False

    def is_catch_all(self, resp) -> bool:
        """True only when the response is proven to be the same catch-all page."""
        if not self.reliable:
            return False

        digest = hashlib.sha256(resp.content).hexdigest()
        if digest in self.catchall_hashes:
            return True

        if resp.status_code not in self.statuses:
            return False

        size = len(resp.content)
        ref = self.catchall_sizes[len(self.catchall_sizes) // 2]
        if not (ref * (1 - self.SIZE_TOLERANCE) <= size <= ref * (1 + self.SIZE_TOLERANCE)):
            return False

        return self._similar_to_baseline(resp.text)

    def classify(self, resp):
        """Returns one of: 'catchall', 'unique', 'unknown'."""
        if not self.reliable:
            return "unknown"
        if self.is_catch_all(resp):
            return "catchall"
        return "unique"
