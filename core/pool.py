"""Concurrency primitives with one real run-wide request ceiling.

Everything here addresses the same I/O shape: a large number of independent
HTTP requests that must not exceed an operator-chosen rate.  Every request now
passes both the global bucket and (optionally) a per-host bucket, so discovering
more subdomains can never multiply ``--rate``.
"""

import concurrent.futures
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import threading
import time
from urllib.parse import urlparse

import config


def _cooperative_sleep(seconds):
    from core.http import RateLimitedSession
    control = RateLimitedSession._control
    if control:
        control.cancelled.wait(seconds)
        control.check()
    else:
        time.sleep(seconds)


class TokenBucket:
    """Slot-scheduled rate limiter.

    Every caller is assigned a distinct moment in the future, then sleeps
    without holding the mutex. The aggregate rate equals `rate` requests per
    second regardless of how many threads are waiting.
    """

    def __init__(self, rate: float, clock=None, sleeper=None):
        try:
            rate = float(rate)
        except (TypeError, ValueError) as exc:
            raise ValueError("rate must be a positive number") from exc
        if rate <= 0:
            raise ValueError("rate must be greater than zero")
        self.rate = rate
        self.min_interval = 1.0 / rate
        self._clock = clock or time.monotonic
        self._sleep = sleeper or _cooperative_sleep
        self._next = 0.0
        self._lock = threading.Lock()
        self.served = 0
        self.wait_total = 0.0

    def acquire(self) -> float:
        with self._lock:
            now = self._clock()
            scheduled = now if now > self._next else self._next
            self._next = scheduled + self.min_interval
            self.served += 1

        delay = max(0.0, scheduled - now)
        if delay > 0:
            self._sleep(delay)
        with self._lock:
            self.wait_total += delay
        return delay

    @property
    def backlog(self) -> float:
        """Seconds of queued work. Measured, not estimated."""
        with self._lock:
            return max(0.0, self._next - self._clock())


class HostPool:
    """One independent budget per host."""

    def __init__(self, rate: float, max_hosts: int = 512, clock=None, sleeper=None):
        if rate is None or float(rate) <= 0:
            raise ValueError("per-host rate must be greater than zero")
        self.rate = float(rate)
        self.max_hosts = max_hosts
        self._clock = clock
        self._sleeper = sleeper
        self._buckets = {}
        self._lock = threading.Lock()

    def bucket(self, host: str) -> TokenBucket:
        if not host:
            return None
        with self._lock:
            existing = self._buckets.get(host)
            if existing is not None:
                return existing
            if len(self._buckets) >= self.max_hosts:
                
                self._buckets.pop(next(iter(self._buckets)))
            bucket = TokenBucket(self.rate, clock=self._clock, sleeper=self._sleeper)
            self._buckets[host] = bucket
            return bucket

    def acquire(self, host: str) -> float:
        bucket = self.bucket(host)
        return bucket.acquire() if bucket else 0.0

    def hosts(self) -> int:
        with self._lock:
            return len(self._buckets)


class Backoff:
    """Doubles the delay for a host that returns 429/503 and halves it when it
    stops, so a rate limit costs a pause rather than being ignored."""

    def __init__(self, initial: float = 0.5, maximum: float = 30.0,
                 trigger=(429, 503)):
        self.initial = initial
        self.maximum = maximum
        self.trigger = set(trigger)
        self._state = {}
        self._lock = threading.Lock()
        self.events = 0

    def observe(self, host: str, response) -> float:
        if not host or response is None:
            return 0.0
        status = getattr(response, "status_code", 0)
        retry_after = self._retry_after_seconds(response)
        with self._lock:
            current = self._state.get(host, 0.0)
            if status in self.trigger:
                self.events += 1
                exponential = max(self.initial,
                                  current * 2.0 if current else self.initial)
                nxt = min(self.maximum, max(exponential, retry_after))
            else:
                nxt = current * 0.5
            self._state[host] = nxt
        return nxt

    @staticmethod
    def _retry_after_seconds(response) -> float:
        headers = getattr(response, "headers", {}) or {}
        raw = headers.get("Retry-After")
        if raw is None:
            return 0.0
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            pass
        try:
            parsed = parsedate_to_datetime(str(raw))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return 0.0

    def delay(self, host: str) -> float:
        return self._state.get(host, 0.0) if host else 0.0

    def report(self) -> dict:
        with self._lock:
            active = {h: round(d, 2) for h, d in self._state.items() if d > 0.05}
        return {"events": self.events, "slowing_hosts": active}


class SessionPool:
    """Shared rate and backoff state for every session in a run.

    Sessions participate in one budget instead of competing, so the operator's
    --rate stays true across all stages and all threads.
    """

    def __init__(self, rate: float, per_host: bool = True,
                 per_host_rate: float = None, clock=None, sleeper=None):
        try:
            rate = float(rate)
        except (TypeError, ValueError) as exc:
            raise ValueError("rate must be a positive number") from exc
        if rate <= 0:
            raise ValueError("rate must be greater than zero")
        self.rate = rate
        self.per_host = per_host
        
        
        self.per_host_rate = min(rate, float(per_host_rate or rate))
        if self.per_host_rate <= 0:
            raise ValueError("per_host_rate must be greater than zero")
        self.hosts = (HostPool(self.per_host_rate, clock=clock, sleeper=sleeper)
                      if per_host else None)
        self.global_bucket = TokenBucket(rate, clock=clock, sleeper=sleeper)
        self.backoff = Backoff()
        self.requests = 0
        self._lock = threading.Lock()

    def acquire(self, host: str = None) -> float:
        
        
        global_delay = self.global_bucket.acquire()
        host_delay = self.hosts.acquire(host) if self.per_host and host else 0.0
        with self._lock:
            self.requests += 1
        return global_delay + host_delay

    def observe(self, host: str, response):
        return self.backoff.observe(host, response)

    def report(self) -> dict:
        with self._lock:
            total = self.requests
        return {
            "requests": total,
            "configured_rate": self.rate,
            "per_host": self.per_host,
            "per_host_rate": self.per_host_rate if self.per_host else None,
            "distinct_hosts": self.hosts.hosts() if self.hosts else 1,
            "backoff": self.backoff.report(),
        }


class WorkerPool:
    """Chooses how many requests should be in flight: rate times latency.

    Ten threads at ten requests per second only help if each request takes a
    second. This measures the actual latency and sizes the pool to fill the
    budget without overcommitting - which on a fast CDN-fronted host correctly
    collapses to very few workers instead of a fixed default.
    """

    def __init__(self, workers=None, adaptive=True, cap=48, floor=1, rate=None):
        self._fixed = workers
        self.adaptive = adaptive and workers is None
        self.cap = cap
        self.floor = floor
        self._rate = rate if rate is not None else config.REQUESTS_PER_SECOND
        self._latencies = []
        self._lock = threading.Lock()
        self._current = workers or 8
        self._executor = None

    @property
    def rate(self) -> float:
        """The rate the request layer is actually enforcing, not the default."""
        if self._rate:
            return self._rate
        try:
            from core.http import RateLimitedSession
            return RateLimitedSession.shared().rate
        except Exception:
            return config.REQUESTS_PER_SECOND

    def size(self) -> int:
        if not self.adaptive:
            return self._fixed or 8
        with self._lock:
            samples = list(self._latencies)
        if len(samples) < 6:
            return self._current

        samples.sort()
        keep = samples[-max(1, len(samples) // 5):]
        average = sum(keep) / len(keep)
        if average <= 0:
            return self._current
        wanted = int(self.rate * average * 1.5) + 1
        new = max(self.floor, min(self.cap, wanted))
        self._current = new
        return new

    def record(self, seconds: float):
        with self._lock:
            self._latencies.append(seconds)
            if len(self._latencies) > 200:
                del self._latencies[:100]

    @property
    def average_latency(self) -> float:
        with self._lock:
            return sum(self._latencies) / len(self._latencies) if self._latencies else 0.0

    def executor(self, workers=None) -> concurrent.futures.ThreadPoolExecutor:
        workers = workers or self.size()
        if self._executor is None or self._executor._max_workers != workers:
            if self._executor is not None:
                self._executor.shutdown(wait=False)
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="kripto-worker"
            )
        return self._executor

    def warm_up(self, fetch, probes: int = 3) -> int:
        """Size the worker count from a few real requests to the target.

        A ThreadPoolExecutor cannot be resized once created, so the count has
        to be chosen after the first few real requests rather than before them.
        The samples come from the target under assessment, never from anywhere
        else, so a scan never contacts a third party just to size its own pool.
        """
        for _ in range(max(1, int(probes))):
            started = time.monotonic()
            try:
                fetch(f"__kripto_calibration_{int(started * 1000) % 100000}__")
            except Exception:
                pass
            self.record(time.monotonic() - started)
        return self.size()

    def close(self):
        if self._executor is not None:
            self._executor.shutdown(wait=False)
            self._executor = None


class RequestTimer:
    """Wraps a callable so its latency feeds the adaptive worker count."""

    def __init__(self, pool: WorkerPool):
        self.pool = pool

    def __call__(self, fn, *args, **kwargs):
        started = time.monotonic()
        try:
            return fn(*args, **kwargs)
        finally:
            self.pool.record(time.monotonic() - started)


def parallel(fn, items, workers=8, pool=None, timer=None, on_result=None, label=""):
    """Bounded fan-out over `items`, preserving input order in the result.

    Rate limiting stays where it belongs, inside the session layer, so this only
    decides how many requests are in flight at once.
    """
    items = list(items)
    if not items:
        return []

    if timer is not None:
        fn = lambda item, _fn=fn: timer(_fn, item)  

    if workers <= 1 or len(items) == 1:
        out = []
        for item in items:
            try:
                out.append(fn(item))
            except Exception:
                out.append(None)
        return out

    results = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool_exec:
        futures = {pool_exec.submit(fn, item): index
                   for index, item in enumerate(items)}
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception:
                results[index] = None
    return results


def host_from(url: str) -> str:
    return urlparse(url).hostname or ""



RateLimiter = TokenBucket

