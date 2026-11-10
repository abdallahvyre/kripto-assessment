"""Run-wide cancellation, request ceiling and concurrency ownership."""
import threading
from contextlib import contextmanager


class Cancelled(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class RunControl:
    def __init__(self, budget=None, concurrency=16):
        self.cancelled = threading.Event()
        self.budget = budget
        self.requests = 0
        self.exhausted = False
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(concurrency)

    def check(self):
        if self.cancelled.is_set():
            raise Cancelled("scan cancelled")

    def reserve(self):
        self.check()
        with self._lock:
            if self.budget is not None and self.requests >= self.budget:
                self.exhausted = True
                raise BudgetExceeded("run-wide request budget reached")
            self.requests += 1

    @contextmanager
    def slot(self):
        while not self._slots.acquire(timeout=0.1):
            self.check()
        try:
            self.check()
            yield
        finally:
            self._slots.release()

    def cancel(self):
        self.cancelled.set()

    def report(self):
        return {"request_budget": self.budget, "requests": self.requests,
                "cancelled": self.cancelled.is_set(),
                "budget_exhausted": self.exhausted}
