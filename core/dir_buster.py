import concurrent.futures
import time

from config import *
from core.banner import info, success, found, warning, make_table
from core.baseline import Baseline
from core.http import RateLimitedSession
from core.pool import WorkerPool


class DirBusterModule:
    def __init__(self, target: str, console, extensions=None, full: bool = False,
                 workers=None, adaptive=True, max_paths: int = None, exclude=None):
        self.target = target.rstrip("/")
        self.console = console
        self.session = RateLimitedSession()
        self.baseline = None
        self.found_dirs = []
        self.catchall_hits = 0
        self.unverified_hits = 0
        self.total_tested = 0
        self.extensions = extensions or (DIR_EXTENSIONS_FULL if full else DIR_EXTENSIONS)
        self.max_paths = max_paths
        self.truncated_at = None
        self.exclude = exclude or []
        self.worker_pool = WorkerPool(workers=workers, adaptive=adaptive)

    def _check_path(self, path: str):
        url = f"{self.target}/{path}"
        if any(url.endswith(p) for p in self.exclude):
            return None
        started = time.monotonic()
        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=False)
        except Exception:
            return None
        finally:
            self.worker_pool.record(time.monotonic() - started)

        status = resp.status_code
        if status not in (200, 201, 301, 302, 303, 307, 308, 401, 403):
            return None

        verdict = self.baseline.classify(resp)
        if verdict == "catchall":
            self.catchall_hits += 1
            return None

        size = len(resp.content)
        if status == 200 and size < 20:
            return None

        redirect = resp.headers.get("Location", "-")
        return {
            "path": f"/{path}",
            "url": url,
            "status": status,
            "size": size,
            "redirect": redirect if status in (301, 302, 303, 307, 308) else "-",
            "verified": verdict == "unique",
        }

    def run(self) -> dict:
        self.baseline = Baseline(self.session, self.target, self.console).collect()

        if self.baseline.catch_all:
            warning(
                self.console,
                "Catch-all / soft-404 routing active (SPA-style host). "
                "Repeated matches against the baseline page are discarded.",
            )

        if self.worker_pool.adaptive:
            probed = self.worker_pool.warm_up(
                lambda path: self.session.get(f"{self.target}/{path}",
                                              timeout=TIMEOUT, allow_redirects=False),
                probes=4,
            )
            info(self.console, f"Latency sample: {self.worker_pool.average_latency*1000:.0f}ms "
                               f"-> {probed} worker(s) in flight")

        targets = []
        for word in DIR_WORDLIST:
            for ext in self.extensions:
                targets.append(f"{word}{ext}")

        if self.max_paths and len(targets) > self.max_paths:
            
            
            self.truncated_at = len(targets)
            targets = targets[: self.max_paths]

        info(self.console, f"Directory bruteforce against {self.target}: "
                           f"{len(targets)} paths to test ({self.worker_pool.size()} workers)"
                           + (f", {self.truncated_at - len(targets)} deferred to respect the "
                              f"run budget" if self.truncated_at else "") + "...")

        status_colors = {200: "green", 301: "yellow", 302: "yellow", 303: "yellow",
                         307: "yellow", 308: "yellow", 403: "red", 401: "magenta"}

        workers = max(1, min(self.worker_pool.size(), len(targets)))
        started_at = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._check_path, t): t for t in targets}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    self.found_dirs.append(result)
                    if not result["verified"]:
                        self.unverified_hits += 1
                    color = status_colors.get(result["status"], "white")
                    tag = "" if result["verified"] else " [UNVERIFIED]"
                    found(
                        self.console,
                        f"[{color}]{result['status']}[/{color}] {result['path']} "
                        f"({result['size']} bytes){tag}",
                    )
                
                
                if done % 100 == 0 or done == len(targets):
                    elapsed = time.monotonic() - started_at
                    observed = done / elapsed if elapsed > 0 else 0.0
                    left = (len(targets) - done) / observed if observed > 0 else 0.0
                    info(
                        self.console,
                        f"  {done}/{len(targets)} tested | {len(self.found_dirs)} found | "
                        f"{observed:.1f} paths/s | {self.worker_pool.average_latency*1000:.0f}ms "
                        f"latency | ETA {left:.0f}s",
                    )

        self.total_tested = len(targets)
        self.found_dirs.sort(key=lambda x: (not x["verified"], x["status"], x["path"]))

        success(
            self.console,
            f"Bruteforce complete: {len(self.found_dirs)} found / {self.total_tested} tested "
            f"({self.catchall_hits} catch-all responses discarded)",
        )
        if self.unverified_hits:
            warning(
                self.console,
                f"{self.unverified_hits} findings are UNVERIFIED because the baseline could not be established.",
            )

        if self.found_dirs:
            rows = [
                (d["path"], str(d["status"]), str(d["size"]), d["redirect"],
                 "yes" if d["verified"] else "no")
                for d in self.found_dirs[:50]
            ]
            self.console.print(
                make_table("Discovered Paths", ["Path", "Status", "Size", "Redirect", "Verified"], rows)
            )

        return {
            "found": self.found_dirs,
            "total_tested": self.total_tested,
            "catchall_discarded": self.catchall_hits,
            "unverified": self.unverified_hits,
            "catchall_detected": self.baseline.catch_all,
            "truncated_at": self.truncated_at,
            "base": self.target,
        }