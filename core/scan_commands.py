"""Console rendering for the scan-history commands.

Keeping this out of ``main.py`` matters: the history commands are read-only
inspectors over the local store, and they should be testable without building an
argument parser or touching a network transport.
"""

from __future__ import annotations

import json
import os
import time

from core.banner import info, make_table, success, warning
from core.redact import display_text
from core.store import ScanStore, StoreError
from rich.markup import escape
from rich.text import Text


def open_store(args) -> ScanStore:
    """The store configured for this invocation."""
    explicit = getattr(args, "store", None)
    if explicit:
        return ScanStore(path=explicit)
    return ScanStore(output_dir=getattr(args, "output", "output"))


def retest_finding(console, args):
    from core import transport
    from core.baseline import Baseline
    from core.http import RateLimitedSession
    from core.runtime import RunControl
    from core.verify import Verifier
    from core.lifecycle import LifecycleError
    store = open_store(args)
    try:
        scan_id, key = args.retest_finding
        scan = store.get_scan(scan_id)
        entry = store.finding_payload(scan_id, key)
        resolution = transport.resolve(args.proxy, start_tor=args.tor_start,
                         tor_root=args.tor_root, tor_data_dir=os.path.join(args.output, "tor"),
                         tor_timeout=args.tor_timeout, tor_host=args.tor_socks_host, tor_port=args.tor_port)
        transport.apply(resolution)
        RateLimitedSession.configure_policy(scan["target"], scope=args.scope,
                                             excludes=(args.exclude or "").split(",") if isinstance(args.exclude, str) else args.exclude)
        RateLimitedSession.configure_runtime(RunControl(args.request_budget, args.threads or 4))
        
        
        from core.auth.sources import _clean_headers
        import config
        if args.headers_file:
            with open(args.headers_file, encoding="utf-8") as headers_file:
                config.REQUEST_HEADERS = _clean_headers(json.load(headers_file), "retest headers")
        session = RateLimitedSession(rate_per_second=min(args.rate, args.max_rate or args.rate))
        baseline = Baseline(session, scan["target"], console).collect()
        verifier = Verifier(scan["target"], console, baseline)
        outcome = verifier.retest_finding(entry)
        record = store.retest_finding(scan_id, key, outcome)
        console.print(Text(json.dumps(record, ensure_ascii=False, indent=2)))
        return 0
    except (StoreError, LifecycleError, transport.TransportError, ValueError) as exc:
        warning(console, str(exc))
        return 1
    finally:
        RateLimitedSession.close_all()
        store.close()


def _stamp(value) -> str:
    if not value:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(value)))
    except (TypeError, ValueError, OSError):
        return str(value)


def list_scans(console, args) -> int:
    """``--list-scans``: the engagement history."""
    store = open_store(args)
    try:
        rows = store.list_scans(limit=getattr(args, "scan_limit", 20) or 20)
    except StoreError as exc:
        warning(console, f"Scan history unavailable: {exc}")
        return 1
    finally:
        store.close()

    if not rows:
        info(console, "No stored scans yet. Run a scan with --store to record one.")
        return 0

    
    
    
    info(console, f"Stored scans ({len(rows)}):")
    for item in rows:
        target = item["target"]
        if len(target) > 30:
            target = target[:29] + "..."
        console.print(
            f"  [kw.cyan]{escape(display_text(item['id']))}[/]  "
            f"{escape(display_text(item['status'])):<9} {escape(display_text(item['mode'])):<6} "
            f"{item['endpoints']:>3}ep {item['findings']:>3}f  "
            f"[kw.muted]{escape(display_text(target))}[/]"
        )
    info(console, "Show one with --show-scan ID, diff two with --compare-scans OLD NEW.")
    return 0


def show_scan(console, args, scan_id: str) -> int:
    store = open_store(args)
    try:
        record = store.get_scan(scan_id)
    except StoreError as exc:
        warning(console, str(exc))
        return 1
    finally:
        store.close()

    console.print(make_table(
        f"Scan {scan_id}",
        ["Field", "Value"],
        [
            ("Target", record["target"]),
            ("Mode", record["mode"]),
            ("Profile", record.get("profile") or "-"),
            ("Status", record["status"]),
            ("Started", _stamp(record["started_at"])),
            ("Finished", _stamp(record["finished_at"])),
            ("Endpoints", str(len(record["endpoints"]))),
            ("Findings", str(len(record["findings"]))),
        ],
        style="cyan",
    ))

    if record["stages"]:
        console.print(make_table(
            "Stages",
            ["Stage", "State", "Note"],
            [(item["name"], item["state"], (item["note"] or "")[:60])
             for item in record["stages"]],
            style="dim cyan",
        ))
    if record["findings"]:
        console.print(make_table(
            "Findings",
            ["Kind", "Title", "Severity", "CVSS", "Status"],
            [(item["kind"], item["title"][:48], item.get("severity") or "-",
              f"{float(item.get('cvss') or 0):.1f}", item.get("status") or "open")
             for item in record["findings"]],
            style="cyan",
        ))
    return 0


def compare_scans(console, args, previous_id: str, current_id: str) -> int:
    store = open_store(args)
    try:
        result = store.compare(previous_id, current_id)
    except StoreError as exc:
        warning(console, str(exc))
        return 1
    finally:
        store.close()

    counts = result["counts"]
    console.print(make_table(
        "Scan Comparison",
        ["Change", "Count"],
        [("New findings", str(counts["new"])),
         ("Not observed (retest needed)", str(counts["resolved"])),
         ("Still present", str(counts["persistent"])),
         ("Severity changed", str(counts["severity_changed"]))],
        style="cyan",
    ))
    if result["new"]:
        console.print(make_table(
            "New", ["Kind", "Title", "Severity"],
            [(item["kind"], item["title"][:56], item.get("severity") or "-")
             for item in result["new"]], style="dim cyan"))
    if result["resolved"]:
        info(console, f"{counts['resolved']} finding(s) were not observed; a fix has not been verified.")
        for item in result["resolved"][:10]:
            console.print(Text(f"  not observed: {display_text(item['title'][:70])}"))
    for change in result["severity_changed"][:10]:
        warning(console, f"severity {change['previous_severity']} -> "
                         f"{change['current_severity']}: {change['title'][:60]}")
    return 0


def export_scan(console, args, scan_id: str) -> int:
    store = open_store(args)
    try:
        document = store.export_scan(scan_id)
    except StoreError as exc:
        warning(console, str(exc))
        return 1
    finally:
        store.close()

    destination = getattr(args, "export_path", None) or\
        os.path.join(getattr(args, "output", "output"), f"scan-{scan_id}.json")
    directory = os.path.dirname(os.path.abspath(destination))
    try:
        os.makedirs(directory, exist_ok=True)
        with open(destination, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, ensure_ascii=False)
    except OSError as exc:
        warning(console, f"Could not write {destination}: {exc}")
        return 1
    success(console, f"Exported scan {scan_id} to {destination}")
    return 0


def load_resume_state(console, args, target: str, mode: str):
    """Resolve ``--resume`` into state the pipeline can restore."""
    scan_id = getattr(args, "resume", None)
    if not scan_id:
        return None
    store = open_store(args)
    try:
        state = store.resume_state(scan_id, target, mode)
    except StoreError as exc:
        warning(console, str(exc))
        return None
    finally:
        store.close()
    return state
