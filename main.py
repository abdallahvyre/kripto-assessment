import argparse
import json
import os
import re
import sys
import threading
import time
import traceback
import math
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box as rbox
from core.banner import THEME
from core.theme import BG, PANEL, background_escape
from core.console_setup import configure_windows_console

import config
from config import REQUEST_TIMEOUT, REQUESTS_PER_SECOND
from core.banner import (
    error, final_summary, found, info, make_table, progress_bar, section_header,
    show_banner, stage_end, stage_start, success, warning, critical, vuln,
)
from core import profiles as profile_registry
from core import tor_manager
from core import transport as transport_layer
from core import scan_commands
from core.http import RateLimitedSession
from core.pipeline import Pipeline
from core.reporter import Reporter
from core.store import INTERRUPTED, StoreError
from core.splash import show_splash
from core.ui import Dashboard, UIConsole

MODULES = [
    ("WAF & CDN Detection", None, None),
    ("SSL/TLS Analysis", None, None),
    ("Baseline / Catch-All", None, None),
    ("Reconnaissance", None, None),
    ("Port Scanning", "skip_ports", "ports"),
    ("Easy-Win Discovery", "skip_passive", "passive"),
    ("Web Crawling", None, None),
    ("Deep JS Analysis", None, None),
    ("Data Extraction", None, None),
    ("Leak Scan", None, None),
    ("Security Headers", None, None),
    ("SQL Injection", "skip_sqli", "sqli"),
    ("XSS Testing", "skip_xss", "xss"),
    ("Vuln Audit", None, None),
    ("Auth/Token Analysis", None, None),
    ("Protocol Analysis", None, None),
    ("Verification", None, None),
    ("Correlation", None, None),
    ("Impact Modeling", None, None),
    ("OOB Confirmation", "skip_oob", "oob"),
    ("Remediation", None, None),
]

SKIP_MAP = {m[1]: m[1] for m in MODULES if m[1]}


def preflight(target: str, console, quiet: bool = False):
    """Check that the target answers HTTP. Returns (reachable, note)."""
    if not quiet:
        console.print(Panel(
            "[bold kw.amber]Reachability pre-flight[/]\n"
            "Checking the target actually answers HTTP before scanning...",
            border_style="kw.amber", box=rbox.ROUNDED, padding=(0, 1),
            style=f"on {PANEL}",
        ))
    session = RateLimitedSession()
    try:
        resp = session.get(target, timeout=REQUEST_TIMEOUT)
        note = f"HTTP {resp.status_code} · {len(resp.content)} bytes"
        if not quiet:
            info(console, f"Target responded: HTTP {resp.status_code} ({len(resp.content)} bytes)")
            success(console, "Target is reachable - starting scan.")
        return True, note
    except Exception as e:
        note = f"unreachable · {type(e).__name__}"
        if not quiet:
            error(console, f"Target is NOT reachable: {e}")
            warning(console, "Scan aborted. Empty results would be meaningless - fix connectivity first.")
            warning(console, "Common causes: firewall/WAF rate limiting, wrong host, or VPN required.")
        return False, note


def build_parser():
    parser = argparse.ArgumentParser(
        description="Kripto - Authorized Web Security Assessment Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -u https://example.com\n"
            "  python main.py --target https://example.com --mode safe\n"
            "  python main.py -u https://example.com --mode active --ack-authorized\n"
            "  python main.py -u https://example.com --mode active --profile web-deep "
            "--ack-authorized\n"
            "  python main.py -u https://example.com --mode active --profile injection "
            "--profile configuration-audit --ack-authorized\n"
            "  python main.py -u https://example.com --mode active --proxy tor --tor-start "
            "--ack-authorized\n"
            "  python main.py --tor-status\n"
            "  python main.py --tor-check\n"
            "  python main.py --list-profiles\n"
            "\nRun with no arguments for an interactive module picker."
        ),
    )
    from core import __version__
    parser.add_argument("--version", action="version", version=f"Kripto {__version__}")
    parser.add_argument("-u", "--url", "--target", dest="url", required=False,
                        help="Target URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output", default="output", help="Output directory for reports")
    parser.add_argument(
        "--mode", choices=("safe", "active", "intrusive"), default="safe",
        help=("Scan safety level: safe=read-only low-impact (default), active=authorized "
              "injection/enumeration, intrusive=explicit high-impact protocol probes"),
    )
    parser.add_argument("--active", dest="mode", action="store_const", const="active",
                        help=argparse.SUPPRESS)
    parser.add_argument("--intrusive", dest="mode", action="store_const", const="intrusive",
                        help=argparse.SUPPRESS)
    parser.add_argument(
        "--ack-authorized", action="store_true",
        help="Confirm you own the target or have explicit permission to assess it",
    )
    parser.add_argument("--insecure", action="store_true",
                        help="Allow invalid TLS certificates (verification is on by default)")
    parser.add_argument("--headers-file", default=None,
                        help="JSON file of request headers for an authorized authenticated scan")
    parser.add_argument("--test-account-headers", default=None,
                        help="JSON file of headers for a SECOND authorised identity; enables "
                             "real horizontal (IDOR/BOLA) verification instead of POTENTIAL-only")
    parser.add_argument("--auth-file", default=None, metavar="PATH",
                        help="JSON identity document (multiple roles, login forms, bearer tokens, "
                             "API keys). Supports ${ENV:NAME} so secrets stay out of the file")
    parser.add_argument("--auth-from-env", action="store_true",
                        help="Build identities from KRIPTO_AUTH_<NAME>_<FIELD> environment variables")
    parser.add_argument("--no-reauth", action="store_true",
                        help="Do not automatically re-authenticate when a session expires")
    parser.add_argument("--list-auth", action="store_true",
                        help="Show the configured identities and their authentication state, then exit")
    parser.add_argument("--store", default=None, metavar="PATH",
                        help="SQLite file holding scan history (default: <output>/kripto.db)")
    parser.add_argument("--no-store", action="store_true",
                        help="Do not record this scan in the local history")
    parser.add_argument("--list-scans", action="store_true",
                        help="List stored scans, then exit")
    parser.add_argument("--show-scan", default=None, metavar="ID",
                        help="Show one stored scan in detail, then exit")
    parser.add_argument("--compare-scans", nargs=2, default=None, metavar=("OLD", "NEW"),
                        help="Compare two stored scans, then exit")
    parser.add_argument("--export-scan", default=None, metavar="ID",
                        help="Write one stored scan to JSON, then exit")
    parser.add_argument("--export-path", default=None, metavar="PATH",
                        help="Destination file for --export-scan")
    parser.add_argument("--resume", default=None, metavar="ID",
                        help="Resume a stored scan: restores its endpoints and prior findings")
    parser.add_argument("--scan-limit", type=int, default=20,
                        help="How many scans --list-scans shows (default 20)")
    parser.add_argument("--profile", action="append", default=None, metavar="NAME",
                        help="Testing profile (repeatable, or comma separated). "
                             "Use --list-profiles to see them all")
    parser.add_argument("--list-profiles", action="store_true",
                        help="Print the testing profiles with the tests each one enables, then exit")
    parser.add_argument("--proxy", default=None, metavar="MODE",
                        help="Network route: 'direct' (default), 'tor', or a proxy URL such as "
                             "socks5://127.0.0.1:9050. A selected proxy never falls back to direct")
    parser.add_argument("--tor-start", action="store_true",
                        help="Start the bundled Tor process for this run")
    parser.add_argument("--tor-stop", action="store_true",
                        help="Stop the Tor process this tool started, then exit")
    parser.add_argument("--tor-status", action="store_true",
                        help="Show Tor installation, process, listener and transport status, then exit")
    parser.add_argument("--tor-check", action="store_true",
                        help="Verify real Tor egress through the SOCKS5 proxy, then exit")
    parser.add_argument("--tor-root", default=None,
                        help="Directory containing tor.exe / tor-real.exe (default: ./tor)")
    parser.add_argument("--tor-socks-host", default="127.0.0.1",
                        help="SOCKS listener host for Tor (default 127.0.0.1)")
    parser.add_argument("--tor-port", type=int, default=9050,
                        help="SOCKS listener port for Tor (default 9050)")
    parser.add_argument("--tor-timeout", type=float, default=60.0,
                        help="Seconds to wait for Tor to bootstrap (default 60)")
    parser.add_argument("--include-secrets", action="store_true",
                        help="Persist full discovered credentials/tokens instead of redacting them")
    parser.add_argument("--download-evidence", action="store_true",
                        help="Download verified exposed files (intrusive mode only; disabled by default)")
    parser.add_argument("--dependencies-file", help="Local npm lockfile for offline dependency review")
    parser.add_argument("--plugin-dir", help="Directory containing trusted Python plugin folders")
    parser.add_argument("--enable-plugin", action="append", default=[], help="Enable a trusted plugin ID (repeatable)")
    parser.add_argument("--disable-plugin", action="append", default=[], help="Disable a plugin ID (takes precedence)")
    parser.add_argument("--list-plugins", action="store_true", help="Validate and list plugin manifests without importing code")
    parser.add_argument("--cloud-file", help="Local CloudFormation JSON for bounded S3 configuration review")
    parser.add_argument("--request-budget", type=int, default=None,
                        help="Optional maximum network requests across the entire run "
                             "(default: use each stage's own limits)")
    parser.add_argument("--report-formats", default="txt,json", help="Structured formats: txt,json,pdf (comma separated)")
    parser.add_argument("--report-language", choices=["en", "ar"], default="en")
    parser.add_argument("--report-font", help="Unicode TTF font path for PDF, required where no suitable system font exists")
    parser.add_argument("--transition-finding", nargs=3, metavar=("SCAN", "FINGERPRINT", "STATUS"),
                        help="Record accepted_risk or false_positive with --reason")
    parser.add_argument("--retest-finding", nargs=2, metavar=("SCAN", "FINGERPRINT"),
                        help="Retest a stored finding in explicitly authorized active mode")
    parser.add_argument("--reason", default="", help="Reason for a finding lifecycle decision")
    parser.add_argument("--verify-evidence", metavar="SHA256", help="Verify and show sanitized evidence from the selected store")
    parser.add_argument("--engagement-name", default="", help="Engagement name for reports")
    parser.add_argument("--client", default="", help="Client name for reports")
    parser.add_argument("--assessor", default="", help="Assessor name for reports")
    parser.add_argument("--browser", action="store_true",
                        help="Render the landing page in a headless browser for "
                             "client-route discovery (needs Playwright and Chromium)")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-sqli", action="store_true", help="Skip SQLi testing")
    parser.add_argument("--skip-xss", action="store_true", help="Skip XSS testing")
    parser.add_argument("--skip-dirs", action="store_true", help="Skip directory bruteforce")
    parser.add_argument("--skip-passive", action="store_true",
                        help="Skip passive subdomain sources (no outbound CT/reverse-DNS queries)")
    parser.add_argument("--skip-oob", action="store_true",
                        help="Do not start the out-of-band listener for blind findings")
    parser.add_argument("--oob-host", default=None,
                        help="Public address remote targets can reach, for out-of-band callbacks")
    parser.add_argument("--oob-bind", default="127.0.0.1",
                        help="Address the out-of-band listener binds (default 127.0.0.1)")
    parser.add_argument("--scope", default=None,
                        help="Host glob that defines the authorized scope (e.g. *.example.com)")
    parser.add_argument("--exclude", default=None,
                        help="Comma-separated paths excluded from crawling and bruteforce")
    parser.add_argument("--max-rate", type=float, default=None,
                        help="Hard ceiling on requests per second, overriding --rate")
    parser.add_argument("--brute-budget", type=int, default=None,
                        help="Maximum bruteforce paths for the whole run (default: profile-dependent)")
    parser.add_argument("--full-exts", action="store_true",
                        help="Use the full extension list for bruteforce (very noisy)")
    parser.add_argument("--rate", type=float, default=REQUESTS_PER_SECOND,
                        help=f"Requests per second, in total across the run (default {REQUESTS_PER_SECOND})")
    parser.add_argument("--threads", type=int, default=None,
                        help="Requests in flight at once (default: sized from measured latency)")
    parser.add_argument("--no-adaptive-threads", action="store_true",
                        help="Use a fixed worker count instead of sizing it from latency")
    parser.add_argument("--depth", type=int, default=None,
                        help="Crawl depth (default: profile-dependent)")
    parser.add_argument("--pages", type=int, default=None,
                        help="Crawl page cap (default: profile-dependent)")
    parser.add_argument("--budget", type=int, default=None,
                        help="Injection test budget, in parameters (default: profile-dependent)")
    parser.add_argument("--rounds", type=int, default=None,
                        help="Maximum discovery rounds (default: 3, or 6 with --deep)")
    parser.add_argument("--deep", action="store_true",
                        help="Deep profile: larger budgets everywhere and more discovery rounds")
    parser.add_argument("--force", action="store_true", help="Scan even if pre-flight fails")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Skip the interactive module picker even when no -u is given")
    parser.add_argument("--no-ui", action="store_true",
                        help="Disable the full-screen dashboard and print classic scrolling output")
    parser.add_argument("--ui", dest="no_ui", action="store_false",
                        help=argparse.SUPPRESS)
    parser.add_argument("--no-splash", action="store_true",
                        help="Skip the startup splash")
    parser.set_defaults(no_ui=bool(os.environ.get("KRIPTO_NO_UI")),
                        no_splash=bool(os.environ.get("KRIPTO_NO_SPLASH")))
    return parser


def validate_args(parser, args) -> None:
    """Reject unsafe or nonsensical settings before any network request is made."""
    if args.mode != "safe" and not args.ack_authorized:
        parser.error(f"--mode {args.mode} requires --ack-authorized")
    if args.download_evidence and args.mode != "intrusive":
        parser.error("--download-evidence requires --mode intrusive and --ack-authorized")
    formats = [part.strip() for part in args.report_formats.split(",")]
    if not formats or any(part not in {"txt", "json", "pdf"} for part in formats):
        parser.error("--report-formats must contain txt, json and/or pdf")
    args.report_formats = ",".join(dict.fromkeys(formats))
    if args.enable_plugin and not args.plugin_dir:
        parser.error("--enable-plugin requires --plugin-dir")

    numeric = (
        ("--rate", args.rate, 0, 1_000),
        ("--max-rate", args.max_rate, 0, 1_000),
        ("--threads", args.threads, 1, 64),
        ("--depth", args.depth, 0, 20),
        ("--pages", args.pages, 1, 100_000),
        ("--budget", args.budget, 1, 100_000),
        ("--brute-budget", args.brute_budget, 1, 250_000),
        ("--rounds", args.rounds, 1, 20),
        ("--request-budget", args.request_budget, 1, 1_000_000),
    )
    for flag, value, minimum, maximum in numeric:
        if value is None:
            continue
        exclusive_minimum = flag in ("--rate", "--max-rate")
        below_minimum = value <= minimum if exclusive_minimum else value < minimum
        if not math.isfinite(value) or below_minimum or value > maximum:
            relation = "greater than" if exclusive_minimum else "at least"
            parser.error(f"{flag} must be {relation} {minimum} and at most {maximum}")


def load_request_headers(path, parser, label="--headers-file"):
    """Load optional assessment headers without exposing their values in reports."""
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as header_file:
            headers = json.load(header_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.error(f"could not read {label}: {exc}")
    if not isinstance(headers, dict) or not headers:
        parser.error(f"{label} must contain a non-empty JSON object of string headers")

    token = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
    forbidden = {"host", "content-length", "connection", "transfer-encoding",
                 "proxy-authorization", "proxy-connection"}
    validated = {}
    seen = set()
    for name, value in headers.items():
        name = str(name)
        if not token.fullmatch(name) or name.lower() in forbidden:
            parser.error(f"{label} contains an invalid or disallowed header name: {name!r}")
        if name.lower() in seen:
            parser.error(f"{label} repeats header name with different casing: {name!r}")
        if not isinstance(value, str):
            parser.error(f"{label} values must be strings (header {name!r})")
        if any((ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in value):
            parser.error(f"{label} values must be single-line strings (header {name!r})")
        seen.add(name.lower())
        validated[name] = value
    return validated


def load_identities(args, parser, legacy_headers=None):
    """Resolve the identity document into validated credential sources.

    Loading performs no network work: it parses, validates and interpolates
    environment references, so a malformed identity document is rejected before
    the scan opens a single connection.
    """
    from core.auth import sources as auth_sources

    identities = []
    auth_file = getattr(args, "auth_file", None)
    from_env = getattr(args, "auth_from_env", False)

    if auth_file or from_env:
        try:
            if auth_file:
                identities = auth_sources.load_credentials(source=auth_file)
            else:
                identities = auth_sources.load_from_env()
        except auth_sources.AuthConfigError as exc:
            parser.error(f"identity configuration is invalid: {exc}")

    if not identities and legacy_headers:
        
        identities = auth_sources.load_credentials(data={
            "identities": [{"name": "primary", "method": "headers",
                            "role": "user", "headers": legacy_headers}],
        })
    return identities


def prepare_authentication(context, console, args) -> dict:
    """Log in every configured identity and adopt the result as the scan session.

    Runs only after the transport and scope policy are bound, so a login request
    is subject to exactly the same route and scope rules as the scan itself.
    """
    if context is None:
        return {}
    from core import redact

    report = context.prepare()
    for secret in context.secret_values():
        redact.register_secret(secret)
    return report


def show_auth(console, args, parser) -> None:
    """Print the configured identities without performing any login."""
    identities = load_identities(args, parser,
                                 legacy_headers=load_request_headers(
                                     getattr(args, "headers_file", None), parser))
    if not identities:
        info(console, "No identities are configured; the scan would run unauthenticated.")
        info(console, "Add one with --auth-file identities.json or --auth-from-env.")
        return

    rows = []
    for identity in identities:
        described = identity.describe()
        rows.append((
            described["name"],
            described["role"],
            described["method"],
            ", ".join(described["header_names"]) or "-",
            described["login_url"] or "-",
        ))
    console.print(make_table("Configured Identities",
                             ["Name", "Role", "Method", "Headers", "Login URL"],
                             rows, style="cyan"))
    info(console, "States are resolved at login time; this listing performs no requests.")
    if not any(identity.authenticated for identity in identities):
        warning(console, "Only the anonymous identity is configured.")


def apply_mode_defaults(args) -> None:
    """Make the low-impact boundary explicit rather than relying on many skip flags."""
    if args.mode == "safe":
        args.skip_ports = True
        args.skip_dirs = True
        args.skip_sqli = True
        args.skip_xss = True
        args.skip_oob = True
    elif args.mode == "active":
        args.skip_oob = True


def _clear_screen(console) -> None:
    """Clear the console reliably on Windows cmd and POSIX terminals."""
    try:
        import os

        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        try:
            console.clear()
        except Exception:
            pass
    try:
        paint_terminal()
    except Exception:
        pass


def interactive_pick(console) -> tuple:
    if console.is_terminal and sys.stdin.isatty():
        from core.setup_ui import run_setup
        return run_setup() or ("", {})
    return _text_pick(console)


def _text_pick(console) -> tuple:
    console.print()
    console.print(Panel(
        "[bold kw.cyan]No target given — interactive mode[/]\n"
        "Choose the modules to run, then set the profile and the target.\n"
        "[kw.muted]Enter 'all' or '22' for a full run.[/]",
        border_style="kw.cyan", box=rbox.ROUNDED, padding=(0, 1),
        style=f"on {BG}",
    ))

    entries = [(f"{i:02d}", name) for i, (name, _, _) in enumerate(MODULES, 1)]
    entries.append(("22", "Full (run everything)"))

    roster = Table.grid(expand=False, padding=(0, 1))
    roster.add_column(justify="right", width=4)
    roster.add_column(justify="left", width=38)
    roster.add_column(justify="right", width=4)
    roster.add_column(justify="left", width=38)
    half = 11
    for row in range(half):
        left = entries[row] if row < len(entries) else ("", "")
        right = entries[row + half] if row + half < len(entries) else ("", "")
        roster.add_row(
            f"[kw.cyan]{left[0]}[/]", left[1],
            f"[kw.cyan]{right[0]}[/]", right[1],
        )
    console.print(roster)
    console.print()

    prompt = "[bold kw.amber]Enter Your Command Krypto ![/]"
    console.print(f"{prompt} Select modules (numbers, '22' for Full, or Enter for all): ", end="")
    chosen = input().strip()
    _clear_screen(console)

    run_all = (chosen == "" or chosen.lower() in ("all", "a", "22", "full", "f"))

    selected = set()
    if not run_all:
        for token in chosen.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                idx = int(token) - 1
                if 0 <= idx < len(MODULES):
                    selected.add(MODULES[idx][1])
            except ValueError:
                pass

    args = {"request_budget": None}
    for name, skip, _ in MODULES:
        if skip:
            if run_all or not selected:
                args[skip] = False
            else:
                args[skip] = skip not in selected

    console.print()
    console.print(f"{prompt} Safety mode (safe/active/intrusive) [safe]: ", end="")
    mode = input().strip().lower()
    if mode not in ("safe", "active", "intrusive"):
        mode = "safe"
    args["mode"] = mode
    args["ack_authorized"] = False
    if mode != "safe":
        console.print(
            f"{prompt} Type AUTHORIZED to confirm explicit permission for this target: ",
            end="",
        )
        args["ack_authorized"] = input().strip() == "AUTHORIZED"
        if not args["ack_authorized"]:
            warning(console, "Authorization was not acknowledged; falling back to safe mode.")
            args["mode"] = "safe"

    console.print()
    console.print(f"{prompt} Coverage profile (default/deep) [default]: ", end="")
    profile = input().strip().lower()
    args["deep"] = profile == "deep"
    if args["deep"]:
        console.print("[kw.cyan]  -> Deep profile: larger budgets, more rounds, more discovery.[/]")
    _clear_screen(console)

    console.print()
    console.print(f"{prompt} Target URL / Domain: ", end="")
    target = input().strip()
    _clear_screen(console)

    return target, args


def is_admin() -> bool:
    """True when the current process already has administrator/root rights."""
    if os.name != "nt":
        return (not hasattr(os, "geteuid")) or os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _cmd_quote(value: str) -> str:
    """Quote one token for cmd.exe."""
    return '"' + str(value).replace('"', '""') + '"'


def cmd_command() -> str:
    """The cmd.exe command line that hosts this exact invocation."""
    invocation = " ".join(_cmd_quote(arg) for arg in [sys.executable] + sys.argv)
    return (
        "color 0F"
        " & title K R I P T O 2.0"
        " & prompt Enter Your Command Krypto !$G"
        f" & cd /d {_cmd_quote(os.getcwd())}"
        " & chcp 65001 >nul"
        " & set PYTHONIOENCODING=utf-8"
        " & " + invocation
    )


def elevation_arguments() -> str:
    """cmd.exe arguments for the elevated relaunch.

    ``/s`` makes cmd treat everything after ``/k`` as one command with only the
    outermost quotes stripped, so the quoted paths inside stay intact.
    """
    return '/s /k "' + cmd_command() + '"'


def ensure_admin(console) -> None:
    """Re-launch inside an elevated cmd.exe window (UAC), never raw python.exe.

    The Python process still does the work, but the visible host stays a cmd
    window with the branded prompt, so the user never sees a bare python.exe
    console.
    """
    if os.name != "nt" or os.environ.get("KRIPTO_NO_ELEVATE") or is_admin():
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return

    try:
        import ctypes

        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            "cmd.exe",
            elevation_arguments(),
            os.getcwd(),
            1,
        )
        if result <= 32:
            raise OSError(f"ShellExecuteW returned {result}")
    except Exception as exc:
        warning(console, f"Elevation failed ({exc}) - running without administrator rights.")
        return
    sys.exit(0)


def paint_terminal() -> None:
    """Set a black Windows console background and repaint supporting terminals."""
    if not sys.stdout.isatty():
        return
    if os.name == "nt":
        try:
            import ctypes

            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            ctypes.windll.kernel32.SetConsoleTextAttribute(handle, 0x0F)
        except Exception:
            pass
    try:
        sys.stdout.write(background_escape(BG))
        sys.stdout.flush()
    except Exception:
        pass


def tor_manager_for(args):
    """Build/reuse the Tor manager configured from the CLI."""
    return tor_manager.get_manager(
        root=getattr(args, "tor_root", None),
        socks_host=getattr(args, "tor_socks_host", "127.0.0.1"),
        socks_port=getattr(args, "tor_port", 9050),
        data_dir=os.path.join(getattr(args, "output", "output"), "tor"),
        start_timeout=getattr(args, "tor_timeout", 60.0),
    )


def show_tor_status(console, args) -> None:
    """Render the Tor diagnostics panel: install, process, listener, transport."""
    manager = tor_manager_for(args)
    diagnostics = manager.diagnostics()
    installation = diagnostics["installation"]
    status = diagnostics["status"]
    socks_check = diagnostics["socks_check"]
    listener = diagnostics["listener"]

    def mark(ok):
        return "[kw.green]yes[/]" if ok else "[kw.red]no[/]"

    rows = [
        ("Tor installation found", mark(installation["valid"] or bool(installation["executable"]))),
        ("Executable path", installation["executable"] or "[kw.dim]not found[/]"),
        ("Tor version", installation["version"] or "[kw.dim]unknown[/]"),
        ("GeoIP database", installation["geoip"] or "[kw.dim]missing[/]"),
        ("Bundled torrc", installation["bundled_torrc"] or "[kw.dim]none[/]"),
        ("Process running", mark(status["running"])),
        ("Managed by Kripto", mark(status["managed"])),
        ("Process id", str(status["pid"]) if status["pid"] else "[kw.dim]none[/]"),
        ("SOCKS address", f"{status['socks_host']}:{status['socks_port']}"),
        ("Listener answering", mark(socks_check["ok"])),
        ("Listener detail", socks_check["detail"]),
        ("Bootstrap", (f"{status['bootstrap_percent']}%"
                       if status["bootstrap_percent"] is not None
                       else "[kw.dim]no log yet[/]")),
        ("Port owner", (f"{listener['name']} (pid {listener['pid']})"
                        if listener.get("pid") else "[kw.dim]nothing listening[/]")),
        ("Selected transport", getattr(args, "proxy", None) or "direct"),
        ("Proxy endpoint", status["proxy_url"]),
        ("Data directory", diagnostics["paths"]["data_dir"]),
        ("Log file", diagnostics["paths"]["log"]),
    ]
    console.print(make_table("Tor Expert Bundle - Diagnostics",
                             ["Setting", "Value"], rows, style="cyan"))

    if status["errors"] or installation["errors"]:
        warning(console, "Diagnostics reported problems:")
        for item in list(installation["errors"]) + list(status["errors"]):
            warning(console, f"  {item}")
    if not installation["valid"]:
        warning(console, "The bundle is incomplete or unusable; Tor transport will refuse to start.")
    if status["log_tail"]:
        section_header(console, "Tor log tail")
        for line in status["log_tail"][-8:]:
            info(console, line)
    info(console, "Kripto makes no anonymity claims: Tor is a configurable network route only.")


def show_profiles(console) -> None:
    """Print every testing profile with the tests it enables."""
    for entry in profile_registry.catalogue():
        console.print()
        console.print(Panel(
            f"[bold kw.cyan]{entry['name']}[/]\n"
            f"[kw.muted]minimum mode:[/] {entry['min_mode']}\n\n"
            f"{entry['summary']}",
            border_style="kw.cyan", box=rbox.ROUNDED, padding=(0, 1),
            style=f"on {PANEL}",
        ))
        for item in entry["enables"]:
            console.print(f"  [kw.green]>[/] {item}")
    console.print()
    info(console, "Select one or more: --profile web-deep --profile injection")
    info(console, "Profiles choose which modules run; they never weaken scope, rate or budgets.")


def handle_utility_flags(console, args, parser) -> bool:
    """Handle flags that finish without a target. Returns True when handled."""
    if args.list_profiles:
        show_profiles(console)
        return True
    if getattr(args, "list_plugins", False):
        from core.plugins import PluginRegistry
        registry = PluginRegistry(args.plugin_dir)
        console.print(json.dumps({"plugins": registry.manifests, "errors": registry.errors}, indent=2))
        return True
    if args.transition_finding:
        scan_id, key, status = args.transition_finding
        if status.lower() not in {"accepted_risk", "false_positive"} or not args.reason:
            parser.error("lifecycle decisions require accepted_risk/false_positive and a non-empty --reason")
        with scan_commands.open_store(args) as store:
            console.print(json.dumps(store.transition_finding(scan_id, key, status, args.reason), ensure_ascii=False, indent=2))
        return True
    if args.verify_evidence:
        with scan_commands.open_store(args) as store:
            console.print(json.dumps(store.evidence.get(args.verify_evidence), ensure_ascii=False, indent=2))
        return True
    if args.retest_finding:
        validate_args(parser, args)
        if args.mode == "safe" or not args.ack_authorized:
            parser.error("--retest-finding requires --mode active --ack-authorized")
        sys.exit(scan_commands.retest_finding(console, args))

    if getattr(args, "list_auth", False):
        show_auth(console, args, parser)
        return True

    
    if getattr(args, "list_scans", False):
        sys.exit(scan_commands.list_scans(console, args))
    if getattr(args, "show_scan", None):
        sys.exit(scan_commands.show_scan(console, args, args.show_scan))
    if getattr(args, "compare_scans", None):
        previous, current = args.compare_scans
        sys.exit(scan_commands.compare_scans(console, args, previous, current))
    if getattr(args, "export_scan", None):
        sys.exit(scan_commands.export_scan(console, args, args.export_scan))

    if args.tor_stop:
        stopped = tor_manager_for(args).stop()
        if stopped:
            success(console, "Stopped the Tor process Kripto started.")
        else:
            info(console, "No Kripto-managed Tor process was running.")
        return True

    if args.tor_status:
        show_tor_status(console, args)
        return True

    if args.tor_check:
        manager = tor_manager_for(args)
        info(console, "Starting Tor (and waiting for bootstrap)...")
        try:
            manager.start(timeout=getattr(args, "tor_timeout", 60.0))
        except tor_manager.TorError as exc:
            error(console, f"Tor could not be started: {exc}")
            return True
        result = manager.verify_connectivity(timeout=max(30.0, args.tor_timeout))
        if result.get("ok") and result.get("is_tor") is not False:
            success(console, f"Tor egress confirmed via {result.get('url')}")
            info(console, f"Exit address: {result.get('exit_ip')}  "
                          f"(latency {result.get('latency')}s)")
        else:
            error(console, f"Tor connectivity check failed: {result.get('error')}")
        if not args.tor_keep_running:
            manager.stop()
            info(console, "Stopped the Tor process used for this check.")
        return True

    return False


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    configure_windows_console()
    console = Console(theme=THEME, style=f"on {BG}")
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "tor_keep_running"):
        args.tor_keep_running = False
    if handle_utility_flags(console, args, parser):
        return
    ensure_admin(console)
    paint_terminal()
    if not args.no_splash:
        try:
            show_splash(console)
        except KeyboardInterrupt:
            warning(console, "Startup cancelled by operator.")
            sys.exit(130)

    target = args.url
    interactive = (target is None and not args.non_interactive)
    if interactive:
        target, picked = interactive_pick(console)
        for k, v in picked.items():
            setattr(args, k, v)
        if not target:
            error(console, "No target provided. Exiting.")
            sys.exit(1)
        if not hasattr(args, "rate"):
            args.rate = REQUESTS_PER_SECOND
        if not hasattr(args, "deep"):
            args.deep = False

    validate_args(parser, args)
    apply_mode_defaults(args)

    if not target:
        console.print("[bold yellow]Enter Your Command Krypto ![/bold yellow] ", end="")
        try:
            target = input().strip()
        except EOFError:
            parser.error("a target is required; pass --url in non-interactive environments")

    if not target:
        error(console, "No target provided. Exiting.")
        sys.exit(1)

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        parser.error("target must be a valid http:// or https:// URL with a hostname")
    if parsed.username or parsed.password:
        parser.error("credentials embedded in the target URL are not allowed")
    domain = parsed.hostname

    config.REQUEST_HEADERS = load_request_headers(args.headers_file, parser)
    args.test_account_headers = load_request_headers(
        getattr(args, "test_account_headers", None), parser,
        label="--test-account-headers",
    )

    
    
    
    auth_identities = load_identities(args, parser,
                                      legacy_headers=config.REQUEST_HEADERS)

    
    
    
    profile_resolution = None
    requested_profiles = getattr(args, "profile", None)
    if requested_profiles:
        try:
            profile_resolution = profile_registry.resolve(
                requested_profiles, mode=args.mode
            )
        except profile_registry.ProfileError as exc:
            parser.error(str(exc))
        args.profile = list(profile_resolution.names)
    else:
        args.profile = []

    
    
    
    try:
        resolution = transport_layer.resolve(
            getattr(args, "proxy", None),
            start_tor=getattr(args, "tor_start", False),
            tor_root=getattr(args, "tor_root", None),
            tor_data_dir=os.path.join(args.output, "tor"),
            tor_timeout=getattr(args, "tor_timeout", 60.0),
            tor_host=getattr(args, "tor_socks_host", "127.0.0.1"),
            tor_port=getattr(args, "tor_port", 9050),
        )
    except transport_layer.TransportError as exc:
        error(console, f"Transport unavailable: {exc}")
        warning(console, "Refusing to scan. The requested proxy could not be used and "
                         "Kripto will not fall back to a direct connection.")
        sys.exit(3)
    transport_layer.apply(resolution)
    from core.runtime import RunControl
    args.run_control = RunControl(args.request_budget, args.threads or 16)
    RateLimitedSession.configure_runtime(args.run_control)

    effective_rate = args.rate
    if getattr(args, "max_rate", None) is not None and args.max_rate < args.rate:
        effective_rate = args.max_rate
    config.REQUESTS_PER_SECOND = effective_rate
    config.TLS_VERIFY = not args.insecure

    if getattr(args, "rounds", None):
        args.rounds = max(1, args.rounds)
    else:
        args.rounds = 6 if getattr(args, "deep", False) else 3

    if getattr(args, "scope", None):
        args.scope = args.scope.strip()
    if getattr(args, "exclude", None):
        args.exclude = [p.strip() for p in args.exclude.split(",") if p.strip()]
    else:
        args.exclude = []

    RateLimitedSession.reset_shared()
    RateLimitedSession.configure_runtime(args.run_control)
    RateLimitedSession.shared(effective_rate)
    try:
        RateLimitedSession.configure_policy(
            target,
            scope=getattr(args, "scope", None),
            excludes=args.exclude,
        )
    except ValueError as exc:
        parser.error(f"invalid scope policy: {exc}")

    auth_context = None
    auth_report = {}
    if auth_identities:
        from core.auth import AuthContext

        auth_context = AuthContext(
            target, console, auth_identities,
            reauthenticate=not getattr(args, "no_reauth", False),
        )
        auth_report = prepare_authentication(auth_context, console, args)

        
        
        
        
        if auth_context.primary_headers():
            config.REQUEST_HEADERS = auth_context.primary_headers()
        if not args.test_account_headers and auth_context.secondary_headers():
            args.test_account_headers = auth_context.secondary_headers()

        for error_text in auth_report.get("errors", []):
            warning(console, f"Identity problem: {error_text}")
        if auth_report.get("authenticated"):
            success(console, "Authentication: " + auth_context.summary_line())
        else:
            warning(console, "Authentication: no configured identity authenticated. "
                             "The scan will run unauthenticated; treat authenticated-only "
                             "checks as INCONCLUSIVE.")
        if auth_context.has_two_identities():
            found(console, "Two distinct identities are available: horizontal access-control "
                           "testing can produce CONFIRMED evidence.")
    args.auth_context = auth_context

    
    
    
    scan_store = None
    scan_id = None
    args.resume_state = None
    if getattr(args, "resume", None):
        args.resume_state = scan_commands.load_resume_state(
            console, args, target, args.mode
        )
        if args.resume_state is None:
            warning(console, "Resume was refused; this run starts from scratch.")
    if not getattr(args, "no_store", False):
        try:
            scan_store = scan_commands.open_store(args)
            scan_store.connect()
            scan_id = scan_store.start_scan(target, args.mode,
                                            profile=",".join(args.profile),
                                            settings={"rate": effective_rate,
                                                      "scope": getattr(args, "scope", None)})
        except StoreError as exc:
            warning(console, f"Scan history disabled: {exc}")
            scan_store, scan_id = None, None
    args.scan_store = scan_store
    args.scan_id = scan_id

    profile = "deep" if getattr(args, "deep", False) else "default"
    use_ui = bool(console.is_terminal) and not args.no_ui and sys.stdout.isatty()

    if not use_ui:
        show_banner(console, target=target, profile=profile)
        console.print(
            Panel(
                f"[bold kw.text]TARGET[/]    {target}\n"
                f"[bold kw.text]DOMAIN[/]    {domain}\n"
                f"[bold kw.text]PROFILES[/]  {', '.join(args.profile)}\n"
                f"[bold kw.text]MODE[/]      {args.mode}\n"
                f"[bold kw.text]TRANSPORT[/] {resolution.label}\n"
                f"[bold kw.text]AUTH[/]      "
                f"{(auth_context.summary_line() if auth_context else 'unauthenticated')}\n"
                f"[bold kw.text]RATE[/]      {effective_rate} req/s   "
                f"[bold kw.text]THREADS[/]  "
                f"{'adaptive' if getattr(args, 'threads', None) is None else args.threads}\n"
                f"[bold kw.text]SCOPE[/]     {getattr(args, 'scope', None) or 'single host'}\n"
                f"[bold kw.text]EXCLUDE[/]   "
                f"{', '.join(getattr(args, 'exclude', [])) or 'none'}",
                title="Target Specifications", border_style="kw.cyan",
                box=rbox.ROUNDED, padding=(0, 1), style=f"on {PANEL}",
            )
        )

    preflight_note = "skipped (--force)" if args.force else ""
    if not args.force:
        reachable, preflight_note = preflight(target, console, quiet=use_ui)
        if not reachable:
            if scan_store is not None and scan_id:
                scan_store.finish_scan(scan_id, "failed")
                scan_store.close()
            RateLimitedSession.close_all()
            sys.exit(2)

    dashboard = None
    scan_console = console
    if use_ui:
        dashboard = Dashboard(
            console=console,
            target=target,
            domain=domain,
            profile=profile,
            rate=effective_rate,
            threads=getattr(args, "threads", None),
            scope=getattr(args, "scope", None),
            exclude=getattr(args, "exclude", []),
            preflight=preflight_note,
        )
        try:
            dashboard.transport = resolution.label
            dashboard.findings_count = 0
        except Exception:
            pass
        scan_console = UIConsole(dashboard, console)

    pipeline = Pipeline(target, scan_console, args)
    pipeline.max_rounds = args.rounds
    if getattr(args, "pages", None):
        pipeline.limits["crawl_pages"] = args.pages
    if getattr(args, "budget", None):
        pipeline.limits["injection_budget"] = args.budget
        pipeline.surface.budget = args.budget
    if getattr(args, "brute_budget", None):
        pipeline.limits["brute_budget"] = args.brute_budget
        pipeline.brute_budget = args.brute_budget
    if getattr(args, "scope", None):
        pipeline.scope = args.scope
    if getattr(args, "exclude", None):
        pipeline.exclude_paths = args.exclude

    if dashboard is not None:
        dashboard.runtime_provider = pipeline.control.report
        dashboard.limits = {
            "rounds": args.rounds,
            "crawl_depth": pipeline.limits.get("crawl_depth"),
            "crawl_pages": pipeline.limits.get("crawl_pages"),
            "injection_budget": pipeline.limits.get("injection_budget"),
            "brute_budget": pipeline.brute_budget,
        }

    start_ticks = time.time()

    try:
        if dashboard is not None:
            outcome = {}

            def worker():
                try:
                    outcome["results"] = pipeline.run()
                except BaseException as exc:  
                    outcome["error"] = exc
                    outcome["traceback"] = exc.__traceback__
                finally:
                    dashboard.finish("error" not in outcome)

            thread = threading.Thread(target=worker, daemon=True, name="krypto-scan")
            thread.start()
            dashboard.run()
            if dashboard.interrupted:
                pipeline.cancel()
                thread.join(timeout=30)
                raise KeyboardInterrupt
            thread.join()
            if "error" in outcome:
                raise outcome["error"].with_traceback(outcome.get("traceback"))
            results = outcome["results"]
        else:
            results = pipeline.run()

        results["target"] = target
        results["profile"] = pipeline.profile
        results["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        policy = RateLimitedSession.get_shared_policy()
        results["scope_policy"] = policy.report() if policy is not None else {}
        results["settings"] = {
            "mode": args.mode,
            "authorized_acknowledged": bool(args.ack_authorized),
            "tls_verification": not args.insecure,
            "secrets_redacted": not args.include_secrets,
            "evidence_downloads": bool(args.download_evidence),
            "rate": effective_rate,
            "depth": pipeline.limits["crawl_depth"],
            "pages": pipeline.limits["crawl_pages"],
            "injection_budget": pipeline.limits["injection_budget"],
            "brute_budget": pipeline.brute_budget,
            "rounds": args.rounds,
            "scope": getattr(args, "scope", None),
            "excluded_paths": getattr(args, "exclude", []),
            "threads": "adaptive" if getattr(args, "threads", None) is None else args.threads,
            "authenticated_headers_configured": bool(config.REQUEST_HEADERS),
            "second_identity_configured": bool(args.test_account_headers),
            "transport": resolution.report(),
            "authentication": auth_report or {},
        }
        if auth_context is not None:
            results["authentication"] = auth_context.report()
            results["authentication"]["login_history"] = {
                session.source.name: session.history()
                for session in auth_context.all()
            }
            results["authentication"]["anonymous_baseline"] = bool(auth_context.anonymous)
        if profile_resolution is not None:
            results.setdefault("profiles", profile_resolution.report())
        results["findings"] = results.get("findings") or []
        results["finding_states"] = results.get("finding_states") or {}
        results["scan_id"] = scan_id
        if scan_store is not None and scan_id:
            try:
                scan_store.finish_scan(scan_id, INTERRUPTED if results.get("interrupted") else "complete")
                info(console, f"Recorded in scan history as {scan_id}")
            except StoreError as exc:
                warning(console, f"Could not record the scan: {exc}")

        section_header(console, "Scan Health Summary")
        failed = pipeline.health.failures()
        inconclusive = pipeline.health.modules("INCONCLUSIVE")
        skipped = pipeline.health.modules("SKIPPED")
        console.print(make_table("Module Status", ["Module", "Status", "Detail"],
                                 pipeline.health.rows(), style="dim cyan"))
        if failed:
            warning(console, f"{len(failed)} module(s) failed: {', '.join(failed)}")
            warning(console, "Treat failed sections as INCONCLUSIVE, not as 'no issues found'.")
        if inconclusive:
            warning(console, f"{len(inconclusive)} module(s) were inconclusive: "
                             f"{', '.join(inconclusive)}")
        if skipped:
            info(console, f"{len(skipped)} module(s) were intentionally skipped: "
                          f"{', '.join(skipped)}")
        if not failed and not inconclusive:
            success(console, "All executed modules completed successfully.")

        section_header(console, "Attack Surface Map")
        stats = results["attack_surface"]
        rows = [
            ("Endpoints discovered", str(stats["endpoints"])),
            ("Parameters discovered", str(stats["params"])),
            ("Parameters probe-confirmed", str(stats["confirmed_params"])),
            ("Forms", str(stats["forms"])),
            ("Discovery rounds", str(results.get("convergence", {}).get("rounds", 0))),
            ("Converged", "yes" if results.get("convergence", {}).get("converged") else "no"),
        ]
        rows += [(f"  from {k}", str(v)) for k, v in stats["by_source"].items()]
        console.print(make_table("Surface Totals", ["Metric", "Value"], rows, style="cyan"))
        if stats["params"] == 0:
            warning(console, "Zero parameters across the whole run. Injection testing was "
                            "structurally impossible - do not read that as 'not vulnerable'.")

        correlated = results.get("correlated", {}) or {}
        section_header(console, "Correlated Findings & Attack Paths")
        paths = correlated.get("attack_paths", []) or []
        if paths:
            for path in paths[:5]:
                marker = "[VULN]" if path["severity"] == "critical" else "[!]"
                lines = [
                    f"{marker} {path['name'].upper()}  (score {path['score']})",
                    f"      1. {path['steps'][0]['action']} -> {path['steps'][0]['result']}",
                ]
                for step in path["steps"][1:]:
                    lines.append(f"      {step['step']}. {step['action']} -> {step['result']}")
                lines.append(f"      => {path['consequence']}")
                for line in lines:
                    vuln(console, line)
        else:
            found(console, "No multi-step chain links the findings that were detected.")

        scored = results.get("scored", {}) or {}
        if scored.get("all"):
            final_summary(
                console,
                "Top Findings (CVSS 3.1)",
                [(f["title"][:52], f"{f['cvss_score']:.1f}", f["band"], f["cwe"])
                 for f in scored["all"][:10]],
                verdict=("critical" if any(f["cvss_score"] >= 9.0 for f in scored["all"])
                         else "high" if any(f["cvss_score"] >= 7.0 for f in scored["all"])
                         else "medium" if any(f["cvss_score"] >= 4.0 for f in scored["all"])
                         else "low"),
            )

        impact = results.get("impact", {}) or {}
        if impact.get("blast_radius"):
            section_header(console, "Impact Model")
            for layer in impact["blast_radius"]:
                if layer["reached"]:
                    vuln(console, f"[VULN] {layer['layer']}: reached - {layer['basis']}")
                else:
                    found(console, f"[+] {layer['layer']}: not reached - {layer['basis']}")
            if impact.get("worst_case"):
                warning(console, f"Worst case: {impact['worst_case']}")

        remediation = results.get("remediation", {}) or {}
        if remediation.get("guidance_count"):
            section_header(console, "Remediation & Code-Level Fixes")
            info(console, f"Framework detected: {remediation.get('framework')}")
            for item in remediation.get("guidance", [])[:12]:
                vuln(console, f"{item['finding']}")
                if item.get("before"):
                    info(console, f"  BEFORE: {item['before']}")
                    info(console, f"  AFTER:  {item['after']}")

        verification = results.get("verification", {}) or {}
        if verification.get("summary"):
            section_header(console, "Verification (re-requested)")
            s = verification["summary"]
            info(console, f"Checked {s.get('checked', 0)} | Reproduced {s.get('verified', 0)} | "
                         f"Refuted {s.get('refuted', 0)}")
            for item in (verification.get("exposed_files_refuted") or [])[:5]:
                warning(console, f"REFUTED: {item['url']} - {item['why']}")

        gaps = correlated.get("coverage_gaps", [])
        if gaps:
            section_header(console, "Coverage Gaps")
            for gap in gaps:
                warning(console, f"{gap['gap']} -> {gap['consequence']}")

        section_header(console, "Generating Comprehensive Output Report")
        pipeline.health.states["Reports"] = "RUNNING"
        pipeline._stage(28, "Executive & Technical Report Generation")
        reporter = Reporter(
            target,
            output_dir=args.output,
            include_secrets=args.include_secrets,
            formats=tuple(args.report_formats.split(",")), language=args.report_language,
            font=args.report_font, engagement={"engagement": args.engagement_name,
                                               "client": args.client, "assessor": args.assessor},
        )
        try:
            report_path = reporter.generate(results)
        except Exception as exc:
            pipeline.health.record("Reports", False, str(exc))
            raise
        pipeline.health.record("Reports", True, f"{len(reporter.outputs) + 2} report files generated")
        results["reports"] = {os.path.basename(path): os.path.abspath(path)
                              for path in [reporter.txt_filename, reporter.json_filename] + reporter.outputs}

        elapsed = time.time() - start_ticks
        final_summary(
            console,
            "Scan Incomplete" if results.get("interrupted") else "Scan Complete",
            [
                ("Elapsed", f"{elapsed:.1f}s"),
                ("Modules", f"{len(pipeline.health.modules('OK'))}/{len(pipeline.health.states)} OK"),
                ("Findings", str(len(results.get("findings") or []))),
                ("Attack paths", str(correlated.get("attack_path_count", 0))),
                ("Highest CVSS", f"{max((f.get('cvss_score', 0) for f in scored.get('all', [])), default=0):.1f}"),
                ("Report", report_path),
            ],
            verdict=("critical" if any(f.get("cvss_score", 0) >= 9.0 for f in scored.get("all", []))
                     else "high" if any(f.get("cvss_score", 0) >= 7.0 for f in scored.get("all", []))
                     else "medium" if any(f.get("cvss_score", 0) >= 4.0 for f in scored.get("all", []))
                     else "low"),
        )

        if dashboard is not None:
            pipeline._publish_ui()
            dashboard.publish(dict(dashboard.snapshot, reports=results["reports"]))
            dashboard.finish(True)
            if not dashboard.dismissed:
                dashboard.view_index = 8
                dashboard.run(review=True)

    except KeyboardInterrupt:
        pipeline.cancel()
        warning(console, "Scan interrupted by operator.")
        if scan_store is not None and scan_id:
            try:
                scan_store.finish_scan(scan_id, INTERRUPTED)
                info(console, f"Partial progress saved as {scan_id}; resume it with "
                              f"--resume {scan_id}")
            except StoreError as exc:
                warning(console, f"Could not record interrupted scan: {exc}")
        sys.exit(130)
    except Exception as e:
        error(console, f"Fatal error during execution: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        if scan_store is not None and scan_id:
            scan_store.finish_scan(scan_id, "failed")
        sys.exit(1)
    finally:
        RateLimitedSession.close_all()
        if scan_store is not None:
            scan_store.close()


if __name__ == "__main__":
    main()
