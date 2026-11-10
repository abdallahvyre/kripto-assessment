"""Manage the local Tor Expert Bundle as a controlled SOCKS5 transport.

The bundle shipped with this project is a Windows Expert Bundle: it has no
installer, no service registration, and no ``tor.exe`` alias.  It exposes
``tor-real.exe`` plus side-by-side DLLs, a ``geoip``/``geoip6`` pair, and a
``torrc`` whose absolute paths point at an install location that does not
exist on this machine.  Running that ``torrc`` directly fails, so this module
never uses it: it writes its own configuration into a private data directory
under ``output/`` and passes it with ``-f``.

Everything here is deliberately conservative:

* the executable is discovered, never downloaded;
* a Tor process this module did not start is detected and reused, never
  killed;
* the process is a real child process with a captured log file, so a failure
  is diagnosable instead of silent;
* every started process is registered for cleanup, so an interrupted scan
  cannot leave an orphan listener behind.

This module performs no anonymity claims.  Tor is a network route, nothing
more.
"""

from __future__ import annotations

import atexit
import os
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050

EXECUTABLE_NAMES = ("tor.exe", "tor-real.exe", "tor.real.exe", "tor")
GEOIP_NAMES = ("geoip",)
GEOIP6_NAMES = ("geoip6",)
BUNDLE_DIR_NAMES = (
    "tor", "Tor", "tor-expert-bundle", "TorBrowser", "tor-browser",
    "Tor Browser", "torbundle", "tor_bundle",
)

VERSION_PATTERN = re.compile(r"Tor version (\d+(?:\.\d+)+)", re.IGNORECASE)
_BOOTSTRAP_PERCENT = re.compile(r"Bootstrapped (\d+)%")



FATAL_HINTS = (
    (r"protocol listed as required in the consensus is not supported",
     "the bundled Tor build is too old for the current Tor network: the "
     "consensus requires descriptor protocols this build does not implement. "
     "Replace the bundle with a current Tor Expert Bundle."),
    (r"Could not bind to .*Address already in use",
     "the SOCKS port is already bound by another process."),
    (r"Unable to open .* for writing|Permission denied",
     "a Tor data or log path is not writable by this process."),
    (r"Could not read GEOIP file|Failed to open GEOIP file",
     "the GeoIP database could not be read from the bundle directory."),
    (r"Unacceptable option value|Failed to parse/validate config",
     "the generated Tor configuration was rejected."),
)
_FATAL_COMPILED = tuple((re.compile(pattern, re.IGNORECASE), text)
                        for pattern, text in FATAL_HINTS)


_CREATE_NO_WINDOW = 0x08000000

DEFAULT_START_TIMEOUT = 60.0
DEFAULT_STOP_TIMEOUT = 10.0


@dataclass
class TorInstallation:
    """A discovered Tor bundle on disk."""

    root: Path
    executable: Path
    geoip: Path | None = None
    geoip6: Path | None = None
    bundled_torrc: Path | None = None
    version: str = ""
    errors: list = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.executable is not None and bool(self.version) and not self.errors

    def report(self) -> dict:
        return {
            "root": str(self.root) if self.root else "",
            "executable": str(self.executable) if self.executable else "",
            "version": self.version,
            "geoip": str(self.geoip) if self.geoip else "",
            "geoip6": str(self.geoip6) if self.geoip6 else "",
            "bundled_torrc": str(self.bundled_torrc) if self.bundled_torrc else "",
            "valid": self.valid,
            "errors": list(self.errors),
        }


@dataclass
class TorStatus:
    """A complete, reportable snapshot of the local Tor transport."""

    installed: bool = False
    executable_path: str = ""
    version: str = ""
    running: bool = False
    managed: bool = False
    pid: int | None = None
    socks_host: str = DEFAULT_SOCKS_HOST
    socks_port: int = DEFAULT_SOCKS_PORT
    socks_listening: bool = False
    bootstrap_percent: int | None = None
    transport: str = "direct"
    errors: list = field(default_factory=list)
    log_tail: list = field(default_factory=list)

    @property
    def proxy_url(self) -> str:
        return f"socks5h://{self.socks_host}:{self.socks_port}"

    def report(self) -> dict:
        return {
            "installed": self.installed,
            "executable_path": self.executable_path,
            "version": self.version,
            "running": self.running,
            "managed": self.managed,
            "pid": self.pid,
            "socks_host": self.socks_host,
            "socks_port": self.socks_port,
            "socks_listening": self.socks_listening,
            "bootstrap_percent": self.bootstrap_percent,
            "transport": self.transport,
            "proxy_url": self.proxy_url,
            "errors": list(self.errors),
            "log_tail": list(self.log_tail),
        }


class TorError(RuntimeError):
    """Raised when a requested Tor operation cannot be completed."""


def _tor_path(path) -> str:
    """Render a filesystem path for a quoted Tor configuration value.

    Tor's config parser treats a single backslash inside a quoted string as an
    escape introducer, so a raw ``"C:\\Users"`` aborts startup with "Invalid
    escape sequence in quoted string".  Doubling every backslash parses back to
    one literal backslash, which keeps the path absolute on Windows.  Forward
    slashes parse too, but Tor then logs a "path is relative" warning for a
    drive-letter path, so escaping is the cleaner option.

    ``os.fspath`` is used instead of ``str(Path(...))`` on purpose: constructing
    a ``Path`` normalises separators, so a POSIX path would silently turn into a
    backslash path with no drive letter and stop being absolute.
    """
    return os.fspath(path).replace("\\", "\\\\")


def _creation_flags() -> int:
    if os.name == "nt":
        return _CREATE_NO_WINDOW
    return 0


def _startupinfo():
    if os.name != "nt":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE
    return info


def read_version(executable: Path, timeout: float = 20.0) -> tuple:
    """Return (version, errors) by asking the binary to describe itself."""
    if not executable or not Path(executable).is_file():
        return "", [f"executable not found: {executable}"]
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            capture_output=True, text=True, timeout=timeout,
            creationflags=_creation_flags(), startupinfo=_startupinfo(),
        )
    except subprocess.TimeoutExpired:
        return "", ["tor --version timed out"]
    except OSError as exc:
        return "", [f"tor --version failed: {exc}"]

    blob = (completed.stdout or "") + (completed.stderr or "")
    match = VERSION_PATTERN.search(blob)
    if match:
        return match.group(1), []
    if completed.returncode != 0:
        return "", [f"tor --version exited {completed.returncode}"]
    return "", ["could not parse a Tor version string"]


def _project_root() -> Path:
    """The directory that contains this package (the project root)."""
    return Path(__file__).resolve().parent.parent


def candidate_roots(explicit=None) -> list:
    """Every directory that could hold a Tor Expert Bundle, in priority order.

    The explicit path wins.  After that the bundled ``tor/`` directory that
    ships with the project is checked, then the current working directory, so
    an operator running from a different folder still gets a hit.
    """
    roots = []
    if explicit:
        roots.append(Path(explicit).expanduser())
    base = _project_root()
    for name in BUNDLE_DIR_NAMES:
        roots.append(base / name)
    for name in BUNDLE_DIR_NAMES:
        roots.append(Path.cwd() / name)
    roots.extend([base, Path.cwd()])

    unique, seen = [], set()
    for root in roots:
        try:
            key = str(root.resolve()).lower()
        except OSError:
            key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def _first_existing(directory: Path, names) -> Path | None:
    for name in names:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def find_executable(root: Path) -> Path | None:
    """Locate the Tor binary inside *root*.

    The Expert Bundle on this machine ships ``tor-real.exe`` rather than
    ``tor.exe``, so both are accepted and the canonical name is preferred.
    """
    if root is None or not Path(root).is_dir():
        return None
    return _first_existing(Path(root), EXECUTABLE_NAMES)


def discover_bundle(root=None, verify=True) -> TorInstallation:
    """Find and validate the Tor bundle without starting or downloading it.

    An explicit *root* is honoured strictly: if the operator points at a
    directory that holds no Tor executable, that is reported as a failure.  It
    is never silently satisfied by a different bundle found elsewhere, because
    that would mean the scan runs over a route the operator did not choose.
    """
    errors = []
    candidates = [Path(root).expanduser()] if root else candidate_roots()
    for candidate in candidates:
        if not candidate or not Path(candidate).is_dir():
            continue
        executable = find_executable(candidate)
        if executable is None:
            continue
        directory = executable.parent
        installation = TorInstallation(
            root=directory,
            executable=executable,
            geoip=_first_existing(directory, GEOIP_NAMES),
            geoip6=_first_existing(directory, GEOIP6_NAMES),
            bundled_torrc=_first_existing(directory, ("torrc",)),
        )
        if verify:
            version, version_errors = read_version(executable)
            installation.version = version
            installation.errors.extend(version_errors)
        else:
            installation.version = ""
        if not installation.geoip:
            
            
            installation.errors.append("geoip database not found next to the executable")
        return installation

    missing = TorInstallation(root=Path(root or ""), executable=None,
                              errors=["no Tor executable was found in any candidate directory"])
    return missing







def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """True when something is accepting TCP connections on host:port."""
    try:
        with socket.create_connection((str(host), int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def socks_greeting(host: str = DEFAULT_SOCKS_HOST, port: int = DEFAULT_SOCKS_PORT,
                   timeout: float = 3.0) -> tuple:
    """Complete a SOCKS5 greeting (no auth) and report whether it was accepted.

    This proves the listener is a SOCKS5 server rather than an arbitrary port
    that happens to be open.  It deliberately stops after the greeting: a full
    CONNECT would generate target traffic, which is the scan layer's job.
    """
    try:
        with socket.create_connection((str(host), int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            reply = sock.recv(2)
    except OSError as exc:
        return False, f"connection failed: {exc.__class__.__name__}"
    if len(reply) < 2:
        return False, "listener closed before a SOCKS5 reply"
    if reply[0] != 0x05:
        return False, f"not SOCKS5 (version byte 0x{reply[0]:02x})"
    if reply[1] != 0x00:
        return False, f"SOCKS5 requires authentication (method 0x{reply[1]:02x})"
    return True, "SOCKS5 no-auth greeting accepted"







def _psutil():
    try:
        import psutil
        return psutil
    except Exception:
        return None


def find_tor_processes() -> list:
    """Return [{pid, name, exe}] for running Tor processes, if enumerable."""
    psutil = _psutil()
    if psutil is None:
        return []
    found = []
    wanted = {name.lower() for name in EXECUTABLE_NAMES}
    try:
        iterator = psutil.process_iter(["pid", "name", "exe"])
    except Exception:
        return []
    for process in iterator:
        try:
            info = process.info
        except Exception:
            continue
        name = str(info.get("name") or "").lower()
        exe = str(info.get("exe") or "")
        if name in wanted or (exe and Path(exe).name.lower() in wanted):
            found.append({"pid": info.get("pid"), "name": name, "exe": exe})
    return found


def find_listener_pid(port: int) -> int | None:
    """Best-effort PID owning a TCP listener on *port*."""
    psutil = _psutil()
    if psutil is None:
        return None
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        return None
    for connection in connections:
        if not connection.laddr or connection.laddr.port != int(port):
            continue
        if connection.status == psutil.CONN_LISTEN and connection.pid:
            return connection.pid
    return None


def describe_listener(port: int) -> dict:
    """What is holding *port*?  Used to refuse to adopt an unknown service."""
    pid = find_listener_pid(port)
    if pid is None:
        return {"pid": None, "name": "", "is_tor": False}
    psutil = _psutil()
    name, exe = "", ""
    if psutil is not None:
        try:
            process = psutil.Process(pid)
            name = process.name()
            exe = process.exe()
        except Exception:
            pass
    is_tor = name.lower() in {n.lower() for n in EXECUTABLE_NAMES}
    return {"pid": pid, "name": name, "exe": exe, "is_tor": is_tor}






CLIENT_TORRC = """\
# Generated by Kripto. Do not edit: it is rewritten before every start.
# The bundle's own torrc points GeoIP at an install prefix that does not
# exist beside the binary, so that file is never used.
SocksPort {socks_host}:{socks_port}
SocksPolicy accept 127.0.0.1
SocksPolicy reject *
ClientOnly 1
AvoidDiskWrites 1
SafeLogging 1
DataDirectory "{data_dir}"
{geoip_lines}
"""

CHECK_URL_DEFAULT = "https://check.torproject.org/api/ip"


class TorManager:
    """Start, supervise and stop one local Tor SOCKS5 listener.

    The manager owns exactly one child process.  A listener it did not start
    is adopted for status and connectivity purposes but is never signalled,
    because killing an operator's existing Tor session would be destructive.
    """

    def __init__(self, root=None, socks_host: str = DEFAULT_SOCKS_HOST,
                 socks_port: int = DEFAULT_SOCKS_PORT, data_dir=None,
                 start_timeout: float = DEFAULT_START_TIMEOUT):
        self.root_hint = root
        self.socks_host = str(socks_host or DEFAULT_SOCKS_HOST)
        self.socks_port = int(socks_port or DEFAULT_SOCKS_PORT)
        self.start_timeout = float(start_timeout)
        if data_dir is None:
            data_dir = Path("output") / "tor"
        self.data_dir = Path(data_dir).expanduser()
        
        
        
        self.log_path = self.data_dir / "tor.log"
        self.process_log_path = self.log_path
        self.torrc_path = self.data_dir / "torrc.kripto"

        self._installation = None
        self._process = None
        self._managed_pid = None
        self._lock = threading.RLock()
        self._registered = False

    

    def installation(self, refresh: bool = False) -> TorInstallation:
        with self._lock:
            if self._installation is None or refresh:
                self._installation = discover_bundle(self.root_hint)
            return self._installation

    @property
    def installed(self) -> bool:
        installation = self.installation()
        return bool(installation.executable) and bool(installation.version)

    

    def write_config(self) -> Path:
        """Write the managed torrc and return its path.

        Absolute paths are quoted because a Windows profile path routinely
        contains spaces, and an unquoted GeoIPFile silently fails to parse.
        """
        installation = self.installation(refresh=True)
        if not installation.executable:
            raise TorError("cannot write a Tor configuration without an executable")

        self.data_dir.mkdir(parents=True, exist_ok=True)
        geoip_lines = []
        if installation.geoip:
            geoip_lines.append(f'GeoIPFile "{_tor_path(installation.geoip)}"')
        if installation.geoip6:
            geoip_lines.append(f'GeoIPv6File "{_tor_path(installation.geoip6)}"')

        content = CLIENT_TORRC.format(
            socks_host=self.socks_host,
            socks_port=self.socks_port,
            data_dir=_tor_path(self.data_dir.resolve()),
            geoip_lines="\n".join(geoip_lines),
        )
        self.torrc_path.write_text(content, encoding="utf-8")
        return self.torrc_path

    

    @property
    def pid(self) -> int | None:
        if self._process is not None and self._process.poll() is None:
            return self._process.pid
        return self._managed_pid if self._managed_pid and self._pid_alive(self._managed_pid) else None

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        psutil = _psutil()
        if psutil is not None:
            try:
                return psutil.pid_exists(int(pid))
            except Exception:
                return False
        return False

    @property
    def managed(self) -> bool:
        return self.pid is not None and self._managed_pid == self.pid

    def socks_ready(self, timeout: float = 1.5) -> tuple:
        """Is a SOCKS5 server answering right now?"""
        if not port_open(self.socks_host, self.socks_port, timeout=timeout):
            return False, "nothing is listening"
        return socks_greeting(self.socks_host, self.socks_port, timeout=max(2.0, timeout))

    def start(self, timeout: float = None, require_bootstrap: bool = True) -> TorStatus:
        """Start Tor and block until it can actually carry traffic.

        An open SOCKS port is *not* proof of a working transport: Tor binds its
        listener before it has a circuit, and an outdated build opens the port
        and then dies during bootstrap.  So unless ``require_bootstrap`` is
        false, success additionally requires the ``Bootstrapped 100%`` log line
        while the child is still alive.

        Raises :class:`TorError` on any failure.  There is deliberately no code
        path that returns success without a usable transport, because the
        caller treats a return value as permission to send scan traffic.
        """
        timeout = float(timeout if timeout is not None else self.start_timeout)
        with self._lock:
            if self.pid is not None and self.managed:
                ready, detail = self.socks_ready()
                if ready:
                    return self.status()
                self.stop()

            if port_open(self.socks_host, self.socks_port):
                ready, detail = self.socks_ready()
                if ready:
                    
                    return self.status()
                raise TorError(
                    f"port {self.socks_port} is already in use by "
                    f"{describe_listener(self.socks_port).get('name') or 'another service'} "
                    f"and it is not a SOCKS5 proxy ({detail})"
                )

            installation = self.installation(refresh=True)
            if not installation.executable:
                raise TorError(
                    "Tor Expert Bundle not found: no tor.exe or tor-real.exe in "
                    + ", ".join(str(p) for p in candidate_roots(self.root_hint)[:4])
                )
            if not installation.version:
                raise TorError(
                    "Tor executable could not report its version: "
                    + "; ".join(installation.errors or ["unknown reason"])
                )

            torrc = self.write_config()
            self.data_dir.mkdir(parents=True, exist_ok=True)
            handle = open(self.process_log_path, "ab")
            try:
                handle.write(
                    f"\n--- kripto starting "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')} ---\n".encode("utf-8")
                )
                handle.flush()
                self._process = subprocess.Popen(
                    [str(installation.executable), "-f", str(torrc)],
                    cwd=str(installation.root),
                    stdin=subprocess.DEVNULL,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    creationflags=_creation_flags(),
                    startupinfo=_startupinfo(),
                )
            except OSError as exc:
                raise TorError(f"could not start Tor: {exc}") from exc
            finally:
                handle.close()

            self._managed_pid = self._process.pid
            self._register_cleanup()

            deadline = time.monotonic() + timeout
            listener_seen = False
            while time.monotonic() < deadline:
                exit_code = self._process.poll()
                if exit_code is not None:
                    self._managed_pid = None
                    raise TorError(self._startup_failure(exit_code))

                if not listener_seen:
                    listener_seen = self.socks_ready(timeout=1.0)[0]

                if not require_bootstrap:
                    if listener_seen:
                        return self.status()
                else:
                    percent = self._bootstrap_percent()
                    if percent is not None and percent >= 100:
                        return self.status()
                time.sleep(0.4)

            self.stop()
            if listener_seen and require_bootstrap:
                raise TorError(
                    "Tor opened its SOCKS listener but never finished bootstrapping "
                    f"within {timeout:.0f}s, so it cannot carry traffic yet. "
                    f"Log: {self.log_path} ({self._log_detail()})"
                )
            raise TorError(
                f"Tor did not open {self.socks_host}:{self.socks_port} within "
                f"{timeout:.0f}s. Log: {self.log_path} ({self._log_detail()})"
            )

    def ensure_started(self, timeout: float = None,
                       require_bootstrap: bool = True) -> TorStatus:
        """Start only when nothing is already serving the SOCKS port.

        A listener that is already answering is adopted as-is: it may be an
        operator's own Tor, whose bootstrap state this process cannot observe.
        """
        ready, _ = self.socks_ready()
        if ready:
            return self.status()
        return self.start(timeout=timeout, require_bootstrap=require_bootstrap)

    def stop(self, timeout: float = DEFAULT_STOP_TIMEOUT) -> bool:
        """Terminate the process this manager started.

        An adopted (external) Tor is left running by design.
        """
        with self._lock:
            process = self._process
            self._process = None
            managed_pid = self._managed_pid
            self._managed_pid = None

            if process is None or process.poll() is not None:
                return False
            try:
                process.terminate()
            except OSError:
                pass
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    process.wait(timeout=timeout)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if managed_pid:
                self._managed_pid = None
            return True

    def _register_cleanup(self):
        if self._registered:
            return
        self._registered = True
        atexit.register(self._atexit_stop)

    def _atexit_stop(self):
        try:
            self.stop(timeout=5.0)
        except Exception:
            pass

    

    def _tail(self, path: Path, lines: int = 14) -> list:
        try:
            if not path or not Path(path).is_file():
                return []
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            return [line for line in text.strip().splitlines()[-lines:]]
        except OSError:
            return []

    def _log_detail(self) -> str:
        tail = self._tail(self.process_log_path, 3) + self._tail(self.log_path, 3)
        return " | ".join(tail[-4:]) if tail else "no log output"

    def _bootstrap_percent(self) -> int | None:
        percentages = []
        for path in (self.log_path, self.process_log_path):
            for line in self._tail(path, 200):
                match = _BOOTSTRAP_PERCENT.search(line)
                if match:
                    percentages.append(int(match.group(1)))
        return max(percentages) if percentages else None

    def _fatal_reason(self) -> str:
        """Explain a Tor startup failure using the log, not just an exit code."""
        blob = "\n".join(self._tail(self.log_path, 120))
        for pattern, explanation in _FATAL_COMPILED:
            if pattern.search(blob):
                return explanation
        return ""

    def _startup_failure(self, exit_code) -> str:
        reason = self._fatal_reason()
        detail = self._log_detail()
        if reason:
            return f"{reason} (Tor exited {exit_code}). Log: {self.log_path} :: {detail}"
        return (f"Tor exited with code {exit_code} during startup. "
                f"Log: {self.log_path} ({detail})")

    def bootstrap_state(self) -> dict:
        """Report bootstrap progress and whether the build was rejected."""
        percent = self._bootstrap_percent()
        return {
            "percent": percent,
            "complete": percent is not None and percent >= 100,
            "fatal": self._fatal_reason(),
            "running": self.pid is not None,
        }

    def status(self, transport: str = "direct") -> TorStatus:
        installation = self.installation()
        status = TorStatus(
            installed=bool(installation.executable),
            executable_path=str(installation.executable or ""),
            version=installation.version,
            socks_host=self.socks_host,
            socks_port=self.socks_port,
            transport=transport,
        )
        if not installation.executable:
            status.errors.extend(installation.errors)
        elif not installation.version:
            status.errors.extend(installation.errors)

        if not port_open(self.socks_host, self.socks_port):
            return status

        ready, detail = socks_greeting(self.socks_host, self.socks_port)
        status.socks_listening = True
        status.running = True
        status.pid = self.pid or find_listener_pid(self.socks_port)
        status.managed = self.managed
        status.bootstrap_percent = self._bootstrap_percent()
        if not ready:
            status.errors.append(detail)
        status.log_tail = self._tail(self.log_path, 12)
        return status

    

    def verify_connectivity(self, check_url: str = None, timeout: float = 30.0) -> dict:
        """Prove real Tor egress by fetching the Tor Project's check endpoint.

        This is the only request this module ever makes, it is off by default,
        and it never touches the assessment target.
        """
        url = check_url or os.environ.get("KRIPTO_TOR_CHECK_URL") or CHECK_URL_DEFAULT
        result = {
            "ok": False, "url": url, "exit_ip": None, "is_tor": None,
            "latency": None, "error": None,
        }
        ready, detail = self.socks_ready()
        if not ready:
            result["error"] = f"SOCKS5 listener is not answering: {detail}"
            return result

        try:
            import requests
        except ImportError:
            result["error"] = "requests is not installed"
            return result

        proxies = {
            "http": f"socks5h://{self.socks_host}:{self.socks_port}",
            "https": f"socks5h://{self.socks_host}:{self.socks_port}",
        }
        started = time.monotonic()
        try:
            response = requests.get(url, proxies=proxies, timeout=timeout)
            result["latency"] = round(time.monotonic() - started, 2)
        except Exception as exc:
            sockerr = _socks_missing_message(exc)
            result["error"] = sockerr or f"{type(exc).__name__}: {exc}"
            return result

        result["status_code"] = response.status_code
        payload = None
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            result["exit_ip"] = payload.get("IP") or payload.get("ip")
            flag = payload.get("IsTor", payload.get("is_tor"))
            result["is_tor"] = bool(flag) if flag is not None else None
        result["ok"] = response.status_code == 200
        if not result["ok"]:
            result["error"] = f"check endpoint returned HTTP {response.status_code}"
        elif result["is_tor"] is False:
            result["error"] = "traffic left the proxy but was NOT recognised as Tor egress"
        return result

    def diagnostics(self) -> dict:
        """Everything the CLI needs for the Tor status panel."""
        status = self.status()
        installation = self.installation()
        ready, detail = self.socks_ready()
        return {
            "installation": installation.report(),
            "status": status.report(),
            "socks_check": {"ok": ready, "detail": detail},
            "listener": describe_listener(self.socks_port),
            "processes": find_tor_processes(),
            "paths": {
                "data_dir": str(self.data_dir),
                "torrc": str(self.torrc_path),
                "log": str(self.log_path),
                "process_log": str(self.process_log_path),
            },
        }


def _socks_missing_message(exc: Exception) -> str:
    """Turn requests' opaque SOCKS failure into an actionable message."""
    text = str(exc)
    if "Missing dependencies for SOCKS support" in text:
        return ("PySocks is not installed, so SOCKS5 cannot be used. "
                "Install it with: python -m pip install PySocks")
    if "SOCKSHTTPConnectionPool" in text or "SOCKSConnectionPool" in text:
        return f"SOCKS proxy refused or dropped the request: {text}"
    return ""


_default_manager = None
_default_lock = threading.Lock()


def get_manager(**kwargs) -> TorManager:
    """Process-wide manager so one run cannot start two Tor children."""
    global _default_manager
    with _default_lock:
        if _default_manager is None:
            _default_manager = TorManager(**kwargs)
        return _default_manager


def reset_manager():
    global _default_manager
    with _default_lock:
        if _default_manager is not None:
            _default_manager.stop()
        _default_manager = None
