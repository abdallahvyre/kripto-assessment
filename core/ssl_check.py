import socket
import ssl
import tempfile
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import *
from core.banner import info, success, warning, error, make_table


def _parse_cert(der_bytes: bytes) -> dict:
    """getpeercert() returns {} when verify_mode is CERT_NONE, so decode the DER."""
    info_out = {}
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        info_out = ssl._ssl._test_decode_cert(path)
    except Exception:
        info_out = {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return info_out


def _flatten(section):
    out = {}
    for rdn in section or ():
        for key, value in rdn:
            out[key] = value
    return out


def _parse_date(value):
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class SSLModule:
    def __init__(self, target: str, console):
        self.target = target
        self.console = console
        parsed = urlparse(target)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_https = parsed.scheme == "https" or self.port == 443

    def run(self) -> dict:
        results = {
            "has_ssl": False,
            "cert_info": {},
            "tls_version": None,
            "cipher": None,
            "issues": [],
            "valid": False,
            "trust_verified": False,
            "expires": None,
            "days_left": None,
            "error": None,
        }

        if not self.is_https:
            info(self.console, "Target uses plain HTTP. SSL/TLS analysis skipped.")
            results["issues"].append("No HTTPS - all traffic is unencrypted")
            warning(self.console, "Target does not offer HTTPS.")
            return results

        info(self.console, f"Analyzing TLS for {self.host}:{self.port}...")

        try:
            def handshake(context):
                from core.network import authorize
                _, allowed_host, _ = authorize(self.target, "TLS handshake")
                with socket.create_connection((allowed_host, self.port), timeout=REQUEST_TIMEOUT) as sock:
                    with context.wrap_socket(sock, server_hostname=allowed_host) as ssock:
                        version = ssock.version()
                        cipher = ssock.cipher()
                        der_cert = ssock.getpeercert(binary_form=True)
                        return version, cipher, der_cert

            try:
                
                
                version, cipher, der = handshake(ssl.create_default_context())
                results["trust_verified"] = True
            except ssl.SSLCertVerificationError as verify_error:
                results["issues"].append(
                    f"Certificate trust/hostname verification failed: {verify_error}"
                )
                warning(self.console, "Certificate chain or hostname verification failed")
                
                
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                version, cipher, der = handshake(context)

            results["has_ssl"] = True
            results["tls_version"] = version
            results["cipher"] = f"{cipher[0]} ({cipher[1]})" if cipher else None

            if der:
                cert = _parse_cert(der)
                if cert:
                    subject = _flatten(cert.get("subject"))
                    issuer = _flatten(cert.get("issuer"))
                    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                    not_after_raw = cert.get("notAfter", "")
                    not_before_raw = cert.get("notBefore", "")

                    results["cert_info"] = {
                        "subject": subject,
                        "issuer": issuer,
                        "common_name": subject.get("commonName"),
                        "sans": sans,
                        "not_before": _parse_date(not_before_raw).strftime("%Y-%m-%d") if _parse_date(not_before_raw) else not_before_raw,
                        "not_after": _parse_date(not_after_raw).strftime("%Y-%m-%d") if _parse_date(not_after_raw) else not_after_raw,
                        "serial_number": cert.get("serialNumber", ""),
                    }

                    exp = _parse_date(not_after_raw)
                    start = _parse_date(not_before_raw)
                    now = datetime.now(timezone.utc)

                    date_valid = False
                    if exp:
                        results["expires"] = exp.strftime("%Y-%m-%d")
                        days_left = (exp - now).days
                        results["days_left"] = days_left

                        if start and now < start:
                            results["issues"].append("Certificate is not yet valid")
                            warning(self.console, "Certificate is not yet valid!")
                        elif days_left < 0:
                            results["issues"].append("Certificate EXPIRED")
                            warning(self.console, f"Certificate EXPIRED ({days_left} days ago)")
                        elif days_left < 30:
                            date_valid = True
                            results["issues"].append(f"Certificate expires soon ({days_left} days left)")
                            warning(self.console, f"Certificate expires in {days_left} days")
                        else:
                            date_valid = not start or now >= start

                    cn = subject.get("commonName")
                    issuer_cn = issuer.get("commonName")
                    if cn and issuer_cn and cn == issuer_cn and not any(
                        s.endswith(issuer_cn) or issuer_cn.endswith(s) for s in sans
                    ):
                        results["issues"].append("Self-signed certificate")
                        warning(self.console, "Certificate appears self-signed")

                    if results["tls_version"] in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        results["issues"].append(f"Deprecated protocol in use ({results['tls_version']})")
                        warning(self.console, f"Deprecated protocol: {results['tls_version']}")

                    results["valid"] = bool(results["trust_verified"] and date_valid)
                else:
                    results["issues"].append("Certificate could not be decoded")

            success(
                self.console,
                f"TLS: {results['tls_version']} | Cipher: {results['cipher']}",
            )
            if results["issues"]:
                for issue in results["issues"]:
                    warning(self.console, f"SSL issue: {issue}")
            elif results["valid"]:
                success(self.console, "Certificate and TLS configuration look valid.")

            rows = [
                ("TLS Version", str(results["tls_version"])),
                ("Cipher", str(results["cipher"])),
                ("Common Name", str(results["cert_info"].get("common_name", "-"))),
                ("Issuer", str(results["cert_info"].get("issuer", {}).get("organizationName", "-"))),
                ("Valid Until", f"{results['expires']} ({results['days_left']} days)" if results["expires"] else "-"),
                ("SANs", str(len(results["cert_info"].get("sans", [])))),
            ]
            self.console.print(make_table("TLS Certificate", ["Field", "Value"], rows))

        except Exception as e:
            results["error"] = str(e)
            results["issues"].append(f"TLS handshake failed: {e}")
            error(self.console, f"SSL analysis failed: {e}")

        return results
