import requests

from config import *
from core.banner import info, success, warning, found, vuln, make_table
from core.cookies import cookie_metadata, get_set_cookie_headers
from core.http import RateLimitedSession


def _int_after(value: str, marker: str) -> int:
    try:
        return int(value.lower().split(marker, 1)[1].split(";")[0].strip().strip('"'))
    except (IndexError, ValueError):
        return -1


class HeaderModule:
    def __init__(self, target: str, console):
        self.target = target
        self.console = console
        self.session = RateLimitedSession()

    def run(self) -> dict:
        results = {"headers": {}, "score": 0.0, "raw_headers": {}, "cookies": [], "error": None}

        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            raw = {}
            for key, value in resp.headers.items():
                if key.lower() == "set-cookie":
                    continue
                raw.setdefault(key, []).append(value)
            cookie_headers = get_set_cookie_headers(resp)
            if cookie_headers:
                raw["Set-Cookie"] = cookie_headers
            results["raw_headers"] = {k: ", ".join(v) for k, v in raw.items()}
        except Exception as e:
            from core.banner import error
            results["error"] = str(e)
            error(self.console, f"Failed to fetch headers: {e}")
            return results

        flat = {k.lower(): ", ".join(v) for k, v in raw.items()}
        from core.assessments import header_analysis
        results["analysis"] = header_analysis(flat, self.target)

        checks = {
            "Content-Security-Policy": {
                "good": lambda v: ("default-src" in v or "script-src" in v) and
                                  not results["analysis"]["findings"],
                "note_good": "CSP policy present",
                "note_weak": "CSP present but may be too permissive",
                "note_missing": "No CSP - XSS risk increased",
            },
            "X-Content-Type-Options": {
                "good": lambda v: v.lower() == "nosniff",
                "note_good": "nosniff set correctly",
                "note_weak": "Unexpected value",
                "note_missing": "Missing - MIME sniffing possible",
            },
            "X-Frame-Options": {
                "good": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
                "note_good": "Frame protection active",
                "note_weak": "Unusual value",
                "note_missing": "Missing - clickjacking possible",
            },
            "Strict-Transport-Security": {
                "good": lambda v: "max-age=" in v.lower() and _int_after(v, "max-age=") >= 31536000,
                "note_good": "HSTS with max-age >= 1 year",
                "note_weak": "HSTS present but max-age below 1 year",
                "note_missing": "No HSTS - downgrade attacks possible",
            },
            "X-XSS-Protection": {
                "good": lambda v: "1" in v and "mode=block" in v.lower(),
                "note_good": "XSS filter enabled with block mode",
                "note_weak": "XSS filter enabled but not blocking",
                "note_missing": "No XSS Protection header",
            },
            "Referrer-Policy": {
                "good": lambda v: v.lower() in (
                    "no-referrer", "same-origin", "strict-origin",
                    "strict-origin-when-cross-origin", "no-referrer-when-downgrade",
                ),
                "note_good": "Referrer policy configured",
                "note_weak": "Referrer policy may leak data",
                "note_missing": "No Referrer-Policy set",
            },
            "Permissions-Policy": {
                "good": lambda v: len(v) > 5,
                "note_good": "Permissions policy set",
                "note_weak": "Policy too permissive",
                "note_missing": "No Permissions-Policy header",
            },
            "Cache-Control": {
                "good": lambda v: "no-store" in v.lower() or "private" in v.lower(),
                "note_good": "Proper cache control for sensitive data",
                "note_weak": "Cache policy may store sensitive data",
                "note_missing": "No Cache-Control - responses may be cached",
            },
        }

        info_headers = {
            "Server": "Server software disclosed",
            "X-Powered-By": "Technology stack disclosed",
            "X-AspNet-Version": "ASP.NET version disclosed",
            "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
        }

        good_count = 0
        total = len(checks)

        for header, check in checks.items():
            value = flat.get(header.lower(), "")

            if value:
                try:
                    is_good = check["good"](value)
                except Exception:
                    is_good = False

                if is_good:
                    status = "GOOD"
                    note = check["note_good"]
                    good_count += 1
                else:
                    status = "WEAK"
                    note = check["note_weak"]
            else:
                status = "MISSING"
                note = check["note_missing"]

            results["headers"][header] = {
                "value": value or "Not Set",
                "status": status,
                "note": note,
            }

        
        for header, desc in info_headers.items():
            value = flat.get(header.lower(), "")
            if value:
                results["headers"][f"[INFO] {header}"] = {
                    "value": value,
                    "status": "DISCLOSURE",
                    "note": desc,
                }
                warning(self.console, f"Info disclosure: {header}: {value}")

        
        for cookie_header in cookie_headers:
            metadata = cookie_metadata(cookie_header)
            name = metadata["name"]
            issues = []
            flags = metadata["flags"]
            if not flags["secure"]:
                issues.append("missing Secure")
            if not flags["httponly"]:
                issues.append("missing HttpOnly")
            if not flags["samesite"]:
                issues.append("missing SameSite")
            results["cookies"].append({
                "name": name,
                "issues": issues,
                "flags": flags,
                "value_length": metadata["value_length"],
                "value_fingerprint": metadata["value_fingerprint"],
                "raw": cookie_header,
                "raw_redacted": metadata["raw_redacted"],
            })
            if issues:
                warning(self.console, f"Cookie '{name}': {', '.join(issues)}")

        results["score"] = (good_count / total) * 100 if total else 0

        status_colors = {"GOOD": "green", "WEAK": "yellow", "MISSING": "red", "DISCLOSURE": "magenta"}
        rows = []
        for header, data in results["headers"].items():
            color = status_colors.get(data["status"], "white")
            rows.append((header, data["value"][:40], f"[{color}]{data['status']}[/{color}]", data["note"]))

        self.console.print(make_table("Security Headers Analysis", ["Header", "Value", "Status", "Note"], rows))
        score_color = "green" if results["score"] >= 75 else "yellow" if results["score"] >= 50 else "red"
        success(self.console, f"Security Header Score: [{score_color}]{results['score']:.0f}%[/{score_color}] ({good_count}/{total})")

        return results
