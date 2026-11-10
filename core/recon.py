import socket
import ssl
import re
import concurrent.futures
from urllib.parse import urlparse

import dns.resolver
import dns.zone
import dns.query
from bs4 import BeautifulSoup

from config import *
from core.banner import info, success, warning, error, found, make_table
from core.http import RateLimitedSession, origin
from core.policy import ScopePolicy, _normalise_host


class ReconModule:
    def __init__(self, target: str, console):
        self.target = target
        self.console = console
        parsed = urlparse(target)
        self.domain = origin(ScopePolicy._absolute_http_url(target))[1]
        self.scheme = parsed.scheme or "https"
        self.session = RateLimitedSession()
        self.wildcard_dns = False
        self.errors = []


    def _resolve(self, name, rtype):
        from core.network import authorize
        
        name = _normalise_host(name)
        _, allowed_host, _ = authorize(self.target, 'DNS lookup')
        allowed_host = _normalise_host(allowed_host)
        if name != allowed_host and not name.endswith('.' + allowed_host):
            raise ValueError('DNS name outside assessed domain')
        return dns.resolver.resolve(name, rtype, lifetime=6)

    def _ip(self):
        from core.network import authorize
        _, allowed_host, _ = authorize(self.target, 'address lookup')
        return socket.gethostbyname(allowed_host)

    def whois_lookup(self) -> dict:
        result = {}
        try:
            from core.network import authorize
            _, allowed_host, _ = authorize(self.target, 'WHOIS lookup')
            import whois
            w = whois.whois(allowed_host)
            result = {
                "domain_name": str(w.domain_name) if w.domain_name else "N/A",
                "registrar": str(w.registrar) if w.registrar else "N/A",
                "creation_date": str(w.creation_date) if w.creation_date else "N/A",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
                "name_servers": w.name_servers if w.name_servers else [],
                "org": str(w.org) if w.org else "N/A",
                "country": str(w.country) if w.country else "N/A",
                "state": str(w.state) if w.state else "N/A",
                "registrar_emails": w.emails if w.emails else [],
                "dnssec": str(w.dnssec) if w.dnssec else "N/A",
            }
            if result["registrar_emails"]:
                result["registrar_emails_note"] = (
                    "Registrant/registrar contacts from WHOIS, NOT confirmed addresses "
                    "on the target site."
                )
            success(self.console, f"WHOIS: Registrar={result['registrar']}, Created={result['creation_date']}")
        except Exception as e:
            error(self.console, f"WHOIS lookup failed: {e}")
        return result

    def dns_records(self) -> dict:
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR", "DS"]
        for rtype in record_types:
            try:
                answers = self._resolve(self.domain, rtype)
                records[rtype] = [str(r) for r in answers]
                info(self.console, f"DNS {rtype}: {', '.join(records[rtype][:3])}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        for rtype in ("DNSKEY", "NSEC3", "HTTPS", "SVCB"):
            try:
                records[rtype] = [str(r) for r in self._resolve(self.domain, rtype)]
            except Exception:
                pass

        try:
            ip = self._ip()
            records["resolved_ip"] = ip
            success(self.console, f"Resolved IP: {ip}")
        except Exception:
            pass

        records.update(self._txt_intelligence(records.get("TXT", [])))
        return records

    def _txt_intelligence(self, txt_records) -> dict:
        """TXT records describe who the organisation has handed tooling to and
        which mail infrastructure exists - both cheap and usually unchecked."""
        out = {}
        joined = " ".join(txt_records)

        spf = re.search(r'v=spf1([^"\s]*(?:\s+[a-z0-9:.\-_=+~\[\]/?]+)*)', joined, re.I)
        if spf:
            include = re.findall(r"include:([^\s]+)", spf.group(0), re.I)
            ip4 = re.findall(r"ip4:([^\s]+)", spf.group(0), re.I)
            spf_text = re.search(r"txt\s+([^\"]+)", spf.group(0), re.I)
            out["spf"] = {
                "record": spf.group(0)[:400],
                "third_parties": include,
                "authorized_ips": ip4,
                "all": "all" in spf.group(0) or "-all" in spf.group(0),
                "loose": "~all" in spf.group(0),
                "txt_challenge": bool(spf_text),
            }
            if out["spf"]["loose"]:
                warning(self.console, f"SPF uses '~all' (softfail) on {self.domain}")
            for party in include[:8]:
                found(self.console, f"SPF authorises third party: {party}")

        try:
            dmarc = self._resolve(f"_dmarc.{self.domain}", "TXT")
            dmarc_text = " ".join(str(r) for r in dmarc)
            out["dmarc"] = {
                "record": dmarc_text[:300],
                "enforced": "p=reject" in dmarc_text,
                "quarantine": "p=quarantine" in dmarc_text,
            }
            if "p=" not in dmarc_text:
                vuln(self.console, f"No DMARC policy for {self.domain} - email spoofing is trivial")
            elif not ("p=reject" in dmarc_text or "p=quarantine" in dmarc_text):
                warning(self.console, f"DMARC on {self.domain} is monitor-only ({dmarc_text[:80]})")
        except Exception:
            out["dmarc"] = {"record": None, "enforced": False,
                            "note": "No _dmarc record - domain can be spoofed in mail From:"}

        return out

    def cert_san_expansion(self) -> list:
        """A wildcard SAN (*.example.com) plus a known label list is an easy
        subdomain source that does not depend on any external service."""
        from core.ssl_check import SSLModule
        cert = SSLModule(self.target, self.console).run().get('cert_info') or {}
        return sorted({f'{label}.{value[2:]}' for value in cert.get('sans', [])
                       if value.startswith('*.') for label in SUBDOMAINS_WORDLIST[:60]})

    def subdomain_enum(self) -> list:
        import random
        import string
        import socket

        found_subs = []
        wildcard_ips = set()
        for _ in range(3):
            rand_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            try:
                for r in self._resolve(f"{rand_label}.{self.domain}", "A"):
                    wildcard_ips.add(str(r))
            except Exception:
                continue

        if wildcard_ips:
            warning(
                self.console,
                f"Wildcard DNS active ({len(wildcard_ips)} IPs) - only subdomains resolving "
                "outside the wildcard range are reported.",
            )

        def check_sub(sub):
            fqdn = f"{sub}.{self.domain}"
            try:
                ips = {str(r) for r in self._resolve(fqdn, "A")}
                if not ips or ips.issubset(wildcard_ips):
                    return None
                try:
                    cnames = [str(r) for r in self._resolve(fqdn, "CNAME")]
                except Exception:
                    cnames = []
                return {"subdomain": fqdn, "ips": sorted(ips), "cnames": cnames}
            except Exception:
                return None

        info(self.console, f"Enumerating subdomains ({len(SUBDOMAINS_WORDLIST)} candidates)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
            futures = {pool.submit(check_sub, s): s for s in SUBDOMAINS_WORDLIST}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    found_subs.append(res)
                    extra = f" (CNAME: {', '.join(res['cnames'])})" if res.get("cnames") else ""
                    found(self.console, f"Subdomain: {res['subdomain']} -> {', '.join(res['ips'])}{extra}")

        self.wildcard_dns = bool(wildcard_ips)
        success(self.console, f"Found {len(found_subs)} subdomains")
        return found_subs

    def tech_detect(self) -> dict:
        techs = {"server": [], "frameworks": [], "cms": [], "js_libs": [], "cdn": [], "other": []}
        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            headers = resp.headers
            body = resp.text.lower()
            soup = BeautifulSoup(resp.text, "html.parser")

            
            if "Server" in headers:
                techs["server"].append(headers["Server"])
            if "X-Powered-By" in headers:
                techs["frameworks"].append(headers["X-Powered-By"])

            
            cms_sigs = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Joomla": ["joomla", "/components/com_", "/media/jui/"],
                "Drupal": ["drupal", "sites/all/", "sites/default/"],
                "Magento": ["magento", "mage/", "skin/frontend/"],
                "Shopify": ["shopify", "cdn.shopify"],
                "Wix": ["wix.com", "_wix_browser_sess"],
                "Squarespace": ["squarespace"],
            }
            for cms, sigs in cms_sigs.items():
                if any(s in body for s in sigs):
                    techs["cms"].append(cms)

            
            js_sigs = {
                "jQuery": ["jquery", "jquery.min.js"],
                "React": ["react.js", "react.min.js", "react-dom", "__NEXT_DATA__"],
                "Angular": ["angular", "ng-app", "ng-controller"],
                "Vue.js": ["vue.js", "vue.min.js", "__vue__"],
                "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
                "Tailwind": ["tailwindcss"],
                "Lodash": ["lodash"],
                "Moment.js": ["moment.min.js"],
            }
            for lib, sigs in js_sigs.items():
                if any(s in body for s in sigs):
                    techs["js_libs"].append(lib)

            
            fw_sigs = {
                "ASP.NET": ["__viewstate", "asp.net", ".aspx"],
                "PHP": [".php", "phpsessid"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "Rails": ["rails", "_rails_", "x-runtime"],
                "Laravel": ["laravel_session", "laravel"],
                "Express": ["express", "x-powered-by: express"],
                "Flask": ["werkzeug", "flask"],
                "Spring": ["jsessionid", "spring"],
                "Next.js": ["__next_data__", "_next/"],
                "Nuxt.js": ["__nuxt", "_nuxt/"],
            }
            for fw, sigs in fw_sigs.items():
                if any(s in body for s in sigs):
                    techs["frameworks"].append(fw)

            
            cookies = resp.headers.get("Set-Cookie", "").lower()
            cookie_sigs = {
                "PHP": "phpsessid", "ASP.NET": "asp.net_sessionid",
                "Java": "jsessionid", "Rails": "_rails_session",
                "Laravel": "laravel_session", "Django": "csrftoken",
            }
            for tech, sig in cookie_sigs.items():
                if sig in cookies and tech not in techs["frameworks"]:
                    techs["frameworks"].append(tech)

            
            cdn_sigs = {
                "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
                "Akamai": ["x-akamai", "akamai"],
                "Fastly": ["x-fastly", "fastly"],
                "CloudFront": ["x-amz-cf", "cloudfront"],
                "Incapsula": ["incap_ses", "x-iinfo"],
                "Netlify": ["x-nf-request-id", "netlify"],
                "Vercel": ["x-vercel-id", "vercel"],
                "GitHub Pages": ["github.com", "githubpages"],
            }
            all_headers = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
            for cdn, sigs in cdn_sigs.items():
                if any(s in all_headers or s in cookies for s in sigs):
                    techs["cdn"].append(cdn)

            
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and gen.get("content"):
                techs["other"].append(f"Generator: {gen['content']}")

            for cat, items in techs.items():
                if items:
                    success(self.console, f"Tech [{cat}]: {', '.join(items)}")

        except Exception as e:
            error(self.console, f"Tech detection failed: {e}")

        return techs

    def reverse_ip(self) -> dict:
        out = {"ip": None, "domains": [], "shared_hosting": False, "note": ""}
        try:
            ip = self._ip()
            out["ip"] = ip
            resp = self.session.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=TIMEOUT,
            )
            if resp.status_code != 200:
                out["note"] = f"Reverse-IP service returned HTTP {resp.status_code}"
                return out

            body = resp.text.strip()
            if "error" in body.lower() or "no records" in body.lower():
                out["note"] = "No reverse-IP data available"
                return out

            domains = [d.strip() for d in body.split("\n") if d.strip()]
            if len(domains) > 25:
                out["shared_hosting"] = True
                out["domains"] = domains[:25]
                out["note"] = (
                    f"Host is shared infrastructure ({len(domains)} domains resolve to {ip}). "
                    f"Only the first 25 are listed - this IP is not a unique vhost."
                )
                warning(self.console, out["note"])
            else:
                out["domains"] = domains
                info(self.console, f"Reverse IP: {len(domains)} domain(s) on {ip}")
        except Exception as e:
            out["note"] = f"Reverse-IP lookup failed: {e}"
        return out

    def run(self) -> dict:
        import config
        import ipaddress
        literal_ip = False
        try:
            ipaddress.ip_address(self.domain)
            literal_ip = True
        except ValueError:
            pass
        if config.TRANSPORT_MODE != 'direct' or literal_ip:
            return {'whois': {}, 'dns': {}, 'subdomains': [],
                    'cert_expansion_candidates': [], 'technologies': self.tech_detect(),
                    'reverse_ip': {'domains': []},
                    'limitations': ['DNS/TLS/WHOIS socket diagnostics unavailable through proxy; no direct fallback.']}
        results = {}
        info(self.console, "Starting WHOIS lookup...")
        results["whois"] = self.whois_lookup()
        info(self.console, "Querying DNS records...")
        results["dns"] = self.dns_records()

        wordlist_subs = self.subdomain_enum()
        results["subdomains"] = wordlist_subs
        results["cert_expansion_candidates"] = self.cert_san_expansion()

        info(self.console, "Detecting technologies...")
        results["technologies"] = self.tech_detect()
        info(self.console, "Running reverse IP lookup...")
        results["reverse_ip"] = self.reverse_ip()

        rows = [
            ("WHOIS", "[OK]" if results["whois"] else "[X]"),
            ("DNS Records", str(sum(len(v) if isinstance(v, list) else 1 for v in results["dns"].values()))),
            ("Subdomains (brute)", str(len(results["subdomains"]))),
            ("Cert SAN candidates", str(len(results["cert_expansion_candidates"]))),
            ("Technologies", str(sum(len(v) for v in results["technologies"].values()))),
            ("Reverse IP", str(len(results["reverse_ip"]["domains"]))),
        ]

        self.console.print(make_table("Recon Summary", ["Module", "Findings"], rows))
        return results
