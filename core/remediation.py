import re






FIXES = {
    "sqli": {
        "principle": "Never build SQL by string concatenation. Send values as parameters "
                     "so the database treats them as data, not as syntax.",
        "frameworks": {
            "generic": ("cursor.execute(f\"SELECT * FROM t WHERE id = {value}\")",
                        "cursor.execute(\"SELECT * FROM t WHERE id = %s\", (value,))"),
            "django": ("Model.objects.raw(f\"SELECT * FROM t WHERE id = {value}\")",
                       "Model.objects.raw(\"SELECT * FROM t WHERE id = %s\", [value])"),
            "rails": ("Model.where(\"name = '#{params[:name]}'\")",
                      "Model.where(\"name = ?\", params[:name])"),
            "laravel": ("DB::select(\"SELECT * FROM t WHERE id = {$id}\")",
                        "DB::select(\"SELECT * FROM t WHERE id = ?\", [$id])"),
            "express": ("db.query(`SELECT * FROM t WHERE id = ${id}`)",
                        "db.query(\"SELECT * FROM t WHERE id = ?\", [id])"),
        },
        "verify": "Re-send the original payload and confirm the response no longer "
                  "differs from the clean request.",
    },
    "command-injection": {
        "principle": "Do not pass user input to a command interpreter. If a subprocess is "
                     "unavoidable, pass an argument list and never a shell string.",
        "frameworks": {
            "generic": ("os.system(f\"ping -c 1 {host}\")",
                        "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)"),
            "php": ("system(\"ping -c 1 \" . $host);",
                    "echo shell_exec(escapeshellarg($host) );"),
        },
        "verify": "Re-send the injection payload and confirm no command output appears.",
    },
    "ssti": {
        "principle": "Treat template strings as untrusted input. Use the framework's "
                     "auto-escaping, or render templates statically and substitute data "
                     "through a whitelisted placeholder API.",
        "frameworks": {
            "generic": ("render_template_string(f\"Hello {name}\")",
                        "render_template(\"hello.html\", name=name)"),
            "jinja": ("jinja2.Template(template_string).render(name=name)",
                      "env.get_template('hello.html').render(name=name)"),
        },
        "verify": "Re-send the arithmetic probe and confirm the evaluator output stops "
                  "appearing.",
    },
    "lfi": {
        "principle": "Never open a path built from input. Map an allow-listed identifier "
                     "to a fixed path, then canonicalise and confine.",
        "frameworks": {
            "generic": ("open(f\"/var/www/files/{name}\")",
                        "open(os.path.realpath(os.path.join(BASE, safe_name)), 'rb')"),
            "php": ("include($_GET['page']);",
                    "include(in_array($page, $whitelist) ? \"pages/$page.php\" : 'pages/home.php');"),
        },
        "verify": "Re-send the traversal payload and confirm it is rejected without "
                  "file contents.",
    },
    "ssrf": {
        "principle": "Restrict outbound requests to an allow-list of schemes, hosts and "
                     "ports resolved at deploy time, and re-resolve at request time to "
                     "defeat DNS rebinding.",
        "frameworks": {
            "generic": ("requests.get(user_url)",
                        "requests.get(user_url, allow_redirects=False) if host_in_allow_list(user_url) else abort()"),
        },
        "verify": "Re-send the metadata address and confirm the request is refused before "
                  "the connection is made.",
    },
    "xss": {
        "principle": "Encode on output according to the output context, and never inject "
                     "user data into raw HTML sinks.",
        "frameworks": {
            "generic": ("html += user_input",
                        "node.textContent = user_input"),
            "react": ("dangerouslySetInnerHTML={{__html: user_input}}",
                      "<p>{userInput}</p>"),
            "vue": ('v-html="userInput"', "{{ userInput }}"),
            "angular": ("[innerHTML]=\"userInput\"", "[textContent]=\"userInput\""),
        },
        "verify": "Re-send the payload and confirm the reflection is encoded rather than "
                  "executed.",
    },
    "dom-sink": {
        "principle": "Same as reflected XSS, but the sink is reached without any server "
                     "round-trip, so the fix belongs entirely in client code.",
        "frameworks": {
            "generic": ("element.innerHTML = location.search.slice(1)",
                        "element.textContent = new URLSearchParams(location.search).get('q')"),
        },
        "verify": "Load the page with the payload in the fragment and confirm the sink "
                  "does not execute.",
    },
    "crlf": {
        "principle": "Reject values that contain CR or LF before they reach any component "
                     "that builds a response or a header.",
        "frameworks": {
            "generic": ("return redirect(url)",
                        "return redirect(url if not re.search(r'[\\r\\n]', url) else '/')"),
        },
        "verify": "Re-send the CRLF payload and confirm no injected header appears.",
    },
    "open-redirect": {
        "principle": "Only redirect to a path on the same origin. Accept a route, not a URL.",
        "frameworks": {
            "generic": ("redirect(next)",
                        "redirect(urlparse(next).path if is_safe(next) else '/')"),
        },
        "verify": "Re-send the off-site payload and confirm the Location stays on-origin.",
    },
    "host-header": {
        "principle": "Do not derive URLs, absolute links or password-reset links from the "
                     "Host header. Configure an explicit canonical host.",
        "frameworks": {
            "generic": ("reset_link = request.build_absolute_uri('/reset')",
                        "reset_link = f\"{SITE_URL}/reset\""),
        },
        "verify": "Send the probe Host header and confirm it is not reflected.",
    },
    "cors": {
        "principle": "Reflect an origin only from a strict allow-list, and only ever "
                     "combine Access-Control-Allow-Credentials with an exact-match origin.",
        "frameworks": {
            "generic": ("allow_origin: '*'",
                        "allow_origin: [allowed origins]"),
        },
        "verify": "Repeat the request with an arbitrary Origin and confirm it is not echoed.",
    },
    "smuggling": {
        "principle": "Reject requests whose framing headers disagree, or normalise them at "
                     "the front end so back ends see one unambiguous framing.",
        "frameworks": {
            "generic": ("(front end forwards Transfer-Encoding verbatim)",
                        "(front end de-chunks and sets a single Content-Length)"),
        },
        "verify": "Re-run the framing probes and confirm the desync no longer appears.",
    },
    "forgeable-jwt": {
        "principle": "Use a signing secret with at least 256 bits of entropy from a CSPRNG, "
                     "pin the algorithm server-side, and set iss/aud/exp/nbf.",
        "frameworks": {
            "generic": ("JWT.encode(payload, 'secret')",
                        "JWT.encode(payload, secrets.token_urlsafe(32), algorithm='HS256')"),
        },
        "verify": "Attempt forgery with the recovered secret and confirm the target rejects it "
                  "after rotation.",
    },
    "secret-leak": {
        "principle": "Rotate the exposed credential first, then remove it from the client bundle. "
                     "Client-side code cannot hold a secret; move the call server-side.",
        "frameworks": {
            "generic": ("const API_KEY = \"sk_live_...\"",
                        "fetch('/api/proxy')  // server holds the credential"),
        },
        "verify": "Re-fetch every bundle and confirm the value is gone from the response.",
    },
    "vcs-exposure": {
        "principle": "Remove the version-control directory from the web root and serve it "
                     "with 403. Rotate anything that ever appeared in history.",
        "frameworks": {
            "nginx": ("location /.git { try_files $uri =404; }",
                      "location ~ /\\.git { deny all; return 404; }"),
            "apache": ("Options Indexes",
                       "RedirectMatch 404 /\\.git"),
        },
        "verify": "Confirm the path returns 404 for every control file.",
    },
    "backup-file": {
        "principle": "Keep backups outside the web root and never with a guessed extension.",
        "frameworks": {"nginx": ("(no rule)",
                                 "location ~* \\.(bak|old|swp|sql|zip)$ { deny all; }")},
        "verify": "Confirm the archive returns 404 and that no variant extension is reachable.",
    },
    "verbose-errors": {
        "principle": "Disable debug output in production. Debug is a value in configuration, "
                     "not a query parameter.",
        "frameworks": {
            "django": ("DEBUG = True", "DEBUG = False  # and remove ?debug=1 handlers"),
            "flask": ("app.run(debug=True)", "app.run(debug=False)"),
        },
        "verify": "Re-send the debug parameter and confirm the response is a plain error page.",
    },
    "verb-tampering": {
        "principle": "Authorise the operation, not the HTTP method. Reject verbs the route "
                     "does not implement before any handler runs.",
        "frameworks": {
            "generic": ("if request.method != 'POST': return 'denied'",
                        "if request.method not in route.methods: return 405"),
        },
        "verify": "Repeat with the unexpected verb and confirm it returns 405.",
    },
    "prototype-pollution": {
        "principle": "Reject __proto__, constructor and prototype keys in any merge, and "
                     "create payload objects with Object.create(null).",
        "frameworks": {
            "generic": ("Object.assign(target, input)",
                        "for (const k of Object.keys(input)) if (!blocked.has(k)) target[k] = input[k]"),
        },
        "verify": "Re-send the payload and confirm the prototype is unchanged.",
    },
    "graphql-introspection": {
        "principle": "Disable introspection in production. It is a debug convenience that "
                     "hands over the complete data model to any unauthenticated caller.",
        "frameworks": {
            "generic": ("(introspection enabled)",
                        "introspection: process.env.NODE_ENV === 'development'"),
        },
        "verify": "Re-run an introspection query and confirm it is refused.",
    },
    "admin-panel": {
        "principle": "Require authentication at the edge, not in the page. An interface that "
                     "answers 200 without a session is exposed regardless of what it shows.",
        "frameworks": {"generic": ("(no auth requirement)",
                                   "require a valid session before any administrative response")},
        "verify": "Request the path without any session and confirm it returns 401/302 to login.",
    },
    "cookie-flag": {
        "principle": "Set Secure, HttpOnly and SameSite on every session cookie, and use the "
                     "__Host- prefix to bind it to the origin.",
        "frameworks": {
            "generic": ("Set-Cookie: sid=x; Path=/",
                        "Set-Cookie: __Host-sid=x; Path=/; Secure; HttpOnly; SameSite=Lax"),
        },
        "verify": "Inspect the response and confirm all three flags are present.",
    },
}

CWE_TO_FIX = {
    "CWE-89": "sqli", "CWE-78": "command-injection", "CWE-1336": "ssti",
    "CWE-22": "lfi", "CWE-918": "ssrf", "CWE-79": "xss", "CWE-93": "crlf",
    "CWE-601": "open-redirect", "CWE-644": "host-header", "CWE-942": "cors",
    "CWE-444": "smuggling", "CWE-347": "forgeable-jwt", "CWE-798": "secret-leak",
    "CWE-527": "vcs-exposure", "CWE-530": "backup-file", "CWE-200": "sensitive-file",
    "CWE-284": "admin-panel", "CWE-863": "verb-tampering", "CWE-1321": "prototype-pollution",
    "CWE-209": "verbose-errors", "CWE-502": "deserialization",
}

FRAMEWORK_SIGNATURES = [
    ("django", ("django", "csrftoken")),
    ("flask", ("flask", "werkzeug")),
    ("rails", ("rails", "x-runtime")),
    ("laravel", ("laravel", "laravel_session")),
    ("express", ("express",)),
    ("spring", ("spring", "jsessionid")),
    ("asp.net", ("asp.net", ".aspx", "x-aspnet-version")),
    ("php", (".php", "phpsessid")),
    ("react", ("react", "__next_data__")),
    ("vue", ("vue", "__nuxt")),
    ("angular", ("angular", "ng-app")),
    ("nginx", ("nginx",)),
    ("apache", ("apache",)),
]

PATCH_TEMPLATES = {
    "sqli": {
        "python": {
            "before": "cursor.execute(f\"SELECT * FROM t WHERE id = {value}\")",
            "after": "cursor.execute(\"SELECT * FROM t WHERE id = %s\", (value,))",
        }
    },
}


def detect_framework(results) -> str:
    techs = (results.get("recon", {}) or {}).get("technologies", {}) or {}
    blob = " ".join(
        str(item).lower()
        for group in techs.values()
        for item in (group or [])
    )
    headers = (results.get("headers", {}) or {}).get("raw_headers", {}) or {}
    blob += " " + " ".join(str(v).lower() for v in headers.values())
    blob += " " + " ".join(
        str(v.get("value", "")).lower() for v in (results.get("headers", {}) or {}).get("headers", {}).values()
    )

    for name, signatures in FRAMEWORK_SIGNATURES:
        if any(sig in blob for sig in signatures):
            return name
    return "generic"


class Remediation:
    """Produces the actual fix for each finding, in the stack the target runs on.

    Generic advice is the reason remediation sections get ignored. This maps each
    finding to the framework detected during recon and shows the before and after
    side by side, plus the check that proves the fix worked.
    """

    def __init__(self, console=None, results=None):
        self.console = console
        self.results = results or {}
        self.framework = detect_framework(self.results)

    @staticmethod
    def _as_pair(code):
        """Accept either {"before": ..., "after": ...} or a (before, after) pair."""
        if isinstance(code, dict):
            return code.get("before", ""), code.get("after", "")
        if isinstance(code, (tuple, list)) and len(code) == 2:
            return code[0], code[1]
        return "", ""

    def for_finding(self, finding: dict) -> dict:
        kind = finding.get("kind", "")
        cwe = finding.get("cwe", "")
        entry = FIXES.get(kind) or FIXES.get(CWE_TO_FIX.get(cwe, ""), {})

        if not entry:
            return {
                "finding": finding.get("title", ""),
                "kind": kind,
                "target": finding.get("target", ""),
                "cwe": cwe,
                "principle": "No specific guidance is mapped for this finding. Treat it as "
                             "an information-disclosure signal and confirm manually.",
                "before": "", "after": "",
                "verify": "Confirm the finding still reproduces before changing anything.",
                "framework": self.framework,
            }

        available = entry.get("frameworks", {}) or {}
        code = available.get(self.framework) or available.get("generic", {})
        before, after = self._as_pair(code)

        return {
            "finding": finding.get("title", ""),
            "kind": kind,
            "target": finding.get("target", ""),
            "cwe": cwe,
            "severity": finding.get("severity"),
            "cvss": finding.get("cvss_score"),
            "principle": entry["principle"],
            "framework": self.framework,
            "before": before,
            "after": after,
            "verify": entry.get("verify", ""),
        }

    def run(self, enriched_findings):
        guidance = []
        for finding in enriched_findings:
            item = self.for_finding(finding)
            if self._is_redundant(guidance, item):
                continue
            guidance.append(item)

        if guidance:
            from core.banner import info
            if self.console:
                info(self.console, f"Remediation generated for {len(guidance)} finding type(s) "
                                   f"against the {self.framework} stack.")
        return {
            "framework": self.framework,
            "guidance_count": len(guidance),
            "guidance": guidance,
            "caveat": "Before/after snippets are illustrative of the pattern, not a patch you "
                      "can apply verbatim. Confirm against your own code paths.",
        }

    @staticmethod
    def _is_redundant(guidance, item):
        """One entry per finding kind and target - the same bug on three URLs is one fix."""
        signature = (item.get("kind"), item.get("target"))
        return any((existing.get("kind"), existing.get("target")) == signature
                   for existing in guidance)