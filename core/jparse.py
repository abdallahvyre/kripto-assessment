import re

_MASTER = re.compile(
    r"""
      (?P<ws>[\s﻿ ]+)
    | (?P<linecomment>//[^\n]*)
    | (?P<blockcomment>/\*.*?\*/)
    | (?P<string>'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*")
    | (?P<number>0[xX][0-9a-fA-F]+n?|\d*\.?\d+(?:[eE][+-]?\d+)?n?)
    | (?P<ident>[A-Za-z_$][\w$]*)
    | (?P<regex>/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+/[gimsuyd]*)
    | (?P<punc>[^\s\w$])
    """,
    re.X,
)

_KEYWORDS_BEFORE_REGEX = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
}
_KEYWORDS_BEFORE_VALUE = {
    "this", "super", "true", "false", "null", "undefined",
}
_IDENT_ENDERS = {")", "]", "}", "++", "--"}

_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
    "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`", "/": "/",
    "\n": "",
}

ROUTE_MARKERS = (
    "fetch", "axios", "request", "got", "ky", "superagent", "http", "https",
    "api", "query", "mutation", "url", "uri", "path", "route", "endpoint",
    "href", "action", "src", "link", "navigate", "redirect", "push", "replace",
)

HTTP_CLIENTS = {
    "fetch", "axios", "request", "superagent", "got", "ky", "http", "https",
    "$.ajax", "$.get", "$.post", "$.getJSON", "XMLHttpRequest", "navigator",
}

SENSITIVE_OBJECT_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
    "id_token", "api_key", "apikey", "apiKey", "client_secret", "authorization",
    "auth", "credential", "credentials", "private_key", "privateKey", "session",
    "cookie", "bearer", "jwt",
}

ENV_OBJECTS = {
    "process.env", "import.meta.env", "Deno.env", "window.__ENV__",
    "window.__CONFIG__", "window.__APP_CONFIG__", "window.__INITIAL_STATE__",
    "__ENV__", "__CONFIG__", "__APP_CONFIG__", "__INITIAL_STATE__",
    "__PRELOADED_STATE__", "__NUXT__", "globalThis.__CONFIG__",
}

URL_KEYS = {
    "url", "path", "endpoint", "apiUrl", "api_url", "baseURL", "baseUrl", "apiBase",
    "href", "action", "src", "uri", "link", "to", "route", "target", "destination",
    "download", "file", "image", "feed", "redirectTo", "next", "controller",
    "template", "handler", "callbackUrl",
}

DANGEROUS_SINKS = {
    "eval": "dynamic code execution",
    "Function": "dynamic function construction",
    "document.write": "HTML injection sink",
    "document.writeln": "HTML injection sink",
    "outerHTML": "HTML injection sink",
    "innerHTML": "HTML injection sink",
    "insertAdjacentHTML": "HTML injection sink",
    "dangerouslySetInnerHTML": "React HTML injection sink",
    "setTimeout": "string-evaluated timer",
    "setInterval": "string-evaluated timer",
    "execScript": "legacy code execution",
    "location": "navigation sink",
    "postMessage": "cross-origin message sink",
    "localStorage.setItem": "client-side storage write",
    "sessionStorage.setItem": "client-side storage write",
    "cookie": "cookie write",
    "XMLHttpRequest": "outbound request",
    "open": "outbound request",
}

USER_SOURCES = (
    "location.search", "location.hash", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "document.location", "window.name", "document.cookie", "window.location",
    "URLSearchParams", "postMessage", "event.data", "e.data", "message",
)

_PATH_PARAM_RE = re.compile(r"\{([A-Za-z_$][\w$]{0,40})\}|:([A-Za-z_$][\w$]{1,40})(?=[/?.#]|$)")


class Token:
    __slots__ = ("kind", "value", "start", "end", "nl_before")

    def __init__(self, kind, value, start, end, nl_before=False):
        self.kind = kind
        self.value = value
        self.start = start
        self.end = end
        self.nl_before = nl_before

    @property
    def is_value_terminator(self):
        return self.kind in ("str", "num", "ident", "regex", "tmpl") or\
            (self.kind == "punc" and self.value in _IDENT_ENDERS)

    def __repr__(self):
        return f"<{self.kind}:{self.value[:24]!r}>"


def _unescape(raw: str) -> str:
    body = raw[1:-1]
    if "\\" not in body:
        return body

    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            break
        esc = body[i]
        if esc == "u":
            if body[i + 1:i + 2] == "{":
                end = body.find("}", i)
                try:
                    out.append(chr(int(body[i + 2:end], 16)))
                    i = end + 1
                    continue
                except Exception:
                    pass
            hexpart = body[i + 1:i + 5]
            try:
                out.append(chr(int(hexpart, 16)))
                i += 5
                continue
            except Exception:
                out.append(esc)
                i += 1
                continue
        if esc == "x":
            try:
                out.append(chr(int(body[i + 1:i + 3], 16)))
                i += 3
                continue
            except Exception:
                out.append(esc)
                i += 1
                continue
        out.append(_ESCAPES.get(esc, esc))
        i += 1
    return "".join(out)


class Lexer:
    """A real JavaScript tokenizer.

    Route mining with regular expressions cannot tell a path apart from a
    fragment of minified code, cannot fold `"/api/" + "v1" + "/users"`, and
    cannot tell whether `/users` is a string or a regular expression. Tokenizing
    first is what makes the difference between hundreds of real endpoints and
    hundreds of false ones.
    """

    def __init__(self, source: str, limit: int = 4_000_000):
        self.source = source[:limit]
        self.pos = 0
        self.tokens = []

    def _regex_allowed(self, prev):
        if prev is None:
            return True
        if prev.kind == "ident":
            return prev.value in _KEYWORDS_BEFORE_REGEX
        if prev.is_value_terminator:
            return False
        if prev.kind == "punc" and prev.value in (")", "]", "}", "++", "--"):
            return False
        return True

    def _parse_template(self, start):
        """Read a template literal, tracking ${ } substitutions by depth."""
        src = self.source
        i = start + 1
        depth = 0
        pieces = []
        buf = []

        while i < len(src):
            ch = src[i]
            if ch == "\\":
                buf.append(src[i:i + 2])
                i += 2
                continue
            if depth == 0 and ch == "`":
                i += 1
                break
            if depth == 0 and ch == "$" and src[i + 1:i + 2] == "{":
                pieces.append(("str", "".join(buf)))
                buf = []
                depth = 1
                sub_start = i + 2
                j = sub_start
                braces = 1
                while j < len(src) and braces:
                    c = src[j]
                    if c == "\\":
                        j += 2
                        continue
                    if c in "'\"`":
                        quote = c
                        j += 1
                        while j < len(src) and src[j] != quote:
                            j += 2 if src[j] == "\\" else 1
                    elif c == "{":
                        braces += 1
                    elif c == "}":
                        braces -= 1
                    j += 1
                pieces.append(("expr", src[sub_start:j - 1]))
                i = j
                depth = 0
                continue
            buf.append(ch)
            i += 1

        pieces.append(("str", "".join(buf)))
        return Token("tmpl", pieces, start, i), i

    def run(self):
        src = self.source
        prev = None
        newline = False

        while self.pos < len(src):
            match = _MASTER.match(src, self.pos)
            if not match:
                self.pos += 1
                continue

            kind = match.lastgroup
            text = match.group()
            start = match.start()
            end = match.end()

            if kind == "ws":
                newline = "\n" in text
                self.pos = end
                continue
            if kind in ("linecomment", "blockcomment"):
                if "\n" in text:
                    newline = True
                self.pos = end
                continue

            if kind == "punc" and text == "`":
                token, new_pos = self._parse_template(start)
                self.tokens.append(token)
                self.pos = new_pos
                prev = token
                continue

            if kind == "regex" and not self._regex_allowed(prev):
                self.pos = start + 1
                newline = False
                prev = Token("punc", "/", start, start + 1)
                self.tokens.append(prev)
                continue

            if kind == "string":
                token = Token("str", _unescape(text), start, end)
            elif kind == "number":
                token = Token("num", text, start, end)
            elif kind == "ident":
                token = Token("kw" if text in _KEYWORDS_BEFORE_VALUE else "ident", text, start, end)
            elif kind == "regex":
                token = Token("regex", text, start, end)
            else:
                token = Token("punc", text, start, end)

            token.nl_before = newline
            newline = False
            self.tokens.append(token)
            self.pos = end
            prev = token

        return self.tokens


class JSModule:
    """Semantic analysis over the token stream."""

    def __init__(self, source: str, url: str = "", origin: str = ""):
        self.source = source
        self.url = url
        self.origin = origin or url
        self.tokens = Lexer(source).run()
        self._pairs, self._reverse_pairs = {}, {}
        stacks = {"(": [], "[": [], "{": []}
        for index, token in enumerate(self.tokens):
            if token.kind != "punc":
                continue
            if token.value in stacks:
                stacks[token.value].append(index)
            elif token.value in (")", "]", "}"):
                stack = stacks[{")": "(", "]": "[", "}": "{"}[token.value]]
                if stack:
                    opener = stack.pop()
                    self._pairs[opener] = index
                    self._reverse_pairs[index] = opener
        self.routes = []
        self._route_set = set()
        self._route_index = {}
        self._consts = {}
        self.constants = {}
        self.calls = []
        self.env_objects = {}
        self.sinks = []
        self.secret_like = []
        self.folded_strings = []
        self.used_sources = set()
        self._work_remaining = 200_000
        self.limitations = []

    

    def _claim_work(self, amount):
        from core.http import RateLimitedSession
        if RateLimitedSession._control is not None:
            RateLimitedSession._control.check()
        if amount > self._work_remaining:
            if not self.limitations:
                self.limitations.append("JavaScript semantic token-work limit reached; partial analysis")
            return False
        self._work_remaining -= max(0, amount)
        return True

    def _callee_name(self, open_index):
        """Resolve the member expression immediately left of the '(' token."""
        tokens = self.tokens
        i = open_index - 1
        if i < 0:
            return None

        token = tokens[i]
        if token.kind == "punc" and token.value in (")", "]", "}"):
            opener = {")": "(", "]": "[", "}": "{"}[token.value]
            start = self._match_backward(tokens, i, opener, token.value)
            if start == -1:
                return None
            i = start - 1

        if i < 0 or tokens[i].kind not in ("ident", "kw"):
            return None

        parts = [tokens[i].value]
        j = i - 1
        while j >= 1 and tokens[j].kind == "punc" and tokens[j].value in (".", "?."):
            j -= 1
            if j < 0 or tokens[j].kind not in ("ident", "kw"):
                return ".".join(reversed(parts))
            parts.append(tokens[j].value)
            j -= 1
        return ".".join(reversed(parts))

    def _match_forward(self, tokens, open_index, open_char, close_char):
        if tokens is self.tokens:
            return self._pairs.get(open_index, -1)
        depth = 0
        for i in range(open_index, len(tokens)):
            token = tokens[i]
            if token.kind != "punc":
                continue
            if token.value == open_char:
                depth += 1
            elif token.value == close_char:
                depth -= 1
                if depth == 0:
                    return i
        return -1

    def _match_backward(self, tokens, index, open_char, close_char):
        if tokens is self.tokens:
            return self._reverse_pairs.get(index, -1)
        depth = 0
        for i in range(index, -1, -1):
            token = tokens[i]
            if token.kind != "punc":
                continue
            if token.value == close_char:
                depth += 1
            elif token.value == open_char:
                depth -= 1
                if depth == 0:
                    return i
        return -1

    def _object_keys(self, open_index):
        """Keys of an object literal, honouring nesting."""
        tokens = self.tokens
        if tokens[open_index].value != "{":
            return []
        close = self._match_forward(tokens, open_index, "{", "}")
        if close == -1:
            return []
        if not self._claim_work(close - open_index):
            return []

        keys = []
        depth = 0
        expect_key = True
        for i in range(open_index, close + 1):
            token = tokens[i]
            if token.kind == "punc":
                if token.value in "{[(":
                    depth += 1
                    expect_key = token.value == "{"
                elif token.value in "}])":
                    depth -= 1
                    expect_key = False
                elif token.value == ":" and depth == 1:
                    expect_key = False
                elif token.value == "," and depth == 1:
                    expect_key = True
                continue
            if depth == 1 and expect_key and token.kind in ("ident", "kw"):
                keys.append(token.value)
            elif depth == 1 and expect_key and token.kind == "str":
                keys.append(token.value)
        return keys

    def _arg_spans(self, open_index):
        """Argument index ranges of a call, respecting nesting."""
        tokens = self.tokens
        close = self._match_forward(tokens, open_index, "(", ")")
        if close == -1:
            return []

        spans = []
        start = open_index + 1
        i = start
        while i < close:
            token = tokens[i]
            if token.kind == "punc" and token.value in "([{":
                nested_end = self._pairs.get(i)
                if nested_end is None or nested_end >= close:
                    return []
                i = nested_end + 1
                continue
            if token.kind == "punc" and token.value == ",":
                spans.append((start, i))
                if len(spans) >= 8:
                    return spans
                start = i + 1
            i += 1
        if start < close:
            spans.append((start, close))
        return spans

    def _fold(self, start, end):
        """Constant-fold concatenation inside a token span.

        The `+` operators themselves are discarded, so `"/api/" + "v1" + "/users"`
        folds to `/api/v1/users`. Unresolved identifiers become \\x00 so a
        partially static path such as BASE + "/users" still yields a usable tail
        instead of being thrown away.
        """
        chunks = []
        unresolved = False
        if not self._claim_work(end - start):
            return "", True
        for token in self.tokens[start:end]:
            if token.kind == "punc" and token.value == "+":
                continue
            if token.kind in ("str", "num"):
                chunks.append(token.value)
            elif token.kind == "tmpl":
                for kind, part in token.value:
                    if kind == "str":
                        if part:
                            chunks.append(part)
                    else:
                        chunks.append("\x00")
                        unresolved = True
            elif token.kind == "ident":
                resolved = self._consts.get(token.value)
                if resolved:
                    chunks.append(resolved)
                else:
                    chunks.append("\x00")
                    unresolved = True
            else:
                chunks.append("\x01")
        return "".join(chunks), unresolved

    @staticmethod
    def _strip_placeholders(text: str) -> str:
        previous = None
        while previous != text:
            previous = text
            text = re.sub(r"[\x00\x01]\s*\+\s*", "", text)
            text = text.strip("\x00\x01+ ")
        return text

    

    def _build_constants(self, rounds=2):
        """Resolve `const BASE = "/api/v2"` so BASE + "/users" folds correctly.

        Without this, every base-URL constant in the bundle becomes an
        unresolvable placeholder and the real endpoint `/api/v2/users` is lost
        in favour of the bare suffix `/users`.
        """
        tokens = self.tokens
        consts = {}
        for _ in range(rounds):
            previous = len(consts)
            for i, token in enumerate(tokens):
                if token.kind != "ident" or token.value not in ("const", "let", "var"):
                    continue
                if i + 1 >= len(tokens) or tokens[i + 1].kind != "ident":
                    continue
                name = tokens[i + 1].value
                if name in consts:
                    continue

                j = i + 2
                if j < len(tokens) and tokens[j].kind == "punc" and tokens[j].value == ":":
                    j += 1
                if j >= len(tokens) or tokens[j].kind != "punc" or tokens[j].value != "=":
                    continue

                end = self._value_end(j + 1)
                folded, unresolved = self._fold(j + 1, end)
                if unresolved or not folded or any(c in folded for c in "\x00\x01"):
                    continue
                if len(folded) <= 200:
                    consts[name] = folded
            if len(consts) == previous:
                break
        return consts

    def analyze(self):
        tokens = self.tokens
        self._consts = self._build_constants()
        if self._consts:
            found_consts = {k: v for k, v in self._consts.items()
                            if v.startswith("/") or v.startswith("http")}
            if found_consts:
                self.constants.update(found_consts)

        for source_name in USER_SOURCES:
            if source_name in self.source:
                self.used_sources.add(source_name)

        for index, token in enumerate(tokens):
            if token.kind == "punc" and token.value == "(":
                callee = self._callee_name(index)
                if callee:
                    self._analyze_call(callee, index)
            elif token.kind in ("ident", "kw"):
                if token.value in ENV_OBJECTS or self._is_env_ref(index):
                    self._capture_env_object(index)

        self._analyze_sinks()
        self._analyze_sensitive_objects()
        self._harvest_literal_paths()

        for entry in self.routes:
            entry["params"] = sorted(p for p in entry["params"] if p)
            entry["config"] = sorted(entry["config"])

        return {
            "routes": self.routes,
            "calls": self.calls,
            "env_objects": self.env_objects,
            "sinks": self.sinks,
            "secret_like": self.secret_like,
            "tokens": len(tokens),
            "constants": self.constants,
            "user_sources": sorted(self.used_sources),
            "limitations": self.limitations,
        }

    def _is_env_ref(self, index):
        """process.env / import.meta.env / Deno.env"""
        tokens = self.tokens
        if tokens[index].value != "env":
            return False
        if index < 2 or tokens[index - 1].kind != "punc" or tokens[index - 1].value != ".":
            return False
        owner = tokens[index - 2]
        if owner.kind not in ("ident", "kw"):
            return False
        if index >= 4 and tokens[index - 2].value == "meta" and\
                tokens[index - 3].kind == "punc" and tokens[index - 3].value == "." and\
                tokens[index - 4].kind in ("ident", "kw") and tokens[index - 4].value == "import":
            return True
        return owner.value in ("process", "Deno", "global", "globalThis")

    def _capture_env_object(self, index):
        j = index + 1
        while j < len(self.tokens) and self.tokens[j].kind == "punc" and\
                self.tokens[j].value in ("=", ":", "."):
            j += 1
        if j >= len(self.tokens) or self.tokens[j].kind != "punc" or self.tokens[j].value != "{":
            return
        close = self._match_forward(self.tokens, j, "{", "}")
        if close == -1:
            return
        name = self.tokens[index].value
        if index > 0 and self.tokens[index - 1].kind == "punc" and self.tokens[index - 1].value == ".":
            name = f"{self.tokens[index - 2].value}.{name}"

        folded, _ = self._fold(j + 1, close)
        self.env_objects.setdefault(name, {
            "keys": self._object_keys(j),
            "body": self._strip_placeholders(folded),
            "raw": self.source[self.tokens[j].start:self.tokens[close].end][:3000],
        })

    def _is_value_chain(self, start, end):
        """True when a span is purely `a + b + "c"` and nothing else."""
        return all(
            token.kind in ("str", "tmpl", "num", "ident")
            or (token.kind == "punc" and token.value == "+")
            for token in self.tokens[start:end]
        )

    def _analyze_call(self, callee, open_index):
        spans = self._arg_spans(open_index)
        if not spans:
            return
        if not self._claim_work(sum(end - start for start, end in spans[:8])):
            return

        tokens = self.tokens
        path = None
        path_inferred = False
        params = set()
        config_keys = set()

        for start, end in spans[:8]:
            if start >= end:
                continue

            head = tokens[start]
            single = (start + 1 == end) and head.kind in ("str", "tmpl")
            chain = self._is_value_chain(start, end)
            if single or chain:
                folded, unresolved = self._fold(start, end)
                cleaned = self._strip_placeholders(folded)
                if path is None and cleaned and any(c in cleaned for c in ("/", "?", "=")):
                    path, path_inferred = cleaned, unresolved
                if single:
                    continue

            if head.kind == "punc" and head.value == "{":
                found = self._extract_key_string(start, end)
                if found and path is None:
                    path, path_inferred = found[0], found[1]
                params.update(self._params_from_options(start, end))
                config_keys.update(self._object_keys(start))
                config_keys.update(self._string_keys(start, end))
            elif head.kind == "punc" and head.value == "[":
                params.update(self._params_from_options(start, end))
                config_keys.update(self._string_keys(start, end))

        if path:
                entry = self._route_index.get(path)
                if entry is None:
                    entry = {
                        "path": path, "callee": callee, "params": set(params),
                        "config": set(config_keys), "inferred": path_inferred,
                    }
                    self._route_index[path] = entry
                    self._route_set.add(path)
                    self.routes.append(entry)
                else:
                    
                    
                    entry["params"] |= params
                    entry["config"] |= config_keys
                self.calls.append({"callee": callee, "arg": path, "index": open_index})

        for key in config_keys:
            if key.lower() in SENSITIVE_OBJECT_KEYS:
                self.secret_like.append(key)

    def _value_end(self, i):
        """Index just past a value expression starting at token i.

        Without this, reading a value runs on into the next property and turns
        `{auth: "tok"}` into a secret that contains half the following object.
        """
        tokens = self.tokens
        if i >= len(tokens):
            return i

        token = tokens[i]
        if token.kind == "punc" and token.value in ("(", "[", "{"):
            closer = {"(": ")", "[": "]", "{": "}"}[token.value]
            close = self._match_forward(tokens, i, token.value, closer)
            return close + 1 if close != -1 else i + 1

        end = i + 1
        while end + 1 < len(tokens)\
                and tokens[end].kind == "punc" and tokens[end].value == "+"\
                and tokens[end + 1].kind in ("str", "tmpl", "num", "ident"):
            end += 2
        return end

    def _extract_key_string(self, start, end):
        """Pull the value of a url/path/endpoint-style key out of an object."""
        tokens = self.tokens
        for i in range(start, end - 2):
            key = tokens[i]
            if key.kind not in ("ident", "str") or key.value not in URL_KEYS:
                continue
            if tokens[i + 1].kind != "punc" or tokens[i + 1].value != ":":
                continue

            value_index = i + 2
            if tokens[value_index].kind in ("str", "tmpl"):
                stop = min(end, self._value_end(value_index))
                folded, unresolved = self._fold(value_index, stop)
                cleaned = self._strip_placeholders(folded)
                if cleaned and any(c in cleaned for c in ("/", "?", "=")):
                    return cleaned, unresolved
        return None, False

    def _string_keys(self, start, end):
        """Keys of an object literal, including quoted ones such as "X-Api-Key"."""
        tokens = self.tokens
        found = set()
        for i in range(start, end):
            token = tokens[i]
            if token.kind == "str" and i + 2 < end and\
                    tokens[i + 1].kind == "punc" and tokens[i + 1].value == ":":
                found.add(token.value)
        return found

    def _params_from_options(self, start, end):
        """Parameter names from axios/fetch style option objects."""
        tokens = self.tokens
        params = set()
        option_keys = ("params", "query", "searchparams", "data", "body", "payload",
                       "formdata", "form", "json", "qs")

        for i in range(start, end):
            token = tokens[i]
            if token.kind != "ident" or token.value.lower() not in option_keys:
                continue
            j = i + 1
            while j < end and tokens[j].kind == "punc" and tokens[j].value in (":", "."):
                j += 1
            if j < end and tokens[j].kind == "punc" and tokens[j].value == "{":
                params.update(self._object_keys(j))
        return params

    def _analyze_sinks(self):
        """Dangerous sinks, each judged only against sources in its own scope.

        A file-wide 'this bundle touches location.search' flag made every sink
        in every bundle look exploitable. A sink is only interesting when a
        user-controlled source actually flows into it nearby.
        """
        tokens = self.tokens
        for index, token in enumerate(tokens):
            name = None
            if token.kind == "punc" and token.value == ".":
                name = self._callee_name(index + 1) or None
            elif token.kind in ("ident", "kw"):
                name = token.value
            if name not in DANGEROUS_SINKS:
                continue
            if token.kind == "punc" and index and tokens[index - 1].kind == "punc" and\
                    tokens[index - 1].value in (".", "?."):
                continue

            lo = max(0, index - 16)
            hi = min(len(tokens) - 1, index + 27)
            raw = self.source[tokens[lo].start:tokens[hi].end]
            raw = re.sub(r"\s+", " ", raw).strip()

            touched = sorted({s for s in self.used_sources if s in raw})
            self.sinks.append({
                "sink": name,
                "why": DANGEROUS_SINKS[name],
                "has_user_source": bool(touched),
                "sources": touched,
                "context": raw[:260],
                "at": tokens[index].start,
            })

    def _harvest_literal_paths(self):
        """Paths that are never passed to a call.

        `const endpoint = "/api/v2/reports/{id}"` then later used as a variable is
        invisible to call-argument analysis, yet it is still a live endpoint.
        Because this pass only sees real string tokens it cannot pull in the
        fragments a pattern-based scanner mistakes for routes.
        """
        for index, token in enumerate(self.tokens):
            if token.kind == "str":
                folded, unresolved = token.value, False
            elif token.kind == "tmpl":
                folded = "".join(part if kind == "str" else "\x00" for kind, part in token.value)
                unresolved = any(kind != "str" for kind, _ in token.value)
            else:
                continue

            
            
            if index and self.tokens[index - 1].kind == "punc" and\
                    self.tokens[index - 1].value == "+":
                continue
            if index + 1 < len(self.tokens) and self.tokens[index + 1].kind == "punc" and\
                    self.tokens[index + 1].value == "+":
                continue

            cleaned = self._strip_placeholders(folded)
            if len(cleaned) < 2 or not cleaned.startswith("/"):
                continue
            if cleaned in self._route_set:
                continue

            self._route_set.add(cleaned)
            self._route_index[cleaned] = entry = {
                "path": cleaned,
                "callee": "",
                "params": {a or b for a, b in _PATH_PARAM_RE.findall(cleaned)},
                "config": set(),
                "inferred": unresolved,
                "literal": True,
            }
            self.routes.append(entry)

    def _analyze_sensitive_objects(self):
        for index, token in enumerate(self.tokens):
            if token.kind not in ("ident", "str"):
                continue
            if token.value.lower() not in SENSITIVE_OBJECT_KEYS:
                continue
            if index + 2 >= len(self.tokens):
                continue
            if self.tokens[index + 1].kind != "punc" or self.tokens[index + 1].value != ":":
                continue

            end = min(len(self.tokens), self._value_end(index + 2))
            folded, _ = self._fold(index + 2, end)
            value = self._strip_placeholders(folded).strip().strip('"').strip("'").strip(",")
            value = value.split(",")[0].strip()
            if 8 <= len(value) <= 200 and not value.startswith(("process.", "import.meta", "$")):
                self.secret_like.append(value)


def analyze(source: str, url: str = "") -> dict:
    return JSModule(source, url).analyze()
