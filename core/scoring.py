import math
import re





AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

RATING_BANDS = [
    (9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "None"),
]


def roundup(value: float) -> float:
    """CVSS 3.1 Appendix A roundup: smallest 1-decimal value >= input."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss_base(av, ac, pr, ui, scope, c, i, a) -> dict:
    av, ac, pr, ui, scope = av.upper(), ac.upper(), pr.upper(), ui.upper(), scope.upper()
    c, i, a = c.upper(), i.upper(), a.upper()

    if scope not in ("U", "C"):
        raise ValueError(f"scope must be U or C, got {scope}")
    if av not in AV or ac not in AC or ui not in UI:
        raise ValueError(f"invalid AV/AC/UI: {av}/{ac}/{ui}")
    if c not in CIA or i not in CIA or a not in CIA:
        raise ValueError(f"invalid C/I/A: {c}/{i}/{a}")

    privileges = PR_UNCHANGED if scope == "U" else PR_CHANGED
    if pr not in privileges:
        raise ValueError(f"invalid PR for scope {scope}: {pr}")

    isc_base = 1.0 - ((1.0 - CIA[c]) * (1.0 - CIA[i]) * (1.0 - CIA[a]))

    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    exploitability = 8.22 * AV[av] * AC[ac] * privileges[pr] * UI[ui]

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = roundup(min(impact + exploitability, 10.0))
    else:
        score = roundup(min(1.08 * (impact + exploitability), 10.0))

    vector = (f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}"
              f"/C:{c}/I:{i}/A:{a}")

    return {
        "score": score,
        "vector": vector,
        "rating": rate(score),
        "impact_subscore": roundup(impact) if impact > 0 else 0.0,
        "exploitability_subscore": roundup(exploitability),
        "isc_base": round(isc_base, 4),
    }


def rate(score: float) -> str:
    for threshold, label in RATING_BANDS:
        if score >= threshold:
            return label
    return "None"


def parse_vector(vector: str) -> dict:
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            key, _, value = part.partition(":")
            metrics[key] = value
    return metrics


def score_vector(vector: str) -> dict:
    m = parse_vector(vector)
    return cvss_base(
        m["AV"], m["AC"], m["PR"], m["UI"], m["S"], m["C"], m["I"], m["A"]
    )






CWE_MAP = {
    "sqli": "CWE-89", "command-injection": "CWE-78", "ssti": "CWE-1336",
    "lfi": "CWE-22", "path-traversal": "CWE-22", "ssrf": "CWE-918",
    "xss": "CWE-79", "dom-sink": "CWE-79", "crlf": "CWE-93",
    "open-redirect": "CWE-601", "host-header": "CWE-644",
    "cors": "CWE-942", "clickjacking": "CWE-1021", "smuggling": "CWE-444",
    "forgeable-jwt": "CWE-347", "jwt-structure": "CWE-347", "jwt-claim": "CWE-200",
    "auth-config": "CWE-306", "secret-leak": "CWE-798", "vcs-exposure": "CWE-527",
    "backup-file": "CWE-530", "sensitive-file": "CWE-200",
    "admin-panel": "CWE-284", "verb-tampering": "CWE-863",
    "graphql-introspection": "CWE-200", "api-spec": "CWE-200",
    "source-map": "CWE-540", "internal-host": "CWE-200", "internal-ip": "CWE-200",
    "cloud-bucket": "CWE-732", "eol-library": "CWE-1104",
    "verbose-errors": "CWE-209", "prototype-pollution": "CWE-1321",
    "xxe": "CWE-611", "deserialization": "CWE-502",
    "csrf": "CWE-352", "cache-poisoning": "CWE-524",
}

DEFAULT_VECTORS = {
    "sqli": dict(av="N", ac="L", pr="L", ui="N", scope="U", c="H", i="H", a="H"),
    "command-injection": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="H", a="H"),
    "ssti": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="H", a="H"),
    "lfi": dict(av="N", ac="L", pr="L", ui="N", scope="U", c="H", i="L", a="N"),
    "ssrf": dict(av="N", ac="L", pr="L", ui="N", scope="C", c="H", i="L", a="N"),
    "xss": dict(av="N", ac="L", pr="N", ui="R", scope="C", c="L", i="L", a="N"),
    "dom-sink": dict(av="N", ac="L", pr="N", ui="R", scope="C", c="L", i="L", a="N"),
    "crlf": dict(av="N", ac="L", pr="L", ui="N", scope="U", c="L", i="L", a="N"),
    "open-redirect": dict(av="N", ac="L", pr="N", ui="R", scope="U", c="L", i="N", a="N"),
    "host-header": dict(av="N", ac="L", pr="N", ui="N", scope="U", c="L", i="L", a="N"),
    "cors": dict(av="N", ac="L", pr="N", ui="R", scope="U", c="H", i="L", a="N"),
    "clickjacking": dict(av="N", ac="L", pr="N", ui="R", scope="U", c="L", i="N", a="N"),
    "smuggling": dict(av="N", ac="H", pr="N", ui="N", scope="C", c="H", i="H", a="H"),
    "forgeable-jwt": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="H", a="N"),
    "jwt-structure": dict(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="L", a="N"),
    "auth-config": dict(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="L", a="N"),
    "secret-leak": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="H", a="N"),
    "vcs-exposure": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="H", a="N"),
    "backup-file": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="L", a="N"),
    "sensitive-file": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="L", a="N"),
    "admin-panel": dict(av="N", ac="L", pr="N", ui="N", scope="U", c="L", i="L", a="N"),
    "verb-tampering": dict(av="N", ac="L", pr="L", ui="N", scope="U", c="H", i="H", a="N"),
    "graphql-introspection": dict(av="N", ac="L", pr="N", ui="N", scope="U", c="L", i="L", a="N"),
    "source-map": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="L", a="N"),
    "eol-library": dict(av="N", ac="H", pr="N", ui="R", scope="U", c="L", i="L", a="N"),
    "verbose-errors": dict(av="N", ac="L", pr="N", ui="N", scope="U", c="L", i="N", a="N"),
    "internal-host": dict(av="N", ac="H", pr="N", ui="N", scope="U", c="L", i="N", a="N"),
    "cloud-bucket": dict(av="N", ac="H", pr="N", ui="N", scope="C", c="H", i="L", a="N"),
    "api-spec": dict(av="N", ac="L", pr="N", ui="N", scope="U", c="L", i="N", a="N"),
    "jwt-claim": dict(av="N", ac="H", pr="N", ui="N", scope="U", c="L", i="N", a="N"),
    "prototype-pollution": dict(av="N", ac="L", pr="N", ui="R", scope="C", c="L", i="L", a="N"),
    "xxe": dict(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="N", a="N"),
    "csrf": dict(av="N", ac="L", pr="N", ui="R", scope="U", c="L", i="L", a="N"),
    "cache-poisoning": dict(av="N", ac="H", pr="N", ui="N", scope="C", c="H", i="L", a="N"),
}


def enrich(finding: dict, exposure: dict = None) -> dict:
    """Attach CVSS, CWE and a prioritised ordering key to a correlated finding.

    `exposure` lets the pipeline raise the Attack Vector when the reachable
    surface is in fact authenticated, so a finding behind a login is not scored
    as if it were unauthenticated.
    """
    kind = finding.get("kind", "")
    vector = dict(DEFAULT_VECTORS.get(kind, DEFAULT_VECTORS["verbose-errors"]))

    if exposure:
        if exposure.get("requires_auth") and vector.get("pr") == "L":
            vector["pr"] = "H"
        if exposure.get("requires_auth"):
            vector["av"] = "N"
        if exposure.get("user_interaction") is False:
            vector["ui"] = "N"
        if exposure.get("scope_changed") is not None:
            vector["scope"] = "C" if exposure["scope_changed"] else "U"

    try:
        cvss = cvss_base(**vector)
    except ValueError:
        cvss = cvss_base(**DEFAULT_VECTORS["verbose-errors"])

    confidence = float(finding.get("confidence", 1.0))
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severity = finding.get("severity", "info")
    ordering = round(cvss["score"] * confidence, 2)
    priority_rank = severity_rank.get(severity, 0)

    return {
        **finding,
        "cvss_score": cvss["score"],
        "cvss_vector": cvss["vector"],
        "cvss_rating": cvss["rating"],
        "cvss_impact": cvss["impact_subscore"],
        "cvss_exploitability": cvss["exploitability_subscore"],
        "cwe": CWE_MAP.get(kind, "CWE-0"),
        "cwe_url": f"https://cwe.mitre.org/data/definitions/"
                   f"{CWE_MAP.get(kind, '0').split('-')[-1]}.html",
        "confidence": round(confidence, 2),
        "ordering_key": ordering,
        "priority_rank": priority_rank,
        "band": _band(ordering),
    }


def _band(score: float) -> str:
    if score >= 9.0:
        return "P0-immediate"
    if score >= 7.0:
        return "P1-scheduled"
    if score >= 4.0:
        return "P2-planned"
    if score >= 1.0:
        return "P3-backlog"
    return "P4-informational"


def summarize(enriched: list) -> dict:
    if not enriched:
        return {"count": 0, "bands": {}, "ratings": {}, "top": []}

    bands, ratings = {}, {}
    for item in enriched:
        bands[item["band"]] = bands.get(item["band"], 0) + 1
        ratings[item["cvss_rating"]] = ratings.get(item["cvss_rating"], 0) + 1

    ordered = sorted(enriched, key=lambda x: (-x["ordering_key"], x["title"]))
    return {
        "count": len(enriched),
        "bands": dict(sorted(bands.items())),
        "ratings": ratings,
        "average": round(sum(i["cvss_score"] for i in enriched) / len(enriched), 2),
        "top": [
            {
                "title": i["title"], "target": i.get("target", ""),
                "cvss": i["cvss_score"], "vector": i["cvss_vector"], "cwe": i["cwe"],
                "band": i["band"], "confidence": i["confidence"],
            }
            for i in ordered[:25]
        ],
        "all": ordered,
    }