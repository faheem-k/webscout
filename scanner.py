#!/usr/bin/env python3
"""
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗██╗   ██╗████████╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██║   ██║╚══██╔══╝
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║     ██║   ██║   ██║   
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║     ██║   ██║   ██║   
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╗╚██████╔╝   ██║   
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝   

WebScout - Web Application Security Header & JWT Analyzer
Author: github.com/yourhandle
"""

import argparse
import base64
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝ ██║   ██║╚══██╔══╝
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║      ██║   ██║   ██║   
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║      ██║   ██║   ██║   
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╗ ╚██████╔╝   ██║   
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
{RESET}{DIM}  Web Application Security Header & JWT Analyzer{RESET}
"""

# ─── Security Headers Definitions ────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "checks": [
            ("max-age", "Missing max-age directive"),
            ("includeSubDomains", "Missing includeSubDomains (recommended)"),
        ],
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "HIGH",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none'",
        "checks": [
            ("default-src", "Missing default-src directive"),
            ("script-src", "Missing script-src directive"),
        ],
        "dangerous_values": [
            ("'unsafe-inline'", "Allows inline scripts — XSS risk"),
            ("'unsafe-eval'", "Allows eval() — XSS risk"),
            ("*", "Wildcard source — overly permissive"),
        ],
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommended": "DENY or SAMEORIGIN",
        "valid_values": ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommended": "nosniff",
        "valid_values": ["nosniff"],
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "LOW",
        "recommended": "strict-origin-when-cross-origin",
        "valid_values": [
            "no-referrer", "no-referrer-when-downgrade",
            "origin", "origin-when-cross-origin",
            "same-origin", "strict-origin",
            "strict-origin-when-cross-origin",
        ],
    },
    "Permissions-Policy": {
        "description": "Controls browser feature permissions",
        "severity": "LOW",
        "recommended": "camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still checked)",
        "severity": "INFO",
        "recommended": "0  (disabled — rely on CSP instead)",
        "note": "Modern browsers ignore this; use CSP instead",
    },
    "Cache-Control": {
        "description": "Controls caching of sensitive responses",
        "severity": "LOW",
        "recommended": "no-store, no-cache (for sensitive pages)",
        "sensitive_missing": ["no-store", "no-cache"],
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context from cross-origin documents",
        "severity": "MEDIUM",
        "recommended": "same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents cross-origin resource loading",
        "severity": "LOW",
        "recommended": "same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls embedding of cross-origin resources",
        "severity": "LOW",
        "recommended": "require-corp",
    },
}

LEAKING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache",
    "X-Varnish", "Via", "X-Runtime", "X-Version",
]

# ─── JWT Utilities ────────────────────────────────────────────────────────────
WEAK_ALGORITHMS = ["none", "hs256", "hs384", "hs512"]
DANGEROUS_ALGORITHMS = ["none"]

KNOWN_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "your-256-bit-secret",
    "your-secret-key", "mysecret", "jwt_secret", "supersecret",
    "verysecretkey", "keyboard cat", "shhhhh", "abcdefgh",
    "qwerty", "letmein", "welcome", "admin", "test",
]


def decode_base64url(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def analyze_jwt(token: str) -> dict:
    issues = []
    info = {}
    parts = token.split(".")

    if len(parts) != 3:
        return {"error": "Not a valid JWT (expected 3 parts)", "issues": []}

    # ── Decode header ──
    try:
        header = json.loads(decode_base64url(parts[0]))
        info["header"] = header
    except Exception:
        return {"error": "Failed to decode JWT header", "issues": []}

    # ── Decode payload ──
    try:
        payload = json.loads(decode_base64url(parts[1]))
        info["payload"] = payload
    except Exception:
        payload = {}
        issues.append(("MEDIUM", "Could not decode JWT payload"))

    # ── Algorithm checks ──
    alg = header.get("alg", "").lower()
    if not alg or alg == "none":
        issues.append(("CRITICAL", f"Algorithm 'none' — signature verification bypassed!"))
    elif alg in ["hs256", "hs384", "hs512"]:
        issues.append(("INFO", f"Symmetric algorithm {alg.upper()} — secret must be strong and kept private"))
    elif alg in ["rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512"]:
        issues.append(("INFO", f"Asymmetric algorithm {alg.upper()} — verify public key handling"))

    # ── Key ID injection ──
    if "kid" in header:
        kid = header["kid"]
        sqli_patterns = ["'", "\"", "--", ";", "/*", "*/", "union", "select", "drop"]
        for p in sqli_patterns:
            if p in kid.lower():
                issues.append(("CRITICAL", f"kid header contains suspicious value '{kid}' — possible SQLi/path traversal"))
                break
        issues.append(("INFO", f"kid present: '{kid}' — ensure server validates this safely"))

    # ── Expiry checks ──
    now = datetime.now(timezone.utc).timestamp()
    if "exp" not in payload:
        issues.append(("HIGH", "No expiration (exp) claim — token never expires!"))
    else:
        exp = payload["exp"]
        if exp < now:
            issues.append(("HIGH", f"Token is EXPIRED (exp: {datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()})"))
        else:
            lifetime = exp - now
            if lifetime > 86400 * 30:
                issues.append(("MEDIUM", f"Token expires in {int(lifetime/86400)} days — consider shorter lifetime"))

    if "nbf" in payload:
        nbf = payload["nbf"]
        if nbf > now:
            issues.append(("MEDIUM", f"Token not yet valid (nbf: {datetime.fromtimestamp(nbf, tz=timezone.utc).isoformat()})"))

    if "iat" not in payload:
        issues.append(("LOW", "No issued-at (iat) claim — can't determine token age"))

    # ── Sensitive data in payload ──
    sensitive_keys = ["password", "passwd", "pwd", "secret", "credit_card",
                       "ssn", "social_security", "cvv", "pin", "private_key"]
    for key in payload:
        if any(s in key.lower() for s in sensitive_keys):
            issues.append(("HIGH", f"Sensitive field '{key}' found in JWT payload — JWTs are base64, NOT encrypted!"))

    # ── Audience / Issuer ──
    if "aud" not in payload:
        issues.append(("LOW", "No audience (aud) claim — token could be replayed to different services"))
    if "iss" not in payload:
        issues.append(("LOW", "No issuer (iss) claim — can't verify token origin"))

    # ── Signature present? ──
    if not parts[2]:
        issues.append(("CRITICAL", "Empty signature — 'none' algorithm attack possible"))

    info["issues"] = issues
    return info


# ─── Header Scanner ───────────────────────────────────────────────────────────
def scan_url(url: str, timeout: int = 10, follow_redirects: bool = True) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "status_code": None,
        "headers": {},
        "missing_headers": [],
        "present_headers": [],
        "header_issues": [],
        "leaking_headers": [],
        "jwt_findings": [],
        "cookies": [],
        "score": 100,
        "grade": "A+",
        "error": None,
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "WebScout-Security-Scanner/1.0"})
        response = urllib.request.urlopen(req, timeout=timeout)
        result["status_code"] = response.status
        headers = dict(response.headers)
        result["headers"] = headers

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        headers = dict(e.headers)
        result["headers"] = headers
    except Exception as e:
        result["error"] = str(e)
        return result

    headers_lower = {k.lower(): v for k, v in headers.items()}

    # ── Check security headers ──
    for header_name, meta in SECURITY_HEADERS.items():
        found_key = next((k for k in headers_lower if k == header_name.lower()), None)
        if not found_key:
            result["missing_headers"].append({
                "header": header_name,
                "severity": meta["severity"],
                "description": meta["description"],
                "recommended": meta.get("recommended", ""),
            })
            severity_penalty = {"HIGH": 15, "MEDIUM": 10, "LOW": 5, "INFO": 2}
            result["score"] -= severity_penalty.get(meta["severity"], 0)
        else:
            value = headers_lower[found_key]
            result["present_headers"].append({"header": header_name, "value": value})

            # Deep value checks
            if "checks" in meta:
                for directive, msg in meta["checks"]:
                    if directive.lower() not in value.lower():
                        result["header_issues"].append({
                            "header": header_name,
                            "severity": "LOW",
                            "issue": msg,
                            "value": value,
                        })

            if "dangerous_values" in meta:
                for dangerous, msg in meta["dangerous_values"]:
                    if dangerous.lower() in value.lower():
                        result["header_issues"].append({
                            "header": header_name,
                            "severity": "MEDIUM",
                            "issue": msg,
                            "value": value,
                        })
                        result["score"] -= 5

            if "valid_values" in meta:
                if not any(v.lower() == value.strip().lower() for v in meta["valid_values"]):
                    result["header_issues"].append({
                        "header": header_name,
                        "severity": "LOW",
                        "issue": f"Unexpected value '{value}' (valid: {', '.join(meta['valid_values'])})",
                        "value": value,
                    })

    # ── Check info-leaking headers ──
    for lh in LEAKING_HEADERS:
        found = next((k for k in headers_lower if k == lh.lower()), None)
        if found:
            result["leaking_headers"].append({
                "header": lh,
                "value": headers_lower[found],
                "issue": f"Reveals server technology — aids fingerprinting",
            })
            result["score"] -= 3

    # ── Cookie analysis ──
    set_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in set_cookies:
        cookie_issues = []
        name = cookie.split("=")[0].strip()
        cookie_lower = cookie.lower()

        if "secure" not in cookie_lower:
            cookie_issues.append("Missing Secure flag — cookie sent over HTTP")
        if "httponly" not in cookie_lower:
            cookie_issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
        if "samesite" not in cookie_lower:
            cookie_issues.append("Missing SameSite attribute — CSRF risk")
        elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
            cookie_issues.append("SameSite=None requires Secure flag")

        # Check if cookie value looks like a JWT
        parts = cookie.split("=", 1)
        if len(parts) == 2:
            val = parts[1].split(";")[0].strip()
            jwt_pattern = r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'
            if re.match(jwt_pattern, val) and len(val) > 50:
                jwt_analysis = analyze_jwt(val)
                result["jwt_findings"].append({
                    "source": f"Cookie: {name}",
                    "token_preview": val[:30] + "...",
                    "analysis": jwt_analysis,
                })

        result["cookies"].append({"name": name, "issues": cookie_issues})
        result["score"] -= len(cookie_issues) * 3

    # ── Check Authorization header responses for JWT ──
    auth_header = headers_lower.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        jwt_analysis = analyze_jwt(token)
        result["jwt_findings"].append({
            "source": "Authorization header",
            "token_preview": token[:30] + "...",
            "analysis": jwt_analysis,
        })

    result["score"] = max(0, min(100, result["score"]))
    result["grade"] = score_to_grade(result["score"])
    return result


def score_to_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


# ─── Output Formatting ────────────────────────────────────────────────────────
def severity_color(severity: str) -> str:
    return {
        "CRITICAL": RED + BOLD,
        "HIGH":     RED,
        "MEDIUM":   YELLOW,
        "LOW":      CYAN,
        "INFO":     DIM,
    }.get(severity.upper(), RESET)


def print_results(result: dict, verbose: bool = False):
    if result.get("error"):
        print(f"\n{RED}[ERROR]{RESET} {result['error']}")
        return

    grade_color = GREEN if result["grade"] in ("A+", "A") else YELLOW if result["grade"] in ("B", "C") else RED

    print(f"\n{'─'*60}")
    print(f"  {BOLD}Target:{RESET}  {result['url']}")
    print(f"  {BOLD}Status:{RESET}  {result['status_code']}")
    print(f"  {BOLD}Scanned:{RESET} {result['timestamp']}")
    print(f"  {BOLD}Score:{RESET}   {grade_color}{result['score']}/100  [{result['grade']}]{RESET}")
    print(f"{'─'*60}")

    # Missing headers
    if result["missing_headers"]:
        print(f"\n{BOLD}🚨 Missing Security Headers ({len(result['missing_headers'])}){RESET}")
        for h in sorted(result["missing_headers"], key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])):
            sc = severity_color(h["severity"])
            print(f"  {sc}[{h['severity']}]{RESET}  {BOLD}{h['header']}{RESET}")
            print(f"           {DIM}{h['description']}{RESET}")
            print(f"           Recommended: {GREEN}{h['recommended']}{RESET}")
    else:
        print(f"\n{GREEN}✅ All security headers present!{RESET}")

    # Header value issues
    if result["header_issues"]:
        print(f"\n{BOLD}⚠️  Header Configuration Issues ({len(result['header_issues'])}){RESET}")
        for issue in result["header_issues"]:
            sc = severity_color(issue["severity"])
            print(f"  {sc}[{issue['severity']}]{RESET}  {issue['header']}")
            print(f"           {issue['issue']}")
            print(f"           Current: {DIM}{issue['value'][:80]}{RESET}")

    # Leaking headers
    if result["leaking_headers"]:
        print(f"\n{BOLD}🔍 Information Disclosure ({len(result['leaking_headers'])}){RESET}")
        for lh in result["leaking_headers"]:
            print(f"  {YELLOW}[INFO]{RESET}  {lh['header']}: {DIM}{lh['value']}{RESET}")

    # Cookie issues
    cookie_issues = [c for c in result["cookies"] if c["issues"]]
    if cookie_issues:
        print(f"\n{BOLD}🍪 Cookie Issues ({len(cookie_issues)}){RESET}")
        for c in cookie_issues:
            print(f"  {YELLOW}[MEDIUM]{RESET}  {c['name']}")
            for issue in c["issues"]:
                print(f"             • {issue}")

    # JWT findings
    if result["jwt_findings"]:
        print(f"\n{BOLD}🔑 JWT Analysis ({len(result['jwt_findings'])}){RESET}")
        for finding in result["jwt_findings"]:
            print(f"\n  Source: {CYAN}{finding['source']}{RESET}")
            analysis = finding["analysis"]
            if "error" in analysis:
                print(f"  {RED}Error: {analysis['error']}{RESET}")
                continue
            if "header" in analysis:
                h = analysis["header"]
                print(f"  Algorithm: {BOLD}{h.get('alg','?')}{RESET}  |  Type: {h.get('typ','?')}")
            if "payload" in analysis:
                p = analysis["payload"]
                if "sub" in p:  print(f"  Subject:   {p['sub']}")
                if "iss" in p:  print(f"  Issuer:    {p['iss']}")
                if "exp" in p:
                    exp_dt = datetime.fromtimestamp(p["exp"], tz=timezone.utc)
                    print(f"  Expires:   {exp_dt.isoformat()}")
            for severity, msg in analysis.get("issues", []):
                sc = severity_color(severity)
                print(f"  {sc}[{severity}]{RESET} {msg}")

    print(f"\n{'─'*60}\n")


def export_json(result: dict, path: str):
    with open(path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"{GREEN}[+]{RESET} JSON report saved: {path}")


def export_markdown(result: dict, path: str):
    lines = [
        f"# WebScout Report: {result['url']}",
        f"\n**Scanned:** {result['timestamp']}  ",
        f"**Status:** {result['status_code']}  ",
        f"**Score:** {result['score']}/100 [{result['grade']}]\n",
        "---\n",
    ]

    if result["missing_headers"]:
        lines.append("## 🚨 Missing Security Headers\n")
        lines.append("| Header | Severity | Description | Recommended |")
        lines.append("|--------|----------|-------------|-------------|")
        for h in result["missing_headers"]:
            lines.append(f"| `{h['header']}` | **{h['severity']}** | {h['description']} | `{h['recommended']}` |")

    if result["header_issues"]:
        lines.append("\n## ⚠️ Header Configuration Issues\n")
        for i in result["header_issues"]:
            lines.append(f"- **[{i['severity']}]** `{i['header']}`: {i['issue']}")

    if result["leaking_headers"]:
        lines.append("\n## 🔍 Information Disclosure\n")
        for lh in result["leaking_headers"]:
            lines.append(f"- `{lh['header']}: {lh['value']}`")

    if result["jwt_findings"]:
        lines.append("\n## 🔑 JWT Findings\n")
        for f_item in result["jwt_findings"]:
            lines.append(f"\n### {f_item['source']}")
            for sev, msg in f_item["analysis"].get("issues", []):
                lines.append(f"- **[{sev}]** {msg}")

    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"{GREEN}[+]{RESET} Markdown report saved: {path}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="WebScout — Web Security Header & JWT Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py https://example.com
  python scanner.py https://example.com --jwt eyJhbGc...
  python scanner.py https://example.com --output report.json
  python scanner.py https://example.com --output report.md
  python scanner.py https://example.com --verbose
        """
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--jwt", metavar="TOKEN", help="Manually provide a JWT token to analyze")
    parser.add_argument("--output", metavar="FILE", help="Save report to file (.json or .md)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    if args.no_color:
        global RED, GREEN, YELLOW, CYAN, BOLD, DIM, RESET
        RED = GREEN = YELLOW = CYAN = BOLD = DIM = RESET = ""

    print(f"{CYAN}[*]{RESET} Scanning: {BOLD}{args.url}{RESET}")
    result = scan_url(args.url, timeout=args.timeout)

    # Manual JWT override
    if args.jwt:
        jwt_analysis = analyze_jwt(args.jwt)
        result["jwt_findings"].append({
            "source": "CLI argument",
            "token_preview": args.jwt[:30] + "...",
            "analysis": jwt_analysis,
        })

    print_results(result, verbose=args.verbose)

    if args.output:
        if args.output.endswith(".json"):
            export_json(result, args.output)
        elif args.output.endswith(".md"):
            export_markdown(result, args.output)
        else:
            print(f"{YELLOW}[!]{RESET} Unknown format. Use .json or .md")

    # Exit code reflects security grade
    sys.exit(0 if result["grade"] in ("A+", "A") else 1)


if __name__ == "__main__":
    main()
