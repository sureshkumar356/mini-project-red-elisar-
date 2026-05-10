"""
targeted_attack_scanner.py — Live Vulnerability Probe for Red ELISAR
=====================================================================
When a --scenario command is run with --target-url, this module:
  1. Reads keywords from the scenario text to detect the attack type
  2. Sends real HTTP probes to the target URL
  3. Returns confirmed vulnerability evidence for the MD report

Supported attack types (auto-detected from scenario keywords):
  xss             → Reflected XSS at /greet?name=
  sql_injection   → SQLi at /search and /login
  exposed_files   → /.env, /backup, /api/users, /admin
  open_redirect   → /redirect?url=
  cors            → Access-Control-Allow-Origin: * header
  missing_headers → Missing CSP, X-Frame-Options, HSTS, etc.
  broken_auth     → Login with admin/admin123
  debug_mode      → Flask Werkzeug debugger enabled
  fingerprinting  → Server version leaking in headers
  mitm_http       → Running plain HTTP, no HTTPS / HSTS
  unauthenticated_api → /api/users accessible without auth
"""

import re
import logging
import requests
from urllib.parse import urljoin, urlparse

import config

logger = logging.getLogger("red_elisar.targeted_scanner")

# ── Severity mapping per attack type ───────────────────────────────
SEVERITY = {
    "sql_injection":       "CRITICAL",
    "debug_mode":          "CRITICAL",
    "broken_auth":         "HIGH",
    "exposed_files":       "HIGH",
    "unauthenticated_api": "HIGH",
    "xss":                 "HIGH",
    "open_redirect":       "MEDIUM",
    "cors":                "MEDIUM",
    "fingerprinting":      "MEDIUM",
    "missing_headers":     "MEDIUM",
    "mitm_http":           "MEDIUM",
}

# ── Keyword sets for auto-detection ───────────────────────────────
ATTACK_KEYWORDS = {
    "sql_injection":       ["sql injection", "sqli", "union select", "bypass authentication",
                            "login form", "database dump", "sqlite"],
    "xss":                 ["cross-site scripting", "xss", "javascript inject",
                            "session cookie", "script injection", "reflected xss", "stored xss"],
    "exposed_files":       ["exposed", ".env", "backup", "sensitive file", "configuration file",
                            "api key", "secret key", "hardcoded credential"],
    "unauthenticated_api": ["unauthenticated", "rest api", "api endpoint",
                            "insecure direct", "idor"],
    "open_redirect":       ["open redirect", "redirect", "url manipulation", "phishing redirect"],
    "cors":                ["cors", "cross-origin", "wildcard", "access-control"],
    "missing_headers":     ["clickjacking", "x-frame", "content-security-policy", "csp",
                            "missing header", "security header", "hsts"],
    "broken_auth":         ["broken authentication", "brute force", "hardcoded", "weak credential",
                            "admin password", "weak password", "rate limiting"],
    "debug_mode":          ["debug mode", "werkzeug", "remote code execution", "rce",
                            "python code", "debugger"],
    "fingerprinting":      ["fingerprint", "server version", "apache", "php version",
                            "software version", "cve", "banner grab"],
    "mitm_http":           ["man-in-the-middle", "mitm", "plain http", "no https",
                            "hsts", "tls", "ssl", "network interception"],
}

DEFAULT_TIMEOUT_S = float(getattr(config, "WEB_UI_PROBE_TIMEOUT_S", 5.0))


def detect_attack_type(scenario: str) -> str:
    """Detect attack type from scenario text via keyword matching."""
    s = scenario.lower()
    scores = {}
    for attack, keywords in ATTACK_KEYWORDS.items():
        scores[attack] = sum(1 for kw in keywords if kw in s)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "generic"


def probe_target(target_url: str, attack_type: str, timeout: float | None = None) -> dict:
    """
    Probe the target URL for the specified attack type.
    Returns a dict with: found, evidence, severity, endpoints_tested, recommendation
    """
    target_url = target_url.rstrip("/")
    probers = {
        "xss":                 _probe_xss,
        "sql_injection":       _probe_sqli,
        "exposed_files":       _probe_exposed_files,
        "unauthenticated_api": _probe_unauth_api,
        "open_redirect":       _probe_open_redirect,
        "cors":                _probe_cors,
        "missing_headers":     _probe_missing_headers,
        "broken_auth":         _probe_broken_auth,
        "debug_mode":          _probe_debug_mode,
        "fingerprinting":      _probe_fingerprinting,
        "mitm_http":           _probe_mitm_http,
        "generic":             _probe_generic,
    }
    probe_fn  = probers.get(attack_type, _probe_generic)
    timeout_s = float(timeout) if timeout is not None else DEFAULT_TIMEOUT_S
    result    = probe_fn(target_url, timeout_s)
    result["attack_type"] = attack_type
    result["target_url"]  = target_url
    result["severity"]    = SEVERITY.get(attack_type, "MEDIUM")
    logger.info(f"[TargetedScanner] {attack_type} → found={result['found']}")
    return result


# ─── Individual Probers ───────────────────────────────────────────

def _probe_xss(base: str, timeout_s: float) -> dict:
    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
    ]
    endpoints_tested = []
    evidence = []

    xss_endpoints = [
        ("/greet", "name"),
        ("/search", "q"),
        ("/", "q"),
    ]

    for path, param in xss_endpoints:
        for payload in payloads:
            url = f"{base}{path}?{param}={payload}"
            endpoints_tested.append(url)
            try:
                r = requests.get(url, timeout=timeout_s, allow_redirects=True)
                if payload.lower() in r.text.lower() or "<script>" in r.text.lower():
                    evidence.append({
                        "url":        url,
                        "status":     r.status_code,
                        "payload":    payload,
                        "confirmed":  True,
                        "detail":     f"Payload reflected in response at {path}?{param}=",
                    })
                    break
            except Exception:
                continue

    found = len(evidence) > 0
    return {
        "found":             found,
        "endpoints_tested":  endpoints_tested[:6],
        "evidence":          evidence,
        "vuln_description":  "Reflected XSS: server returns user-supplied JavaScript unescaped, allowing session hijacking.",
        "manual_test":       f"{base}/greet?name=<script>alert(document.cookie)</script>",
        "recommendation":    "Escape all user input on output (use Jinja2 autoescaping). Add Content-Security-Policy header.",
    }


def _probe_sqli(base: str, timeout_s: float) -> dict:
    payloads = [
        ("' OR '1'='1", "shows all results — authentication bypass"),
        ("' OR '1'='1'--", "comments out password check"),
        ("' UNION SELECT 1,2,3,4--", "UNION-based data extraction"),
    ]
    evidence  = []
    endpoints = [("/search", "q", "GET"), ("/login", "username", "POST")]
    endpoints_tested = []

    # Test GET /search
    for payload, meaning in payloads[:2]:
        url = f"{base}/search?q={payload}"
        endpoints_tested.append(url)
        try:
            r = requests.get(url, timeout=timeout_s)
            if r.status_code == 200 and len(r.text) > 500:
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   payload,
                    "confirmed": True,
                    "detail":    f"SQLi at /search — {meaning}. Response length: {len(r.text)} bytes",
                })
        except Exception:
            pass

    # Test POST /login
    try:
        r = requests.post(
            f"{base}/login",
            data={"username": "' OR '1'='1'--", "password": "x"},
            timeout=timeout_s,
            allow_redirects=False,
        )
        endpoints_tested.append(f"{base}/login [POST SQLi]")
        if r.status_code in (302, 200) and "admin" in r.text.lower():
            evidence.append({
                "url":       f"{base}/login",
                "status":    r.status_code,
                "payload":   "' OR '1'='1'-- (POST login)",
                "confirmed": True,
                "detail":    "SQL injection bypasses login authentication entirely",
            })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "SQL Injection: unsanitised user input is inserted directly into SQL queries, allowing auth bypass and data extraction.",
        "manual_test":       f"{base}/search?q=' OR '1'='1",
        "recommendation":    "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings.",
    }


def _probe_exposed_files(base: str, timeout_s: float) -> dict:
    sensitive_paths = [
        ("/.env",     "Environment file with API keys and secrets"),
        ("/backup",   "Database backup with all records"),
        ("/admin",    "Admin panel without authentication"),
        ("/api/users","User API exposing all passwords"),
        ("/robots.txt","robots.txt listing sensitive paths"),
        ("/.git",     "Git repository metadata"),
        ("/config",   "Configuration endpoint"),
    ]
    evidence         = []
    endpoints_tested = []

    for path, description in sensitive_paths:
        url = f"{base}{path}"
        endpoints_tested.append(url)
        try:
            r = requests.get(url, timeout=timeout_s)
            if r.status_code == 200:
                snippet = r.text[:200].replace("\n", " ")
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   "Direct GET request (no auth)",
                    "confirmed": True,
                    "detail":    f"{description} — accessible without authentication. Preview: {snippet}",
                })
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Sensitive File Exposure: configuration files, backups, and admin panels are publicly accessible without authentication.",
        "manual_test":       f"{base}/.env",
        "recommendation":    "Remove sensitive files from web root. Use server-level access controls. Never commit secrets to source code.",
    }


def _probe_unauth_api(base: str, timeout_s: float) -> dict:
    api_endpoints = [
        ("/api/users",    "User database with passwords"),
        ("/api/products", "Product data"),
        ("/admin",        "Admin panel"),
    ]
    evidence         = []
    endpoints_tested = []

    for path, desc in api_endpoints:
        url = f"{base}{path}"
        endpoints_tested.append(url)
        try:
            r = requests.get(url, timeout=timeout_s)
            if r.status_code == 200:
                has_sensitive = any(w in r.text.lower()
                                    for w in ["password", "email", "username", "secret", "token"])
                if has_sensitive:
                    evidence.append({
                        "url":       url,
                        "status":    r.status_code,
                        "payload":   "GET (no Authorization header)",
                        "confirmed": True,
                        "detail":    f"{desc} — returns sensitive data without any authentication",
                    })
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Unauthenticated API: sensitive endpoints accessible with no authentication, exposing user credentials and data.",
        "manual_test":       f"{base}/api/users",
        "recommendation":    "Require authentication (JWT/session) on all API endpoints. Apply role-based access control.",
    }


def _probe_open_redirect(base: str, timeout_s: float) -> dict:
    test_url         = f"{base}/redirect?url=http://evil-example.com"
    endpoints_tested = [test_url]
    evidence         = []
    try:
        r = requests.get(test_url, timeout=timeout_s, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if "evil-example.com" in loc or "http://" in loc:
                evidence.append({
                    "url":       test_url,
                    "status":    r.status_code,
                    "payload":   "url=http://evil-example.com",
                    "confirmed": True,
                    "detail":    f"Redirects to attacker-controlled URL: Location: {loc}",
                })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Open Redirect: the /redirect endpoint forwards users to any external URL without validation, enabling phishing.",
        "manual_test":       test_url,
        "recommendation":    "Validate redirect destinations against an allowlist. Reject or encode external URLs.",
    }


def _probe_cors(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    try:
        r = requests.get(
            base,
            timeout=timeout_s,
            headers={"Origin": "http://evil-attacker.com"},
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil-attacker.com" in acao:
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "Origin: http://evil-attacker.com",
                "confirmed": True,
                "detail":    f"Access-Control-Allow-Origin: {acao} — any origin allowed to read responses",
            })

        # Also check ACAO on API endpoint
        r2 = requests.get(
            f"{base}/api/users",
            timeout=timeout_s,
            headers={"Origin": "http://evil-attacker.com"},
        )
        acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
        if acao2 == "*":
            evidence.append({
                "url":       f"{base}/api/users",
                "status":    r2.status_code,
                "payload":   "Origin: http://evil-attacker.com",
                "confirmed": True,
                "detail":    f"API endpoint also has CORS wildcard: {acao2}",
            })
    except Exception:
        pass

    endpoints_tested.append(f"{base}/api/users")
    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "CORS Misconfiguration: wildcard Access-Control-Allow-Origin allows any website to read API responses.",
        "manual_test":       f"curl -H 'Origin: http://evil.com' -I {base}",
        "recommendation":    "Restrict Access-Control-Allow-Origin to specific trusted domains only. Never use * on authenticated endpoints.",
    }


def _probe_missing_headers(base: str, timeout_s: float) -> dict:
    required = {
        "Content-Security-Policy":    "Prevents XSS attacks",
        "X-Frame-Options":            "Prevents clickjacking",
        "Strict-Transport-Security":  "Enforces HTTPS",
        "X-Content-Type-Options":     "Prevents MIME sniffing",
        "Referrer-Policy":            "Controls referrer leakage",
        "Permissions-Policy":         "Controls browser features",
    }
    evidence         = []
    endpoints_tested = [base]
    try:
        r = requests.get(base, timeout=timeout_s)
        for header, purpose in required.items():
            if header not in r.headers:
                evidence.append({
                    "url":       base,
                    "status":    r.status_code,
                    "payload":   f"Missing: {header}",
                    "confirmed": True,
                    "detail":    f"Header '{header}' absent — {purpose}",
                })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  f"Missing Security Headers: {len(evidence)} required HTTP security headers are absent.",
        "manual_test":       f"curl -I {base}",
        "recommendation":    "Add CSP, X-Frame-Options: DENY, Strict-Transport-Security, X-Content-Type-Options: nosniff to all responses.",
    }


def _probe_broken_auth(base: str, timeout_s: float) -> dict:
    credentials = [
        ("admin", "admin123"),
        ("admin", "admin"),
        ("admin", "password"),
        ("root",  "root"),
    ]
    evidence         = []
    endpoints_tested = []

    for user, pwd in credentials:
        url = f"{base}/login"
        endpoints_tested.append(f"{url} [{user}:{pwd}]")
        try:
            r = requests.post(
                url,
                data={"username": user, "password": pwd},
                timeout=timeout_s,
                allow_redirects=True,
            )
            if (r.status_code == 200 and
                    ("welcome" in r.text.lower() or
                     "dashboard" in r.text.lower() or
                     "admin" in r.text.lower() or
                     "logout" in r.text.lower())):
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   f"username={user}&password={pwd}",
                    "confirmed": True,
                    "detail":    f"Login succeeded with weak credentials {user}/{pwd} — no rate limiting or CAPTCHA",
                })
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Broken Authentication: hardcoded/default credentials accepted with no lockout or rate limiting.",
        "manual_test":       f"curl -X POST {base}/login -d 'username=admin&password=admin123'",
        "recommendation":    "Remove hardcoded credentials. Enforce strong passwords, account lockout after 5 failed attempts, and multi-factor authentication.",
    }


def _probe_debug_mode(base: str, timeout_s: float) -> dict:
    test_url         = f"{base}/error_test"
    endpoints_tested = [test_url, f"{base}/nonexistent-page-12345"]
    evidence         = []

    for url in endpoints_tested:
        try:
            r = requests.get(url, timeout=timeout_s)
            body = r.text.lower()
            if any(sig in body for sig in
                   ["traceback", "werkzeug", "debugger", "interactive console",
                    "pin:", "python", "flask"]):
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   "Direct GET request",
                    "confirmed": True,
                    "detail":    "Flask/Werkzeug debug mode active — full Python stack traces exposed, interactive console possible",
                })
                break
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Debug Mode Enabled: Flask is running with debug=True exposing stack traces and potentially an interactive Python console.",
        "manual_test":       test_url,
        "recommendation":    "Set debug=False in production. Use environment variables: FLASK_ENV=production. Never expose stack traces to users.",
    }


def _probe_fingerprinting(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    try:
        r    = requests.get(base, timeout=timeout_s)
        srv  = r.headers.get("Server", "")
        xpow = r.headers.get("X-Powered-By", "")
        if any(c.isdigit() for c in srv):   # version number in Server
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HTTP response headers",
                "confirmed": True,
                "detail":    f"Server: {srv} — version exposed, attackers can look up known CVEs",
            })
        if xpow:
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HTTP response headers",
                "confirmed": True,
                "detail":    f"X-Powered-By: {xpow} — technology stack exposed",
            })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Server Fingerprinting: HTTP headers reveal exact server software version, enabling targeted CVE exploitation.",
        "manual_test":       f"curl -I {base}",
        "recommendation":    "Remove or mask Server and X-Powered-By headers in server configuration.",
    }


def _probe_mitm_http(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    parsed           = urlparse(base)
    try:
        r    = requests.get(base, timeout=timeout_s)
        hsts = r.headers.get("Strict-Transport-Security", "")
        if parsed.scheme == "http":
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HTTP scheme check",
                "confirmed": True,
                "detail":    "Site runs over plain HTTP — all traffic (cookies, passwords) sent in cleartext",
            })
        if not hsts:
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HSTS header check",
                "confirmed": True,
                "detail":    "Missing Strict-Transport-Security header — browsers won't enforce HTTPS",
            })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "No HTTPS / Missing HSTS: all traffic is transmitted unencrypted, vulnerable to network interception.",
        "manual_test":       f"Check: {base} (uses http:// not https://)",
        "recommendation":    "Deploy a TLS certificate (Let's Encrypt is free). Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    }


def _probe_generic(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    try:
        r = requests.get(base, timeout=timeout_s)
        evidence.append({
            "url":       base,
            "status":    r.status_code,
            "payload":   "GET request",
            "confirmed": False,
            "detail":    f"Target reachable — HTTP {r.status_code}. Run specific attack probes for detailed findings.",
        })
    except Exception as e:
        evidence.append({"url": base, "confirmed": False, "detail": str(e)})

    return {
        "found":             False,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Generic probe — target is reachable.",
        "manual_test":       base,
        "recommendation":    "Run specific attack scenario commands for targeted vulnerability detection.",
    }


def format_probe_result_markdown(result: dict) -> str:
    """Format probe results as a Markdown section for injection into the report."""
    found     = result.get("found", False)
    atype     = result.get("attack_type", "unknown").replace("_", " ").title()
    sev       = result.get("severity", "MEDIUM")
    evidence  = result.get("evidence", [])
    endpoints = result.get("endpoints_tested", [])
    icons     = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}
    icon      = icons.get(sev, "[UNK]")

    lines = [
        "## Live Vulnerability Verification",
        "",
        f"> **Attack Type Probed:** {atype}",
        f"> **Target:** `{result.get('target_url', 'N/A')}`",
        f"> **Status:** {'[OK] VULNERABILITY CONFIRMED' if found else '[WARN] Not confirmed (may need manual check)'}",
        f"> **Severity:** {icon} {sev}",
        "",
    ]

    if found:
        lines += [
            "### Confirmed Findings",
            "",
        ]
        for i, ev in enumerate(evidence, 1):
            if ev.get("confirmed"):
                lines += [
                    f"#### Finding {i}",
                    f"- **URL Tested:** `{ev.get('url', 'N/A')}`",
                    f"- **HTTP Status:** {ev.get('status', 'N/A')}",
                    f"- **Payload/Method:** `{ev.get('payload', 'N/A')}`",
                    f"- **Evidence:** {ev.get('detail', 'N/A')}",
                    "",
                ]
    else:
        lines += [
            "### Probe Results",
            "",
            f"No automatic confirmation - the vulnerability may require manual testing.",
            f"**Manual Test URL:** `{result.get('manual_test', 'N/A')}`",
            "",
        ]

    lines += [
        "### Endpoints Probed",
        "",
    ]
    for ep in endpoints[:8]:
        lines.append(f"- `{ep}`")

    lines += [
        "",
        f"**Vulnerability Description:** {result.get('vuln_description', 'N/A')}",
        "",
        f"**Recommendation:** {result.get('recommendation', 'N/A')}",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)
