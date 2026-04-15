"""
vuln_scanner.py — Vulnerability Analysis for Red ELISAR
========================================================
Takes reconnaissance data from WebReconAgent and produces a
structured list of vulnerabilities, each with:
  - type, detail, severity, cwe_id, mitre_hint, recommendation

Severity scale: CRITICAL > HIGH > MEDIUM > LOW > INFO

Usage (standalone test):
  python vuln_scanner.py http://127.0.0.1:5000
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger("red_elisar.vuln_scanner")

# ─── Severity Definitions ─────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Header → (severity, CWE, MITRE technique hint, recommendation)
HEADER_VULN_MAP = {
    "Content-Security-Policy": (
        "HIGH",
        "CWE-79",
        "T1059.007",   # Command and Scripting Interpreter: JavaScript
        "Add a Content-Security-Policy header to whitelist trusted content sources. "
        "Example: Content-Security-Policy: default-src 'self'"
    ),
    "Strict-Transport-Security": (
        "HIGH",
        "CWE-311",
        "T1557",       # Adversary-in-the-Middle
        "Enable HSTS to force HTTPS. "
        "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "CWE-1021",
        "T1185",       # Browser Session Hijacking (via clickjacking)
        "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks."
    ),
    "X-Content-Type-Options": (
        "MEDIUM",
        "CWE-430",
        "T1204",       # User Execution
        "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing."
    ),
    "Referrer-Policy": (
        "LOW",
        "CWE-200",
        "T1592",       # Gather Victim Host Info
        "Add Referrer-Policy: no-referrer or strict-origin to limit referrer leakage."
    ),
    "Permissions-Policy": (
        "LOW",
        "CWE-693",
        "T1562",       # Impair Defenses
        "Add Permissions-Policy to restrict browser features (camera, mic, geolocation)."
    ),
}

# Sensitive paths → (severity, CWE, MITRE hint, recommendation)
SENSITIVE_PATH_MAP = {
    "/.env":         ("CRITICAL", "CWE-312", "T1552", "Remove .env from web root. Never expose configuration files publicly."),
    "/backup":       ("CRITICAL", "CWE-312", "T1552", "Remove backup files. Store backups outside the web root."),
    "/.git/config":  ("CRITICAL", "CWE-312", "T1213", "Block .git directory access via web server config."),
    "/admin":        ("HIGH",     "CWE-284", "T1078", "Protect admin routes with authentication and authorization."),
    "/api/users":    ("CRITICAL", "CWE-306", "T1078", "Add authentication to all API endpoints exposing user data."),
    "/phpinfo.php":  ("HIGH",     "CWE-200", "T1592", "Remove phpinfo.php from production environments."),
    "/server-status":("MEDIUM",  "CWE-200", "T1592", "Disable Apache server-status or restrict by IP."),
    "/.htaccess":    ("MEDIUM",  "CWE-200", "T1592", "Block .htaccess access via web server configuration."),
    "/robots.txt":   ("INFO",    "CWE-200", "T1592", "Avoid listing sensitive paths in robots.txt (security by obscurity is not security)."),
    "/debug":        ("CRITICAL", "CWE-94",  "T1190", "Disable debug endpoints in production."),
}

# Leaky header patterns → (severity, CWE, MITRE hint, recommendation)
LEAKY_HEADER_RULES = {
    "Server":       ("MEDIUM", "CWE-200", "T1592", "Remove or genericize the Server header to hide version information."),
    "X-Powered-By": ("MEDIUM", "CWE-200", "T1592", "Remove X-Powered-By header to avoid exposing technology stack."),
    "X-App-Version":("LOW",    "CWE-200", "T1592", "Remove X-App-Version to prevent version enumeration."),
}


class VulnerabilityScanner:
    """
    Analyzes recon data to identify vulnerabilities and
    map them to MITRE ATT&CK technique hints.
    """

    def __init__(self, recon_data: dict):
        self.data           = recon_data
        self.vulnerabilities = []
        self.scan_time       = datetime.now(timezone.utc).isoformat()

    # ─── Main Entry Point ────────────────────────────────────────
    def scan(self) -> dict:
        """Run all checks and return a structured vulnerability report."""
        logger.info(f"[Scanner] Starting vulnerability scan for: {self.data.get('target_url')}")

        if not self.data.get("reachable"):
            return {"error": "Target not reachable", "vulnerabilities": []}

        self._check_missing_headers()
        self._check_leaky_headers()
        self._check_exposed_paths()
        self._check_cors()
        self._check_open_redirect()
        self._check_ssl()
        self._check_debug_mode()
        self._check_http_only()

        # Sort by severity
        self.vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v["severity"], 99))

        stats = {
            "CRITICAL": sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL"),
            "HIGH":     sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH"),
            "MEDIUM":   sum(1 for v in self.vulnerabilities if v["severity"] == "MEDIUM"),
            "LOW":      sum(1 for v in self.vulnerabilities if v["severity"] == "LOW"),
            "INFO":     sum(1 for v in self.vulnerabilities if v["severity"] == "INFO"),
        }

        logger.info(
            f"[Scanner] Found {len(self.vulnerabilities)} vulnerabilities — "
            f"CRITICAL:{stats['CRITICAL']} HIGH:{stats['HIGH']} "
            f"MEDIUM:{stats['MEDIUM']} LOW:{stats['LOW']}"
        )

        return {
            "target_url":      self.data.get("target_url"),
            "scan_timestamp":  self.scan_time,
            "total_vulns":     len(self.vulnerabilities),
            "severity_counts": stats,
            "overall_risk":    self._calculate_overall_risk(stats),
            "vulnerabilities": self.vulnerabilities,
        }

    # ─── Check: Missing Security Headers ────────────────────────
    def _check_missing_headers(self):
        missing = self.data.get("missing_security_headers", {})
        for header, description in missing.items():
            if header in HEADER_VULN_MAP:
                severity, cwe, mitre_hint, rec = HEADER_VULN_MAP[header]
                self._add_vuln(
                    vuln_type  = "Missing Security Header",
                    detail     = f"HTTP header '{header}' is not set — {description}",
                    severity   = severity,
                    cwe_id     = cwe,
                    mitre_hint = mitre_hint,
                    recommendation = rec,
                    evidence   = f"Response header '{header}': not present",
                )

    # ─── Check: Information Leakage via Headers ──────────────────
    def _check_leaky_headers(self):
        leaked = self.data.get("leaked_info_headers", {})
        for header, value in leaked.items():
            if header in LEAKY_HEADER_RULES:
                severity, cwe, mitre_hint, rec = LEAKY_HEADER_RULES[header]
                self._add_vuln(
                    vuln_type  = "Information Disclosure (HTTP Header)",
                    detail     = f"Header '{header}' exposes technology details: '{value}'",
                    severity   = severity,
                    cwe_id     = cwe,
                    mitre_hint = mitre_hint,
                    recommendation = rec,
                    evidence   = f"{header}: {value}",
                )

    # ─── Check: Sensitive Exposed Paths ─────────────────────────
    def _check_exposed_paths(self):
        for path_info in self.data.get("exposed_paths", []):
            path   = path_info["path"]
            status = path_info["status_code"]
            mapped = SENSITIVE_PATH_MAP.get(path)

            if mapped:
                severity, cwe, mitre_hint, rec = mapped
            else:
                severity, cwe, mitre_hint, rec = (
                    "MEDIUM", "CWE-200", "T1592",
                    f"Restrict access to {path} or remove it from the web root."
                )

            self._add_vuln(
                vuln_type  = "Exposed Sensitive Resource",
                detail     = f"Sensitive path '{path}' is publicly accessible (HTTP {status})",
                severity   = severity,
                cwe_id     = cwe,
                mitre_hint = mitre_hint,
                recommendation = rec,
                evidence   = f"GET {path} → {status} ({path_info['size_bytes']} bytes)",
                extra      = {"preview": path_info.get("content_preview", "")[:100]},
            )

    # ─── Check: CORS Misconfiguration ────────────────────────────
    def _check_cors(self):
        cors = self.data.get("cors", {})
        for issue in cors.get("issues", []):
            self._add_vuln(
                vuln_type  = "CORS Misconfiguration",
                detail     = issue,
                severity   = "HIGH",
                cwe_id     = "CWE-942",
                mitre_hint = "T1557",   # Adversary-in-the-Middle
                recommendation = (
                    "Replace 'Access-Control-Allow-Origin: *' with specific allowed origins. "
                    "Never use wildcard CORS for authenticated endpoints."
                ),
                evidence   = f"Access-Control-Allow-Origin: {cors.get('origin', '*')}",
            )

    # ─── Check: Open Redirect ─────────────────────────────────────
    def _check_open_redirect(self):
        redirects = self.data.get("redirects", {})
        if redirects.get("open_redirect_likely"):
            for detail in redirects.get("details", []):
                self._add_vuln(
                    vuln_type  = "Open Redirect",
                    detail     = f"URL parameter causes redirect to external site: {detail.get('redirects_to')}",
                    severity   = "MEDIUM",
                    cwe_id     = "CWE-601",
                    mitre_hint = "T1204",   # User Execution (phishing link)
                    recommendation = (
                        "Validate and whitelist redirect destinations. "
                        "Never redirect to user-supplied external URLs."
                    ),
                    evidence   = f"GET {detail.get('test_url')} → 302 → {detail.get('redirects_to')}",
                )

    # ─── Check: SSL/TLS ──────────────────────────────────────────
    def _check_ssl(self):
        ssl = self.data.get("ssl", {})
        if not ssl.get("enabled"):
            self._add_vuln(
                vuln_type  = "No HTTPS / Plain HTTP",
                detail     = "Site is served over HTTP — all traffic is unencrypted",
                severity   = "CRITICAL",
                cwe_id     = "CWE-319",
                mitre_hint = "T1557",   # Adversary-in-the-Middle
                recommendation = (
                    "Enable HTTPS with a valid SSL/TLS certificate. "
                    "Use Let's Encrypt for free certificates."
                ),
                evidence   = f"URL scheme: http://",
            )
        elif not ssl.get("valid"):
            self._add_vuln(
                vuln_type  = "Invalid SSL Certificate",
                detail     = f"SSL certificate error: {ssl.get('error')}",
                severity   = "HIGH",
                cwe_id     = "CWE-295",
                mitre_hint = "T1557",
                recommendation = "Renew or correct the SSL certificate.",
                evidence   = ssl.get("error", ""),
            )

    # ─── Check: Debug Mode Active ────────────────────────────────
    def _check_debug_mode(self):
        indicators = self.data.get("debug_indicators", [])
        if indicators:
            self._add_vuln(
                vuln_type  = "Debug Mode Enabled",
                detail     = f"Application appears to be running in debug mode: {'; '.join(indicators)}",
                severity   = "CRITICAL",
                cwe_id     = "CWE-94",
                mitre_hint = "T1190",   # Exploit Public-Facing Application
                recommendation = (
                    "Disable debug mode in production. "
                    "Set DEBUG=False and FLASK_ENV=production. "
                    "Debug mode in Flask allows arbitrary code execution via the Werkzeug debugger."
                ),
                evidence   = str(indicators),
            )

    # ─── Check: HTTP site (no HSTS enforcement) ──────────────────
    def _check_http_only(self):
        if self.data.get("scheme") == "http" or self.data.get("target_url", "").startswith("http://"):
            # Already flagged in SSL check as CRITICAL
            pass

    # ─── Add Vulnerability ────────────────────────────────────────
    def _add_vuln(self, vuln_type, detail, severity, cwe_id,
                  mitre_hint, recommendation, evidence="", extra=None):
        self.vulnerabilities.append({
            "type":           vuln_type,
            "detail":         detail,
            "severity":       severity,
            "cwe_id":         cwe_id,
            "mitre_hint":     mitre_hint,   # Technique ID hint for MITRE mapper
            "recommendation": recommendation,
            "evidence":       evidence,
            **({"extra": extra} if extra else {}),
        })

    # ─── Calculate Overall Risk ───────────────────────────────────
    def _calculate_overall_risk(self, stats: dict) -> str:
        if stats["CRITICAL"] > 0:
            return "CRITICAL"
        elif stats["HIGH"] >= 2:
            return "HIGH"
        elif stats["HIGH"] >= 1 or stats["MEDIUM"] >= 3:
            return "MEDIUM"
        elif stats["MEDIUM"] > 0:
            return "LOW"
        return "INFO"


# ─── Standalone Test ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys, json, logging
    from web_recon import WebReconAgent

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    recon  = WebReconAgent(target).run()
    result = VulnerabilityScanner(recon).scan()
    print(json.dumps(result, indent=2, default=str))
