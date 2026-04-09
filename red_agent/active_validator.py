"""
active_validator.py — Safe Active Validation for Authorized Local Targets
==========================================================================
Performs non-destructive, proof-based checks to confirm common vulnerabilities.
This module is intentionally restricted to localhost targets.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

logger = logging.getLogger("red_elisar.active_validator")

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ActiveValidator:
    """Run safe validation checks against authorized localhost targets only."""

    def __init__(self, target_url: str, timeout: int = 8):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def run(self) -> dict:
        parsed = urlparse(self.target_url)
        host = (parsed.hostname or "").lower()
        if host not in LOCAL_HOSTS:
            raise ValueError(
                "Active validation is restricted to localhost targets only. "
                f"Refusing host: {host or 'unknown'}"
            )

        checks = [
            self._check_reflected_xss(),
            self._check_open_redirect(),
            self._check_sqli_indicator(),
            self._check_sensitive_paths(),
            self._check_debug_trace(),
        ]
        findings = [c for c in checks if c is not None]
        confirmed = sum(1 for f in findings if f["result"] == "confirmed")

        return {
            "enabled": True,
            "target": self.target_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_checks": len(checks),
            "confirmed_count": confirmed,
            "findings": findings,
            "mode": "safe-local-active-validation",
        }

    def _check_reflected_xss(self):
        payload = "<script>alert(1)</script>"
        path = "/greet"
        try:
            r = self.session.get(f"{self.target_url}{path}", params={"name": payload}, timeout=self.timeout)
            reflected = payload in r.text
            return {
                "name": "Reflected XSS",
                "path": f"{path}?name=<script>...",
                "result": "confirmed" if reflected else "not_confirmed",
                "evidence": "Payload reflected unsanitized in HTML response" if reflected else "No unsanitized reflection detected",
            }
        except Exception as e:
            logger.warning(f"[ActiveValidator] Reflected XSS check failed: {e}")
            return {
                "name": "Reflected XSS",
                "path": path,
                "result": "error",
                "evidence": str(e),
            }

    def _check_open_redirect(self):
        path = "/redirect"
        test_url = "http://example.com"
        try:
            r = self.session.get(
                f"{self.target_url}{path}",
                params={"url": test_url},
                timeout=self.timeout,
                allow_redirects=False,
            )
            location = r.headers.get("Location", "")
            confirmed = r.status_code in (301, 302, 303, 307, 308) and location.startswith("http")
            return {
                "name": "Open Redirect",
                "path": f"{path}?url=http://example.com",
                "result": "confirmed" if confirmed else "not_confirmed",
                "evidence": f"HTTP {r.status_code}, Location={location or 'N/A'}",
            }
        except Exception as e:
            logger.warning(f"[ActiveValidator] Open redirect check failed: {e}")
            return {
                "name": "Open Redirect",
                "path": path,
                "result": "error",
                "evidence": str(e),
            }

    def _check_sqli_indicator(self):
        path = "/search"
        sqli = "' OR '1'='1"
        try:
            r = self.session.get(f"{self.target_url}{path}", params={"q": sqli}, timeout=self.timeout)
            text = r.text.lower()
            indicator = (
                "admin@vuln-shop.local" in text
                or "alice@vuln-shop.local" in text
                or "bob@vuln-shop.local" in text
            )
            return {
                "name": "SQL Injection Indicator",
                "path": f"{path}?q=' OR '1'='1",
                "result": "confirmed" if indicator else "not_confirmed",
                "evidence": "User records appeared in search results" if indicator else "No user-record leakage pattern observed",
            }
        except Exception as e:
            logger.warning(f"[ActiveValidator] SQLi check failed: {e}")
            return {
                "name": "SQL Injection Indicator",
                "path": path,
                "result": "error",
                "evidence": str(e),
            }

    def _check_sensitive_paths(self):
        findings = []
        for p in ("/.env", "/backup", "/api/users"):
            try:
                r = self.session.get(f"{self.target_url}{p}", timeout=self.timeout)
                if r.status_code == 200:
                    findings.append(p)
            except Exception:
                continue

        return {
            "name": "Sensitive Resource Exposure",
            "path": " /.env, /backup, /api/users",
            "result": "confirmed" if findings else "not_confirmed",
            "evidence": f"Exposed paths: {', '.join(findings)}" if findings else "No listed sensitive paths returned HTTP 200",
        }

    def _check_debug_trace(self):
        path = "/error_test"
        try:
            r = self.session.get(f"{self.target_url}{path}", timeout=self.timeout)
            text = r.text.lower()
            trace = "zerodivisionerror" in text or "traceback" in text
            return {
                "name": "Debug Stack Trace Exposure",
                "path": path,
                "result": "confirmed" if trace else "not_confirmed",
                "evidence": "Stack trace markers detected in response" if trace else f"HTTP {r.status_code} without clear stack-trace markers",
            }
        except Exception as e:
            logger.warning(f"[ActiveValidator] Debug check failed: {e}")
            return {
                "name": "Debug Stack Trace Exposure",
                "path": path,
                "result": "error",
                "evidence": str(e),
            }
