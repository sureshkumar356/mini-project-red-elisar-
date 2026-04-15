"""Passive web reconnaissance for the VulnShop demo.

This module is intentionally lightweight:
- Performs a single baseline GET to the target URL
- Extracts basic tech hints from response headers
- Probes a small set of common sensitive paths
- Records missing security headers and information-leaking headers

It is used by `vuln_checks.web_vuln_agent`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urljoin

import requests

logger = logging.getLogger("red_elisar.web_recon")


_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "Mitigates XSS by restricting allowed content sources",
    "Strict-Transport-Security": "Forces HTTPS to reduce MITM risk",
    "X-Frame-Options": "Mitigates clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Limits referrer leakage",
    "Permissions-Policy": "Restricts browser features",
}

_LEAKY_HEADERS = ["Server", "X-Powered-By", "X-App-Version"]

_DEFAULT_SENSITIVE_PATHS = [
    "/.env",
    "/backup",
    "/.git/config",
    "/admin",
    "/api/users",
    "/phpinfo.php",
    "/server-status",
    "/.htaccess",
    "/robots.txt",
    "/debug",
]


@dataclass
class WebReconAgent:
    """Collects passive recon signals from a target web app."""

    target_url: str
    timeout_s: float = 8.0

    def run(self) -> dict[str, Any]:
        parsed = urlparse(self.target_url)
        domain = parsed.netloc or parsed.path
        base_url = self.target_url.rstrip("/")

        out: dict[str, Any] = {
            "target_url": base_url,
            "domain": domain,
            "reachable": False,
            "status_code": None,
            "tech_stack": {"server": "Unknown", "language": "Unknown", "versions": {}},
            "ssl": {"enabled": parsed.scheme.lower() == "https", "valid": None, "error": None},
            "missing_security_headers": {},
            "leaked_info_headers": {},
            "exposed_paths": [],
            "cors": {"origin": None, "issues": []},
            "redirects": {"open_redirect_likely": False, "details": []},
            "error": None,
        }

        try:
            resp = requests.get(base_url, timeout=self.timeout_s, allow_redirects=True)
            out["reachable"] = True
            out["status_code"] = resp.status_code

            server = resp.headers.get("Server")
            powered = resp.headers.get("X-Powered-By")
            out["tech_stack"]["server"] = server or "Unknown"

            language = "Unknown"
            if powered:
                language = powered
            elif server and "werkzeug" in server.lower():
                language = "Python/Flask"
            out["tech_stack"]["language"] = language

            versions: dict[str, str] = {}
            if server:
                versions["server"] = server
            if powered:
                versions["x_powered_by"] = powered
            out["tech_stack"]["versions"] = versions

            for header, desc in _SECURITY_HEADERS.items():
                if header not in resp.headers:
                    out["missing_security_headers"][header] = desc

            for header in _LEAKY_HEADERS:
                if header in resp.headers and str(resp.headers.get(header, "")).strip():
                    out["leaked_info_headers"][header] = str(resp.headers.get(header, "")).strip()

            # CORS quick check
            acao = resp.headers.get("Access-Control-Allow-Origin")
            if acao:
                out["cors"]["origin"] = acao
                if acao.strip() == "*":
                    out["cors"]["issues"].append("Access-Control-Allow-Origin is wildcard (*)")

            # Probe a small set of sensitive paths (passive-ish GET)
            out["exposed_paths"] = self._probe_paths(base_url)

        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)
            logger.warning("Recon failed for %s: %s", base_url, e)

        # SSL validity (best-effort)
        if out["ssl"]["enabled"]:
            try:
                requests.get(base_url, timeout=self.timeout_s, verify=True)
                out["ssl"]["valid"] = True
            except Exception as e:  # noqa: BLE001
                out["ssl"]["valid"] = False
                out["ssl"]["error"] = str(e)
        else:
            out["ssl"]["valid"] = False

        return out

    def _probe_paths(self, base_url: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for path in _DEFAULT_SENSITIVE_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            try:
                resp = requests.get(url, timeout=self.timeout_s, allow_redirects=False)
                preview = ""
                try:
                    preview = (resp.text or "")[:200]
                except Exception:
                    preview = ""

                # record only interesting statuses to keep output small
                if resp.status_code < 400:
                    results.append(
                        {
                            "path": path,
                            "status_code": resp.status_code,
                            "size_bytes": len(resp.content or b""),
                            "content_preview": preview,
                        }
                    )
            except Exception:
                continue
        return results


if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    ap = argparse.ArgumentParser(description="Passive web reconnaissance (Red ELISAR)")
    ap.add_argument("url", help="Target URL, e.g. http://127.0.0.1:5000")
    ap.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    args = ap.parse_args()

    data = WebReconAgent(args.url, timeout_s=args.timeout).run()
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
