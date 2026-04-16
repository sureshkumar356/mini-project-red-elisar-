"""Interactive Red Agent CLI entry point.

This runner composes existing modules from red_agent/ without changing
their core logic.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

# Optional parser; fallback regex parsing is used when bs4 is unavailable.
try:
    from bs4 import BeautifulSoup
except Exception:  # noqa: BLE001
    BeautifulSoup = None


# ── Bootstrap path/cwd exactly once ────────────────────────────────────────
PROJECT_DIR = Path(__file__).resolve().parent
AGENT_DIR = PROJECT_DIR / "red_agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))
os.chdir(AGENT_DIR)

import config
from llm.attack_chain_generator import AttackChainGenerator
from mappings.mitre_mapper import MITREMapper
from rag.chunking import chunk_techniques
from rag.mitre_parser import MITREParser
from rag.rag_engine import RAGEngine
from rag.vector_store_faiss import FAISSVectorStore
from reporting.report_generator import ReportGenerator
from vuln_checks.input_sanitizer import sanitize_scenario
from vuln_checks.live_vuln_checker import LiveVulnChecker
from vuln_checks.targeted_attack_scanner import detect_attack_type, probe_target
from vuln_checks.vuln_scanner import VulnerabilityScanner
from vuln_checks.web_recon import WebReconAgent

logger = logging.getLogger("red_elisar.run_cli")

COMMON_PATHS = [
    "/admin",
    "/login",
    "/register",
    "/api",
    "/api/users",
    "/search",
    "/redirect",
    "/debug",
    "/backup",
    "/.env",
    "/robots.txt",
    "/sitemap.xml",
]

ATTACK_FLOW_TACTICS = [
    "reconnaissance",
    "initial-access",
    "execution",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "exfiltration",
    "impact",
]

GENERIC_CONTEXT_TOKENS = {
    "http",
    "https",
    "www",
    "com",
    "net",
    "org",
    "url",
    "target",
    "application",
    "web",
    "vulnerability",
    "attack",
    "mitre",
    "technique",
    "endpoint",
}

TOOL_NOISE_KEYWORDS = {
    "agent tesla",
    "astaroth",
    "dridex",
    "emotet",
    "trickbot",
    "nation state",
    "apt",
}

WEB_TOOL_HINTS = {
    "web",
    "http",
    "https",
    "browser",
    "api",
    "cookie",
    "session",
    "credential",
    "password",
    "token",
    "shell",
    "proxy",
}

MALWARE_STYLE_KEYWORDS = {
    "malware",
    "adware",
    "ransomware",
    "trojan",
    "infostealer",
    "worm",
    "botnet",
}

WEB_TOOL_ALLOWLIST = {
    "sqlmap",
    "burp suite",
    "curl",
    "browser",
}

FORM_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
]

FORM_XSS_PAYLOADS = [
    "<script>alert('x')</script>",
    "\"><img src=x onerror=alert('x')>",
]

SQL_ERROR_PATTERNS = [
    r"sqlite",
    r"syntax error",
    r"unrecognized token",
    r"mysql",
    r"postgre",
    r"ORA-",
    r"database error",
]


def setup_logging() -> None:
    config.ensure_directories()
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(config.LOG_FILE, encoding="utf-8", mode="a"))
    except Exception:  # noqa: BLE001
        pass
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
        format=config.LOG_FORMAT,
        handlers=handlers,
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)


class RuntimeContext:
    """Lazy-loaded shared runtime components."""

    def __init__(self) -> None:
        self.store: FAISSVectorStore | None = None
        self.rag: RAGEngine | None = None
        self.mapper: MITREMapper | None = None
        self.generator: AttackChainGenerator | None = None
        self.mitre_db: MitreAttackDatabase | None = None

    def ensure_rag(self, force_reindex: bool = False) -> None:
        if self.store and self.rag and self.mapper and self.generator:
            return

        store = FAISSVectorStore()
        if not force_reindex and store.is_ready():
            print("\n[INFO] Loading existing FAISS index...")
            store.load()
        else:
            print("\n[INFO] Building FAISS index from MITRE ATT&CK bundle...")
            parser = MITREParser()
            techniques = parser.parse()
            chunks = chunk_techniques(techniques)
            store.index_chunks(chunks, force_reindex=force_reindex)
            print(f"[OK] Indexed {len(techniques)} techniques.")

        self.store = store
        self.rag = RAGEngine(store)
        self.mapper = MITREMapper(self.rag)
        self.generator = AttackChainGenerator(store)
        self.ensure_mitre_db()

    def ensure_mitre_db(self) -> None:
        if self.mitre_db is None:
            self.mitre_db = MitreAttackDatabase(config.MITRE_STIX_PATH)


class MitreAttackDatabase:
    """Minimal MITRE ATT&CK STIX reader for technique/tactic/tools enrichment."""

    def __init__(self, stix_path: Path):
        self.stix_path = stix_path
        self.technique_index: dict[str, dict[str, Any]] = {}
        self.technique_stix_to_external: dict[str, str] = {}
        self.software_index: dict[str, dict[str, str]] = {}
        self.tools_by_technique: dict[str, list[dict[str, str]]] = {}
        self.tactic_id_to_name: dict[str, str] = {}
        self.tactic_order: list[str] = []
        self._loaded = False
        self._load()

    def _load(self) -> None:
        self._loaded = True
        if not self.stix_path.exists():
            return
        try:
            bundle = json.loads(self.stix_path.read_text(encoding="utf-8"))
        except Exception:
            return

        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        software_types = {"tool", "malware"}

        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                self.tactic_id_to_name[obj.get("id", "")] = str(obj.get("name", "")).strip().lower()

        # Build tactic sequence from ATT&CK matrix ordering in STIX (no hardcoded stage order).
        for obj in objects:
            if obj.get("type") != "x-mitre-matrix":
                continue
            refs = obj.get("tactic_refs", [])
            ordered = []
            for ref in refs:
                nm = self.tactic_id_to_name.get(ref)
                if nm:
                    ordered.append(nm)
            if ordered:
                self.tactic_order = ordered
                break

        for obj in objects:
            otype = obj.get("type")
            if otype in software_types:
                self.software_index[obj.get("id", "")] = {
                    "name": obj.get("name", "Unknown Tool"),
                    "description": (obj.get("description", "") or "").strip(),
                }

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = ""
            for ref in obj.get("external_references", []):
                eid = str(ref.get("external_id", "")).strip()
                if eid.startswith("T"):
                    ext_id = eid
                    break
            if not ext_id:
                continue

            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    pname = str(phase.get("phase_name", "")).strip()
                    if pname:
                        tactics.append(pname)

            self.technique_index[ext_id] = {
                "technique_id": ext_id,
                "technique_name": obj.get("name", "Unknown Technique"),
                "description": (obj.get("description", "") or "").strip(),
                "tactics": sorted(set(tactics)),
                "stix_id": obj.get("id", ""),
            }
            self.technique_stix_to_external[obj.get("id", "")] = ext_id

        temp_tools: dict[str, dict[str, dict[str, str]]] = {}
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            target_ref = obj.get("target_ref", "")
            source_ref = obj.get("source_ref", "")
            technique_id = self.technique_stix_to_external.get(target_ref)
            software = self.software_index.get(source_ref)
            if not technique_id or not software:
                continue
            bucket = temp_tools.setdefault(technique_id, {})
            bucket[software.get("name", "Unknown Tool")] = software

        self.tools_by_technique = {
            tid: list(name_map.values()) for tid, name_map in temp_tools.items()
        }

    def get_technique(self, technique_id: str) -> dict[str, Any]:
        return self.technique_index.get(technique_id, {})

    def get_tools_for_technique(self, technique_id: str) -> list[dict[str, str]]:
        return list(self.tools_by_technique.get(technique_id, []))

    def tactic_rank(self, tactic: str) -> int:
        key = str(tactic or "").strip().lower()
        if key in self.tactic_order:
            return self.tactic_order.index(key)
        return 10_000


def normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("URL cannot be empty.")
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return raw.rstrip("/")


def same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc


def canonicalize(url: str) -> str:
    p = urlparse(url)
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", query, ""))


def parse_html_links_and_forms(base_url: str, html: str) -> tuple[set[str], list[dict[str, Any]]]:
    links: set[str] = set()
    forms: list[dict[str, Any]] = []

    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href", "")).strip()
            if not href or href.startswith(("javascript:", "mailto:", "#")):
                continue
            links.add(urljoin(base_url + "/", href))

        for form in soup.find_all("form"):
            action = str(form.get("action") or "").strip() or base_url
            method = str(form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(str(name))
            forms.append(
                {
                    "action": urljoin(base_url + "/", action),
                    "method": method,
                    "params": sorted(set(inputs)),
                }
            )
        return links, forms

    # Regex fallback for environments without bs4.
    for match in re.findall(r"href=[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE):
        href = match.strip()
        if href and not href.startswith(("javascript:", "mailto:", "#")):
            links.add(urljoin(base_url + "/", href))

    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, flags=re.IGNORECASE | re.DOTALL):
        form_attrs = match.group(1) or ""
        form_body = match.group(2) or ""

        method_m = re.search(r"\bmethod\s*=\s*[\"']?([^\"' >]+)", form_attrs, flags=re.IGNORECASE)
        action_m = re.search(r"\baction\s*=\s*[\"']?([^\"' >]+)", form_attrs, flags=re.IGNORECASE)

        method = (method_m.group(1) if method_m else "GET").upper()
        action = (action_m.group(1) if action_m else "").strip() or base_url

        params = sorted(
            {
                p.strip()
                for p in re.findall(
                    r"<(?:input|textarea|select)[^>]*\bname\s*=\s*[\"']?([^\"' >]+)",
                    form_body,
                    flags=re.IGNORECASE,
                )
                if p.strip()
            }
        )

        forms.append(
            {
                "action": urljoin(base_url + "/", action),
                "method": method,
                "params": params,
            }
        )

    return links, forms


def discover_attack_surface(base_url: str, max_pages: int = 30, timeout: int = 8) -> dict[str, Any]:
    """Discover routes dynamically via crawl + form detection + common-path probing."""
    session = requests.Session()
    visited: set[str] = set()
    discovered_routes: set[str] = set()
    discovered_forms: list[dict[str, Any]] = []
    params_by_route: dict[str, set[str]] = {}
    queue = deque([base_url])

    while queue and len(visited) < max_pages:
        current = canonicalize(queue.popleft())
        if current in visited:
            continue
        visited.add(current)

        try:
            resp = session.get(current, timeout=timeout, allow_redirects=True)
        except Exception:
            continue

        if resp.status_code >= 500:
            continue

        discovered_routes.add(canonicalize(resp.url))

        parsed = urlparse(resp.url)
        if parsed.query:
            params_by_route.setdefault(canonicalize(resp.url.split("?")[0]), set()).update(
                [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            )

        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "text/html" not in content_type:
            continue

        links, forms = parse_html_links_and_forms(resp.url, resp.text)
        for form in forms:
            form_action = canonicalize(form["action"])
            discovered_routes.add(form_action)
            discovered_forms.append(form)
            params_by_route.setdefault(form_action, set()).update(form.get("params", []))

        for candidate in links:
            if not candidate.startswith(("http://", "https://")):
                continue
            if same_host(base_url, candidate):
                c = canonicalize(candidate)
                discovered_routes.add(c)
                if c not in visited:
                    queue.append(c)

    # Common path probing for additional reachable endpoints.
    for path in COMMON_PATHS:
        test_url = canonicalize(urljoin(base_url + "/", path.lstrip("/")))
        if test_url in discovered_routes:
            continue
        try:
            r = session.get(test_url, timeout=timeout, allow_redirects=False)
            if r.status_code < 400:
                discovered_routes.add(test_url)
        except Exception:
            continue

    route_params: dict[str, list[str]] = {
        route: sorted(v) for route, v in params_by_route.items() if v
    }

    return {
        "base_url": base_url,
        "visited_pages": sorted(visited),
        "routes": sorted(discovered_routes),
        "forms": discovered_forms,
        "params_by_route": route_params,
    }


def _merge_vulnerabilities(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged_by_key: dict[str, dict[str, Any]] = {}
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    def endpoint_key(v: dict[str, Any]) -> str:
        def normalize_endpoint(u: str) -> str:
            p = urlparse(u)
            if p.scheme and p.netloc:
                return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", "", ""))
            return u

        direct = str(v.get("endpoint", "")).strip()
        if direct:
            try:
                return normalize_endpoint(direct)
            except Exception:
                return direct
        inferred = _infer_affected_url(v, "")
        if inferred:
            try:
                return normalize_endpoint(inferred)
            except Exception:
                return inferred
        return "unknown-endpoint"

    def split_evidence(text: str) -> list[str]:
        if not text:
            return []
        return [p.strip() for p in re.split(r"\n|\s+\|\s+|\s*;\s*", text) if p.strip()]

    def normalize_type(vtype: str) -> str:
        t = (vtype or "Unknown").strip()
        t = re.sub(r"\s*\([^)]*\)", "", t).strip()
        low = t.lower()
        if "sql injection" in low:
            return "SQL Injection"
        if "cross-site scripting" in low or "xss" in low:
            return "Reflected Cross-Site Scripting (XSS)"
        if "sensitive file" in low or "exposed sensitive resource" in low:
            return "Exposed Sensitive Resource"
        return t

    for group in groups:
        for v in group:
            vtype = normalize_type(str(v.get("type", "Unknown")))
            endpoint = endpoint_key(v)
            key = f"{endpoint}::{vtype.lower()}"

            if key not in merged_by_key:
                base = dict(v)
                base["type"] = vtype
                base["endpoint"] = endpoint
                base["_evidence_items"] = split_evidence(str(v.get("evidence", "")))
                merged_by_key[key] = base
                continue

            curr = merged_by_key[key]
            evidence_items = curr.get("_evidence_items", [])
            for piece in split_evidence(str(v.get("evidence", ""))):
                if piece not in evidence_items:
                    evidence_items.append(piece)
            curr["_evidence_items"] = evidence_items

            curr_sev = severity_rank.get(str(curr.get("severity", "INFO")).upper(), 0)
            new_sev = severity_rank.get(str(v.get("severity", "INFO")).upper(), 0)
            if new_sev > curr_sev:
                curr["severity"] = v.get("severity", curr.get("severity"))

            if len(str(v.get("detail", ""))) > len(str(curr.get("detail", ""))):
                curr["detail"] = v.get("detail", curr.get("detail"))
            if not curr.get("mitre_hint") and v.get("mitre_hint"):
                curr["mitre_hint"] = v.get("mitre_hint")
            if len(str(v.get("recommendation", ""))) > len(str(curr.get("recommendation", ""))):
                curr["recommendation"] = v.get("recommendation", curr.get("recommendation"))

    merged: list[dict[str, Any]] = []
    for item in merged_by_key.values():
        evidence_items = item.pop("_evidence_items", [])
        if evidence_items:
            item["evidence"] = " | ".join(evidence_items)
        merged.append(item)
    return merged


def _probe_discovered_forms(base_url: str, forms: list[dict[str, Any]], timeout: int = 8) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    session = requests.Session()

    for form in forms:
        action = str(form.get("action", "")).strip()
        method = str(form.get("method", "GET")).upper().strip()
        params = [str(p).strip() for p in (form.get("params", []) or []) if str(p).strip()]
        if not action or not params:
            continue

        url = action if action.startswith(("http://", "https://")) else urljoin(base_url + "/", action)

        for param in params[:6]:
            for payload in FORM_SQLI_PAYLOADS:
                try:
                    data = {param: payload}
                    if method == "POST":
                        resp = session.post(url, data=data, timeout=timeout, allow_redirects=True)
                    else:
                        resp = session.get(url, params=data, timeout=timeout, allow_redirects=True)
                    body = (resp.text or "")[:8000].lower()
                    matched = next((pat for pat in SQL_ERROR_PATTERNS if re.search(pat, body, re.IGNORECASE)), None)
                    if matched:
                        key = f"sqli::{url}::{param}"
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            {
                                "type": "SQL Injection",
                                "detail": f"Form parameter '{param}' at {url} appears SQL injectable.",
                                "severity": "CRITICAL",
                                "cwe_id": "CWE-89",
                                "mitre_hint": "T1190",
                                "recommendation": "Use parameterized queries for all database access and validate input.",
                                "evidence": f"{method} {url} param={param} payload={payload} pattern={matched}",
                                "endpoint": url,
                                "confirmed_live": True,
                            }
                        )
                except Exception:
                    continue

            for payload in FORM_XSS_PAYLOADS:
                try:
                    data = {param: payload}
                    if method == "POST":
                        resp = session.post(url, data=data, timeout=timeout, allow_redirects=True)
                    else:
                        resp = session.get(url, params=data, timeout=timeout, allow_redirects=True)
                    body = resp.text or ""
                    if payload[:20] in body or "alert('x')" in body.lower():
                        key = f"xss::{url}::{param}"
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            {
                                "type": "Reflected Cross-Site Scripting (XSS)",
                                "detail": f"Form parameter '{param}' at {url} reflects unescaped input.",
                                "severity": "HIGH",
                                "cwe_id": "CWE-79",
                                "mitre_hint": "T1059.007",
                                "recommendation": "Apply output encoding and input validation for form parameters.",
                                "evidence": f"{method} {url} param={param} payload={payload}",
                                "endpoint": url,
                                "confirmed_live": True,
                            }
                        )
                except Exception:
                    continue

    return findings


def _severity_counts(vulns: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        sev = str(v.get("severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _overall_risk(counts: dict[str, int]) -> str:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if counts.get("HIGH", 0) >= 2:
        return "HIGH"
    if counts.get("HIGH", 0) >= 1 or counts.get("MEDIUM", 0) >= 3:
        return "MEDIUM"
    if counts.get("MEDIUM", 0) > 0:
        return "LOW"
    return "INFO"


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s|`]+", text or "")


def _infer_affected_url(vuln: dict[str, Any], target_url: str) -> str:
    urls = _extract_urls(str(vuln.get("evidence", "")))
    if urls:
        return urls[0]
    return target_url


def _split_recommendation_lines(recommendation: str) -> list[str]:
    text = (recommendation or "").strip()
    if not text:
        return ["Review and remediate this vulnerability according to secure coding standards."]
    chunks = [c.strip() for c in re.split(r"[.;]\s+", text) if c.strip()]
    return chunks or [text]


def _normalize_tools(raw_tools: list[dict[str, str]], max_items: int = 6) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for t in raw_tools:
        name = str(t.get("name", "Unknown Tool")).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        desc = str(t.get("description", "")).strip()
        if len(desc) > 220:
            desc = desc[:217] + "..."
        normalized.append({"name": name, "description": desc})
        if len(normalized) >= max_items:
            break
    return normalized


def _resolve_technique_record(
    technique: dict[str, Any],
    vuln: dict[str, Any],
    mitre_db: MitreAttackDatabase | None,
) -> dict[str, Any]:
    candidate_id = str(technique.get("technique_id") or vuln.get("mitre_hint") or "").strip()
    db_info = mitre_db.get_technique(candidate_id) if (mitre_db and candidate_id) else {}

    technique_id = db_info.get("technique_id") or candidate_id or "N/A"
    technique_name = db_info.get("technique_name") or str(technique.get("name") or "Unknown Technique")
    tactics = db_info.get("tactics") or technique.get("tactics") or []
    if isinstance(tactics, str):
        tactics = [tactics]

    tools = _normalize_tools(mitre_db.get_tools_for_technique(technique_id) if mitre_db else [])
    relevance = float(technique.get("relevance_score", 0) or 0)
    description = (
        str(technique.get("description_preview") or "").strip()
        or str(technique.get("document") or "").strip()
        or db_info.get("description", "")
        or str(vuln.get("detail", ""))
    )

    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactics": [str(t).strip().lower() for t in tactics if str(t).strip()],
        "tools": tools,
        "relevance": relevance,
        "description": description,
    }


def _vulnerability_rag_query(vuln: dict[str, Any]) -> str:
    vtype = str(vuln.get("type", "")).strip()
    detail = str(vuln.get("detail", "")).strip()
    evidence = str(vuln.get("evidence", "")).strip()
    endpoint = ""
    urls = _extract_urls(evidence)
    if urls:
        try:
            endpoint = urlparse(urls[0]).path or ""
        except Exception:
            endpoint = ""
    endpoint_text = endpoint if endpoint else "unknown endpoint"
    return (
        f"MITRE ATT&CK techniques for {vtype or 'web vulnerability'} in web application. "
        f"Details: {detail or 'no detail provided'}. "
        f"Evidence: {evidence or 'no evidence provided'}. "
        f"Endpoint: {endpoint_text}. "
        "Focus on web exploitation, data exposure, credential access, and realistic post-exploitation progression."
    )


def _tokenize_text(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}", (text or "").lower())}


def _text_overlap_score(a: str, b: str) -> float:
    ta = _tokenize_text(a)
    tb = _tokenize_text(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def _select_context_tools(
    tools: list[dict[str, str]],
    context_text: str,
    max_tools: int = 3,
) -> list[dict[str, str]]:
    if not tools:
        return []
    scored: list[tuple[float, dict[str, str]]] = []
    for t in tools:
        text = f"{t.get('name', '')} {t.get('description', '')}".strip()
        low = text.lower()
        overlap = _text_overlap_score(context_text, text)

        if any(k in low for k in MALWARE_STYLE_KEYWORDS) and "malware" not in context_text.lower():
            continue
        if any(k in low for k in TOOL_NOISE_KEYWORDS) and overlap < 0.04:
            continue
        has_web_hint = any(k in low for k in WEB_TOOL_HINTS)
        if overlap < 0.05 and not (has_web_hint and overlap >= 0.02):
            continue
        scored.append((overlap, t))

    scored.sort(key=lambda x: x[0], reverse=True)
    selected: list[dict[str, str]] = []
    for _, tool in scored:
        name = str(tool.get("name", "")).strip().lower()
        if name in WEB_TOOL_ALLOWLIST:
            selected.append(tool)
        if len(selected) >= max_tools:
            break
    return selected


def _expected_primary_technique(vuln: dict[str, Any]) -> str:
    text = " ".join(
        [
            str(vuln.get("type", "")),
            str(vuln.get("detail", "")),
            str(vuln.get("evidence", "")),
        ]
    ).lower()

    if "sql injection" in text or "cwe-89" in text:
        return "T1190"
    if ".env" in text or "backup" in text or "unsecured credentials" in text:
        return "T1552"
    if "plain http" in text or "no https" in text or "unencrypted http" in text or "no tls" in text:
        return "T1048"
    if "cors" in text:
        return "T1552"
    return str(vuln.get("mitre_hint", "")).strip()


def _fallback_web_tools(vuln: dict[str, Any], tactic: str) -> list[dict[str, str]]:
    text = " ".join(
        [
            str(vuln.get("type", "")),
            str(vuln.get("detail", "")),
            str(vuln.get("evidence", "")),
            str(tactic),
        ]
    ).lower()

    if "sql" in text:
        names = ["sqlmap", "Burp Suite", "curl"]
    elif "xss" in text or "cors" in text:
        names = ["Burp Suite", "browser", "curl"]
    else:
        names = ["curl", "browser"]

    out: list[dict[str, str]] = []
    for n in names[:3]:
        out.append({"name": n, "description": "Relevant web testing tool"})
    return out


def _flow_rank(tactic: str) -> int:
    t = str(tactic or "").strip().lower()
    if t in ATTACK_FLOW_TACTICS:
        return ATTACK_FLOW_TACTICS.index(t)
    return 10_000


def _context_profile(vuln: dict[str, Any]) -> dict[str, Any]:
    vtype = str(vuln.get("type", ""))
    detail = str(vuln.get("detail", ""))
    evidence = str(vuln.get("evidence", ""))
    query = _vulnerability_rag_query(vuln)
    strict_context_text = " ".join([vtype, detail, evidence]).strip()
    context_text = " ".join([strict_context_text, query]).strip()

    terms = _tokenize_text(context_text)
    terms = {t for t in terms if t not in GENERIC_CONTEXT_TOKENS and len(t) >= 3}

    lowered = context_text.lower()
    allows_cloud = any(k in lowered for k in ["cloud", "aws", "azure", "gcp", "s3", "iam"])
    allows_phishing = any(k in lowered for k in ["phish", "email", "inbox", "attachment"])
    return {
        "context_text": context_text,
        "strict_context_text": strict_context_text,
        "focus_terms": terms,
        "allows_cloud": allows_cloud,
        "allows_phishing": allows_phishing,
        "mitre_hint": str(vuln.get("mitre_hint", "")).strip(),
        "expected_primary": _expected_primary_technique(vuln),
    }


def _record_text(record: dict[str, Any]) -> str:
    return " ".join(
        [
            str(record.get("technique_name", "")),
            str(record.get("description", "")),
            " ".join(record.get("tactics", []) or []),
        ]
    )


def _is_contextually_relevant(
    record: dict[str, Any],
    context_text: str,
    focus_terms: set[str],
    allows_cloud: bool,
    allows_phishing: bool,
) -> bool:
    text = _record_text(record)
    low = text.lower()
    overlap = _text_overlap_score(context_text, text)
    relevance = float(record.get("relevance", 0.0))

    if not allows_phishing and any(k in low for k in ["phish", "spearphish", "email attachment", "inbox"]):
        return False
    if not allows_cloud and any(k in low for k in ["aws", "azure", "gcp", "s3", "ec2", "iam", "kubernetes"]):
        return False
    if any(k in low for k in ["malware", "ransomware", "trojan", "rat", "nation-state", "apt"]):
        return False

    # Keep web/data/credential-centric results with clear contextual signal.
    has_focus_term = bool(focus_terms & _tokenize_text(text))
    has_relevant_tactic = any(t in (record.get("tactics", []) or []) for t in ATTACK_FLOW_TACTICS)

    if not has_relevant_tactic:
        return False
    if overlap >= 0.02:
        return True
    if has_focus_term and relevance >= 0.14:
        return True
    return False


def _primary_score(
    record: dict[str, Any],
    context_text: str,
    focus_terms: set[str],
    mitre_hint: str,
    expected_primary: str,
    avoid_primary_ids: set[str],
) -> float:
    tid = str(record.get("technique_id", "")).strip()
    text = _record_text(record)
    overlap = _text_overlap_score(context_text, text)
    relevance = float(record.get("relevance", 0.0))
    direct_term_hits = len(focus_terms & _tokenize_text(text))
    directness = min(1.0, direct_term_hits / 5.0)

    score = (0.5 * overlap) + (0.3 * relevance) + (0.2 * directness)
    if mitre_hint and tid == mitre_hint:
        score += 0.2
    if expected_primary and tid == expected_primary:
        score += 1.5
    elif expected_primary and tid != expected_primary:
        score -= 0.4
    if tid in avoid_primary_ids:
        score -= 0.08
    return score


def _downsample_chain_preserve_order(chain: list[dict[str, Any]], max_steps: int) -> list[dict[str, Any]]:
    if len(chain) <= max_steps:
        return chain
    if max_steps <= 0:
        return []
    if max_steps == 1:
        return [chain[0]]
    idxs = {
        round(i * (len(chain) - 1) / (max_steps - 1))
        for i in range(max_steps)
    }
    selected = [chain[i] for i in sorted(idxs)]
    return selected[:max_steps]


def _build_dynamic_chain_from_mapping(
    vuln: dict[str, Any],
    mapping: dict[str, Any],
    mitre_db: MitreAttackDatabase | None,
    rag_engine: RAGEngine | None,
    top_k: int = 20,
    avoid_primary_ids: set[str] | None = None,
    avoid_chain_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    avoid_primary_ids = avoid_primary_ids or set()
    avoid_chain_ids = avoid_chain_ids or set()

    techniques = mapping.get("mitre_techniques") or []
    records = [_resolve_technique_record(t, vuln, mitre_db) for t in techniques]

    profile = _context_profile(vuln)
    query = str(profile.get("context_text", ""))
    strict_context_text = str(profile.get("strict_context_text", query))
    focus_terms = set(profile.get("focus_terms", set()))
    allows_cloud = bool(profile.get("allows_cloud", False))
    allows_phishing = bool(profile.get("allows_phishing", False))
    mitre_hint = str(profile.get("mitre_hint", ""))
    expected_primary = str(profile.get("expected_primary", ""))

    if rag_engine is not None:
        try:
            broad = rag_engine.retrieve(query, top_k=top_k)
            records.extend(_resolve_technique_record(t, vuln, mitre_db) for t in broad)
        except Exception:
            pass

    # Deduplicate and keep highest relevance per technique.
    dedup: dict[str, dict[str, Any]] = {}
    for r in records:
        tid = str(r.get("technique_id", "")).strip()
        if not tid or tid == "N/A":
            continue
        prev = dedup.get(tid)
        if prev is None or float(r.get("relevance", 0.0)) > float(prev.get("relevance", 0.0)):
            dedup[tid] = r

    records = list(dedup.values())

    # Force tactic diversity by querying for missing lifecycle tactics.
    tactic_order = ATTACK_FLOW_TACTICS
    covered = {t for r in records for t in r.get("tactics", [])}
    missing = [t for t in tactic_order if t not in covered]

    if rag_engine is not None:
        for tactic in missing:
            try:
                tactic_query = f"{query} techniques for tactic {tactic.replace('-', ' ')}"
                extra = rag_engine.retrieve(tactic_query, top_k=8)
                for t in extra:
                    rec = _resolve_technique_record(t, vuln, mitre_db)
                    tid = str(rec.get("technique_id", "")).strip()
                    if not tid or tid == "N/A":
                        continue
                    prev = dedup.get(tid)
                    if prev is None or float(rec.get("relevance", 0.0)) > float(prev.get("relevance", 0.0)):
                        dedup[tid] = rec
            except Exception:
                continue

    records = list(dedup.values())
    if not records:
        return []

    if expected_primary and expected_primary not in {str(r.get("technique_id", "")).strip() for r in records} and mitre_db:
        forced = mitre_db.get_technique(expected_primary)
        if forced:
            records.append(
                {
                    "technique_id": forced.get("technique_id", expected_primary),
                    "technique_name": forced.get("technique_name", "Unknown Technique"),
                    "tactics": forced.get("tactics", []) or ["execution"],
                    "tools": [],
                    "relevance": 1.0,
                    "description": forced.get("description", ""),
                }
            )

    context_text = query

    # Context-aware filtering and ranking to reduce irrelevant noise.
    filtered: list[dict[str, Any]] = []
    for r in records:
        if not _is_contextually_relevant(
            r,
            context_text=context_text,
            focus_terms=focus_terms,
            allows_cloud=allows_cloud,
            allows_phishing=allows_phishing,
        ):
            continue

        overlap = _text_overlap_score(
            context_text,
            f"{r.get('technique_name', '')} {r.get('description', '')} {' '.join(r.get('tactics', []))}",
        )
        relevance = float(r.get("relevance", 0.0))
        score = (0.55 * relevance) + (0.45 * overlap)
        if str(r.get("technique_id", "")) in avoid_chain_ids:
            score -= 0.06
        enriched = dict(r)
        enriched["_score"] = score
        filtered.append(enriched)

    records = filtered
    if not records:
        return []

    primary_candidates = sorted(
        records,
        key=lambda r: _primary_score(
            r,
            context_text=context_text,
            focus_terms=focus_terms,
            mitre_hint=mitre_hint,
            expected_primary=expected_primary,
            avoid_primary_ids=set(),
        ),
        reverse=True,
    )
    primary = primary_candidates[0]
    if expected_primary:
        for candidate in primary_candidates:
            if str(candidate.get("technique_id", "")).strip() == expected_primary:
                primary = candidate
                break
    elif avoid_primary_ids:
        for candidate in primary_candidates:
            tid = str(candidate.get("technique_id", "")).strip()
            if tid and tid not in avoid_primary_ids:
                primary = candidate
                break
    primary_id = str(primary.get("technique_id", "")).strip()
    primary_tactics = primary.get("tactics", []) or []
    primary_tactic = next((t for t in primary_tactics if t in ATTACK_FLOW_TACTICS), "execution")
    primary_rank = _flow_rank(primary_tactic)

    # Group by tactic and sort each tactic bucket by relevance.
    tactic_groups: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        tactics = r.get("tactics", []) or ["unknown"]
        for tactic in tactics:
            tactic_groups.setdefault(tactic, []).append(r)

    for tactic in tactic_groups:
        tactic_groups[tactic].sort(key=lambda x: -float(x.get("_score", x.get("relevance", 0.0))))

    chain: list[dict[str, Any]] = []
    used_techniques: set[str] = set()
    used_tactics: set[str] = set()

    # Follow requested lifecycle order first for logical progression.
    ordered_tactics = [t for t in ATTACK_FLOW_TACTICS if t in tactic_groups]

    for tactic in ordered_tactics:
        rank = _flow_rank(tactic)
        if rank < primary_rank - 1 or rank > primary_rank + 4:
            continue
        bucket = tactic_groups.get(tactic, [])
        if not bucket:
            continue
        selected = None
        if primary_id:
            for candidate in bucket:
                if str(candidate.get("technique_id", "")) == primary_id:
                    selected = candidate
                    break
        if selected is None:
            for candidate in bucket:
                tid = str(candidate.get("technique_id", ""))
                if tid and tid not in used_techniques:
                    selected = candidate
                    break
        if selected is None:
            continue
        used_techniques.add(str(selected.get("technique_id", "")))
        used_tactics.add(tactic)
        step_tools = _select_context_tools(selected.get("tools", []), strict_context_text, max_tools=3)
        if not step_tools:
            step_tools = _fallback_web_tools(vuln, tactic)
        chain.append(
            {
                "step": len(chain) + 1,
                "technique_id": selected.get("technique_id", "N/A"),
                "technique_name": selected.get("technique_name", "Unknown Technique"),
                "tactic": tactic,
                "tools": step_tools,
                "description": selected.get("description", "No description available."),
                "is_primary": str(selected.get("technique_id", "")) == primary_id,
            }
        )
        if len(chain) >= 6:
            break

    # Add remaining non-duplicate techniques, prioritizing tactics not yet covered.
    remaining = sorted(records, key=lambda x: -float(x.get("_score", x.get("relevance", 0.0))))
    remaining_unique_tactics = []
    remaining_repeat_tactics = []
    for rec in remaining:
        tid = str(rec.get("technique_id", ""))
        if not tid or tid in used_techniques:
            continue
        tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
        if tactic not in ATTACK_FLOW_TACTICS:
            continue
        rank = _flow_rank(tactic)
        if rank < primary_rank - 1 or rank > primary_rank + 4:
            continue
        if tactic in used_tactics:
            remaining_repeat_tactics.append(rec)
        else:
            remaining_unique_tactics.append(rec)

    for rec in remaining_unique_tactics:
        if len(chain) >= 6:
            break
        tid = str(rec.get("technique_id", ""))
        tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
        step_tools = _select_context_tools(rec.get("tools", []), strict_context_text, max_tools=3)
        if not step_tools:
            step_tools = _fallback_web_tools(vuln, tactic)
        chain.append(
            {
                "step": len(chain) + 1,
                "technique_id": rec.get("technique_id", "N/A"),
                "technique_name": rec.get("technique_name", "Unknown Technique"),
                "tactic": tactic,
                "tools": step_tools,
                "description": rec.get("description", "No description available."),
                "is_primary": str(rec.get("technique_id", "")) == primary_id,
            }
        )
        used_techniques.add(tid)
        used_tactics.add(tactic)

    # Keep output concise and useful: 5-7 logical steps.
    if len(chain) < 5:
        # Allow repeated tactics only when needed to reach minimum depth.
        fallback = [c for c in remaining_repeat_tactics if str(c.get("technique_id", "")) not in used_techniques]
        for rec in fallback:
            tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
            chain.append(
                {
                    "step": len(chain) + 1,
                    "technique_id": rec.get("technique_id", "N/A"),
                    "technique_name": rec.get("technique_name", "Unknown Technique"),
                    "tactic": tactic,
                    "tools": (_select_context_tools(rec.get("tools", []), strict_context_text, max_tools=3) or _fallback_web_tools(vuln, tactic)),
                    "description": rec.get("description", "No description available."),
                    "is_primary": str(rec.get("technique_id", "")) == primary_id,
                }
            )
            used_techniques.add(str(rec.get("technique_id", "")))
            if len(chain) >= 5 or len(chain) >= 7:
                break

    if len(chain) < 5:
        # Last-resort fill: keep flow-compatible, non-duplicate techniques to hit minimum depth.
        final_fill = [
            r
            for r in remaining
            if str(r.get("technique_id", "")) not in used_techniques
            and (r.get("tactics", ["unknown"]) or ["unknown"])[0] in ATTACK_FLOW_TACTICS
        ]
        for rec in final_fill:
            tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
            chain.append(
                {
                    "step": len(chain) + 1,
                    "technique_id": rec.get("technique_id", "N/A"),
                    "technique_name": rec.get("technique_name", "Unknown Technique"),
                    "tactic": tactic,
                    "tools": (_select_context_tools(rec.get("tools", []), strict_context_text, max_tools=3) or _fallback_web_tools(vuln, tactic)),
                    "description": rec.get("description", "No description available."),
                    "is_primary": str(rec.get("technique_id", "")) == primary_id,
                }
            )
            used_techniques.add(str(rec.get("technique_id", "")))
            if len(chain) >= 5:
                break

    # Ensure primary technique is always included even if it fell outside flow picks.
    if primary_id and all(str(step.get("technique_id", "")) != primary_id for step in chain):
        chain.insert(
            0,
            {
                "step": 1,
                "technique_id": primary.get("technique_id", "N/A"),
                "technique_name": primary.get("technique_name", "Unknown Technique"),
                "tactic": primary_tactic,
                "tools": (_select_context_tools(primary.get("tools", []), strict_context_text, max_tools=3) or _fallback_web_tools(vuln, primary_tactic)),
                "description": primary.get("description", "No description available."),
                "is_primary": True,
            },
        )

    chain = _downsample_chain_preserve_order(chain, max_steps=6)
    for i, step in enumerate(chain, 1):
        step["step"] = i
    return chain


@contextlib.contextmanager
def _silent_execution() -> Any:
    """Suppress stdout/stderr and non-critical logs during option execution."""
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    previous_disable = logging.root.manager.disable
    try:
        logging.disable(logging.CRITICAL)
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            yield
    finally:
        logging.disable(previous_disable)


def _write_scan_text_report(
    target_url: str,
    discovery: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    mapped: list[dict[str, Any]],
    mitre_db: MitreAttackDatabase | None,
    rag_engine: RAGEngine | None,
) -> Path:
    config.ensure_directories()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    out_path = config.OUTPUT_DIR / f"scan_report_{ts}.txt"

    lines: list[str] = [
        "===============================",
        "RED AGENT SCAN REPORT",
        "===============================",
        "",
        f"Target: {target_url}",
        f"Scan Time: {scan_time}",
        f"Discovered Routes: {len(discovery.get('routes', []))}",
        f"Discovered Forms: {len(discovery.get('forms', []))}",
        "",
    ]

    used_primary_ids: set[str] = set()
    used_chain_ids: set[str] = set()

    for i, vuln in enumerate(vulnerabilities, 1):
        mapping = mapped[i - 1] if i - 1 < len(mapped) else {}
        chain = _build_dynamic_chain_from_mapping(
            vuln,
            mapping,
            mitre_db,
            rag_engine=rag_engine,
            top_k=25,
            avoid_primary_ids=used_primary_ids,
            avoid_chain_ids=used_chain_ids,
        )
        primary = next((s for s in chain if s.get("is_primary")), chain[0] if chain else {})
        technique_id = str(primary.get("technique_id", "N/A"))
        technique_name = str(primary.get("technique_name", "Unknown Technique"))
        tactics = sorted({str(step.get("tactic", "unknown")) for step in chain}) if chain else []
        tools = _normalize_tools([tool for step in chain for tool in step.get("tools", [])], max_items=4)
        if technique_id and technique_id != "N/A":
            used_primary_ids.add(technique_id)
        for step in chain:
            sid = str(step.get("technique_id", "")).strip()
            if sid:
                used_chain_ids.add(sid)
        affected_url = _infer_affected_url(vuln, target_url)
        evidence_text = str(vuln.get("evidence", "N/A"))
        recommendation = str(vuln.get("recommendation", ""))

        lines.extend(
            [
                "--------------------------------",
                f"[VULNERABILITY #{i}]",
                f"Type: {vuln.get('type', 'Unknown')}",
                f"Severity: {vuln.get('severity', 'N/A')}",
                "",
                "Affected URL:",
                affected_url,
                "",
                "Evidence:",
                f"- {evidence_text}",
                "",
                "--------------------------------",
                "MITRE ATT&CK MAPPING",
                f"Technique ID: {technique_id}",
                f"Technique Name: {technique_name}",
                f"Tactics: {', '.join(tactics) if tactics else 'N/A'}",
                "Tools / Software:",
            ]
        )
        for tool in tools:
            lines.append(f"- {tool.get('name', 'Unknown Tool')}: {tool.get('description', 'N/A')}")
        if not tools:
            lines.append("- No tools found in MITRE dataset")
        lines.extend(["", "--------------------------------", "ATTACK CHAIN:", ""])

        for idx, step in enumerate(chain, 1):
            lines.append(f"{idx}. {str(step.get('tactic', 'unknown')).replace('-', ' ').title()}:")
            lines.append(
                f"   Technique: {step.get('technique_id', 'N/A')} - {step.get('technique_name', 'Unknown')}"
            )
            step_tools = step.get("tools", [])
            lines.append(
                "   Tools: " + (", ".join(t.get("name", "Unknown Tool") for t in step_tools) if step_tools else "No tools found in MITRE dataset")
            )
            lines.append(f"   Description: {step.get('description', 'N/A')}")
            lines.append("")

        lines.extend(
            [
                "--------------------------------",
                "RECOMMENDATION:",
            ]
        )
        for rec in _split_recommendation_lines(recommendation):
            lines.append(f"- {rec}")
        lines.extend(["", "================================", ""])

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def _save_enriched_report(prefix: str, payload: dict[str, Any]) -> tuple[Path, Path]:
    """Keep enriched JSON/Markdown generation for interactive scan outputs."""
    config.ensure_directories()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = config.OUTPUT_DIR / f"{prefix}_{ts}.json"
    md_path = config.OUTPUT_DIR / f"{prefix}_{ts}.md"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    lines = [
        f"# {prefix.replace('_', ' ').title()}",
        "",
        f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- Target URL: {payload.get('target_url', 'N/A')}",
        f"- Total vulnerabilities: {len(payload.get('vulnerabilities', []))}",
        "",
        "## MITRE Mapping Per Vulnerability",
        "",
    ]

    for i, item in enumerate(payload.get("vuln_mappings", []), 1):
        vuln = item.get("vulnerability", {})
        lines.append(f"### {i}. {vuln.get('type', 'Unknown')} [{vuln.get('severity', 'N/A')}]")
        lines.append(f"- Detail: {vuln.get('detail', 'N/A')}")
        techniques = item.get("top_techniques", [])
        if techniques:
            lines.append("- Techniques:")
            for t in techniques:
                lines.append(f"  - [{t.get('technique_id', 'N/A')}] {t.get('name', 'Unknown')}")
        else:
            lines.append("- Techniques: None")
        lines.append("")

    lines += ["## Attack Chain", ""]
    for step in payload.get("attack_chain", []):
        lines.append(
            f"- Step {step.get('step', '?')}: "
            f"[{step.get('technique_id', 'N/A')}] {step.get('technique_name', 'Unknown')} "
            f"({step.get('tactic', 'N/A')})"
        )

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return json_path, md_path


def _write_option_text_report(
    option_slug: str,
    mode_name: str,
    scenario: str | None,
    target_url: str | None,
    vulnerabilities: list[dict[str, Any]],
    mapped: list[dict[str, Any]],
    mitre_db: MitreAttackDatabase | None,
    rag_engine: RAGEngine | None,
) -> Path:
    """Write a structured TXT report for options 2/3/4 (and reusable elsewhere)."""
    config.ensure_directories()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = config.OUTPUT_DIR / f"report_{option_slug}_{ts}.txt"
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    lines: list[str] = [
        "===============================",
        "RED AGENT REPORT",
        "===============================",
        "",
        f"Timestamp: {scan_time}",
        f"Mode: {mode_name}",
        f"Target URL: {target_url or 'N/A'}",
        f"Scenario: {scenario or 'N/A'}",
        "",
    ]

    used_primary_ids: set[str] = set()
    used_chain_ids: set[str] = set()

    if not vulnerabilities:
        vulnerabilities = [
            {
                "type": "Analysis Item",
                "severity": "INFO",
                "detail": "No concrete vulnerability evidence available for this run.",
                "evidence": "N/A",
                "recommendation": "Review scenario assumptions and run with target context if needed.",
                "mitre_hint": "",
            }
        ]

    for i, vuln in enumerate(vulnerabilities, 1):
        mapping = mapped[i - 1] if i - 1 < len(mapped) else {}
        chain = _build_dynamic_chain_from_mapping(
            vuln,
            mapping,
            mitre_db,
            rag_engine=rag_engine,
            top_k=25,
            avoid_primary_ids=used_primary_ids,
            avoid_chain_ids=used_chain_ids,
        )
        primary = next((s for s in chain if s.get("is_primary")), chain[0] if chain else {})
        technique_id = str(primary.get("technique_id", "N/A"))
        technique_name = str(primary.get("technique_name", "Unknown Technique"))
        tactics = sorted({str(step.get("tactic", "unknown")) for step in chain}) if chain else []
        tools = _normalize_tools([tool for step in chain for tool in step.get("tools", [])], max_items=4)
        if technique_id and technique_id != "N/A":
            used_primary_ids.add(technique_id)
        for step in chain:
            sid = str(step.get("technique_id", "")).strip()
            if sid:
                used_chain_ids.add(sid)
        evidence_text = str(vuln.get("evidence", "N/A"))
        recommendation = str(vuln.get("recommendation", ""))
        affected_url = _infer_affected_url(vuln, target_url or "N/A")

        lines.extend(
            [
                "--------------------------------",
                f"[ITEM #{i}]",
                f"Type: {vuln.get('type', 'Unknown')}",
                f"Severity: {vuln.get('severity', 'N/A')}",
                "",
                "Affected URL:",
                affected_url,
                "",
                "Evidence:",
                f"- {evidence_text}",
                "",
                "--------------------------------",
                "MITRE ATT&CK MAPPING",
                f"Technique ID: {technique_id}",
                f"Technique Name: {technique_name}",
                f"Tactics: {', '.join(tactics) if tactics else 'N/A'}",
                "Tools / Software:",
            ]
        )
        for tool in tools:
            lines.append(f"- {tool.get('name', 'Unknown Tool')}: {tool.get('description', 'N/A')}")
        if not tools:
            lines.append("- No tools found in MITRE dataset")
        lines.extend(
            [
                "",
                "--------------------------------",
                "ATTACK CHAIN:",
                "",
            ]
        )

        for idx, step in enumerate(chain, 1):
            lines.append(f"{idx}. {str(step.get('tactic', 'unknown')).replace('-', ' ').title()}:")
            lines.append(
                f"   Technique: {step.get('technique_id', 'N/A')} - {step.get('technique_name', 'Unknown')}"
            )
            step_tools = step.get("tools", [])
            lines.append(
                "   Tools: " + (", ".join(t.get("name", "Unknown Tool") for t in step_tools) if step_tools else "No tools found in MITRE dataset")
            )
            lines.append(f"   Description: {step.get('description', 'N/A')}")
            lines.append("")

        lines.extend(["--------------------------------", "RECOMMENDATION:"])
        for rec in _split_recommendation_lines(recommendation):
            lines.append(f"- {rec}")
        lines.extend(["", "================================", ""])

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def run_full_web_scan(ctx: RuntimeContext) -> None:
    try:
        target_url = normalize_url(input("Target URL: ").strip())
    except ValueError:
        return

    with _silent_execution():
        discovery = discover_attack_surface(target_url)
        routes = discovery.get("routes", [])

        # Fallback rule: if crawl yields nothing useful, scan the base URL directly.
        if len(routes) <= 1:
            routes = [target_url]

        recon_data = WebReconAgent(target_url).run()
        if not recon_data.get("reachable"):
            return

        passive = VulnerabilityScanner(recon_data).scan()
        passive_vulns = passive.get("vulnerabilities", [])

        live_vulns: list[dict[str, Any]] = []
        try:
            report = LiveVulnChecker(target_url).run_full_check()
            for finding in report.get("vulnerabilities", []):
                if finding.get("confirmed_live"):
                    live_vulns.append(finding)
        except Exception as e:  # noqa: BLE001
            logger.warning("Live scan failed for %s: %s", target_url, e)

        form_vulns = _probe_discovered_forms(target_url, discovery.get("forms", []))

        merged_vulns = _merge_vulnerabilities(passive_vulns, live_vulns, form_vulns)
        counts = _severity_counts(merged_vulns)
        scan_result = {
            "target_url": target_url,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_vulns": len(merged_vulns),
            "severity_counts": counts,
            "overall_risk": _overall_risk(counts),
            "vulnerabilities": merged_vulns,
            "tech_stack": recon_data.get("tech_stack", {}),
        }

        ctx.ensure_rag(force_reindex=False)
        assert ctx.mapper is not None
        assert ctx.mitre_db is not None
        mapped = ctx.mapper.map_vulnerabilities(merged_vulns)
        chain = ctx.mapper.build_attack_chain(mapped, target_url=target_url)

        # Keep existing report generation behavior (JSON + MD standard report).
        report = ReportGenerator().generate(
            target_url=target_url,
            recon_data=recon_data,
            scan_result=scan_result,
            attack_chain=chain,
            llm_analysis=(
                "LLM analysis skipped in interactive full-scan mode. "
                "Use web_vuln_agent.py directly for narrative generation."
            ),
        )

        # Keep existing interactive_web_scan enriched JSON + MD generation.
        enriched = {
            "target_url": target_url,
            "discovery": discovery,
            "vulnerabilities": merged_vulns,
            "vuln_mappings": [
                {
                    "vulnerability": m.get("vulnerability"),
                    "top_techniques": [
                        {
                            "technique_id": t.get("technique_id"),
                            "name": t.get("name"),
                        }
                        for t in (m.get("mitre_techniques") or [])[:3]
                    ],
                }
                for m in mapped
            ],
            "attack_chain": chain,
            "standard_report_paths": {
                "json": report.get("json_path"),
                "markdown": report.get("md_path"),
            },
        }
        _save_enriched_report("interactive_web_scan", enriched)

        # Extra text report for option 1.
        _write_scan_text_report(
            target_url=target_url,
            discovery=discovery,
            vulnerabilities=merged_vulns,
            mapped=mapped,
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


def run_scenario_generation(ctx: RuntimeContext) -> None:
    raw = input("Scenario text: ").strip()
    if not raw:
        return

    try:
        scenario = sanitize_scenario(raw)
    except Exception:  # noqa: BLE001
        return

    target_env = input(
        "Target environment [Enter=Enterprise Windows Active Directory network]: "
    ).strip() or "Enterprise Windows Active Directory network"
    chain_len_raw = input(f"Chain length [Enter={config.DEFAULT_CHAIN_LENGTH}]: ").strip()
    chain_len = int(chain_len_raw) if chain_len_raw.isdigit() else config.DEFAULT_CHAIN_LENGTH

    try:
        with _silent_execution():
            ctx.ensure_rag(force_reindex=False)
            assert ctx.generator is not None
            result = ctx.generator.generate(
                scenario=scenario,
                target_environment=target_env,
                chain_length=chain_len,
            )
            ctx.generator.export_json(result)
            ctx.generator.export_markdown(result)

            chain = result.get("attack_chain", {}).get("attack_chain", [])
            vulnerabilities = []
            for step in chain:
                vulnerabilities.append(
                    {
                        "type": "Scenario Attack Step",
                        "severity": "MEDIUM",
                        "detail": step.get("description", step.get("technique_name", "Scenario step")),
                        "evidence": step.get("rationale", "Generated from scenario and RAG context."),
                        "recommendation": step.get("mitigation", "Apply layered security controls and ATT&CK-aligned mitigations."),
                        "mitre_hint": step.get("technique_id", ""),
                    }
                )

            assert ctx.mapper is not None
            assert ctx.mitre_db is not None
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _write_option_text_report(
                option_slug="scenario",
                mode_name="Generate Attack Scenario (No URL)",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
    except Exception as e:  # noqa: BLE001
        _write_option_text_report(
            option_slug="scenario",
            mode_name="Generate Attack Scenario (No URL)",
            scenario=scenario,
            target_url=None,
            vulnerabilities=[
                {
                    "type": "Execution Failure",
                    "severity": "LOW",
                    "detail": "Scenario generation failed during execution.",
                    "evidence": str(e),
                    "recommendation": "Verify API keys and environment setup, then retry.",
                    "mitre_hint": "",
                }
            ],
            mapped=[],
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


def run_scenario_url_validation(ctx: RuntimeContext) -> None:
    raw = input("Scenario text: ").strip()
    url_raw = input("Target URL: ").strip()
    if not raw or not url_raw:
        return

    try:
        scenario = sanitize_scenario(raw)
        target_url = normalize_url(url_raw)
    except Exception:  # noqa: BLE001
        return

    try:
        with _silent_execution():
            attack_type = detect_attack_type(scenario)
            probe = probe_target(target_url, attack_type)
            status = "FOUND" if probe.get("found") else "NOT FOUND"

            ctx.ensure_rag(force_reindex=False)
            assert ctx.mapper is not None
            assert ctx.mitre_db is not None

            evidence = probe.get("evidence", [])
            vuln_items: list[dict[str, Any]] = []
            for ev in evidence:
                if not ev.get("confirmed"):
                    continue
                vuln_items.append(
                    {
                        "type": f"Targeted Validation ({attack_type})",
                        "detail": ev.get("detail", "Targeted evidence detected"),
                        "severity": probe.get("severity", "MEDIUM"),
                        "cwe_id": "CWE-20",
                        "mitre_hint": "",
                        "recommendation": probe.get("recommendation", "Review and patch issue."),
                        "evidence": f"{ev.get('url', target_url)} | {ev.get('payload', 'probe')}",
                        "confirmed_live": bool(ev.get("confirmed")),
                    }
                )

            if not vuln_items:
                vuln_items.append(
                    {
                        "type": f"Targeted Validation ({attack_type})",
                        "detail": "No automatic confirmation; manual verification recommended.",
                        "severity": "LOW",
                        "cwe_id": "CWE-200",
                        "mitre_hint": "",
                        "recommendation": probe.get("recommendation", "Perform manual validation."),
                        "evidence": probe.get("manual_test", target_url),
                        "confirmed_live": False,
                    }
                )

            mapped = ctx.mapper.map_vulnerabilities(vuln_items)
            chain = ctx.mapper.build_attack_chain(mapped, target_url=target_url)

            recon = WebReconAgent(target_url).run()
            counts = _severity_counts(vuln_items)
            report = ReportGenerator().generate(
                target_url=target_url,
                recon_data=recon,
                scan_result={
                    "target_url": target_url,
                    "total_vulns": len(vuln_items),
                    "severity_counts": counts,
                    "overall_risk": _overall_risk(counts),
                    "vulnerabilities": vuln_items,
                    "tech_stack": recon.get("tech_stack", {}),
                },
                attack_chain=chain,
                llm_analysis=(
                    f"Scenario-driven validation completed for attack type '{attack_type}'. "
                    f"Status: {status}."
                ),
            )

            enriched = {
                "target_url": target_url,
                "scenario": scenario,
                "attack_type": attack_type,
                "probe_result": probe,
                "vulnerabilities": vuln_items,
                "vuln_mappings": [
                    {
                        "vulnerability": m.get("vulnerability"),
                        "top_techniques": [
                            {
                                "technique_id": t.get("technique_id"),
                                "name": t.get("name"),
                            }
                            for t in (m.get("mitre_techniques") or [])[:3]
                        ],
                    }
                    for m in mapped
                ],
                "attack_chain": chain,
                "standard_report_paths": {
                    "json": report.get("json_path"),
                    "markdown": report.get("md_path"),
                },
            }
            _save_enriched_report("scenario_url_validation", enriched)

            _write_option_text_report(
                option_slug="validation",
                mode_name="Validate Scenario on Target URL",
                scenario=scenario,
                target_url=target_url,
                vulnerabilities=vuln_items,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
    except Exception as e:  # noqa: BLE001
        _write_option_text_report(
            option_slug="validation",
            mode_name="Validate Scenario on Target URL",
            scenario=scenario,
            target_url=target_url,
            vulnerabilities=[
                {
                    "type": "Execution Failure",
                    "severity": "LOW",
                    "detail": "Scenario+URL validation failed during execution.",
                    "evidence": str(e),
                    "recommendation": "Verify target reachability and API credentials, then retry.",
                    "mitre_hint": "",
                }
            ],
            mapped=[],
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


def run_scenario_only_analysis(ctx: RuntimeContext) -> None:
    raw = input("Scenario text: ").strip()
    if not raw:
        return

    try:
        scenario = sanitize_scenario(raw)
    except Exception:  # noqa: BLE001
        return

    try:
        with _silent_execution():
            ctx.ensure_rag(force_reindex=False)
            assert ctx.generator is not None

            result = ctx.generator.generate(
                scenario=scenario,
                target_environment="General enterprise environment",
                chain_length=config.DEFAULT_CHAIN_LENGTH,
            )

            ctx.generator.export_json(result)
            ctx.generator.export_markdown(result)

            chain = result.get("attack_chain", {}).get("attack_chain", [])
            vulnerabilities = []
            for step in chain:
                vulnerabilities.append(
                    {
                        "type": "Scenario Analysis Step",
                        "severity": "MEDIUM",
                        "detail": step.get("description", step.get("technique_name", "Analysis step")),
                        "evidence": step.get("rationale", "Derived from scenario-only analysis."),
                        "recommendation": step.get("mitigation", "Apply ATT&CK-aligned defensive controls."),
                        "mitre_hint": step.get("technique_id", ""),
                    }
                )

            assert ctx.mapper is not None
            assert ctx.mitre_db is not None
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _write_option_text_report(
                option_slug="analysis",
                mode_name="Analyze Scenario Only",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
    except Exception as e:  # noqa: BLE001
        _write_option_text_report(
            option_slug="analysis",
            mode_name="Analyze Scenario Only",
            scenario=scenario,
            target_url=None,
            vulnerabilities=[
                {
                    "type": "Execution Failure",
                    "severity": "LOW",
                    "detail": "Scenario-only analysis failed during execution.",
                    "evidence": str(e),
                    "recommendation": "Verify LLM/RAG environment and retry.",
                    "mitre_hint": "",
                }
            ],
            mapped=[],
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


def menu_loop() -> None:
    ctx = RuntimeContext()

    while True:
        print("\n=== RED AGENT CLI ===")
        print("1. Full Web Vulnerability Scan (Auto Route Discovery + Attack Chain Output)")
        print("2. Generate Attack Scenario (No URL)")
        print("3. Validate Scenario on Target URL")
        print("4. Analyze Scenario Only")
        print("5. Exit")

        choice = input("Select option [1-5]: ").strip()

        if choice == "1":
            try:
                run_full_web_scan(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Full scan failed")

        elif choice == "2":
            try:
                run_scenario_generation(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Scenario generation failed")

        elif choice == "3":
            try:
                run_scenario_url_validation(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Scenario+URL validation failed")

        elif choice == "4":
            try:
                run_scenario_only_analysis(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Scenario-only analysis failed")

        elif choice == "5":
            print("Exiting Red Agent CLI.")
            break

        else:
            print("Invalid option. Please choose 1, 2, 3, 4, or 5.")


def main() -> int:
    setup_logging()
    print("\nRed ELISAR Interactive Red Agent CLI")
    print("Use only against systems you own or are authorized to test.")
    menu_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
