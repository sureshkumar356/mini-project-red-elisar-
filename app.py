"""
Red ELISAR — Flask Web Application
Wraps all 4 run.py menu options in a local browser UI with live streaming output.
Run: python app.py
Then open: http://127.0.0.1:7860
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Bootstrap paths (same as run.py) ────────────────────────────────────────
PROJECT_DIR = Path(__file__).resolve().parent
AGENT_DIR   = PROJECT_DIR / "red_agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))
os.chdir(AGENT_DIR)

from flask import Flask, Response, abort, jsonify, make_response, render_template, request, send_file, stream_with_context

import config
from llm.attack_chain_generator import AttackChainGenerator
from mappings.mitre_mapper import MITREMapper
from rag.chunking import chunk_techniques
from rag.mitre_parser import MITREParser
from rag.rag_engine import RAGEngine
from rag.vector_store_faiss import FAISSVectorStore
from reporting.report_generator import ReportGenerator
from reporting.pdf_reporter import render_markdown_to_pdf
from vuln_checks.input_sanitizer import sanitize_scenario
from vuln_checks.live_vuln_checker import LiveVulnChecker
from vuln_checks.targeted_attack_scanner import detect_attack_type, probe_target
from vuln_checks.vuln_scanner import VulnerabilityScanner
from vuln_checks.web_recon import WebReconAgent

# Re-import helpers from run.py (since they're defined there)
import run as run_module

app = Flask(__name__)
app.secret_key = "red-elisar-local-only"


@app.route("/api/report/download")
def api_report_download():
    path = (request.args.get("path") or "").strip()
    if not path:
        abort(404)
    report_path = Path(path).expanduser().resolve()
    output_dir = config.OUTPUT_DIR.resolve()
    if output_dir not in report_path.parents and report_path != output_dir:
        abort(403)
    if (not report_path.exists() or not report_path.is_file()) and report_path.suffix.lower() == ".pdf":
        # Auto-heal missing PDF by rendering from sibling markdown when available.
        md_candidate = report_path.with_suffix(".md")
        if md_candidate.exists() and md_candidate.is_file():
            try:
                render_markdown_to_pdf(md_candidate, report_path)
            except Exception as exc:
                return jsonify({"error": f"PDF render failed: {exc}"}), 500
    if not report_path.exists() or not report_path.is_file():
        abort(404)
    return send_file(report_path, as_attachment=True, download_name=report_path.name)

# ── Global runtime context (lazy-loaded) ─────────────────────────────────────
_ctx_lock = threading.Lock()
_runtime_ctx: run_module.RuntimeContext | None = None

_latest_lock = threading.Lock()
_latest_results: dict[str, dict] = {}
_latest_meta: dict[str, str] = {}
_cancel_lock = threading.Lock()
_cancel_events: dict[str, threading.Event] = {}


class RequestCancelledError(Exception):
    pass


def _register_request(request_id: str | None) -> threading.Event | None:
    if not request_id:
        return None
    with _cancel_lock:
        ev = _cancel_events.get(request_id)
        if ev is None:
            ev = threading.Event()
            _cancel_events[request_id] = ev
        return ev


def _cleanup_request(request_id: str | None) -> None:
    if not request_id:
        return
    with _cancel_lock:
        _cancel_events.pop(request_id, None)


def _check_cancel(cancel_event: threading.Event | None):
    if cancel_event is not None and cancel_event.is_set():
        raise RequestCancelledError("Request cancelled by user")


def get_ctx() -> run_module.RuntimeContext:
    global _runtime_ctx
    with _ctx_lock:
        if _runtime_ctx is None:
            _runtime_ctx = run_module.RuntimeContext()
        return _runtime_ctx


def _store_latest(mode: str, payload: dict) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    with _latest_lock:
        _latest_results[mode] = payload
        _latest_results["last"] = payload
        _latest_meta["mode"] = mode
        _latest_meta["timestamp"] = timestamp


def _get_latest(mode: str | None = None) -> tuple[dict | None, dict]:
    with _latest_lock:
        if mode and mode in _latest_results:
            return _latest_results.get(mode), dict(_latest_meta)
        return _latest_results.get("last"), dict(_latest_meta)


# ── SSE streaming helper ──────────────────────────────────────────────────────
class StreamQueue:
    """Thread-safe queue used to stream log lines back to the browser via SSE."""

    def __init__(self):
        self.q: queue.Queue[str | None] = queue.Queue()

    def put(self, line: str):
        self.q.put(line)

    def done(self):
        self.q.put(None)  # sentinel

    def get(self, timeout: float | None = None):
        return self.q.get(timeout=timeout)

    def __iter__(self):
        while True:
            item = self.q.get()
            if item is None:
                break
            yield item


class QueueHandler(logging.Handler):
    """Redirect log records into the SSE stream queue."""

    def __init__(self, sq: StreamQueue):
        super().__init__()
        self.sq = sq

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.sq.put(msg)
        except Exception:
            pass


def _stream_gen(sq: StreamQueue, heartbeat_s: float | None = None):
    """Generator that yields SSE-formatted events from the queue with keepalive."""
    heartbeat = heartbeat_s or float(getattr(config, "WEB_UI_STREAM_HEARTBEAT_S", 12.0))
    while True:
        try:
            line = sq.get(timeout=heartbeat)
        except queue.Empty:
            yield ": keepalive\n\n"
            continue
        if line is None:
            break
        safe = str(line).replace("\n", "\\n")
        yield f"data: {safe}\n\n"
    yield "data: __DONE__\n\n"


def _prewarm_runtime():
    """Warm up RAG + MITRE context in the background for faster first responses."""
    try:
        ctx = get_ctx()
        ctx.ensure_rag(force_reindex=False)
    except Exception as exc:
        app.logger.warning("Runtime prewarm failed: %s", exc)


def _enrich_chain(chain_steps: list, rag) -> list:
    """Replace 'Unknown' technique names using available technique lookup sources."""
    enriched = []
    for step in chain_steps:
        s = dict(step)
        tid = str(s.get("technique_id") or "").strip().upper()
        name = str(s.get("technique_name") or s.get("name") or "").strip()
        if (not name or name.lower() == "unknown") and tid and rag:
            try:
                record = None
                if hasattr(rag, "vector_store") and hasattr(rag.vector_store, "query_by_technique_id"):
                    record = rag.vector_store.query_by_technique_id(tid)
                elif hasattr(rag, "get_technique"):
                    record = rag.get_technique(tid)
                if record:
                    s["technique_name"] = record.get("name") or record.get("technique_name") or tid
                    if not s.get("tactic") and record.get("tactic"):
                        s["tactic"] = record["tactic"]
                else:
                    s["technique_name"] = tid  # fallback: show ID itself
            except Exception:
                s["technique_name"] = tid
        enriched.append(s)
    return enriched


def _coerce_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _build_step_attribution(chain_steps: list, retrieval_results: list | None = None) -> list:
    """Build explainable retrieval attribution for each generated chain step."""
    retrieval_results = retrieval_results or []
    by_tid = {}
    for rank, r in enumerate(retrieval_results, start=1):
        tid = str(r.get("technique_id") or "").strip().upper()
        if not tid or tid in by_tid:
            continue
        by_tid[tid] = (rank, r)

    attributions = []
    for i, step in enumerate(chain_steps, start=1):
        tid = str(step.get("technique_id") or "").strip().upper()
        tname = str(step.get("technique_name") or step.get("name") or tid or f"Step {i}")
        rationale = str(step.get("rationale") or "").strip()
        rank, source = by_tid.get(tid, (None, None))

        similarity = 0.0
        evidence = []
        flags = []

        if source:
            similarity = _coerce_float(source.get("relevance_score"), 0.0)
            snippet = str(source.get("description") or "").strip()
            evidence.append(
                {
                    "source_type": "faiss_hit",
                    "source_id": str(source.get("technique_id") or tid),
                    "rank": rank,
                    "similarity_score": round(similarity, 4),
                    "snippet": snippet[:280],
                    "matched_terms": [],
                }
            )
            if similarity < 0.35:
                flags.append("low_similarity")
        else:
            evidence.append(
                {
                    "source_type": "fallback",
                    "source_id": tid or f"step-{i}",
                    "rank": None,
                    "similarity_score": 0.0,
                    "snippet": "No direct retrieval evidence found; used generated step context.",
                    "matched_terms": [],
                }
            )
            flags.append("fallback_used")

        confidence = max(0.15, min(0.98, 0.4 + (similarity * 0.6)))
        if not rationale:
            flags.append("sparse_evidence")

        attributions.append(
            {
                "step_id": i,
                "technique_id": tid,
                "technique_name": tname,
                "confidence_score": round(confidence, 4),
                "evidence": evidence,
                "rationale_summary": (rationale[:240] if rationale else "Generated from scenario context and mapped ATT&CK behavior."),
                "attribution_flags": sorted(set(flags)),
            }
        )

    return attributions


def _build_causal_attack_graph(chain_steps: list, vulnerabilities: list | None = None) -> dict:
    """Convert linear chain into a lightweight causal graph with branch edges."""
    vulnerabilities = vulnerabilities or []
    nodes = []
    edges = []
    entry_nodes = []
    objective_nodes = []

    for i, step in enumerate(chain_steps, start=1):
        sid = f"tech-{i}"
        tactic = str(step.get("tactic") or step.get("phase") or "unknown")
        prob = max(0.15, 0.72 - (0.03 * (i - 1)))
        cost = 2 + i
        nodes.append(
            {
                "id": sid,
                "type": "technique",
                "label": str(step.get("technique_name") or step.get("name") or step.get("technique_id") or f"Step {i}"),
                "technique_id": str(step.get("technique_id") or ""),
                "tactic": tactic,
                "base_probability": round(prob, 3),
                "base_cost": cost,
                "detectability": round(min(0.9, 0.25 + (0.05 * i)), 3),
            }
        )

        if i == 1:
            entry_nodes.append(sid)
        if i == len(chain_steps):
            objective_nodes.append(sid)
        if i > 1:
            edges.append(
                {
                    "source": f"tech-{i-1}",
                    "target": sid,
                    "relation": "enables",
                    "weight": 1.0,
                    "explanation": "Prior technique establishes conditions for next stage.",
                }
            )

        if i > 2 and (i % 2 == 0):
            edges.append(
                {
                    "source": f"tech-{i-2}",
                    "target": sid,
                    "relation": "alternative_path",
                    "weight": 0.55,
                    "explanation": "Alternative attacker path inferred from tactic-level continuity.",
                }
            )

    for vi, vuln in enumerate(vulnerabilities[:6], start=1):
        vid = f"vuln-{vi}"
        vlabel = str(vuln.get("type") or "Vulnerability")
        sev = str(vuln.get("severity") or "MEDIUM").upper()
        sev_weight = {"CRITICAL": 0.85, "HIGH": 0.75, "MEDIUM": 0.6, "LOW": 0.45}.get(sev, 0.5)
        nodes.append(
            {
                "id": vid,
                "type": "condition",
                "label": vlabel,
                "tactic": "initial-access",
                "base_probability": sev_weight,
                "base_cost": 1,
                "detectability": 0.35,
            }
        )
        if entry_nodes:
            edges.append(
                {
                    "source": vid,
                    "target": entry_nodes[0],
                    "relation": "requires",
                    "weight": round(sev_weight, 2),
                    "explanation": "Discovered weakness can enable initial attacker foothold.",
                }
            )

    return {
        "nodes": nodes,
        "edges": edges,
        "entry_nodes": entry_nodes,
        "objective_nodes": objective_nodes,
    }


def _simulate_defense_what_if(graph: dict, controls: list[dict] | None = None) -> dict:
    """Run a lightweight what-if simulation over attack graph nodes."""
    controls = controls or [
        {
            "control_id": "waf_strict_mode",
            "name": "Strict WAF Rules",
            "target_tactics": ["initial-access", "execution"],
            "effect": "weaken",
            "probability_multiplier": 0.65,
            "cost_multiplier": 1.2,
            "enabled": True,
        },
        {
            "control_id": "mfa_everywhere",
            "name": "MFA Everywhere",
            "target_tactics": ["credential-access", "lateral-movement"],
            "effect": "block",
            "probability_multiplier": 0.4,
            "cost_multiplier": 1.35,
            "enabled": True,
        },
        {
            "control_id": "edr_behavioral",
            "name": "EDR Behavioral Detection",
            "target_tactics": ["execution", "persistence", "impact"],
            "effect": "detect",
            "probability_multiplier": 0.75,
            "cost_multiplier": 1.5,
            "enabled": True,
        },
    ]

    technique_nodes = [n for n in graph.get("nodes", []) if n.get("type") == "technique"]
    if not technique_nodes:
        return {
            "active_controls": controls,
            "path_results": [],
            "global_metrics": {
                "best_attack_path_probability": 0.0,
                "mean_time_to_objective": 0.0,
                "residual_risk_score": 0.0,
                "control_effectiveness_delta": 0.0,
            },
        }

    baseline_prob = 1.0
    baseline_cost = 0.0
    adjusted_prob = 1.0
    adjusted_cost = 0.0

    per_step = []
    for n in technique_nodes:
        p = _coerce_float(n.get("base_probability"), 0.5)
        c = _coerce_float(n.get("base_cost"), 1.0)
        baseline_prob *= p
        baseline_cost += c

        p_adj = p
        c_adj = c
        tactic = str(n.get("tactic") or "")
        blockers = []
        for ctrl in controls:
            if not ctrl.get("enabled"):
                continue
            if tactic not in (ctrl.get("target_tactics") or []):
                continue
            p_adj *= _coerce_float(ctrl.get("probability_multiplier"), 1.0)
            c_adj *= _coerce_float(ctrl.get("cost_multiplier"), 1.0)
            blockers.append(ctrl.get("name", "Control"))

        adjusted_prob *= max(0.01, p_adj)
        adjusted_cost += c_adj
        per_step.append(
            {
                "node_id": n.get("id"),
                "technique_id": n.get("technique_id", ""),
                "tactic": tactic,
                "base_probability": round(p, 4),
                "adjusted_probability": round(max(0.01, p_adj), 4),
                "base_cost": round(c, 2),
                "adjusted_cost": round(c_adj, 2),
                "affected_by": blockers,
            }
        )

    delta = 0.0
    if baseline_prob > 0:
        delta = max(0.0, min(1.0, 1.0 - (adjusted_prob / baseline_prob)))

    return {
        "active_controls": controls,
        "path_results": [
            {
                "path_id": "primary_path",
                "success_probability": round(adjusted_prob, 6),
                "expected_cost": round(adjusted_cost, 2),
                "expected_time": round(adjusted_cost * 0.85, 2),
                "blocked_by_controls": sorted({b for s in per_step for b in s.get("affected_by", [])}),
            }
        ],
        "per_step_effects": per_step,
        "global_metrics": {
            "baseline_path_probability": round(baseline_prob, 6),
            "best_attack_path_probability": round(adjusted_prob, 6),
            "mean_time_to_objective": round(adjusted_cost * 0.85, 2),
            "residual_risk_score": round(min(1.0, adjusted_prob * 2.0), 4),
            "control_effectiveness_delta": round(delta, 4),
        },
    }


def _attach_novelty(result_payload: dict, chain_steps: list, vulnerabilities: list | None = None, retrieval_results: list | None = None):
    """Attach explainability and what-if simulation artifacts to API result payload."""
    attributions = _build_step_attribution(chain_steps=chain_steps, retrieval_results=retrieval_results)
    graph = _build_causal_attack_graph(chain_steps=chain_steps, vulnerabilities=vulnerabilities)
    simulation = _simulate_defense_what_if(graph)
    result_payload["attack_chain_attribution"] = attributions
    result_payload["attack_graph"] = graph
    result_payload["what_if_simulation"] = simulation


def _build_readable_scenario_text(scenario: str, target_env: str | None, chain_steps: list) -> dict:
    """Create readable, user-focused narrative paragraphs from LLM-generated chain steps."""
    steps = chain_steps or []
    top_steps = steps[:8]
    names = [str(s.get("technique_name") or s.get("name") or s.get("technique_id") or "attack step").strip() for s in top_steps]
    tactics = [str(s.get("tactic") or s.get("phase") or "unknown").strip().replace("-", " ") for s in top_steps]
    env = (target_env or "enterprise environment").strip()

    if names:
        attack_flow = ", then ".join(names[:5])
        if len(names) > 5:
            attack_flow += ", followed by additional chained stages"
    else:
        attack_flow = "multi-stage behavior mapped from your scenario"

    intent_para = (
        f"This scenario models a realistic multi-step security pathway in the {env}, "
        f"aligned to your stated objective and likely progression points."
    )
    flow_para = (
        f"The generated chain indicates a practical progression: {attack_flow}. "
        f"This sequence is modeled from your scenario context and ATT&CK-grounded LLM reasoning."
    )
    workflow_para = (
        "Use this chain as a structured execution and validation workflow: confirm prerequisites, verify each transition, "
        "capture evidence at each stage, and record outcome quality before moving to the next step."
    )
    actions = []
    detailed_flow = []
    proceed_guidance = []
    for idx, step in enumerate(top_steps[:8], start=1):
        name = str(step.get("technique_name") or step.get("name") or step.get("technique_id") or f"Step {idx}")
        tactic = str(step.get("tactic") or step.get("phase") or "unknown").replace("-", " ")
        desc = str(step.get("description") or "No detailed description provided by the chain.").strip()
        rationale = str(step.get("rationale") or "Mapped from scenario context and ATT&CK behavior.").strip()
        mitigation = str(step.get("mitigation") or "Apply layered controls, detection, and hardening for this step.").strip()
        actions.append(f"Step {idx}: Focus on {name} under {tactic} with clear success criteria.")
        detailed_flow.append(
            f"Step {idx} ({tactic}) - {name}. "
            f"Process detail: {desc} "
            f"Chain role: {rationale}"
        )
        proceed_guidance.append(
            f"Step {idx} execution guidance: Prepare required conditions for {name}, run controlled validation for this stage, "
            f"collect concrete evidence artifacts, and confirm that outputs satisfy step-specific success criteria. "
            f"Quality note: {mitigation}"
        )

    return {
        "summary": " ".join([intent_para, flow_para]),
        "paragraphs": [intent_para, flow_para, workflow_para],
        "operator_actions": actions,
        "detailed_attack_flow": detailed_flow,
        "how_to_proceed": proceed_guidance,
        "tactic_sequence": tactics,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    resp = make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/api/status")
def api_status():
    """Quick health ping."""
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/api/latest")
def api_latest():
    mode = (request.args.get("mode") or "").strip().lower()
    payload, meta = _get_latest(mode or None)
    if not payload:
        return jsonify({"error": "No cached result available"}), 404
    return jsonify({"result": payload, "meta": meta})


@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    data = request.get_json(force=True) or {}
    request_id = str(data.get("request_id") or "").strip()
    if not request_id:
        return jsonify({"error": "request_id is required"}), 400
    with _cancel_lock:
        ev = _cancel_events.get(request_id)
        if ev is None:
            return jsonify({"status": "not_found", "request_id": request_id}), 404
        ev.set()
    return jsonify({"status": "cancelled", "request_id": request_id})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Option 1 — Full Web Vulnerability Scan."""
    data = request.get_json(force=True) or {}
    target_url_raw = (data.get("target_url") or "").strip()
    request_id = str(data.get("request_id") or "").strip()

    if not target_url_raw:
        return jsonify({"error": "target_url is required"}), 400

    try:
        target_url = run_module.normalize_url(target_url_raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        # Attach queue handler to root logger
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Starting full web scan on: {target_url}")

            # Step 1 – Attack surface discovery
            sq.put("[STEP 1/5] Discovering attack surface (crawl + common paths)…")
            discovery = run_module.discover_attack_surface(
                target_url,
                max_pages=int(getattr(config, "WEB_UI_DISCOVERY_MAX_PAGES", 18)),
                timeout=float(getattr(config, "WEB_UI_DISCOVERY_TIMEOUT_S", 6.0)),
            )
            routes = discovery.get("routes", [])
            _check_cancel(cancel_event)
            sq.put(f"[OK] Found {len(routes)} routes, {len(discovery.get('forms', []))} forms.")

            # Step 2 – Web Recon
            sq.put("[STEP 2/5] Running web recon…")
            recon_data = WebReconAgent(
                target_url,
                timeout_s=float(getattr(config, "WEB_UI_RECON_TIMEOUT_S", 6.0)),
            ).run()
            _check_cancel(cancel_event)
            if not recon_data.get("reachable"):
                sq.put(f"[ERROR] Target {target_url} is not reachable. Aborting.")
                return

            # Step 3 – Passive + live vulnerability scan
            sq.put("[STEP 3/5] Scanning for vulnerabilities (passive + live)…")
            passive_result = VulnerabilityScanner(recon_data).scan()
            passive_vulns = passive_result.get("vulnerabilities", [])
            _check_cancel(cancel_event)
            sq.put(f"[OK] Passive scanner found {len(passive_vulns)} issue(s).")

            live_vulns: list = []
            try:
                live_report = LiveVulnChecker(
                    target_url,
                    timeout=int(getattr(config, "WEB_UI_LIVE_TIMEOUT_S", 6.0)),
                ).run_full_check()
                _check_cancel(cancel_event)
                live_vulns = [f for f in live_report.get("vulnerabilities", []) if f.get("confirmed_live")]
                sq.put(f"[OK] Live checker confirmed {len(live_vulns)} issue(s).")
            except Exception as exc:
                sq.put(f"[WARN] Live check failed: {exc}")

            form_vulns = run_module._probe_discovered_forms(
                target_url,
                discovery.get("forms", []),
                timeout=float(getattr(config, "WEB_UI_FORM_TIMEOUT_S", 5.0)),
            )
            _check_cancel(cancel_event)
            sq.put(f"[OK] Form probe found {len(form_vulns)} issue(s).")

            merged_vulns = run_module._merge_vulnerabilities(passive_vulns, live_vulns, form_vulns)
            counts = run_module._severity_counts(merged_vulns)
            risk = run_module._overall_risk(counts)
            sq.put(f"[OK] Merged total: {len(merged_vulns)} vulnerabilities. Overall risk: {risk}")

            # Step 4 – MITRE mapping + RAG
            sq.put("[STEP 4/5] Loading FAISS index and mapping to MITRE ATT&CK…")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)
            mapped = ctx.mapper.map_vulnerabilities(merged_vulns)
            chain = ctx.mapper.build_attack_chain(mapped, target_url=target_url)
            sq.put(f"[OK] MITRE mapping complete. Attack chain has {len(chain)} steps.")

            # Step 5 – Report generation
            sq.put("[STEP 5/5] Generating reports…")
            scan_result = {
                "target_url": target_url,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "total_vulns": len(merged_vulns),
                "severity_counts": counts,
                "overall_risk": risk,
                "vulnerabilities": merged_vulns,
                "tech_stack": recon_data.get("tech_stack", {}),
            }
            report = ReportGenerator().generate(
                target_url=target_url,
                recon_data=recon_data,
                scan_result=scan_result,
                attack_chain=chain,
                llm_analysis="LLM analysis skipped in web UI mode.",
            )
            _check_cancel(cancel_event)
            txt_path = run_module._write_scan_text_report(
                target_url=target_url,
                discovery=discovery,
                vulnerabilities=merged_vulns,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report saved: {txt_path.name}")
            sq.put(f"[OK] JSON report: {Path(report.get('json_path', '')).name}")
            sq.put(f"[OK] Markdown report: {Path(report.get('md_path', '')).name}")

            # Emit structured result for the UI to parse
            chain_with_vuln = []
            for s in chain:
                x = dict(s)
                sv = x.get("source_vulnerability") or {}
                x["vulnerability_name"] = str(sv.get("type") or "")
                x["vulnerability_detail"] = str(sv.get("detail") or "")
                x["vulnerability_severity"] = str(sv.get("severity") or "")
                chain_with_vuln.append(x)

            scenario_summary = (
                f"Full scan for {target_url}. "
                f"Total findings: {len(merged_vulns)}. "
                f"Risk profile: {risk}. "
                f"Primary findings include: {', '.join([str(v.get('type') or 'Finding') for v in merged_vulns[:6]])}."
            )
            result_payload = {
                "type": "result",
                "target_url": target_url,
                "overall_risk": risk,
                "severity_counts": counts,
                "total_vulns": len(merged_vulns),
                "vulnerabilities": merged_vulns,
                "attack_chain": chain_with_vuln,
                "readable_scenario": _build_readable_scenario_text(
                    scenario=scenario_summary,
                    target_env=target_url,
                    chain_steps=chain_with_vuln,
                ),
                "reports": {
                    "txt": str(txt_path),
                    "json": str(report.get("json_path", "")),
                    "md": str(report.get("md_path", "")),
                    "pdf": str(report.get("pdf_path", "")),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=chain,
                vulnerabilities=merged_vulns,
                retrieval_results=[],
            )
            _store_latest("fullscan", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Scan complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/scenario", methods=["POST"])
def api_scenario():
    """Option 2 — Generate Attack Scenario (No URL)."""
    data = request.get_json(force=True) or {}
    raw_scenario  = (data.get("scenario") or "").strip()
    request_id = str(data.get("request_id") or "").strip()
    target_env    = (data.get("target_env") or "Enterprise Windows Active Directory network").strip()
    chain_len_raw = str(data.get("chain_length") or config.DEFAULT_CHAIN_LENGTH).strip()

    if not raw_scenario:
        return jsonify({"error": "scenario is required"}), 400

    try:
        scenario = sanitize_scenario(raw_scenario)
    except Exception as exc:
        return jsonify({"error": f"Invalid scenario: {exc}"}), 400

    # Use 14 steps by default for full ATT&CK tactic coverage when possible.
    chain_len = int(chain_len_raw) if chain_len_raw.isdigit() else 14
    chain_len = max(8, min(chain_len, 14))  # clamp 8–14

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Generating attack scenario: {scenario[:80]}")
            sq.put(f"[INFO] Target environment: {target_env}")
            sq.put(f"[INFO] Chain length: {chain_len}")

            sq.put("[STEP 1/3] Loading FAISS index…")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)
            sq.put("[OK] RAG engine ready.")

            sq.put("[STEP 2/3] Generating attack chain via RAG + LLM…")
            result = ctx.generator.generate(
                scenario=scenario,
                target_environment=target_env,
                chain_length=chain_len,
            )
            _check_cancel(cancel_event)
            json_path = ctx.generator.export_json(result)
            md_path   = ctx.generator.export_markdown(result)
            pdf_path = ""
            try:
                pdf_path = render_markdown_to_pdf(Path(md_path), Path(md_path).with_suffix(".pdf"))
            except Exception as exc:
                sq.put(f"[WARN] PDF generation failed: {exc}")
            sq.put(f"[OK] Chain generated with {len(result.get('attack_chain', {}).get('attack_chain', []))} steps.")

            sq.put("[STEP 3/3] Building MITRE mapping report…")
            chain_steps = result.get("attack_chain", {}).get("attack_chain", [])
            vulnerabilities = [
                {
                    "type": "Scenario Attack Step",
                    "severity": "MEDIUM",
                    "detail": s.get("description", s.get("technique_name", "")),
                    "evidence": s.get("rationale", "Generated from scenario and RAG context."),
                    "recommendation": s.get("mitigation", "Apply layered security controls."),
                    "mitre_hint": s.get("technique_id", ""),
                }
                for s in chain_steps
            ]
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _check_cancel(cancel_event)
            txt_path = run_module._write_option_text_report(
                option_slug="scenario",
                mode_name="Generate Attack Scenario (No URL)",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report: {txt_path.name}")
            sq.put(f"[OK] JSON report: {Path(json_path).name}")
            sq.put(f"[OK] Markdown report: {Path(md_path).name}")

            analysis  = result.get("analysis", {})
            latency   = result.get("latency", {})
            retrieval = result.get("retrieval_results", [])

            # Enrich chain steps — replace 'Unknown' names from FAISS
            enriched_chain = _enrich_chain(chain_steps, ctx.rag)

            result_payload = {
                "type": "result",
                "scenario": scenario,
                "target_env": target_env,
                "faithfulness_score": result.get("faithfulness_score", 0),
                "tactical_coverage": analysis.get("tactical_coverage", {}).get("coverage_ratio", 0),
                "unique_techniques": analysis.get("unique_techniques", 0),
                "pipeline_latency_s": latency.get("pipeline_total_s", 0),
                "attack_chain": enriched_chain,
                "readable_scenario": _build_readable_scenario_text(
                    scenario=scenario,
                    target_env=target_env,
                    chain_steps=enriched_chain,
                ),
                "reports": {
                    "txt": str(txt_path),
                    "json": str(json_path),
                    "md": str(md_path),
                    "pdf": str(pdf_path),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=enriched_chain,
                vulnerabilities=vulnerabilities,
                retrieval_results=retrieval,
            )
            _store_latest("scenario", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Scenario generation complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Option 3 — Validate Scenario on Target URL."""
    data = request.get_json(force=True) or {}
    raw_scenario  = (data.get("scenario") or "").strip()
    target_url_raw = (data.get("target_url") or "").strip()
    request_id = str(data.get("request_id") or "").strip()

    if not raw_scenario or not target_url_raw:
        return jsonify({"error": "scenario and target_url are required"}), 400

    try:
        scenario   = sanitize_scenario(raw_scenario)
        target_url = run_module.normalize_url(target_url_raw)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Validating scenario on: {target_url}")

            sq.put("[STEP 1/4] Detecting attack type from scenario…")
            attack_type = detect_attack_type(scenario)
            _check_cancel(cancel_event)
            sq.put(f"[OK] Detected attack type: {attack_type}")

            sq.put(f"[STEP 2/4] Probing target for {attack_type}…")
            probe = probe_target(
                target_url,
                attack_type,
                timeout=float(getattr(config, "WEB_UI_PROBE_TIMEOUT_S", 5.0)),
            )
            _check_cancel(cancel_event)
            status = "CONFIRMED" if probe.get("found") else "NOT CONFIRMED"
            sq.put(f"[OK] Probe result: {status} | Severity: {probe.get('severity', 'N/A')}")

            sq.put("[STEP 3/4] Loading RAG engine and mapping MITRE techniques…")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)

            evidence = probe.get("evidence", [])
            vuln_items = []
            for ev in evidence:
                if not ev.get("confirmed"):
                    continue
                vuln_items.append({
                    "type": f"Targeted Validation ({attack_type})",
                    "detail": ev.get("detail", "Targeted evidence detected"),
                    "severity": probe.get("severity", "MEDIUM"),
                    "cwe_id": "CWE-20",
                    "mitre_hint": "",
                    "recommendation": probe.get("recommendation", "Review and patch issue."),
                    "evidence": f"{ev.get('url', target_url)} | {ev.get('payload', 'probe')}",
                    "confirmed_live": True,
                })
            if not vuln_items:
                vuln_items.append({
                    "type": f"Targeted Validation ({attack_type})",
                    "detail": "No automatic confirmation; manual verification recommended.",
                    "severity": "LOW",
                    "cwe_id": "CWE-200",
                    "mitre_hint": "",
                    "recommendation": probe.get("recommendation", "Perform manual validation."),
                    "evidence": probe.get("manual_test", target_url),
                    "confirmed_live": False,
                })

            mapped = ctx.mapper.map_vulnerabilities(vuln_items)
            _check_cancel(cancel_event)
            chain  = ctx.mapper.build_attack_chain(mapped, target_url=target_url)
            sq.put(f"[OK] MITRE mapping: {len(chain)} attack chain steps.")

            sq.put("[STEP 4/4] Generating reports…")
            recon  = WebReconAgent(target_url).run()
            counts = run_module._severity_counts(vuln_items)
            risk   = run_module._overall_risk(counts)
            report = ReportGenerator().generate(
                target_url=target_url,
                recon_data=recon,
                scan_result={
                    "target_url": target_url,
                    "total_vulns": len(vuln_items),
                    "severity_counts": counts,
                    "overall_risk": risk,
                    "vulnerabilities": vuln_items,
                    "tech_stack": recon.get("tech_stack", {}),
                },
                attack_chain=chain,
                llm_analysis=(
                    f"Scenario-driven validation for attack type '{attack_type}'. Status: {status}."
                ),
            )
            _check_cancel(cancel_event)
            txt_path = run_module._write_option_text_report(
                option_slug="validation",
                mode_name="Validate Scenario on Target URL",
                scenario=scenario,
                target_url=target_url,
                vulnerabilities=vuln_items,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report: {txt_path.name}")

            result_payload = {
                "type": "result",
                "scenario": scenario,
                "target_url": target_url,
                "attack_type": attack_type,
                "probe_status": status,
                "probe_severity": probe.get("severity", "N/A"),
                "overall_risk": risk,
                "severity_counts": counts,
                "vulnerabilities": vuln_items,
                "attack_chain": chain,
                "reports": {
                    "txt": str(txt_path),
                    "json": str(report.get("json_path", "")),
                    "md": str(report.get("md_path", "")),
                    "pdf": str(report.get("pdf_path", "")),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=chain,
                vulnerabilities=vuln_items,
                retrieval_results=[],
            )
            _store_latest("validate", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Validation complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Option 4 — Analyze Scenario Only (RAG + MITRE, no LLM call)."""
    data = request.get_json(force=True) or {}
    raw_scenario = (data.get("scenario") or "").strip()
    chain_len_raw = str(data.get("chain_length") or config.DEFAULT_CHAIN_LENGTH).strip()
    request_id = str(data.get("request_id") or "").strip()

    if not raw_scenario:
        return jsonify({"error": "scenario is required"}), 400

    try:
        scenario = sanitize_scenario(raw_scenario)
    except Exception as exc:
        return jsonify({"error": f"Invalid scenario: {exc}"}), 400

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Analyzing scenario: {scenario[:80]}")

            sq.put("[STEP 1/3] Loading FAISS index…")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)
            sq.put("[OK] RAG engine ready.")

            chain_len = int(chain_len_raw) if chain_len_raw.isdigit() else config.DEFAULT_CHAIN_LENGTH
            chain_len = max(8, min(chain_len, 14))

            sq.put("[STEP 2/3] Generating attack chain via RAG + LLM...")
            result = ctx.generator.generate(
                scenario=scenario,
                target_environment="General enterprise environment",
                chain_length=chain_len,
            )
            _check_cancel(cancel_event)
            json_path = ctx.generator.export_json(result)
            md_path = ctx.generator.export_markdown(result)
            pdf_path = ""
            try:
                pdf_path = render_markdown_to_pdf(Path(md_path), Path(md_path).with_suffix(".pdf"))
            except Exception as exc:
                sq.put(f"[WARN] PDF generation failed: {exc}")
            chain_steps = result.get("attack_chain", {}).get("attack_chain", [])
            sq.put(f"[OK] {len(chain_steps)} steps generated.")

            sq.put("[STEP 3/3] Building MITRE mapping and text report…")
            vulnerabilities = [
                {
                    "type": "Scenario Analysis Step",
                    "severity": "MEDIUM",
                    "detail": s.get("description", s.get("technique_name", "")),
                    "evidence": s.get("rationale", "Derived from scenario-only analysis."),
                    "recommendation": s.get("mitigation", "Apply ATT&CK-aligned defensive controls."),
                    "mitre_hint": s.get("technique_id", ""),
                }
                for s in chain_steps
            ]
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _check_cancel(cancel_event)
            txt_path = run_module._write_option_text_report(
                option_slug="analysis",
                mode_name="Analyze Scenario Only",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report: {txt_path.name}")

            analysis = result.get("analysis", {})
            latency  = result.get("latency", {})
            retrieval = result.get("retrieval_results", [])

            # Enrich chain steps — replace 'Unknown' names from MITRE DB
            enriched_chain = _enrich_chain(chain_steps, ctx.mitre_db)

            result_payload = {
                "type": "result",
                "scenario": scenario,
                "faithfulness_score": result.get("faithfulness_score", 0),
                "tactical_coverage": analysis.get("tactical_coverage", {}).get("coverage_ratio", 0),
                "unique_techniques": analysis.get("unique_techniques", 0),
                "pipeline_latency_s": latency.get("pipeline_total_s", 0),
                "attack_chain": enriched_chain,
                "readable_scenario": _build_readable_scenario_text(
                    scenario=scenario,
                    target_env="General enterprise environment",
                    chain_steps=enriched_chain,
                ),
                "reports": {
                    "txt": str(txt_path),
                    "json": str(json_path),
                    "md": str(md_path),
                    "pdf": str(pdf_path),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=enriched_chain,
                vulnerabilities=vulnerabilities,
                retrieval_results=retrieval,
            )
            _store_latest("analyze", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Analysis complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── Server entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    config.ensure_directories()
    run_module.setup_logging()
    threading.Thread(target=_prewarm_runtime, daemon=True).start()
    print("\n" + "=" * 60)
    print("  Red ELISAR — Web Application")
    print("  Open your browser at: http://127.0.0.1:7860")
    print("  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=7860, debug=False, threaded=True)
