"""
web_vuln_agent.py — Master Orchestrator for Red ELISAR Web Assessment
======================================================================
Ties all 5 modules together into one autonomous pipeline:

  URL Input
    → [1] WebReconAgent    (passive recon)
    → [2] VulnerabilityScanner (find vulns)
    → [3] MITREMapper      (map to ATT&CK via existing FAISS RAG)
    → [4] RAGEngine + LLM  (generate attack narrative via Ollama)
    → [5] ReportGenerator  (markdown + JSON output)

Usage:
  python web_vuln_agent.py http://127.0.0.1:5000
  python web_vuln_agent.py http://127.0.0.1:5000 --no-llm   (skip LLM, faster)
"""

import sys
import json
import time
import logging
import argparse
from pathlib import Path

# ── ensure red_agent is importable when run directly ─────────────
sys.path.insert(0, str(Path(__file__).parent.resolve()))

import config
from web_recon          import WebReconAgent
from vuln_scanner       import VulnerabilityScanner
from live_vuln_checker  import LiveVulnChecker
from mitre_mapper       import MITREMapper
from report_generator   import ReportGenerator
from vector_store_faiss import FAISSVectorStore
from rag_engine         import RAGEngine
from mitre_parser       import MITREParser
from chunking           import chunk_techniques

logger = logging.getLogger("red_elisar.web_vuln_agent")

TACTIC_ICONS = {
    "reconnaissance": "[RECON]",
    "resource-development": "[RESOURCE]",
    "initial-access": "[INITIAL]",
    "execution": "[EXEC]",
    "persistence": "[PERSIST]",
    "privilege-escalation": "[PRIV-ESC]",
    "defense-evasion": "[DEF-EVASION]",
    "credential-access": "[CRED]",
    "discovery": "[DISCOVERY]",
    "lateral-movement": "[LATERAL]",
    "collection": "[COLLECT]",
    "exfiltration": "[EXFIL]",
    "impact": "[IMPACT]",
}


# LLM prompt for web vulnerability narrative
WEB_ANALYSIS_SYSTEM = """You are Red ELISAR, an expert penetration tester and MITRE ATT&CK specialist.
Your role is to analyze web application vulnerabilities and describe:
1. How a real attacker would exploit the discovered vulnerabilities step by step
2. The realistic risk and business impact
3. The most critical mitigations to apply first

Be concrete and specific. Use the provided scan data. Respond in plain prose (no JSON required here).
Keep your response under 400 words."""

WEB_ANALYSIS_PROMPT = """
Target Website: {url}
Server Technology: {server} | Language: {language}
Overall Risk: {risk}

VULNERABILITIES DISCOVERED:
{vuln_list}

MITRE ATT&CK ATTACK CHAIN IDENTIFIED:
{chain_summary}

Please provide:
1. ATTACK NARRATIVE: How would a real attacker chain these vulnerabilities to compromise this website?
2. HIGHEST PRIORITY FIX: What single change would reduce risk the most?
3. OVERALL ASSESSMENT: 2-3 sentences on the security posture of this application.
"""


class WebVulnAgent:
    """
    Autonomous web vulnerability assessment agent using the full
    Red ELISAR pipeline (Recon → Scan → MITRE Map → LLM → Report).
    """

    def __init__(self, force_reindex: bool = False):
        config.ensure_directories()
        self._setup_logging()
        self.store  = self._load_or_build_index(force_reindex)
        self.rag    = RAGEngine(self.store)
        self.mapper = MITREMapper(self.rag)

    # Main entry point
    def assess(self, url: str, use_llm: bool = True) -> dict:
        """
        Run the full autonomous vulnerability assessment pipeline.

        Args:
            url:     Target URL (e.g. http://127.0.0.1:5000)
            use_llm: If True, run Groq LLM for narrative analysis.
                     If False, skip LLM (faster, no API call).

        Returns:
            dict with report paths and summary data.
        """
        total_start = time.perf_counter()

        print("\n" + "=" * 65)
        print("  RED ELISAR — AUTONOMOUS WEB VULNERABILITY ASSESSMENT")
        print("  (Passive Recon + Live Active Confirmation + MITRE RAG)")
        print("=" * 65)
        print(f"  Target  : {url}")
        print(f"  LLM     : {'Groq API (enabled)' if use_llm else 'Disabled (--no-llm)'}")
        print("=" * 65)

        # Phase 1: reconnaissance
        print("\n  [1/5] Running Reconnaissance...")
        t1 = time.perf_counter()
        recon = WebReconAgent(url).run()

        if not recon.get("reachable"):
            print(f"\n  Target is not reachable: {recon.get('error')}")
            print("     Make sure the target app is running!")
            sys.exit(1)

        tech = recon.get("tech_stack", {})
        print(f"       Server  : {tech.get('server', 'Unknown')}")
        print(f"       Language: {tech.get('language', 'Unknown')}")
        print(f"       Status  : HTTP {recon.get('status_code')}")
        print(f"       Done in: {time.perf_counter()-t1:.2f}s")

        # Phase 2: passive vulnerability scanning
        print("\n  [2/5] Passive Vulnerability Scan...")
        t2 = time.perf_counter()
        scanner    = VulnerabilityScanner(recon)
        scan_result = scanner.scan()

        counts = scan_result["severity_counts"]
        print(f"       Found  : {scan_result['total_vulns']} vulnerabilities (passive)")
        print(f"       Risk   : {scan_result['overall_risk']}")
        print(f"       CRIT={counts.get('CRITICAL',0)} HIGH={counts.get('HIGH',0)} "
              f"MED={counts.get('MEDIUM',0)} LOW={counts.get('LOW',0)}")
        print(f"       Done in: {time.perf_counter()-t2:.2f}s")

        # Phase 2b: LIVE active confirmation scan
        print("\n  [2b/5] Live Active Confirmation Scan...")
        t2b = time.perf_counter()
        try:
            live_checker  = LiveVulnChecker(url)
            live_report   = live_checker.run_full_check()
            live_vulns    = live_report.get("vulnerabilities", [])
            # Merge confirmed live findings into scan_result
            existing_types = {v["type"] for v in scan_result["vulnerabilities"]}
            new_confirmed  = [v for v in live_vulns
                              if v.get("confirmed_live") and v["type"] not in existing_types]
            scan_result["vulnerabilities"].extend(new_confirmed)
            scan_result["total_vulns"] = len(scan_result["vulnerabilities"])
            live_counts = live_report.get("severity_counts", {})
            for sev, cnt in live_counts.items():
                scan_result["severity_counts"][sev] = (
                    scan_result["severity_counts"].get(sev, 0) + cnt
                )
            # Re-calculate overall risk
            crit = scan_result["severity_counts"].get("CRITICAL", 0)
            high = scan_result["severity_counts"].get("HIGH", 0)
            scan_result["overall_risk"] = (
                "CRITICAL" if crit > 0 else
                "HIGH"     if high >= 2 else
                "MEDIUM"   if high >= 1 else "LOW"
            )
            print(f"       Active findings : {len(new_confirmed)} additional confirmed vulns")
            print(f"       Updated Risk    : {scan_result['overall_risk']}")
        except Exception as e:
            logger.warning(f"Live scan error (non-fatal): {e}")
        print(f"       Done in: {time.perf_counter()-t2b:.2f}s")

        # Phase 3: MITRE ATT&CK mapping
        print("\n  [3/5] Mapping to MITRE ATT&CK (RAG Engine)...")
        t3 = time.perf_counter()
        vulns      = scan_result.get("vulnerabilities", [])
        mapped     = self.mapper.map_vulnerabilities(vulns)
        chain      = self.mapper.build_attack_chain(mapped, target_url=url)

        print(f"       Techniques retrieved via FAISS RAG")
        print(f"       Attack chain: {len(chain)} steps "
              f"across {len(set(s['tactic'] for s in chain))} tactics")
        for step in chain:
            ic = TACTIC_ICONS.get(step["tactic"], "[STEP]")
            print(f"         Step {step['step']}: {ic} [{step['technique_id']}] "
                  f"{step['technique_name']}")
        print(f"       Done in: {time.perf_counter()-t3:.2f}s")

        # Phase 4: LLM narrative
        llm_analysis = ""
        if use_llm:
            print("\n  [4/5] Running LLM Analysis (Groq API)...")
            t4 = time.perf_counter()
            llm_analysis = self._run_llm_analysis(url, scan_result, chain)
            print(f"       Done in: {time.perf_counter()-t4:.2f}s")
        else:
            print("\n  [4/5] LLM skipped (--no-llm flag set)")
            llm_analysis = (
                "LLM analysis skipped. Run without --no-llm flag to get "
                "an AI-generated attack narrative."
            )

        # Phase 5: report generation
        print("\n  [5/5] Generating Reports...")
        t5 = time.perf_counter()
        generator = ReportGenerator()
        result    = generator.generate(
            target_url   = url,
            recon_data   = recon,
            scan_result  = scan_result,
            attack_chain = chain,
            llm_analysis = llm_analysis,
        )
        print(f"       Done in: {time.perf_counter()-t5:.2f}s")

        total_time = time.perf_counter() - total_start
        print(f"\n  Assessment complete in {total_time:.2f}s")
        print(f"  Markdown report : {result['md_path']}")
        print(f"  JSON report     : {result['json_path']}")
        print("=" * 65 + "\n")

        return result

    # LLM analysis
    def _run_llm_analysis(self, url: str, scan_result: dict,
                          chain: list) -> str:
        """Send scan results to Groq API for narrative analysis."""
        # Format vulnerabilities list
        vulns = scan_result.get("vulnerabilities", [])
        vuln_lines = "\n".join(
            f"  - [{v['severity']}] {v['type']}: {v['detail'][:100]}"
            for v in vulns[:10]
        )

        # Format chain summary
        chain_lines = "\n".join(
            f"  Step {s['step']}: [{s['technique_id']}] {s['technique_name']} ({s['tactic']})"
            for s in chain
        )

        tech = scan_result.get("tech_stack", {})
        prompt = WEB_ANALYSIS_PROMPT.format(
            url           = url,
            server        = tech.get("server", "Unknown"),
            language      = tech.get("language", "Unknown"),
            risk          = scan_result.get("overall_risk", "Unknown"),
            vuln_list     = vuln_lines,
            chain_summary = chain_lines,
        )

        # ── Groq Cloud API ────────────────────────────────────────
        try:
            from groq import Groq
            client   = Groq(api_key=config.LLAMA3_API_KEY)
            response = client.chat.completions.create(
                model    = config.GROQ_MODEL,
                messages = [
                    {"role": "system", "content": WEB_ANALYSIS_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                temperature = 0.3,
                max_tokens  = 600,
            )
            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.warning(f"[WebVulnAgent] Groq API error: {e}")
            return f"[WARN] Groq API error: {e}"

        # ── OLD Ollama code (commented out) ───────────────────────
        # try:
        #     import requests as req
        #     payload = {
        #         "model": config.OLLAMA_MODEL,
        #         "messages": [
        #             {"role": "system", "content": WEB_ANALYSIS_SYSTEM},
        #             {"role": "user",   "content": prompt},
        #         ],
        #         "stream": False,
        #         "options": {"temperature": 0.3, "num_predict": 600, "num_ctx": 2048},
        #     }
        #     resp = req.post(f"{config.OLLAMA_BASE_URL}/api/chat",
        #                     json=payload, timeout=config.LLM_TIMEOUT)
        #     resp.raise_for_status()
        #     return resp.json().get("message", {}).get("content", "").strip()
        # except Exception as e:
        #     return f"LLM analysis failed: {e}"
        # ── END Ollama code ───────────────────────────────────────

    # ─── Index Setup ────────────────────────────────────────────
    def _load_or_build_index(self, force_reindex: bool) -> FAISSVectorStore:
        """Load existing FAISS index or build it from MITRE STIX data."""
        store = FAISSVectorStore()
        if not force_reindex and store.is_ready():
            logger.info("[WebVulnAgent] FAISS index already built — loading cached index")
            store.load()
            return store

        logger.info("[WebVulnAgent] Building FAISS index from MITRE ATT&CK data...")
        print("  Building MITRE ATT&CK index (first run — may take 1-2 mins)...")
        parser     = MITREParser()
        techniques = parser.parse()
        chunks     = chunk_techniques(techniques)
        store.index_chunks(chunks, force_reindex=force_reindex)
        print(f"  Index ready: {len(techniques)} techniques indexed.")
        return store

    # ─── Logging Setup ───────────────────────────────────────────
    def _setup_logging(self):
        log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
        handlers  = [logging.StreamHandler(sys.stdout)]
        try:
            fh = logging.FileHandler(config.LOG_FILE, encoding="utf-8", mode="a")
            handlers.append(fh)
        except Exception:
            pass
        logging.basicConfig(
            level=log_level,
            format=config.LOG_FORMAT,
            handlers=handlers,
            force=True,
        )
        logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)


# ─── CLI Entry Point ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Red ELISAR — Autonomous Web Vulnerability Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_vuln_agent.py http://127.0.0.1:5000
  python web_vuln_agent.py http://127.0.0.1:5000 --no-llm
  python web_vuln_agent.py http://127.0.0.1:5000 --force-reindex
        """,
    )
    parser.add_argument("url", help="Target URL to assess (e.g. http://127.0.0.1:5000)")
    parser.add_argument("--no-llm",       action="store_true",
                        help="Skip Groq LLM analysis (faster, no API call)")
    parser.add_argument("--force-reindex", action="store_true",
                        help="Force rebuild of MITRE ATT&CK FAISS index")
    args = parser.parse_args()

    agent  = WebVulnAgent(force_reindex=args.force_reindex)
    result = agent.assess(args.url, use_llm=not args.no_llm)
    return 0


if __name__ == "__main__":
    sys.exit(main())
