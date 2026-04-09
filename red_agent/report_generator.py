"""
report_generator.py — Vulnerability Assessment Report Generator
===============================================================
Produces formatted output reports from Red ELISAR's web assessment:
  - Markdown report (.md) — human-readable full report
  - JSON report (.json)   — machine-readable for further processing

Both files are saved to red_agent/output/ directory.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import config

logger = logging.getLogger("red_elisar.report_generator")

SEVERITY_ICONS = {
    "CRITICAL": "[CRIT]",
    "HIGH":     "[HIGH]",
    "MEDIUM":   "[MED]",
    "LOW":      "[LOW]",
    "INFO":     "[INFO]",
}

TACTIC_ICONS = {
    "reconnaissance":       "[RECON]",
    "resource-development": "[RESOURCE]",
    "initial-access":       "[INITIAL]",
    "execution":            "[EXEC]",
    "persistence":          "[PERSIST]",
    "privilege-escalation": "[PRIV-ESC]",
    "defense-evasion":      "[DEF-EVASION]",
    "credential-access":    "[CRED]",
    "discovery":            "[DISCOVERY]",
    "lateral-movement":     "[LATERAL]",
    "collection":           "[COLLECT]",
    "exfiltration":         "[EXFIL]",
    "impact":               "[IMPACT]",
}


class ReportGenerator:
    """Generates Markdown and JSON vulnerability assessment reports."""

    def __init__(self):
        config.ensure_directories()
        self.output_dir = config.OUTPUT_DIR

    def generate(
        self,
        target_url:   str,
        recon_data:   dict,
        scan_result:  dict,
        attack_chain: list,
        llm_analysis: str,
    ) -> dict:
        """
        Generate both Markdown and JSON reports.
        Returns dict with report paths and summary.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"vuln_report_{timestamp}"

        # Build full report data structure
        report = self._build_report(target_url, recon_data, scan_result,
                                    attack_chain, llm_analysis)

        # Save JSON
        json_path = self.output_dir / f"{base_name}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"[Report] JSON saved: {json_path}")

        # Save Markdown
        md_path = self.output_dir / f"{base_name}.md"
        md_content = self._render_markdown(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"[Report] Markdown saved: {md_path}")

        # Print summary to console
        self._print_console_summary(report)

        return {
            "report_data":  report,
            "json_path":    str(json_path),
            "md_path":      str(md_path),
            "overall_risk": report["overall_risk"],
            "total_vulns":  report["total_vulns"],
        }

    # ─── Build Report Data ────────────────────────────────────────
    def _build_report(self, target_url, recon_data, scan_result,
                      attack_chain, llm_analysis) -> dict:
        tech  = recon_data.get("tech_stack", {})
        vulns = scan_result.get("vulnerabilities", [])

        return {
            "report_title":    "Red ELISAR — Autonomous Web Vulnerability Assessment",
            "target_url":      target_url,
            "scan_date":       datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "overall_risk":    scan_result.get("overall_risk", "UNKNOWN"),
            "total_vulns":     scan_result.get("total_vulns", 0),
            "severity_counts": scan_result.get("severity_counts", {}),
            "tech_stack": {
                "server":   tech.get("server", "Unknown"),
                "language": tech.get("language", "Unknown"),
                "versions": tech.get("versions", {}),
            },
            "recon_summary": {
                "domain":           recon_data.get("domain"),
                "status_code":      recon_data.get("status_code"),
                "ssl_enabled":      recon_data.get("ssl", {}).get("enabled", False),
                "exposed_paths":    len(recon_data.get("exposed_paths", [])),
                "missing_headers":  len(recon_data.get("missing_security_headers", {})),
                "leaked_headers":   len(recon_data.get("leaked_info_headers", {})),
            },
            "vulnerabilities": vulns,
            "attack_chain":    attack_chain,
            "llm_analysis":    llm_analysis,
            "disclaimer": (
                "EDUCATIONAL USE ONLY. This assessment was performed on a "
                "deliberately vulnerable application for learning purposes. "
                "Unauthorized use of this tool against real systems is illegal."
            ),
        }

    # ─── Render Markdown Report ───────────────────────────────────
    def _render_markdown(self, report: dict) -> str:
        risk      = report["overall_risk"]
        risk_icon = SEVERITY_ICONS.get(risk, "[UNK]")
        vulns     = report["vulnerabilities"]
        chain     = report["attack_chain"]
        counts    = report["severity_counts"]
        tech      = report["tech_stack"]

        lines = []

        # Title
        lines += [
            "# Red ELISAR — Autonomous Web Vulnerability Assessment Report",
            "",
            f"> **Generated by:** Red ELISAR (Privacy-Preserving Autonomous Offensive Security Agent)",
            f"> **Framework:** MITRE ATT&CK Enterprise v14",
            "",
            "---",
            "",
        ]

        # Summary box
        lines += [
            "## Executive Summary",
            "",
            f"| Field              | Value                          |",
            f"|-------------------|-------------------------------|",
            f"| **Target URL**    | `{report['target_url']}`      |",
            f"| **Scan Date**     | {report['scan_date']}          |",
            f"| **Overall Risk**  | {risk_icon} **{risk}**         |",
            f"| **Server**        | {tech['server']}               |",
            f"| **Language**      | {tech['language']}             |",
            f"| **Total Vulns**   | **{report['total_vulns']}**    |",
            f"| Critical         | {counts.get('CRITICAL', 0)}    |",
            f"| High             | {counts.get('HIGH', 0)}        |",
            f"| Medium           | {counts.get('MEDIUM', 0)}      |",
            f"| Low              | {counts.get('LOW', 0)}         |",
            "",
            "---",
            "",
        ]

        # Reconnaissance Summary
        recon = report["recon_summary"]
        lines += [
            "## Reconnaissance Summary",
            "",
            f"- **Domain:** `{recon['domain']}`",
            f"- **HTTP Status:** {recon['status_code']}",
            f"- **SSL/HTTPS:** {'Enabled' if recon['ssl_enabled'] else 'Not Enabled (HTTP only)'}",
            f"- **Missing Security Headers:** {recon['missing_headers']}",
            f"- **Leaky Info Headers:** {recon['leaked_headers']}",
            f"- **Exposed Sensitive Paths:** {recon['exposed_paths']}",
            "",
            "---",
            "",
        ]

        # Vulnerability Findings Table
        lines += [
            "## Vulnerability Findings",
            "",
            "| # | Severity | Type | MITRE Hint | CWE |",
            "|---|----------|------|------------|-----|",
        ]
        for i, v in enumerate(vulns, 1):
            icon = SEVERITY_ICONS.get(v["severity"], "[UNK]")
            lines.append(
                f"| {i} | {icon} {v['severity']} | {v['type']} "
                f"| `{v.get('mitre_hint', '-')}` | {v.get('cwe_id', '-')} |"
            )

        lines += ["", "### Detailed Findings", ""]
        for i, v in enumerate(vulns, 1):
            icon = SEVERITY_ICONS.get(v["severity"], "[UNK]")
            lines += [
                f"#### {i}. {icon} {v['severity']} — {v['type']}",
                "",
                f"**Detail:** {v['detail']}",
                "",
                f"**Evidence:** `{v.get('evidence', 'N/A')}`",
                "",
                f"**MITRE ATT&CK:** `{v.get('mitre_hint', 'N/A')}` | "
                f"**CWE:** `{v.get('cwe_id', 'N/A')}`",
                "",
                f"**Recommendation:** {v.get('recommendation', 'N/A')}",
                "",
            ]

        lines += ["---", ""]

        # MITRE ATT&CK Attack Chain
        lines += [
            "## MITRE ATT&CK Attack Chain",
            "",
            f"*Based on discovered vulnerabilities, a realistic attack chain for `{report['target_url']}`:*",
            "",
        ]
        for step in chain:
            tactic_icon = TACTIC_ICONS.get(step["tactic"], "[STEP]")
            vuln_info   = step.get("source_vulnerability", {})
            lines += [
                f"### Step {step['step']}: {tactic_icon} [{step['technique_id']}] {step['technique_name']}",
                f"**Tactic:** `{step['tactic']}`",
                "",
                f"**Description:** {step.get('description', 'N/A')[:250]}",
                "",
                f"**Source Vulnerability:** {vuln_info.get('severity', '')} — {vuln_info.get('type', '')}",
                f"> {vuln_info.get('detail', '')}",
                "",
                f"**Mitigation:** {step.get('recommendation', 'N/A')}",
                "",
            ]

        lines += ["---", ""]

        # LLM Analysis
        if report.get("llm_analysis"):
            lines += [
                "## LLM Attack Narrative (Ollama / Red ELISAR)",
                "",
                report["llm_analysis"],
                "",
                "---",
                "",
            ]

        # Disclaimer
        lines += [
            "## Disclaimer",
            "",
            f"> {report['disclaimer']}",
            "",
        ]

        return "\n".join(lines)

    # ─── Console Summary ──────────────────────────────────────────
    def _print_console_summary(self, report: dict):
        risk      = report["overall_risk"]
        risk_icon = SEVERITY_ICONS.get(risk, "[UNK]")
        counts    = report["severity_counts"]
        chain     = report["attack_chain"]
        vulns     = report["vulnerabilities"]

        print("\n" + "=" * 65)
        print("  RED ELISAR — VULNERABILITY ASSESSMENT REPORT")
        print("=" * 65)
        print(f"  Target     : {report['target_url']}")
        print(f"  Scan Date  : {report['scan_date']}")
        print(f"  Server     : {report['tech_stack']['server']}")
        print(f"  Language   : {report['tech_stack']['language']}")
        print(f"  Risk Level : {risk_icon} {risk}")
        print(f"  Vulns Found: {report['total_vulns']}  "
              f"(CRIT={counts.get('CRITICAL',0)} HIGH={counts.get('HIGH',0)} "
              f"MED={counts.get('MEDIUM',0)} LOW={counts.get('LOW',0)})")
        print("-" * 65)

        print("\n  VULNERABILITIES:")
        for i, v in enumerate(vulns[:10], 1):
            icon = SEVERITY_ICONS.get(v["severity"], "[UNK]")
            print(f"  {i:2}. {icon} [{v['severity']:<8}] {v['type']}")
            print(f"       {v['detail'][:70]}...")

        print("\n  MITRE ATT&CK ATTACK CHAIN:")
        for step in chain:
            tac_icon = TACTIC_ICONS.get(step["tactic"], "[STEP]")
            print(
                f"  Step {step['step']}: {tac_icon} [{step['technique_id']}] "
                f"{step['technique_name']} ({step['tactic']})"
            )

        print("=" * 65)
