import json
import time
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import config
from rag.vector_store_faiss import FAISSVectorStore
from rag.rag_engine import RAGEngine

logger = logging.getLogger("red_elisar.chain_generator")


PREDEFINED_SCENARIOS = {
    "apt_phishing_to_exfil": {
        "scenario": (
            "Advanced persistent threat group targets a corporate enterprise network. "
            "The attack begins with spear-phishing emails containing weaponized Office documents, "
            "establishes persistence through scheduled tasks and registry modifications, "
            "escalates privileges via token manipulation, performs Active Directory reconnaissance, "
            "moves laterally using pass-the-hash, and exfiltrates sensitive data over encrypted C2 channels."
        ),
        "target_environment": "Enterprise Windows Active Directory network with Exchange email servers",
        "chain_length": 7,
    },
    "insider_threat": {
        "scenario": (
            "A malicious insider with valid credentials attempts to escalate access, "
            "disable security monitoring, access restricted file shares, "
            "and exfiltrate intellectual property while evading detection."
        ),
        "target_environment": "Corporate Windows environment with DLP and SIEM monitoring",
        "chain_length": 5,
    },
    "ransomware_attack": {
        "scenario": (
            "Ransomware operator gains initial access through exposed RDP service, "
            "disables antivirus and endpoint detection, deploys ransomware across the network "
            "using PsExec and Group Policy, and encrypts critical data for extortion."
        ),
        "target_environment": "Healthcare organization with Windows servers and workstations",
        "chain_length": 6,
    },
    "supply_chain": {
        "scenario": (
            "Adversary compromises a software supply chain by injecting malicious code into "
            "a trusted software update mechanism, achieving code execution on downstream targets, "
            "establishing covert persistence, and collecting sensitive data."
        ),
        "target_environment": "Enterprise environment with automated software deployment pipeline",
        "chain_length": 5,
    },
    "cloud_hybrid": {
        "scenario": (
            "Attacker targets a hybrid cloud environment by exploiting web application vulnerabilities, "
            "stealing cloud credentials, moving from on-premises to cloud infrastructure, "
            "and accessing cloud storage containing sensitive data."
        ),
        "target_environment": "Hybrid enterprise with on-premises Active Directory and cloud services",
        "chain_length": 6,
    },
}


class AttackChainGenerator:

    def __init__(self, vector_store: FAISSVectorStore, model: str = None):
        self.rag_engine = RAGEngine(vector_store, model=model)
        self.vector_store = vector_store
        self.generation_history: list[dict] = []

    def generate(
        self,
        scenario: str,
        target_environment: str = "Enterprise Windows Active Directory network",
        chain_length: int = None,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> dict:
        result = self.rag_engine.generate_attack_chain(
            scenario=scenario,
            target_environment=target_environment,
            chain_length=chain_length,
            top_k=top_k,
            tactic_filter=tactic_filter,
            platform_filter=platform_filter,
        )
        result["analysis"] = self.analyze_chain(result)
        self.generation_history.append(result)
        return result

    def generate_fast(
        self,
        scenario: str,
        target_environment: str = "Enterprise Windows Active Directory network",
        chain_length: int = None,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> dict:
        result = self.rag_engine.generate_attack_chain_fast(
            scenario=scenario,
            target_environment=target_environment,
            chain_length=chain_length,
            top_k=top_k,
            tactic_filter=tactic_filter,
            platform_filter=platform_filter,
        )
        result["analysis"] = self.analyze_chain(result)
        self.generation_history.append(result)
        return result

    def generate_predefined(self, scenario_key: str) -> dict:
        if scenario_key not in PREDEFINED_SCENARIOS:
            available = ", ".join(PREDEFINED_SCENARIOS.keys())
            raise KeyError(f"Unknown scenario '{scenario_key}'. Available: {available}")
        params = dict(PREDEFINED_SCENARIOS[scenario_key])
        # Respect the predefined scenario length; fall back to DEFAULT_CHAIN_LENGTH only when missing.
        params["chain_length"] = int(params.get("chain_length") or config.DEFAULT_CHAIN_LENGTH)
        logger.info(f"Generating predefined scenario: {scenario_key}")
        return self.generate(**params)

    def generate_batch(self, scenario_keys: Optional[list[str]] = None) -> list[dict]:
        if scenario_keys is None:
            scenario_keys = list(PREDEFINED_SCENARIOS.keys())
        results = []
        for i, key in enumerate(scenario_keys, 1):
            logger.info(f"\n{'#'*60}")
            logger.info(f"BATCH {i}/{len(scenario_keys)}: {key}")
            logger.info(f"{'#'*60}")
            try:
                result = self.generate_predefined(key)
                result["scenario_key"] = key
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to generate {key}: {e}")
                results.append({
                    "scenario_key": key,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        return results

    def analyze_chain(self, result: dict) -> dict:
        chain = result.get("attack_chain", {}).get("attack_chain", [])
        if not chain:
            return {"error": "No attack chain to analyze"}

        # Standard MITRE kill chain phases
        mitre_tactics = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]

        chain_tactics = [step.get("tactic", "").lower().replace(" ", "-") for step in chain]
        covered_tactics = set(chain_tactics) & set(mitre_tactics)

        technique_ids = [step.get("technique_id", "") for step in chain]
        unique_techniques = set(technique_ids)

        steps_with_detection = sum(
            1 for step in chain if step.get("detection_considerations", "").strip()
        )
        hallucinated_steps = sum(
            1 for step in chain if step.get("_hallucination_flag", False)
        )

        return {
            "total_steps": len(chain),
            "unique_techniques": len(unique_techniques),
            "technique_reuse": len(chain) - len(unique_techniques),
            "tactical_coverage": {
                "covered": sorted(covered_tactics),
                "total_mitre_tactics": len(mitre_tactics),
                "coverage_ratio": len(covered_tactics) / len(mitre_tactics),
            },
            "detection_coverage": {
                "steps_with_detection": steps_with_detection,
                "coverage_ratio": steps_with_detection / len(chain) if chain else 0,
            },
            "hallucination_metrics": {
                "hallucinated_steps": hallucinated_steps,
                "total_steps": len(chain),
                "faithfulness_score": result.get("faithfulness_score", 0),
            },
            "latency_summary": {
                "total_pipeline_s": result.get("latency", {}).get("pipeline_total_s", 0),
                "retrieval_ms": result.get("latency", {}).get("retrieval_time_s", 0) * 1000,
                "generation_s": result.get("latency", {}).get("llm_latency_s", 0),
                "tokens_per_second": result.get("latency", {}).get("tokens_per_second", 0),
            },
        }

    def export_json(self, result: dict, output_path: Optional[Path] = None) -> Path:
        config.ensure_directories()
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = config.OUTPUT_DIR / f"attack_chain_{timestamp}.json"
        # Serialize, stripping non-JSON-serializable fields
        clean_result = json.loads(json.dumps(result, default=str))
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(clean_result, f, indent=2, ensure_ascii=False)
        logger.info(f"Attack chain exported to: {output_path}")
        return output_path

    def export_markdown(self, result: dict, output_path: Optional[Path] = None) -> Path:
        config.ensure_directories()
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = config.OUTPUT_DIR / f"attack_chain_report_{timestamp}.md"

        chain    = result.get("attack_chain", {}).get("attack_chain", [])
        analysis = result.get("analysis", {})
        latency  = result.get("latency", {})

        lines = [
            "# Red ELISAR — Attack Chain Report",
            "",
            f"**Generated:** {result.get('timestamp', 'N/A')}",
            f"**Scenario:** {result.get('scenario', 'N/A')}",
            f"**Target Environment:** {result.get('target_environment', 'N/A')}",
            f"**Faithfulness Score:** {result.get('faithfulness_score', 0):.0%}",
            "",
            "---",
            "",
        ]

        # ── Inject live vulnerability probe results if available ──
        probe = result.get("probe_result")
        if probe:
            from vuln_checks.targeted_attack_scanner import format_probe_result_markdown
            lines.append(format_probe_result_markdown(probe))

        lines += [
            "## Attack Chain",
            "",
        ]

        for step in chain:
            hallucinated = " [WARN HALLUCINATED]" if step.get("_hallucination_flag") else ""
            lines.extend([
                f"### Step {step.get('step', '?')}: {step.get('technique_name', 'Unknown')}{hallucinated}",
                "",
                f"- **Technique ID:** `{step.get('technique_id', 'N/A')}`",
                f"- **Tactic:** {step.get('tactic', 'N/A')}",
                f"- **Description:** {step.get('description', 'N/A')}",
                f"- **Rationale:** {step.get('rationale', 'N/A')}",
                f"- **Prerequisites:** {', '.join(step.get('prerequisites', ['None']))}",
                f"- **Detection:** {step.get('detection_considerations', 'N/A')}",
                f"- **Mitigation:** {step.get('mitigation', 'N/A')}",
            ])
            tool_cmds = step.get('tool_commands', [])
            if tool_cmds:
                lines.append(f"- **Tool Commands:**")
                for cmd in tool_cmds[:3]:
                    lines.append(f"  - `{cmd}`")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## Retrieved Techniques (Context)",
            "",
            "| Technique ID | Name | Relevance Score | Tactics |",
            "|:---|:---|:---|:---|",
        ])

        for tech in result.get("retrieval_results", []):
            tactics = ", ".join(tech.get("tactics", [])) if isinstance(tech.get("tactics"), list) else str(tech.get("tactics", ""))
            lines.append(
                f"| `{tech['technique_id']}` | {tech['name']} | "
                f"{tech.get('relevance_score', 'N/A')} | {tactics} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## Performance Metrics",
            "",
            f"- **Total Pipeline Latency:** {latency.get('pipeline_total_s', 0):.2f}s",
            f"- **Retrieval Latency:** {latency.get('retrieval_time_s', 0)*1000:.0f}ms",
            f"- **LLM Generation Latency:** {latency.get('llm_latency_s', 0):.2f}s",
            f"- **Tokens/Second:** {latency.get('tokens_per_second', 0):.1f}",
            "",
            "## Analysis",
            "",
            f"- **Tactical Coverage:** {analysis.get('tactical_coverage', {}).get('coverage_ratio', 0):.0%} "
            f"({len(analysis.get('tactical_coverage', {}).get('covered', []))} / "
            f"{analysis.get('tactical_coverage', {}).get('total_mitre_tactics', 14)} tactics)",
            f"- **Unique Techniques:** {analysis.get('unique_techniques', 0)}",
            f"- **Detection Coverage:** {analysis.get('detection_coverage', {}).get('coverage_ratio', 0):.0%}",
            f"- **Hallucinated Steps:** {analysis.get('hallucination_metrics', {}).get('hallucinated_steps', 0)}",
            "",
            "---",
            "",
            "*Generated by Red ELISAR — Privacy-Preserving Autonomous Offensive Security Agent*",
        ])

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        logger.info(f"Markdown report exported to: {output_path}")
        return output_path

    def export_batch(self, results: list[dict], output_dir: Optional[Path] = None) -> Path:
        config.ensure_directories()
        if output_dir is None:
            output_dir = config.OUTPUT_DIR
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"batch_results_{timestamp}.json"
        clean_results = json.loads(json.dumps(results, default=str))
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "batch_timestamp": datetime.now(timezone.utc).isoformat(),
                "total_scenarios": len(results),
                "results": clean_results,
            }, f, indent=2, ensure_ascii=False)
        logger.info(f"Batch results exported to: {output_path}")
        return output_path

    def list_scenarios(self) -> dict:
        return {
            key: {
                "scenario_preview": val["scenario"][:100] + "...",
                "target_environment": val["target_environment"],
                "chain_length": val["chain_length"],
            }
            for key, val in PREDEFINED_SCENARIOS.items()
        }

    def health_check(self) -> dict:
        status = {
            "vector_store": self.vector_store.get_collection_stats(),
            "ollama": self.rag_engine.check_ollama_health(),
            "system_ready": False,
        }
        vs_ready = status["vector_store"]["total_documents"] > 0
        ollama_ready = (
            status["ollama"]["ollama_reachable"]
            and status["ollama"]["model_available"]
        )
        status["system_ready"] = vs_ready and ollama_ready
        if not vs_ready:
            status["action_required"] = "Index MITRE ATT&CK techniques first"
        elif not ollama_ready:
            status["action_required"] = status["ollama"].get("error", "Start Ollama")
        return status
