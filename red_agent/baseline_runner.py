"""
Red ELISAR — Baseline Comparison Module (Paper-Aligned)
=========================================================
Compares Red ELISAR (RAG+FAISS) against baseline models
(no RAG) to demonstrate RAG performance improvement.

Paper Comparison Targets:
    1. Mistral 7B (no RAG) — direct LLM generation
    2. LLaMA 3 8B (no RAG) — direct LLM generation
    3. Red ELISAR: Mistral + RAG+FAISS — full pipeline
    4. Red ELISAR: LLaMA 3 + RAG+FAISS — full pipeline

Metrics Collected (per Table in paper):
    - Accuracy: proportion of valid technique IDs in output
    - Precision: correctly retrieved / total retrieved
    - Recall: correctly retrieved / total expected
    - F1 Score: harmonic mean of precision and recall
    - Context Relevance (recall@5): relevant in top-5 / 5
    - Latency (s): end-to-end generation time

Evaluation Protocol:
    - 50 offensive scenarios (18 single + 32 multi-step)
    - 5 independent runs per configuration
    - Report mean ± std for all metrics
"""

import json
import time
import logging
import statistics
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import requests

import config
from vector_store_faiss import FAISSVectorStore
from rag_engine import RAGEngine
from attack_chain_generator import AttackChainGenerator
from llm_client import groq_chat_json, mistral_chat_json

logger = logging.getLogger("red_elisar.baseline")


# ============================================================================
# BASELINE (NO-RAG) GENERATOR
# ============================================================================

class BaselineGenerator:
    """
    Direct LLM generation without RAG retrieval.

    Used as the baseline to measure RAG improvement. The LLM generates
    attack chains purely from its parametric knowledge without any
    retrieved MITRE ATT&CK context.
    """

    BASELINE_SYSTEM_PROMPT = (
        "You are a cybersecurity expert. Generate a realistic MITRE ATT&CK technique sequence. "
        "For multi-step scenarios, ensure logical progression across tactics (Recon → Initial Access → Execution → Persistence/Privilege Escalation → Discovery → Lateral Movement → Collection/Exfiltration/Impact). "
        "Output ONLY valid JSON. No markdown, no extra text."
    )

    BASELINE_USER_PROMPT = """SCENARIO:
{scenario}

TARGET ENVIRONMENT:
{target_environment}

TASK:
Generate exactly {chain_length} steps.

OUTPUT FORMAT (STRICT JSON):
{{
    "steps": [
        {{"step": 1, "technique_id": "Txxxx", "technique_name": "...", "tactic": "...", "description": "..."}}
    ]
}}
"""

    def __init__(self, model: str = None):
        """
        Initialize baseline generator.

        Args:
            model: Model name string. Use 'llama-3.1-8b-instant' (Groq)
                   or 'mistral-small-latest' (Mistral API).
                   Defaults to config.GROQ_MODEL.
        """
        self.model       = model or config.GROQ_MODEL
        # Detect which API to call from the model name
        self._use_mistral = "mistral" in self.model.lower()

    def generate(
        self,
        scenario: str,
        target_environment: str = "Enterprise Windows Active Directory network",
        chain_length: int = 5,
    ) -> dict:
        """Generate attack chain WITHOUT RAG context (baseline).

        Routes to Mistral API if model name contains 'mistral',
        otherwise routes to Groq API (LLaMA 3).
        """
        start = time.perf_counter()

        user_content = self.BASELINE_USER_PROMPT.format(
            chain_length=chain_length,
            scenario=scenario,
            target_environment=target_environment,
        )
        messages = [
            {"role": "system", "content": self.BASELINE_SYSTEM_PROMPT},
            {"role": "user",   "content": user_content},
        ]

        try:
            if self._use_mistral:
                result = mistral_chat_json(
                    messages=messages,
                    model=self.model,
                    max_tokens=config.LLM_MAX_TOKENS,
                    temperature=config.LLM_TEMPERATURE,
                    top_p=config.LLM_TOP_P,
                )
            else:
                result = groq_chat_json(
                    messages=messages,
                    model=self.model,
                    max_tokens=config.LLM_MAX_TOKENS,
                    temperature=config.LLM_TEMPERATURE,
                    top_p=config.LLM_TOP_P,
                )

            raw_text = result.content

        except Exception as e:  # noqa: BLE001
            logger.error(f"Baseline generation failed ({self.model}): {e}")
            return {"error": str(e), "model": self.model,
                    "latency_s": time.perf_counter() - start}

        latency_s = time.perf_counter() - start

        # Parse JSON response
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            import re as _re
            match = _re.search(r'\{.*\}', raw_text, _re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group())
                except json.JSONDecodeError:
                    parsed = {"attack_chain": [], "metadata": {}}
            else:
                parsed = {"attack_chain": [], "metadata": {}}

        return {
            "attack_chain": parsed,
            "model":        self.model,
            "rag_enabled":  False,
            "latency_s":    latency_s,
            "scenario":     scenario,
        }



# ============================================================================
# EVALUATION METRICS
# ============================================================================

def compute_metrics(
    generated_chain: dict,
    expected_techniques: list[str],
    retrieved_techniques: list[str] = None,
) -> dict:
    """
    Compute paper-aligned evaluation metrics.

    Args:
        generated_chain: Parsed attack chain output.
        expected_techniques: Ground truth technique IDs.
        retrieved_techniques: Retrieved technique IDs (for context relevance).

    Returns:
        Dictionary of metric values.
    """
    import re

    # Extract technique IDs from generated output (supports legacy and new formats)
    chain_steps = []
    if isinstance(generated_chain, dict):
        if isinstance(generated_chain.get("attack_chain"), list):
            chain_steps = generated_chain.get("attack_chain", [])
        elif isinstance(generated_chain.get("steps"), list):
            chain_steps = generated_chain.get("steps", [])
        elif isinstance(generated_chain.get("attack_chain"), dict):
            chain_steps = generated_chain.get("attack_chain", {}).get("attack_chain", [])
    
    generated_ids: list[str] = []
    for step in chain_steps:
        if not isinstance(step, dict):
            continue
        tid = step.get("technique_id") or step.get("technique") or ""
        tid = str(tid).strip().upper()
        if re.match(r"^T\d{4}(\.\d{3})?$", tid):
            generated_ids.append(tid)

    # -- Accuracy: proportion of valid MITRE technique IDs
    total_steps = len(chain_steps)
    valid_ids = len(generated_ids)
    accuracy = valid_ids / total_steps if total_steps > 0 else 0.0

    # -- Precision: correctly generated / total generated
    expected_set = {str(x).strip().upper() for x in (expected_techniques or []) if str(x).strip()}
    generated_set = set(generated_ids)
    
    # Use base technique matching (T1059 matches T1059.001)
    true_positives = 0
    for gid in generated_set:
        base_gid = gid.split(".")[0]
        if gid in expected_set or base_gid in expected_set:
            true_positives += 1
        else:
            for eid in expected_set:
                if eid.split(".")[0] == base_gid:
                    true_positives += 1
                    break

    precision = true_positives / len(generated_set) if generated_set else 0.0
    recall = true_positives / len(expected_set) if expected_set else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    # -- Context Relevance (recall@5): relevant retrieved / 5
    context_relevance = 0.0
    if retrieved_techniques:
        retrieved_set = {str(x).strip().upper() for x in (retrieved_techniques or []) if str(x).strip()}
        relevant_retrieved = 0
        for rid in retrieved_techniques[:5]:
            rid = str(rid).strip().upper()
            base_rid = rid.split(".")[0]
            if rid in expected_set or base_rid in expected_set:
                relevant_retrieved += 1
            else:
                for eid in expected_set:
                    if eid.split(".")[0] == base_rid:
                        relevant_retrieved += 1
                        break
        context_relevance = relevant_retrieved / 5.0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "context_relevance": round(context_relevance, 4),
        "generated_technique_count": len(generated_ids),
        "expected_technique_count": len(expected_techniques),
        "true_positives": true_positives,
    }


# ============================================================================
# BASELINE RUNNER — Full Comparison Suite
# ============================================================================

class BaselineRunner:
    """
    Runs the complete baseline comparison experiment.

    Executes all scenarios across all model configurations
    for n_runs each, collecting metrics for statistical comparison.
    """

    def __init__(self, vector_store: FAISSVectorStore = None):
        """
        Initialize the baseline runner.

        Args:
            vector_store: Optional FAISSVectorStore for RAG configurations.
        """
        self.vector_store = vector_store
        self.results: list[dict] = []

    def load_scenarios(self) -> list[dict]:
        """Load the 50 offensive scenarios from data directory."""
        scenarios_path = config.DATA_DIR / "offensive_logs.json"
        if not scenarios_path.exists():
            logger.error(f"Scenarios file not found: {scenarios_path}")
            return []

        with open(scenarios_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data.get("scenarios", [])

    def run_baseline(
        self,
        model: str,
        scenarios: list[dict],
        n_runs: int = None,
    ) -> list[dict]:
        """
        Run baseline (no RAG) evaluation for a model.

        Args:
            model: Ollama model name.
            scenarios: List of scenario dicts.
            n_runs: Number of runs per scenario.

        Returns:
            List of result dicts.
        """
        if n_runs is None:
            n_runs = config.N_EVALUATION_RUNS

        generator = BaselineGenerator(model=model)
        results = []

        for run_idx in range(n_runs):
            logger.info(f"[Baseline {model}] Run {run_idx + 1}/{n_runs}")

            for scenario in scenarios:
                sid = scenario["scenario_id"]
                query = scenario.get("query", scenario.get("description", ""))
                expected = scenario.get("expected_techniques", [])

                logger.info(f"  Scenario {sid}: {query[:50]}...")

                result = generator.generate(
                    scenario=query,
                    chain_length=len(expected) if expected else 5,
                )

                metrics = compute_metrics(
                    result.get("attack_chain", {}),
                    expected,
                )

                results.append({
                    "config": f"{model}_no_rag",
                    "model": model,
                    "rag_enabled": False,
                    "run": run_idx + 1,
                    "scenario_id": sid,
                    "scenario_type": scenario.get("scenario_type", ""),
                    "metrics": metrics,
                    "latency_s": result.get("latency_s", 0),
                })

        return results

    def run_rag(
        self,
        model: str,
        scenarios: list[dict],
        n_runs: int = None,
    ) -> list[dict]:
        """
        Run RAG-enhanced evaluation for a model.

        Args:
            model: Ollama model name.
            scenarios: List of scenario dicts.
            n_runs: Number of runs.

        Returns:
            List of result dicts.
        """
        if n_runs is None:
            n_runs = config.N_EVALUATION_RUNS

        if self.vector_store is None:
            logger.error("Vector store not provided for RAG evaluation")
            return []

        generator = AttackChainGenerator(self.vector_store, model=model)
        results = []

        for run_idx in range(n_runs):
            logger.info(f"[RAG {model}] Run {run_idx + 1}/{n_runs}")

            for scenario in scenarios:
                sid = scenario["scenario_id"]
                query = scenario.get("query", scenario.get("description", ""))
                expected = scenario.get("expected_techniques", [])

                logger.info(f"  Scenario {sid}: {query[:50]}...")

                start = time.perf_counter()
                try:
                    result = generator.generate(
                        scenario=query,
                        chain_length=len(expected) if expected else 5,
                    )
                    latency = time.perf_counter() - start

                    # Extract retrieved technique IDs
                    retrieved_ids = [
                        r["technique_id"]
                        for r in result.get("retrieval_results", [])
                    ]

                    metrics = compute_metrics(
                        result.get("attack_chain", {}),
                        expected,
                        retrieved_techniques=retrieved_ids,
                    )

                except Exception as e:
                    logger.error(f"RAG generation failed for {sid}: {e}")
                    latency = time.perf_counter() - start
                    metrics = {
                        "accuracy": 0,
                        "precision": 0,
                        "recall": 0,
                        "f1_score": 0,
                        "context_relevance": 0,
                    }
                    retrieved_ids = []

                results.append({
                    "config": f"{model}_rag",
                    "model": model,
                    "rag_enabled": True,
                    "run": run_idx + 1,
                    "scenario_id": sid,
                    "scenario_type": scenario.get("scenario_type", ""),
                    "metrics": metrics,
                    "latency_s": latency,
                })

        return results

    def run_full_comparison(
        self,
        n_runs: int = None,
        max_scenarios: int = None,
    ) -> dict:
        """
        Run the complete comparison experiment.

        Executes:
        1. Mistral (no RAG)
        2. LLaMA 3 (no RAG)
        3. Mistral + RAG
        4. LLaMA 3 + RAG

        Args:
            n_runs: Number of runs per config (default: 5).
            max_scenarios: Limit scenarios for testing.

        Returns:
            Complete comparison results dict.
        """
        if n_runs is None:
            n_runs = config.N_EVALUATION_RUNS

        scenarios = self.load_scenarios()
        if not scenarios:
            return {"error": "No scenarios loaded"}

        if max_scenarios:
            scenarios = scenarios[:max_scenarios]

        logger.info(
            f"Starting full comparison: {len(scenarios)} scenarios × "
            f"{n_runs} runs × {len(config.BENCHMARK_MODELS)} models × 2 configs"
        )

        all_results = []

        for model in config.BENCHMARK_MODELS:
            # Baseline (no RAG)
            logger.info(f"\n{'='*60}")
            logger.info(f"BASELINE: {model} (no RAG)")
            logger.info(f"{'='*60}")
            baseline_results = self.run_baseline(model, scenarios, n_runs)
            all_results.extend(baseline_results)

            # RAG-enhanced
            if self.vector_store:
                logger.info(f"\n{'='*60}")
                logger.info(f"RAG: {model} + FAISS HNSW")
                logger.info(f"{'='*60}")
                rag_results = self.run_rag(model, scenarios, n_runs)
                all_results.extend(rag_results)

        # Aggregate statistics
        summary = self._aggregate_results(all_results)

        # Export results
        self._export_results(all_results, summary)

        return {
            "all_results": all_results,
            "summary": summary,
            "n_scenarios": len(scenarios),
            "n_runs": n_runs,
            "models": config.BENCHMARK_MODELS,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _aggregate_results(self, all_results: list[dict]) -> dict:
        """Compute mean ± std for all metrics per configuration."""
        configs = {}
        for r in all_results:
            cfg = r["config"]
            if cfg not in configs:
                configs[cfg] = {
                    "accuracy": [],
                    "precision": [],
                    "recall": [],
                    "f1_score": [],
                    "context_relevance": [],
                    "latency_s": [],
                }

            for metric in ["accuracy", "precision", "recall", "f1_score", "context_relevance"]:
                val = r.get("metrics", {}).get(metric, 0)
                configs[cfg][metric].append(val)

            configs[cfg]["latency_s"].append(r.get("latency_s", 0))

        summary = {}
        for cfg, metrics in configs.items():
            summary[cfg] = {}
            for metric, values in metrics.items():
                if values:
                    mean_val = statistics.mean(values)
                    std_val = statistics.stdev(values) if len(values) > 1 else 0.0
                    summary[cfg][metric] = {
                        "mean": round(mean_val, 4),
                        "std": round(std_val, 4),
                        "min": round(min(values), 4),
                        "max": round(max(values), 4),
                        "n": len(values),
                    }

        return summary

    def _export_results(self, all_results: list[dict], summary: dict):
        """Export experiment results to JSON and formatted table."""
        config.ensure_directories()
        output_dir = config.OUTPUT_DIR
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Full results JSON
        results_path = output_dir / f"baseline_comparison_{timestamp}.json"
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(
                {"results": all_results, "summary": summary},
                f,
                indent=2,
                ensure_ascii=False,
            )
        logger.info(f"Results exported: {results_path}")

        # Summary table
        print("\n" + "=" * 90)
        print("  BASELINE COMPARISON RESULTS (Mean ± Std)")
        print("=" * 90)
        print(
            f"  {'Configuration':<25} {'Accuracy':<14} {'Precision':<14} "
            f"{'Recall':<14} {'F1':<14} {'Latency(s)':<14}"
        )
        print("-" * 90)

        for cfg, metrics in summary.items():
            acc = metrics.get("accuracy", {})
            prec = metrics.get("precision", {})
            rec = metrics.get("recall", {})
            f1 = metrics.get("f1_score", {})
            lat = metrics.get("latency_s", {})

            print(
                f"  {cfg:<25} "
                f"{acc.get('mean', 0):.3f}±{acc.get('std', 0):.3f}  "
                f"{prec.get('mean', 0):.3f}±{prec.get('std', 0):.3f}  "
                f"{rec.get('mean', 0):.3f}±{rec.get('std', 0):.3f}  "
                f"{f1.get('mean', 0):.3f}±{f1.get('std', 0):.3f}  "
                f"{lat.get('mean', 0):.2f}±{lat.get('std', 0):.2f}"
            )

        print("=" * 90)


# ============================================================================
# STANDALONE EXECUTION
# ============================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)

    parser = argparse.ArgumentParser(description="Red ELISAR Baseline Comparison")
    parser.add_argument("--n-runs", type=int, default=1, help="Runs per config")
    parser.add_argument("--max-scenarios", type=int, default=5, help="Limit scenarios")
    parser.add_argument("--model", type=str, default=None, help="Single model to test")
    args = parser.parse_args()

    # Initialize FAISS store
    store = FAISSVectorStore()

    runner = BaselineRunner(vector_store=store)

    if args.model:
        scenarios = runner.load_scenarios()[:args.max_scenarios]
        print(f"\nRunning baseline for {args.model}...")
        baseline = runner.run_baseline(args.model, scenarios, args.n_runs)
        print(f"Baseline: {len(baseline)} results")

        print(f"\nRunning RAG for {args.model}...")
        rag = runner.run_rag(args.model, scenarios, args.n_runs)
        print(f"RAG: {len(rag)} results")
    else:
        results = runner.run_full_comparison(
            n_runs=args.n_runs,
            max_scenarios=args.max_scenarios,
        )
        print(f"\nComparison complete: {len(results.get('all_results', []))} total results")
