"""
Red ELISAR — Evaluation Module
================================
Provides systematic evaluation methodology for the RAG-based
attack chain generation system.

Evaluation Dimensions:
    1. RETRIEVAL QUALITY — How well does the vector search return
       relevant techniques for a given scenario?
    2. GENERATION FAITHFULNESS — Does the LLM only cite techniques
       from the retrieved context (anti-hallucination)?
    3. TACTICAL COHERENCE — Does the generated chain follow a
       logical kill chain progression?
    4. LATENCY PROFILE — End-to-end and per-phase timing metrics.
    5. EMBEDDING QUALITY — Semantic similarity accuracy of the
       embedding model on ATT&CK technique retrieval.

Evaluation Protocol (suggested for academic paper):
    - Run all 5 predefined scenarios 3 times each (15 total runs)
    - Compute mean and standard deviation for all metrics
    - Compare faithfulness score across runs (should be deterministic
      at temperature=0 but Ollama may have minor variance)
    - Measure latency on target hardware (16GB laptop)
    - Report tactical coverage distribution across scenarios

Metrics Reference:
    - Faithfulness: Proportion of cited techniques in retrieval set
    - Recall@k: Proportion of ground-truth techniques in top-k results
    - MRR: Mean Reciprocal Rank of first relevant technique
    - Tactical Coverage: Ratio of kill chain phases covered
    - Latency: End-to-end pipeline time in seconds
"""

import json
import time
import logging
import statistics
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import config
from rag.vector_store_faiss import FAISSVectorStore
from llm.attack_chain_generator import AttackChainGenerator, PREDEFINED_SCENARIOS

logger = logging.getLogger("red_elisar.evaluate")


# ============================================================================
# GROUND TRUTH DATA (for retrieval quality evaluation)
# ============================================================================
# These are expert-curated expected techniques for each predefined scenario.
# Used to compute Recall@k and MRR metrics.

GROUND_TRUTH = {
    "apt_phishing_to_exfil": {
        "expected_techniques": [
            "T1566.001",  # Phishing: Spearphishing Attachment
            "T1059",      # Command and Scripting Interpreter
            "T1053",      # Scheduled Task/Job
            "T1547",      # Boot or Logon Autostart Execution
            "T1134",      # Access Token Manipulation
            "T1087",      # Account Discovery
            "T1550",      # Use Alternate Authentication Material
            "T1041",      # Exfiltration Over C2 Channel
        ],
        "expected_tactics": [
            "initial-access", "execution", "persistence",
            "privilege-escalation", "discovery", "lateral-movement",
            "exfiltration",
        ],
    },
    "insider_threat": {
        "expected_techniques": [
            "T1078",      # Valid Accounts
            "T1562",      # Impair Defenses
            "T1083",      # File and Directory Discovery
            "T1005",      # Data from Local System
            "T1048",      # Exfiltration Over Alternative Protocol
        ],
        "expected_tactics": [
            "defense-evasion", "credential-access", "collection",
            "exfiltration",
        ],
    },
    "ransomware_attack": {
        "expected_techniques": [
            "T1133",      # External Remote Services
            "T1562",      # Impair Defenses
            "T1021",      # Remote Services
            "T1486",      # Data Encrypted for Impact
            "T1490",      # Inhibit System Recovery
        ],
        "expected_tactics": [
            "initial-access", "execution", "defense-evasion",
            "lateral-movement", "impact",
        ],
    },
    "supply_chain": {
        "expected_techniques": [
            "T1195",      # Supply Chain Compromise
            "T1059",      # Command and Scripting Interpreter
            "T1543",      # Create or Modify System Process
            "T1005",      # Data from Local System
        ],
        "expected_tactics": [
            "initial-access", "execution", "persistence", "collection",
        ],
    },
    "cloud_hybrid": {
        "expected_techniques": [
            "T1190",      # Exploit Public-Facing Application
            "T1528",      # Steal Application Access Token
            "T1021",      # Remote Services
            "T1530",      # Data from Cloud Storage
        ],
        "expected_tactics": [
            "initial-access", "credential-access",
            "lateral-movement", "collection",
        ],
    },
}


# ============================================================================
# RETRIEVAL EVALUATION METRICS
# ============================================================================

class RetrievalEvaluator:
    """
    Evaluates retrieval quality using standard IR metrics.
    
    Metrics:
    - Recall@k: What fraction of expected techniques appear in top-k?
    - Precision@k: What fraction of top-k results are expected?
    - MRR: Mean Reciprocal Rank — how early does first relevant appear?
    - Hit Rate: Did at least one expected technique appear?
    """
    
    def __init__(self, vector_store: FAISSVectorStore):
        self.vector_store = vector_store
    
    def evaluate_scenario(
        self,
        scenario_key: str,
        top_k: int = None,
    ) -> dict:
        """
        Evaluate retrieval quality for a single scenario.
        
        Args:
            scenario_key: Key from PREDEFINED_SCENARIOS.
            top_k: Number of results to retrieve.
        
        Returns:
            Dictionary with retrieval metrics.
        """
        if top_k is None:
            top_k = config.RAG_TOP_K
        
        scenario = PREDEFINED_SCENARIOS[scenario_key]
        ground_truth = GROUND_TRUTH.get(scenario_key, {})
        expected_ids = set(ground_truth.get("expected_techniques", []))
        
        if not expected_ids:
            logger.warning(f"No ground truth for scenario: {scenario_key}")
            return {"error": "No ground truth available"}
        
        # Run retrieval
        start = time.perf_counter()
        results = self.vector_store.query(
            query_text=scenario["scenario"],
            top_k=top_k,
        )
        retrieval_time = time.perf_counter() - start
        
        retrieved_ids = [r["technique_id"] for r in results]
        retrieved_set = set(retrieved_ids)
        
        # Recall@k: |expected ∩ retrieved| / |expected|
        hits = expected_ids & retrieved_set
        recall_at_k = len(hits) / len(expected_ids) if expected_ids else 0
        
        # Precision@k: |expected ∩ retrieved| / |retrieved|
        precision_at_k = len(hits) / len(retrieved_ids) if retrieved_ids else 0
        
        # MRR: 1 / rank_of_first_relevant
        mrr = 0.0
        for rank, rid in enumerate(retrieved_ids, 1):
            # Check exact match or parent technique match (T1059.001 matches T1059)
            if rid in expected_ids or rid.split(".")[0] in expected_ids:
                mrr = 1.0 / rank
                break
        
        # Hit Rate: at least one expected technique retrieved
        hit_rate = 1.0 if hits else 0.0
        
        # F1 Score
        f1 = (
            2 * precision_at_k * recall_at_k / (precision_at_k + recall_at_k)
            if (precision_at_k + recall_at_k) > 0 else 0.0
        )
        
        return {
            "scenario_key": scenario_key,
            "top_k": top_k,
            "expected_techniques": sorted(expected_ids),
            "retrieved_techniques": retrieved_ids,
            "hits": sorted(hits),
            "recall_at_k": round(recall_at_k, 4),
            "precision_at_k": round(precision_at_k, 4),
            "f1_score": round(f1, 4),
            "mrr": round(mrr, 4),
            "hit_rate": hit_rate,
            "retrieval_time_ms": round(retrieval_time * 1000, 2),
        }
    
    def evaluate_all(self, top_k: int = None) -> dict:
        """
        Evaluate retrieval quality across all predefined scenarios.
        
        Returns:
            Aggregate evaluation results.
        """
        results = {}
        all_recall = []
        all_precision = []
        all_mrr = []
        all_f1 = []
        all_latency = []
        
        for key in PREDEFINED_SCENARIOS:
            if key in GROUND_TRUTH:
                r = self.evaluate_scenario(key, top_k=top_k)
                results[key] = r
                
                all_recall.append(r["recall_at_k"])
                all_precision.append(r["precision_at_k"])
                all_mrr.append(r["mrr"])
                all_f1.append(r["f1_score"])
                all_latency.append(r["retrieval_time_ms"])
        
        aggregate = {
            "mean_recall_at_k": round(statistics.mean(all_recall), 4) if all_recall else 0,
            "mean_precision_at_k": round(statistics.mean(all_precision), 4) if all_precision else 0,
            "mean_f1": round(statistics.mean(all_f1), 4) if all_f1 else 0,
            "mean_mrr": round(statistics.mean(all_mrr), 4) if all_mrr else 0,
            "mean_retrieval_ms": round(statistics.mean(all_latency), 2) if all_latency else 0,
            "std_retrieval_ms": round(statistics.stdev(all_latency), 2) if len(all_latency) > 1 else 0,
        }
        
        return {
            "per_scenario": results,
            "aggregate": aggregate,
            "top_k": top_k or config.RAG_TOP_K,
            "total_scenarios_evaluated": len(results),
        }


# ============================================================================
# GENERATION EVALUATION METRICS
# ============================================================================

class GenerationEvaluator:
    """
    Evaluates the quality of generated attack chains.
    
    Metrics:
    - Faithfulness: All cited technique IDs exist in retrieval set
    - Tactical Coherence: Kill chain phase ordering makes sense
    - Completeness: Required JSON fields are populated
    - Consistency: Deterministic output across identical runs (temp=0)
    """
    
    @staticmethod
    def evaluate_chain(result: dict) -> dict:
        """
        Evaluate a single generated attack chain.
        
        Args:
            result: Pipeline result from AttackChainGenerator.
        
        Returns:
            Evaluation metrics dictionary.
        """
        chain = result.get("attack_chain", {}).get("attack_chain", [])
        retrieved = result.get("retrieval_results", [])
        
        if not chain:
            return {"error": "Empty chain"}
        
        retrieved_ids = {r["technique_id"] for r in retrieved}
        
        # --- Faithfulness ---
        cited_ids = [step.get("technique_id", "") for step in chain]
        grounded = [cid for cid in cited_ids if cid in retrieved_ids]
        faithfulness = len(grounded) / len(cited_ids) if cited_ids else 0
        
        # --- Structural Completeness ---
        required_fields = ["step", "technique_id", "technique_name", "tactic", "description", "rationale"]
        completeness_scores = []
        
        for step in chain:
            present = sum(1 for f in required_fields if step.get(f))
            completeness_scores.append(present / len(required_fields))
        
        avg_completeness = statistics.mean(completeness_scores) if completeness_scores else 0
        
        # --- Tactical Coherence ---
        # Define expected tactical ordering (kill chain)
        tactic_order = {
            "reconnaissance": 0, "resource-development": 1,
            "initial-access": 2, "execution": 3, "persistence": 4,
            "privilege-escalation": 5, "defense-evasion": 6,
            "credential-access": 7, "discovery": 8,
            "lateral-movement": 9, "collection": 10,
            "command-and-control": 11, "exfiltration": 12, "impact": 13,
        }
        
        chain_tactic_indices = []
        for step in chain:
            tactic = step.get("tactic", "").lower().replace(" ", "-")
            idx = tactic_order.get(tactic, -1)
            if idx >= 0:
                chain_tactic_indices.append(idx)
        
        # Coherence = fraction of adjacent pairs that are non-decreasing
        coherent_pairs = 0
        total_pairs = max(len(chain_tactic_indices) - 1, 1)
        
        for i in range(len(chain_tactic_indices) - 1):
            if chain_tactic_indices[i] <= chain_tactic_indices[i + 1]:
                coherent_pairs += 1
        
        tactical_coherence = coherent_pairs / total_pairs
        
        # --- Unique Technique Diversity ---
        unique_ratio = len(set(cited_ids)) / len(cited_ids) if cited_ids else 0
        
        # --- Detection Coverage ---
        detection_count = sum(
            1 for step in chain
            if step.get("detection_considerations", "").strip()
        )
        detection_coverage = detection_count / len(chain) if chain else 0
        
        return {
            "faithfulness": round(faithfulness, 4),
            "structural_completeness": round(avg_completeness, 4),
            "tactical_coherence": round(tactical_coherence, 4),
            "technique_diversity": round(unique_ratio, 4),
            "detection_coverage": round(detection_coverage, 4),
            "chain_length": len(chain),
            "cited_techniques": cited_ids,
            "grounded_techniques": grounded,
            "hallucinated_count": len(cited_ids) - len(grounded),
        }
    
    @staticmethod
    def evaluate_consistency(results: list[dict]) -> dict:
        """
        Evaluate output consistency across multiple runs of the same scenario.
        
        At temperature=0, outputs should be deterministic. This metric
        measures how consistent the technique selections and ordering are.
        
        Args:
            results: List of pipeline results for the SAME scenario.
        
        Returns:
            Consistency metrics.
        """
        if len(results) < 2:
            return {"error": "Need at least 2 runs for consistency evaluation"}
        
        technique_sequences = []
        for r in results:
            chain = r.get("attack_chain", {}).get("attack_chain", [])
            seq = [step.get("technique_id", "") for step in chain]
            technique_sequences.append(seq)
        
        # Check exact match across runs
        exact_matches = sum(
            1 for seq in technique_sequences[1:]
            if seq == technique_sequences[0]
        )
        exact_consistency = exact_matches / (len(results) - 1)
        
        # Check set overlap (order-independent)
        base_set = set(technique_sequences[0])
        set_overlaps = []
        for seq in technique_sequences[1:]:
            other_set = set(seq)
            if base_set or other_set:
                jaccard = len(base_set & other_set) / len(base_set | other_set)
                set_overlaps.append(jaccard)
        
        avg_jaccard = statistics.mean(set_overlaps) if set_overlaps else 0
        
        return {
            "total_runs": len(results),
            "exact_sequence_consistency": round(exact_consistency, 4),
            "mean_jaccard_similarity": round(avg_jaccard, 4),
            "technique_sequences": technique_sequences,
        }


# ============================================================================
# LATENCY PROFILER
# ============================================================================

class LatencyProfiler:
    """
    Profiles and reports latency across pipeline phases.
    
    Measures:
    - Retrieval latency (embedding + vector search)
    - Prompt construction latency
    - LLM inference latency
    - Validation latency
    - End-to-end pipeline latency
    """
    
    @staticmethod
    def profile_from_results(results: list[dict]) -> dict:
        """
        Compute latency statistics from a set of pipeline results.
        
        Args:
            results: List of pipeline results with latency metrics.
        
        Returns:
            Latency profile with mean, stdev, min, max per phase.
        """
        phases = {
            "retrieval_time_s": [],
            "augmentation_time_s": [],
            "llm_latency_s": [],
            "validation_time_s": [],
            "pipeline_total_s": [],
            "tokens_per_second": [],
        }
        
        for r in results:
            lat = r.get("latency", {})
            for phase, values in phases.items():
                if phase in lat:
                    values.append(lat[phase])
        
        profile = {}
        for phase, values in phases.items():
            if values:
                profile[phase] = {
                    "mean": round(statistics.mean(values), 4),
                    "stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0,
                    "min": round(min(values), 4),
                    "max": round(max(values), 4),
                    "n_samples": len(values),
                }
        
        return profile


# ============================================================================
# FULL EVALUATION SUITE
# ============================================================================

class EvaluationSuite:
    """
    Runs the complete evaluation protocol and generates a report.
    
    Protocol:
    1. Evaluate retrieval quality across all scenarios
    2. Generate attack chains for all predefined scenarios
    3. Evaluate generation quality for each chain
    4. Profile latency across all runs
    5. Export comprehensive evaluation report
    """
    
    def __init__(self, vector_store: FAISSVectorStore):
        self.vector_store = vector_store
        self.retrieval_evaluator = RetrievalEvaluator(vector_store)
        self.generation_evaluator = GenerationEvaluator()
        self.latency_profiler = LatencyProfiler()
        self.generator = AttackChainGenerator(vector_store)
    
    def run_full_evaluation(
        self,
        n_runs: int = 1,
        scenario_keys: Optional[list[str]] = None,
        export: bool = True,
    ) -> dict:
        """
        Run the complete evaluation suite.
        
        Args:
            n_runs: Number of repetitions per scenario (for consistency).
            scenario_keys: Scenarios to evaluate. None = all predefined.
            export: Whether to export results to file.
        
        Returns:
            Complete evaluation report.
        """
        if scenario_keys is None:
            scenario_keys = list(PREDEFINED_SCENARIOS.keys())
        
        eval_start = time.perf_counter()
        
        report = {
            "evaluation_metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "n_runs_per_scenario": n_runs,
                "scenarios_evaluated": scenario_keys,
                "model": config.GROQ_MODEL,
                "embedding_model": config.EMBEDDING_MODEL_NAME,
                "top_k": config.RAG_TOP_K,
                "temperature": config.LLM_TEMPERATURE,
            },
        }
        
        # --- 1. Retrieval Evaluation ---
        logger.info("=" * 60)
        logger.info("EVALUATION PHASE 1: Retrieval Quality")
        logger.info("=" * 60)
        
        report["retrieval_evaluation"] = self.retrieval_evaluator.evaluate_all()
        
        # --- 2. Generation Evaluation ---
        logger.info("=" * 60)
        logger.info("EVALUATION PHASE 2: Generation Quality")
        logger.info("=" * 60)
        
        all_generation_results = []
        per_scenario_results = {}
        
        for key in scenario_keys:
            scenario_runs = []
            for run_idx in range(n_runs):
                logger.info(f"Generating: {key} (run {run_idx + 1}/{n_runs})")
                try:
                    result = self.generator.generate_predefined(key)
                    result["run_index"] = run_idx
                    result["scenario_key"] = key
                    scenario_runs.append(result)
                    all_generation_results.append(result)
                except Exception as e:
                    logger.error(f"Generation failed for {key} run {run_idx}: {e}")
                    scenario_runs.append({"error": str(e), "scenario_key": key})
            
            # Evaluate this scenario's runs
            valid_runs = [r for r in scenario_runs if "error" not in r]
            
            per_scenario_results[key] = {
                "generation_metrics": [
                    self.generation_evaluator.evaluate_chain(r) for r in valid_runs
                ],
                "successful_runs": len(valid_runs),
                "failed_runs": n_runs - len(valid_runs),
            }
            
            # Consistency eval if multiple runs
            if len(valid_runs) >= 2:
                per_scenario_results[key]["consistency"] = (
                    self.generation_evaluator.evaluate_consistency(valid_runs)
                )
        
        report["generation_evaluation"] = per_scenario_results
        
        # --- 3. Aggregate Generation Metrics ---
        all_faith = []
        all_coherence = []
        all_completeness = []
        all_diversity = []
        
        for key, data in per_scenario_results.items():
            for m in data.get("generation_metrics", []):
                if "error" not in m:
                    all_faith.append(m["faithfulness"])
                    all_coherence.append(m["tactical_coherence"])
                    all_completeness.append(m["structural_completeness"])
                    all_diversity.append(m["technique_diversity"])
        
        report["aggregate_generation_metrics"] = {
            "mean_faithfulness": round(statistics.mean(all_faith), 4) if all_faith else 0,
            "mean_tactical_coherence": round(statistics.mean(all_coherence), 4) if all_coherence else 0,
            "mean_structural_completeness": round(statistics.mean(all_completeness), 4) if all_completeness else 0,
            "mean_technique_diversity": round(statistics.mean(all_diversity), 4) if all_diversity else 0,
        }
        
        # --- 4. Latency Profile ---
        logger.info("=" * 60)
        logger.info("EVALUATION PHASE 3: Latency Profile")
        logger.info("=" * 60)
        
        valid_results = [r for r in all_generation_results if "error" not in r]
        report["latency_profile"] = self.latency_profiler.profile_from_results(valid_results)
        
        # --- 5. Total Evaluation Time ---
        report["evaluation_metadata"]["total_evaluation_time_s"] = round(
            time.perf_counter() - eval_start, 2
        )
        
        # --- 6. Export ---
        if export:
            self._export_report(report)
        
        # Print summary
        self._print_summary(report)
        
        return report
    
    def _export_report(self, report: dict):
        """Export evaluation report to JSON."""
        config.ensure_directories()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = config.OUTPUT_DIR / f"evaluation_report_{timestamp}.json"
        
        clean_report = json.loads(json.dumps(report, default=str))
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(clean_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Evaluation report exported to: {output_path}")
    
    def _print_summary(self, report: dict):
        """Print a formatted evaluation summary."""
        print("\n" + "=" * 60)
        print("  RED ELISAR — EVALUATION REPORT SUMMARY")
        print("=" * 60)
        
        # Retrieval
        ret = report.get("retrieval_evaluation", {}).get("aggregate", {})
        print(f"\n📊 Retrieval Quality (top-k={report.get('retrieval_evaluation', {}).get('top_k', '?')}):")
        print(f"  Mean Recall@k:     {ret.get('mean_recall_at_k', 0):.4f}")
        print(f"  Mean Precision@k:  {ret.get('mean_precision_at_k', 0):.4f}")
        print(f"  Mean F1:           {ret.get('mean_f1', 0):.4f}")
        print(f"  Mean MRR:          {ret.get('mean_mrr', 0):.4f}")
        print(f"  Mean Latency:      {ret.get('mean_retrieval_ms', 0):.1f}ms")
        
        # Generation
        gen = report.get("aggregate_generation_metrics", {})
        print(f"\n📊 Generation Quality:")
        print(f"  Mean Faithfulness:     {gen.get('mean_faithfulness', 0):.4f}")
        print(f"  Mean Coherence:        {gen.get('mean_tactical_coherence', 0):.4f}")
        print(f"  Mean Completeness:     {gen.get('mean_structural_completeness', 0):.4f}")
        print(f"  Mean Tech Diversity:   {gen.get('mean_technique_diversity', 0):.4f}")
        
        # Latency
        lat = report.get("latency_profile", {})
        if "pipeline_total_s" in lat:
            p = lat["pipeline_total_s"]
            print(f"\n⏱️  Latency Profile:")
            print(f"  Pipeline Total:  {p['mean']:.2f}s ± {p.get('stdev', 0):.2f}s")
        if "llm_latency_s" in lat:
            l = lat["llm_latency_s"]
            print(f"  LLM Generation:  {l['mean']:.2f}s ± {l.get('stdev', 0):.2f}s")
        if "tokens_per_second" in lat:
            t = lat["tokens_per_second"]
            print(f"  Throughput:      {t['mean']:.1f} tok/s")
        
        eval_time = report.get("evaluation_metadata", {}).get("total_evaluation_time_s", 0)
        print(f"\n  Total Evaluation Time: {eval_time:.1f}s")
        print("=" * 60)


# ============================================================================
# STANDALONE EXECUTION
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)
    
    parser = argparse.ArgumentParser(description="Red ELISAR Evaluation Suite")
    parser.add_argument("--n-runs", type=int, default=1,
                       help="Number of runs per scenario (default: 1)")
    parser.add_argument("--retrieval-only", action="store_true",
                       help="Only evaluate retrieval (no LLM needed)")
    parser.add_argument("--scenarios", nargs="+", default=None,
                       choices=list(PREDEFINED_SCENARIOS.keys()),
                       help="Specific scenarios to evaluate")
    args = parser.parse_args()
    
    store = FAISSVectorStore()
    
    if args.retrieval_only:
        evaluator = RetrievalEvaluator(store)
        results = evaluator.evaluate_all()
        print(json.dumps(results, indent=2))
    else:
        suite = EvaluationSuite(store)
        suite.run_full_evaluation(
            n_runs=args.n_runs,
            scenario_keys=args.scenarios,
        )
