
import argparse
import json
import logging
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from rag.mitre_parser import MITREParser
from rag.chunking import chunk_techniques
from rag.vector_store_faiss import FAISSVectorStore
try:
    from .baseline_runner import BaselineRunner
except ImportError:  # pragma: no cover
    from baseline_runner import BaselineRunner
from evaluation.feedback_loop import FeedbackLoop
try:
    from .plot_generator import generate_all_plots, generate_plots_from_file
except ImportError:  # pragma: no cover
    from plot_generator import generate_all_plots, generate_plots_from_file
from reporting.diagram_generator import generate_diagram

logger = logging.getLogger("red_elisar.experiment")


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(level: str = "INFO"):
    """Configure experiment logging."""
    config.ensure_directories()
    generate_diagram(quiet=True)

    log_level = getattr(logging, level.upper(), logging.INFO)
    log_file = config.LOG_DIR / "experiment.log"

    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, encoding="utf-8", mode="a"),
    ]

    logging.basicConfig(
        level=log_level,
        format=config.LOG_FORMAT,
        handlers=handlers,
        force=True,
    )

    # Suppress noisy loggers
    for name in ["sentence_transformers", "urllib3", "httpx", "transformers"]:
        logging.getLogger(name).setLevel(logging.WARNING)


# ============================================================================
# EXPERIMENT PIPELINE
# ============================================================================

def run_experiment(
    n_runs: int = None,
    max_scenarios: int = None,
    force_reindex: bool = False,
) -> dict:
    """
    Run the complete Red ELISAR experiment pipeline.

    Steps:
        1. Parse MITRE ATT&CK → techniques
        2. Chunk (512/128) → chunks
        3. Index into FAISS HNSW → vector store
        4. Run baseline comparison → metrics
        5. Record feedback → feedback store
        6. Generate plots → figures/

    Args:
        n_runs: Number of runs per config (default: config.N_EVALUATION_RUNS).
        max_scenarios: Limit scenarios for quick testing.
        force_reindex: Rebuild FAISS index from scratch.

    Returns:
        Complete experiment results dict.
    """
    if n_runs is None:
        n_runs = config.N_EVALUATION_RUNS

    total_start = time.perf_counter()

    print("\n" + "=" * 70)
    print("  Red ELISAR — Full Experiment Pipeline")
    print("  Reproducing ELISAR Paper Evaluation")
    print("=" * 70)

    # ===== STEP 1: Parse MITRE ATT&CK =====
    print(f"\n{'─'*70}")
    print("  STEP 1/6: Parsing MITRE ATT&CK STIX 2.1 Bundle")
    print(f"{'─'*70}")

    parser = MITREParser()
    techniques = parser.parse()
    print(f"  Parsed {len(techniques)} techniques")

    # ===== STEP 2: Chunk Techniques =====
    print(f"\n{'─'*70}")
    print(f"  STEP 2/6: Chunking ({config.CHUNK_SIZE_TOKENS}/{config.CHUNK_OVERLAP_TOKENS} tokens)")
    print(f"{'─'*70}")

    chunks = chunk_techniques(techniques)
    print(f"  Generated {len(chunks)} chunks from {len(techniques)} techniques")

    # ===== STEP 3: FAISS Indexing =====
    print(f"\n{'─'*70}")
    print(f"  STEP 3/6: FAISS HNSW Indexing (M={config.FAISS_HNSW_M}, efSearch={config.FAISS_HNSW_EF_SEARCH})")
    print(f"{'─'*70}")

    store = FAISSVectorStore()
    index_stats = store.index_chunks(chunks, force_reindex=force_reindex)
    print(f"  Indexed {index_stats['indexed']} chunks in {index_stats['total_time_s']:.2f}s")

    # ===== STEP 4: Baseline Comparison =====
    print(f"\n{'─'*70}")
    print(f"  STEP 4/6: Running Baseline Comparison")
    models_str = ", ".join(config.BENCHMARK_MODELS)
    print(f"  Models: {models_str} | Runs: {n_runs} | Max Scenarios: {max_scenarios or 'all'}")
    print(f"{'─'*70}")

    runner = BaselineRunner(vector_store=store)
    comparison = runner.run_full_comparison(
        n_runs=n_runs,
        max_scenarios=max_scenarios,
    )

    # ===== STEP 5: Feedback Loop =====
    print(f"\n{'─'*70}")
    print("  STEP 5/6: Recording Feedback Loop Data")
    print(f"{'─'*70}")

    feedback = FeedbackLoop()
    # Record feedback for RAG results
    rag_results = [r for r in comparison.get("all_results", []) if r.get("rag_enabled")]
    feedback_count = 0
    for result in rag_results[:20]:  # Record up to 20 feedback entries
        try:
            feedback.record_outcome(
                scenario=result.get("scenario_id", ""),
                retrieved_techniques=[],  # simplified
                generated_chain={"attack_chain": []},
                faithfulness_score=result.get("metrics", {}).get("accuracy", 0),
            )
            feedback_count += 1
        except Exception as e:
            logger.warning(f"Feedback recording failed: {e}")

    feedback_summary = feedback.get_feedback_summary()
    print(f"  Recorded {feedback_count} feedback entries")
    print(f"  Avg reward: {feedback_summary.get('avg_reward', 0):.3f}")

    # ===== STEP 6: Generate Plots =====
    print(f"\n{'─'*70}")
    print("  STEP 6/6: Generating Publication Figures")
    print(f"{'─'*70}")

    summary = comparison.get("summary", {})
    if summary:
        plot_paths = generate_all_plots(summary)
        print(f"  Generated {len(plot_paths)} figures in {config.FIGURES_DIR}")
    else:
        print("  No summary data — skipping plots")
        plot_paths = []

    # ===== COMPLETE =====
    total_elapsed = time.perf_counter() - total_start

    print(f"\n{'='*70}")
    print(f"  EXPERIMENT COMPLETE")
    print(f"  Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f}min)")
    print(f"  Results: {config.OUTPUT_DIR}")
    print(f"  Figures: {config.FIGURES_DIR}")
    print(f"  Feedback: {config.FEEDBACK_STORE_PATH}")
    print(f"{'='*70}\n")

    return {
        "parse_stats": {"technique_count": len(techniques)},
        "chunk_stats": {"chunk_count": len(chunks)},
        "index_stats": index_stats,
        "comparison": comparison,
        "feedback_summary": feedback_summary,
        "plot_paths": [str(p) for p in plot_paths],
        "total_time_s": total_elapsed,
    }


# ============================================================================
# CLI
# ============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Red ELISAR Experiment Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_experiment.py --full                   # Full paper experiment
  python run_experiment.py --quick                  # Quick test (5 scenarios, 1 run)
  python run_experiment.py --n-runs 3 --max 20      # Custom
  python run_experiment.py --demo-plots             # Demo figures
  python run_experiment.py --plots-only --results-file output/results.json
        """,
    )

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="Full experiment (50 scenarios, 5 runs)")
    mode.add_argument("--quick", action="store_true", help="Quick test (5 scenarios, 1 run)")
    mode.add_argument("--demo-plots", action="store_true", help="Generate demo plots")
    mode.add_argument("--plots-only", action="store_true", help="Generate plots from results file")

    ap.add_argument("--n-runs", type=int, default=None, help="Runs per config")
    ap.add_argument("--max", type=int, default=None, dest="max_scenarios",
                    help="Maximum scenarios")
    ap.add_argument("--force-reindex", action="store_true", help="Rebuild FAISS index")
    ap.add_argument("--results-file", type=str, help="Results JSON for --plots-only")
    ap.add_argument("--log-level", type=str, default="INFO",
                    choices=["DEBUG", "INFO", "WARNING"])

    args = ap.parse_args()
    setup_logging(args.log_level)

    if args.demo_plots:
        from plot_generator import generate_all_plots
        demo_summary = {
            "mistral_no_rag": {
                "accuracy": {"mean": 0.72, "std": 0.05},
                "precision": {"mean": 0.45, "std": 0.08},
                "recall": {"mean": 0.38, "std": 0.07},
                "f1_score": {"mean": 0.41, "std": 0.06},
                "context_relevance": {"mean": 0.0, "std": 0.0},
                "latency_s": {"mean": 8.5, "std": 1.2},
            },
            "llama3_no_rag": {
                "accuracy": {"mean": 0.68, "std": 0.06},
                "precision": {"mean": 0.42, "std": 0.09},
                "recall": {"mean": 0.35, "std": 0.08},
                "f1_score": {"mean": 0.38, "std": 0.07},
                "context_relevance": {"mean": 0.0, "std": 0.0},
                "latency_s": {"mean": 10.2, "std": 1.5},
            },
            "mistral_rag": {
                "accuracy": {"mean": 0.91, "std": 0.03},
                "precision": {"mean": 0.78, "std": 0.05},
                "recall": {"mean": 0.72, "std": 0.06},
                "f1_score": {"mean": 0.75, "std": 0.04},
                "context_relevance": {"mean": 0.82, "std": 0.04},
                "latency_s": {"mean": 12.1, "std": 1.8},
            },
            "llama3_rag": {
                "accuracy": {"mean": 0.88, "std": 0.04},
                "precision": {"mean": 0.74, "std": 0.06},
                "recall": {"mean": 0.68, "std": 0.07},
                "f1_score": {"mean": 0.71, "std": 0.05},
                "context_relevance": {"mean": 0.78, "std": 0.05},
                "latency_s": {"mean": 14.3, "std": 2.1},
            },
        }
        paths = generate_all_plots(demo_summary)
        print(f"Demo plots: {[str(p) for p in paths]}")
        return

    if args.plots_only:
        if not args.results_file:
            print("Error: --plots-only requires --results-file")
            sys.exit(1)
        paths = generate_plots_from_file(Path(args.results_file))
        print(f"Generated {len(paths)} plots")
        return

    if args.full:
        n_runs = args.n_runs or config.N_EVALUATION_RUNS
        max_scenarios = args.max_scenarios  # None = all 50
    elif args.quick:
        n_runs = args.n_runs or 1
        max_scenarios = args.max_scenarios or 5
    else:
        n_runs = args.n_runs or 1
        max_scenarios = args.max_scenarios or 5

    run_experiment(
        n_runs=n_runs,
        max_scenarios=max_scenarios,
        force_reindex=args.force_reindex,
    )


if __name__ == "__main__":
    main()
