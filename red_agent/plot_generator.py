"""
Red ELISAR — Plot Generator Module (Paper-Aligned)
=====================================================
Generates publication-quality figures matching the paper's
visualization style for experimental results.

Figures Generated:
    1. red_accuracy.png — Accuracy comparison bar chart
    2. red_context.png — Context relevance comparison
    3. red_latency.png — Latency comparison across configs
    4. red_f1_comparison.png — F1 score comparison
    5. red_metrics_radar.png — Radar chart of all metrics

Paper Style:
    - Grouped bar charts with model configurations
    - Error bars showing standard deviation
    - Color scheme: blue (no-RAG), green (RAG-enhanced)
    - 300 DPI, publication-ready sizing
"""

import json
import logging
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless rendering
import matplotlib.pyplot as plt
import numpy as np

import config

logger = logging.getLogger("red_elisar.plots")

# ============================================================================
# STYLE CONFIGURATION
# ============================================================================

COLORS = {
    "no_rag": "#4A90D9",       # Blue — baseline (no RAG)
    "rag": "#27AE60",          # Green — RAG-enhanced
    "mistral": "#E74C3C",      # Red — Mistral
    "llama3": "#F39C12",       # Orange — LLaMA 3
    "background": "#F8F9FA",   # Light gray background
}

FIGURE_DPI = 300
FIGSIZE_BAR = (10, 6)
FIGSIZE_RADAR = (8, 8)
FONT_SIZE = 12


def _setup_style():
    """Apply consistent publication-ready plot style."""
    plt.rcParams.update({
        "font.size": FONT_SIZE,
        "axes.titlesize": 14,
        "axes.labelsize": 12,
        "xtick.labelsize": 11,
        "ytick.labelsize": 11,
        "legend.fontsize": 10,
        "figure.facecolor": "white",
        "axes.facecolor": "#FAFAFA",
        "axes.grid": True,
        "grid.alpha": 0.3,
        "grid.linestyle": "--",
    })


# ============================================================================
# BAR CHART GENERATORS
# ============================================================================

def plot_accuracy_comparison(summary: dict, output_dir: Path = None) -> Path:
    """
    Generate accuracy comparison bar chart.

    Args:
        summary: Aggregated results from BaselineRunner._aggregate_results().
        output_dir: Directory to save the figure.

    Returns:
        Path to the saved figure.
    """
    _setup_style()
    output_dir = output_dir or config.FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=FIGSIZE_BAR)

    configs = list(summary.keys())
    means = [summary[c].get("accuracy", {}).get("mean", 0) for c in configs]
    stds = [summary[c].get("accuracy", {}).get("std", 0) for c in configs]

    colors = [COLORS["rag"] if "rag" in c else COLORS["no_rag"] for c in configs]
    labels = [c.replace("_", " ").title() for c in configs]

    bars = ax.bar(labels, means, yerr=stds, capsize=5, color=colors,
                  edgecolor="white", linewidth=1.5, alpha=0.85)

    ax.set_title("Accuracy Comparison: Baseline vs Red ELISAR (RAG)", fontweight="bold")
    ax.set_ylabel("Accuracy Score")
    ax.set_ylim(0, 1.0)

    # Add value labels on bars
    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + std + 0.02,
                f"{mean:.3f}", ha="center", va="bottom", fontsize=10, fontweight="bold")

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=COLORS["no_rag"], label="Baseline (No RAG)"),
        Patch(facecolor=COLORS["rag"], label="Red ELISAR (RAG+FAISS)"),
    ]
    ax.legend(handles=legend_elements, loc="upper left")

    plt.tight_layout()
    path = output_dir / "red_accuracy.png"
    fig.savefig(path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)

    logger.info(f"Accuracy plot saved: {path}")
    return path


def plot_context_relevance(summary: dict, output_dir: Path = None) -> Path:
    """Generate context relevance (recall@5) comparison chart."""
    _setup_style()
    output_dir = output_dir or config.FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=FIGSIZE_BAR)

    # Only RAG configs have context relevance
    rag_configs = [c for c in summary if "rag" in c and "no_rag" not in c]

    if not rag_configs:
        logger.warning("No RAG configurations with context relevance data")
        plt.close(fig)
        return output_dir / "red_context.png"

    labels = [c.replace("_", " ").title() for c in rag_configs]
    means = [summary[c].get("context_relevance", {}).get("mean", 0) for c in rag_configs]
    stds = [summary[c].get("context_relevance", {}).get("std", 0) for c in rag_configs]

    bars = ax.bar(labels, means, yerr=stds, capsize=5,
                  color=COLORS["rag"], edgecolor="white", linewidth=1.5, alpha=0.85)

    ax.set_title("Context Relevance (Recall@5) — Red ELISAR", fontweight="bold")
    ax.set_ylabel("Context Relevance Score")
    ax.set_ylim(0, 1.0)

    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + std + 0.02,
                f"{mean:.3f}", ha="center", va="bottom", fontsize=10, fontweight="bold")

    plt.tight_layout()
    path = output_dir / "red_context.png"
    fig.savefig(path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)

    logger.info(f"Context relevance plot saved: {path}")
    return path


def plot_latency_comparison(summary: dict, output_dir: Path = None) -> Path:
    """Generate latency comparison chart."""
    _setup_style()
    output_dir = output_dir or config.FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=FIGSIZE_BAR)

    configs = list(summary.keys())
    means = [summary[c].get("latency_s", {}).get("mean", 0) for c in configs]
    stds = [summary[c].get("latency_s", {}).get("std", 0) for c in configs]

    colors = [COLORS["rag"] if "rag" in c and "no_rag" not in c else COLORS["no_rag"] for c in configs]
    labels = [c.replace("_", " ").title() for c in configs]

    bars = ax.bar(labels, means, yerr=stds, capsize=5, color=colors,
                  edgecolor="white", linewidth=1.5, alpha=0.85)

    ax.set_title("Latency Comparison (seconds)", fontweight="bold")
    ax.set_ylabel("Latency (s)")

    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + std + 0.1,
                f"{mean:.2f}s", ha="center", va="bottom", fontsize=10, fontweight="bold")

    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=COLORS["no_rag"], label="Baseline (No RAG)"),
        Patch(facecolor=COLORS["rag"], label="Red ELISAR (RAG+FAISS)"),
    ]
    ax.legend(handles=legend_elements, loc="upper left")

    plt.tight_layout()
    path = output_dir / "red_latency.png"
    fig.savefig(path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)

    logger.info(f"Latency plot saved: {path}")
    return path


def plot_f1_comparison(summary: dict, output_dir: Path = None) -> Path:
    """Generate F1 score grouped bar chart."""
    _setup_style()
    output_dir = output_dir or config.FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=FIGSIZE_BAR)

    # Group by model
    models = config.BENCHMARK_MODELS
    x = np.arange(len(models))
    width = 0.35

    no_rag_means = []
    no_rag_stds = []
    rag_means = []
    rag_stds = []

    for model in models:
        nr_key = f"{model}_no_rag"
        r_key = f"{model}_rag"
        no_rag_means.append(summary.get(nr_key, {}).get("f1_score", {}).get("mean", 0))
        no_rag_stds.append(summary.get(nr_key, {}).get("f1_score", {}).get("std", 0))
        rag_means.append(summary.get(r_key, {}).get("f1_score", {}).get("mean", 0))
        rag_stds.append(summary.get(r_key, {}).get("f1_score", {}).get("std", 0))

    bars1 = ax.bar(x - width / 2, no_rag_means, width, yerr=no_rag_stds,
                   label="No RAG (Baseline)", color=COLORS["no_rag"],
                   capsize=5, alpha=0.85)
    bars2 = ax.bar(x + width / 2, rag_means, width, yerr=rag_stds,
                   label="Red ELISAR (RAG+FAISS)", color=COLORS["rag"],
                   capsize=5, alpha=0.85)

    ax.set_title("F1 Score Comparison by Model", fontweight="bold")
    ax.set_ylabel("F1 Score")
    ax.set_xticks(x)
    ax.set_xticklabels([m.title() for m in models])
    ax.set_ylim(0, 1.0)
    ax.legend()

    # Value labels
    for bars, means, stds in [(bars1, no_rag_means, no_rag_stds), (bars2, rag_means, rag_stds)]:
        for bar, mean, std in zip(bars, means, stds):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + std + 0.02,
                    f"{mean:.3f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    plt.tight_layout()
    path = output_dir / "red_f1_comparison.png"
    fig.savefig(path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)

    logger.info(f"F1 comparison plot saved: {path}")
    return path


def plot_all_metrics_grouped(summary: dict, output_dir: Path = None) -> Path:
    """Generate a comprehensive grouped bar chart with all core metrics."""
    _setup_style()
    output_dir = output_dir or config.FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics = ["accuracy", "precision", "recall", "f1_score"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1 Score"]

    configs = sorted(summary.keys())
    x = np.arange(len(metric_labels))
    width = 0.8 / max(len(configs), 1)

    fig, ax = plt.subplots(figsize=(12, 6))

    for i, cfg in enumerate(configs):
        means = [summary[cfg].get(m, {}).get("mean", 0) for m in metrics]
        stds = [summary[cfg].get(m, {}).get("std", 0) for m in metrics]
        color = COLORS["rag"] if "rag" in cfg and "no_rag" not in cfg else COLORS["no_rag"]
        ax.bar(x + i * width - (len(configs) - 1) * width / 2,
               means, width, yerr=stds, label=cfg.replace("_", " ").title(),
               color=color, alpha=0.7 + 0.1 * i, capsize=3)

    ax.set_title("Red ELISAR — All Metrics Comparison", fontweight="bold")
    ax.set_ylabel("Score")
    ax.set_xticks(x)
    ax.set_xticklabels(metric_labels)
    ax.set_ylim(0, 1.0)
    ax.legend(loc="upper right", fontsize=9)

    plt.tight_layout()
    path = output_dir / "red_metrics_grouped.png"
    fig.savefig(path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)

    logger.info(f"All metrics grouped plot saved: {path}")
    return path


# ============================================================================
# BATCH PLOT GENERATION
# ============================================================================

def generate_all_plots(summary: dict, output_dir: Path = None) -> list[Path]:
    """
    Generate all paper figures from summary data.

    Args:
        summary: Aggregated results from baseline comparison.
        output_dir: Output directory.

    Returns:
        List of generated figure paths.
    """
    output_dir = output_dir or config.FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = []

    try:
        paths.append(plot_accuracy_comparison(summary, output_dir))
    except Exception as e:
        logger.error(f"Failed to generate accuracy plot: {e}")

    try:
        paths.append(plot_context_relevance(summary, output_dir))
    except Exception as e:
        logger.error(f"Failed to generate context relevance plot: {e}")

    try:
        paths.append(plot_latency_comparison(summary, output_dir))
    except Exception as e:
        logger.error(f"Failed to generate latency plot: {e}")

    try:
        paths.append(plot_f1_comparison(summary, output_dir))
    except Exception as e:
        logger.error(f"Failed to generate F1 plot: {e}")

    try:
        paths.append(plot_all_metrics_grouped(summary, output_dir))
    except Exception as e:
        logger.error(f"Failed to generate grouped metrics plot: {e}")

    logger.info(f"Generated {len(paths)} plots in {output_dir}")
    return paths


def generate_plots_from_file(results_file: Path, output_dir: Path = None) -> list[Path]:
    """
    Generate plots from a saved comparison results JSON file.

    Args:
        results_file: Path to baseline_comparison_*.json.
        output_dir: Output directory.

    Returns:
        List of generated figure paths.
    """
    with open(results_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    summary = data.get("summary", {})
    if not summary:
        logger.error("No summary data in results file")
        return []

    return generate_all_plots(summary, output_dir)


# ============================================================================
# STANDALONE EXECUTION
# ============================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)

    parser = argparse.ArgumentParser(description="Red ELISAR Plot Generator")
    parser.add_argument("--results-file", type=str, help="Path to comparison results JSON")
    parser.add_argument("--output-dir", type=str, default=None, help="Output directory")
    parser.add_argument("--demo", action="store_true", help="Generate demo plots with sample data")
    args = parser.parse_args()

    if args.demo:
        # Generate demo plots with synthetic data
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

        output_dir = Path(args.output_dir) if args.output_dir else config.FIGURES_DIR
        paths = generate_all_plots(demo_summary, output_dir)
        print(f"Demo plots generated: {[str(p) for p in paths]}")

    elif args.results_file:
        output_dir = Path(args.output_dir) if args.output_dir else None
        paths = generate_plots_from_file(Path(args.results_file), output_dir)
        print(f"Generated {len(paths)} plots")

    else:
        print("Usage: python plot_generator.py --demo | --results-file <path>")
