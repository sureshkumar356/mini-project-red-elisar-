"""
RAG vs Baseline Model Comparison Runner

Runs three configurations on the offensive scenario dataset:
1) Red ELISAR (RAG enabled)
2) Mistral (no RAG, direct model call)
3) Llama 3 (no RAG, direct model call via Groq)

For each execution, exports:
- JSON raw results
- Markdown comparison report

Usage:
  python compare_rag_vs_baselines.py --runs 1 --max-scenarios 10
  python compare_rag_vs_baselines.py --runs 3 --max-scenarios 50

Environment variables required:
  LLAMA3_API_KEY
  MISTRAL_API_KEY

Optional:
  GROQ_MODEL (default: llama-3.1-8b-instant)
  MISTRAL_MODEL (default: mistral-small-latest)
"""

import argparse
import json
import logging
import re
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

import config
from attack_chain_generator import AttackChainGenerator
from baseline_runner import compute_metrics
from vector_store_faiss import FAISSVectorStore
from llm_client import groq_chat_json, mistral_chat_json

logger = logging.getLogger("red_elisar.compare")


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


def _extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            pass

    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return json.loads(text[first : last + 1])

    raise ValueError("No valid JSON object found in model output")


def _count_steps(payload: dict[str, Any]) -> int:
    if not isinstance(payload, dict):
        return 0
    if isinstance(payload.get("steps"), list):
        return len(payload.get("steps", []))
    if isinstance(payload.get("attack_chain"), list):
        return len(payload.get("attack_chain", []))
    if isinstance(payload.get("attack_chain"), dict) and isinstance(payload.get("attack_chain", {}).get("attack_chain"), list):
        return len(payload.get("attack_chain", {}).get("attack_chain", []))
    return 0


def _call_groq_no_rag(
    scenario: str,
    target_environment: str,
    chain_length: int,
    model: str,
    api_key: str,
    temperature: float,
    top_p: float,
    max_tokens: int,
) -> tuple[dict[str, Any], float]:
    messages = [
        {"role": "system", "content": BASELINE_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": BASELINE_USER_PROMPT.format(
                chain_length=chain_length,
                scenario=scenario,
                target_environment=target_environment,
            ),
        },
    ]

    result = groq_chat_json(
        messages=messages,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        api_key=api_key,
    )
    parsed = _extract_json(result.content)
    return parsed, result.latency_s


def _call_mistral_no_rag(
    scenario: str,
    target_environment: str,
    chain_length: int,
    model: str,
    api_key: str,
    temperature: float,
    top_p: float,
    max_tokens: int,
) -> tuple[dict[str, Any], float]:
    messages = [
        {"role": "system", "content": BASELINE_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": BASELINE_USER_PROMPT.format(
                chain_length=chain_length,
                scenario=scenario,
                target_environment=target_environment,
            ),
        },
    ]

    result = mistral_chat_json(
        messages=messages,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        api_key=api_key,
    )
    parsed = _extract_json(result.content)
    return parsed, result.latency_s


def _load_scenarios(
    max_scenarios: int | None,
    balanced_classes: bool = True,
) -> list[dict[str, Any]]:
    scenarios_path = config.DATA_DIR / "offensive_logs.json"
    with open(scenarios_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    scenarios = payload.get("scenarios", [])

    if max_scenarios and balanced_classes and max_scenarios < len(scenarios):
        single = [s for s in scenarios if s.get("scenario_type") == "single_step"]
        multi = [s for s in scenarios if s.get("scenario_type") == "multi_step"]

        # Only balance when both classes exist in the dataset.
        if single and multi:
            selected: list[dict[str, Any]] = []
            half = max_scenarios // 2

            n_single = min(len(single), half)
            n_multi = min(len(multi), half)
            selected.extend(single[:n_single])
            selected.extend(multi[:n_multi])

            # Fill remaining slots deterministically from the original order.
            remaining = max_scenarios - len(selected)
            if remaining > 0:
                selected_ids = {
                    s.get("scenario_id", f"S-{idx}")
                    for idx, s in enumerate(selected, 1)
                }
                for s in scenarios:
                    sid = s.get("scenario_id", "")
                    if sid in selected_ids:
                        continue
                    selected.append(s)
                    selected_ids.add(sid)
                    if len(selected) >= max_scenarios:
                        break

            return selected

    if max_scenarios:
        scenarios = scenarios[:max_scenarios]
    return scenarios


def _summarize(all_results: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, dict[str, list[float]]] = {}
    for row in all_results:
        if row.get("success") is False:
            continue
        if not row.get("metrics"):
            continue
        cfg = row["config"]
        grouped.setdefault(
            cfg,
            {
                "accuracy": [],
                "precision": [],
                "recall": [],
                "f1_score": [],
                "context_relevance": [],
                "latency_s": [],
            },
        )

        grouped[cfg]["accuracy"].append(row["metrics"].get("accuracy", 0.0))
        grouped[cfg]["precision"].append(row["metrics"].get("precision", 0.0))
        grouped[cfg]["recall"].append(row["metrics"].get("recall", 0.0))
        grouped[cfg]["f1_score"].append(row["metrics"].get("f1_score", 0.0))
        grouped[cfg]["context_relevance"].append(row["metrics"].get("context_relevance", 0.0))
        grouped[cfg]["latency_s"].append(row.get("latency_s", 0.0))

    summary: dict[str, Any] = {}
    for cfg, m in grouped.items():
        summary[cfg] = {}
        for metric_name, values in m.items():
            if not values:
                continue
            mean = statistics.mean(values)
            std = statistics.stdev(values) if len(values) > 1 else 0.0
            summary[cfg][metric_name] = {
                "mean": round(mean, 4),
                "std": round(std, 4),
                "n": len(values),
            }
    return summary


def _summarize_classwise(all_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate precision/recall/F1 by scenario class (single_step, multi_step)."""
    grouped: dict[str, dict[str, dict[str, list[float]]]] = {}

    for row in all_results:
        if row.get("success") is False:
            continue
        if not row.get("metrics"):
            continue
        cfg = row.get("config", "unknown")
        scenario_type = row.get("scenario_type", "unknown")
        grouped.setdefault(cfg, {})
        grouped[cfg].setdefault(
            scenario_type,
            {
                "precision": [],
                "recall": [],
                "f1_score": [],
            },
        )

        metrics = row.get("metrics", {})
        grouped[cfg][scenario_type]["precision"].append(metrics.get("precision", 0.0))
        grouped[cfg][scenario_type]["recall"].append(metrics.get("recall", 0.0))
        grouped[cfg][scenario_type]["f1_score"].append(metrics.get("f1_score", 0.0))

    out: dict[str, Any] = {}
    for cfg, classes in grouped.items():
        out[cfg] = {}
        for cls, metric_lists in classes.items():
            out[cfg][cls] = {}
            for metric_name, values in metric_lists.items():
                if not values:
                    continue
                mean = statistics.mean(values)
                std = statistics.stdev(values) if len(values) > 1 else 0.0
                out[cfg][cls][metric_name] = {
                    "mean": round(mean, 4),
                    "std": round(std, 4),
                    "n": len(values),
                }
    return out


def _write_markdown_report(
    out_path: Path,
    summary: dict[str, Any],
    classwise_summary: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    rows: list[str] = []
    for cfg in ["red_elisar_rag", "mistral_no_rag", "llama3_no_rag"]:
        if cfg not in summary:
            continue
        s = summary[cfg]
        rows.append(
            "| "
            + " | ".join(
                [
                    cfg,
                    f"{s.get('accuracy', {}).get('mean', 0):.4f} +- {s.get('accuracy', {}).get('std', 0):.4f}",
                    f"{s.get('precision', {}).get('mean', 0):.4f} +- {s.get('precision', {}).get('std', 0):.4f}",
                    f"{s.get('recall', {}).get('mean', 0):.4f} +- {s.get('recall', {}).get('std', 0):.4f}",
                    f"{s.get('f1_score', {}).get('mean', 0):.4f} +- {s.get('f1_score', {}).get('std', 0):.4f}",
                    f"{s.get('context_relevance', {}).get('mean', 0):.4f} +- {s.get('context_relevance', {}).get('std', 0):.4f}",
                    f"{s.get('latency_s', {}).get('mean', 0):.3f} +- {s.get('latency_s', {}).get('std', 0):.3f}",
                ]
            )
            + " |"
        )

    rag_f1 = summary.get("red_elisar_rag", {}).get("f1_score", {}).get("mean", 0)
    mis_f1 = summary.get("mistral_no_rag", {}).get("f1_score", {}).get("mean", 0)
    lla_f1 = summary.get("llama3_no_rag", {}).get("f1_score", {}).get("mean", 0)

    rag_ctx = summary.get("red_elisar_rag", {}).get("context_relevance", {}).get("mean", 0)
    mis_ctx = summary.get("mistral_no_rag", {}).get("context_relevance", {}).get("mean", 0)
    lla_ctx = summary.get("llama3_no_rag", {}).get("context_relevance", {}).get("mean", 0)

    content = [
        "# RAG vs Mistral vs Llama3 Comparison",
        "",
        f"Generated: {metadata['timestamp']}",
        f"Scenarios: {metadata['n_scenarios']}",
        f"Runs per scenario: {metadata['n_runs']}",
        f"Groq model (llama3 baseline): {metadata['groq_model']}",
        f"Mistral model (baseline): {metadata['mistral_model']}",
        f"Single-step scenarios: {metadata.get('single_step_count', 0)}",
        f"Multi-step scenarios: {metadata.get('multi_step_count', 0)}",
        "",
        "## Success Rate",
        "",
    ]

    success = metadata.get("success", {})
    for cfg in ["red_elisar_rag", "mistral_no_rag", "llama3_no_rag"]:
        s = success.get(cfg, {})
        ok = int(s.get("success", 0) or 0)
        bad = int(s.get("failed", 0) or 0)
        total = ok + bad
        content.append(f"- {cfg}: {ok} / {total} successful" if total else f"- {cfg}: N/A")

    content.extend(
        [
            "",
            "## Aggregate Metrics (Mean +- Std)",
            "",
            "| Configuration | Accuracy | Precision | Recall | F1 | Context Relevance | Latency (s) |",
            "|---|---:|---:|---:|---:|---:|---:|",
            *rows,
            "",
            "## Headline Comparison",
            "",
            f"- F1 gain (RAG vs Mistral no-RAG): {(rag_f1 - mis_f1):.4f}",
            f"- F1 gain (RAG vs Llama3 no-RAG): {(rag_f1 - lla_f1):.4f}",
            f"- Context relevance gain (RAG vs Mistral no-RAG): {(rag_ctx - mis_ctx):.4f}",
            f"- Context relevance gain (RAG vs Llama3 no-RAG): {(rag_ctx - lla_ctx):.4f}",
            "",
            "## Class-wise Performance (Single-Step vs Multi-Step)",
            "",
            "| Configuration | Class | Precision | Recall | F1 |",
            "|---|---|---:|---:|---:|",
        ]
    )

    for cfg in ["red_elisar_rag", "mistral_no_rag", "llama3_no_rag"]:
        for cls in ["single_step", "multi_step"]:
            cls_data = classwise_summary.get(cfg, {}).get(cls, {})
            p = cls_data.get("precision", {})
            r = cls_data.get("recall", {})
            f = cls_data.get("f1_score", {})
            p_text = f"{p.get('mean', 0):.4f} +- {p.get('std', 0):.4f}" if p.get("n", 0) else "N/A"
            r_text = f"{r.get('mean', 0):.4f} +- {r.get('std', 0):.4f}" if r.get("n", 0) else "N/A"
            f_text = f"{f.get('mean', 0):.4f} +- {f.get('std', 0):.4f}" if f.get("n", 0) else "N/A"
            content.append(
                "| "
                + " | ".join(
                    [
                        cfg,
                        cls,
                        p_text,
                        r_text,
                        f_text,
                    ]
                )
                + " |"
            )

    content.extend(
        [
            "",
            "## Notes",
            "",
            "- Baselines are direct model generation without retrieval context.",
            "- Red ELISAR uses retrieval-augmented generation with FAISS-backed context.",
            "- Results depend on API model versions and prompt determinism.",
        ]
    )

    if metadata.get("n_scenarios", 0) < 20 or metadata.get("n_runs", 0) < 3:
        content.extend(
            [
                "",
                "## Stability Warning",
                "",
                "- Current run size is small. Use at least 50 scenarios and 3-5 runs for paper-grade comparisons.",
            ]
        )

    out_path.write_text("\n".join(content), encoding="utf-8")


def run_comparison(
    n_runs: int,
    max_scenarios: int | None,
    target_environment: str,
    groq_model: str,
    mistral_model: str,
    balanced_classes: bool,
) -> dict[str, Any]:
    config.ensure_directories()
    groq_api_key = config.LLAMA3_API_KEY
    mistral_api_key = str(__import__("os").getenv("MISTRAL_API_KEY", "")).strip()

    if not groq_api_key:
        raise RuntimeError("Missing LLAMA3_API_KEY in environment")
    if not mistral_api_key:
        raise RuntimeError("Missing MISTRAL_API_KEY in environment")

    scenarios = _load_scenarios(
        max_scenarios=max_scenarios,
        balanced_classes=balanced_classes,
    )
    if not scenarios:
        raise RuntimeError("No scenarios found in data/offensive_logs.json")

    # Ensure RAG run uses the chosen Groq model.
    __import__("os").environ["GROQ_MODEL"] = groq_model

    store = FAISSVectorStore()
    rag_generator = AttackChainGenerator(store, model=groq_model)

    all_results: list[dict[str, Any]] = []

    stats = {
        "red_elisar_rag": {"success": 0, "failed": 0},
        "mistral_no_rag": {"success": 0, "failed": 0},
        "llama3_no_rag": {"success": 0, "failed": 0},
    }

    for run_idx in range(1, n_runs + 1):
        logger.info("Run %d/%d", run_idx, n_runs)

        for idx, sc in enumerate(scenarios, 1):
            sid = sc.get("scenario_id", f"S-{idx}")
            query = sc.get("query", sc.get("description", ""))
            expected = sc.get("expected_techniques", [])
            scenario_type = sc.get("scenario_type", "")
            if scenario_type == "single_step":
                chain_len = 1
            else:
                chain_len = min(6, max(4, len(expected) or 4))

            logger.info("Scenario %s (%d/%d)", sid, idx, len(scenarios))

            # 1) RAG
            start = time.perf_counter()
            try:
                rag_result = rag_generator.generate(
                    scenario=query,
                    target_environment=target_environment,
                    chain_length=chain_len,
                )
                rag_latency = time.perf_counter() - start
                retrieved_ids = [
                    r.get("technique_id", "")
                    for r in rag_result.get("retrieval_results", [])
                ]
                rag_metrics = compute_metrics(
                    rag_result.get("attack_chain", {}),
                    expected,
                    retrieved_techniques=retrieved_ids,
                )
                if _count_steps(rag_result.get("attack_chain", {})) < (1 if chain_len <= 1 else 3):
                    raise ValueError("Generated chain too short")
                rag_success = True
                rag_error = None
                stats["red_elisar_rag"]["success"] += 1
            except Exception as e:
                rag_latency = time.perf_counter() - start
                rag_metrics = None
                rag_success = False
                rag_error = str(e)
                stats["red_elisar_rag"]["failed"] += 1
                logger.warning("RAG generation failed for %s: %s", sid, e)

            all_results.append(
                {
                    "config": "red_elisar_rag",
                    "run": run_idx,
                    "scenario_id": sid,
                    "scenario_type": scenario_type,
                    "model": groq_model,
                    "rag_enabled": True,
                    "success": rag_success,
                    "error": rag_error,
                    "metrics": rag_metrics,
                    "latency_s": rag_latency,
                }
            )

            # 2) Mistral no-RAG
            start = time.perf_counter()
            try:
                mis_chain, mis_latency = _call_mistral_no_rag(
                    scenario=query,
                    target_environment=target_environment,
                    chain_length=chain_len,
                    model=mistral_model,
                    api_key=mistral_api_key,
                    temperature=config.LLM_TEMPERATURE,
                    top_p=config.LLM_TOP_P,
                    max_tokens=config.LLM_MAX_TOKENS,
                )
                mis_metrics = compute_metrics(mis_chain, expected)
                if _count_steps(mis_chain) < (1 if chain_len <= 1 else 3):
                    raise ValueError("Generated chain too short")
                mis_success = True
                mis_error = None
                stats["mistral_no_rag"]["success"] += 1
            except Exception as e:
                mis_latency = time.perf_counter() - start
                mis_metrics = None
                mis_success = False
                mis_error = str(e)
                stats["mistral_no_rag"]["failed"] += 1
                logger.warning("Mistral baseline failed for %s: %s", sid, e)

            all_results.append(
                {
                    "config": "mistral_no_rag",
                    "run": run_idx,
                    "scenario_id": sid,
                    "scenario_type": scenario_type,
                    "model": mistral_model,
                    "rag_enabled": False,
                    "success": mis_success,
                    "error": mis_error,
                    "metrics": mis_metrics,
                    "latency_s": mis_latency,
                }
            )

            # 3) Llama3 no-RAG (Groq)
            start = time.perf_counter()
            try:
                lla_chain, lla_latency = _call_groq_no_rag(
                    scenario=query,
                    target_environment=target_environment,
                    chain_length=chain_len,
                    model=groq_model,
                    api_key=groq_api_key,
                    temperature=config.LLM_TEMPERATURE,
                    top_p=config.LLM_TOP_P,
                    max_tokens=config.LLM_MAX_TOKENS,
                )
                lla_metrics = compute_metrics(lla_chain, expected)
                if _count_steps(lla_chain) < (1 if chain_len <= 1 else 3):
                    raise ValueError("Generated chain too short")
                lla_success = True
                lla_error = None
                stats["llama3_no_rag"]["success"] += 1
            except Exception as e:
                lla_latency = time.perf_counter() - start
                lla_metrics = None
                lla_success = False
                lla_error = str(e)
                stats["llama3_no_rag"]["failed"] += 1
                logger.warning("Llama3 baseline failed for %s: %s", sid, e)

            all_results.append(
                {
                    "config": "llama3_no_rag",
                    "run": run_idx,
                    "scenario_id": sid,
                    "scenario_type": scenario_type,
                    "model": groq_model,
                    "rag_enabled": False,
                    "success": lla_success,
                    "error": lla_error,
                    "metrics": lla_metrics,
                    "latency_s": lla_latency,
                }
            )

    summary = _summarize(all_results)
    classwise_summary = _summarize_classwise(all_results)

    single_step_count = sum(1 for s in scenarios if s.get("scenario_type") == "single_step")
    multi_step_count = sum(1 for s in scenarios if s.get("scenario_type") == "multi_step")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "n_runs": n_runs,
        "n_scenarios": len(scenarios),
        "single_step_count": single_step_count,
        "multi_step_count": multi_step_count,
        "groq_model": groq_model,
        "mistral_model": mistral_model,
        "success": stats,
    }

    logger.info(
        "Success rate (RAG): %d/%d | (Mistral): %d/%d | (Llama3): %d/%d",
        stats["red_elisar_rag"]["success"],
        stats["red_elisar_rag"]["success"] + stats["red_elisar_rag"]["failed"],
        stats["mistral_no_rag"]["success"],
        stats["mistral_no_rag"]["success"] + stats["mistral_no_rag"]["failed"],
        stats["llama3_no_rag"]["success"],
        stats["llama3_no_rag"]["success"] + stats["llama3_no_rag"]["failed"],
    )

    json_out = config.OUTPUT_DIR / f"rag_vs_baselines_{timestamp}.json"
    md_out = config.OUTPUT_DIR / f"rag_vs_baselines_{timestamp}.md"

    json_out.write_text(
        json.dumps(
            {
                "metadata": metadata,
                "summary": summary,
                "classwise_summary": classwise_summary,
                "results": all_results,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    _write_markdown_report(
        md_out,
        summary=summary,
        classwise_summary=classwise_summary,
        metadata=metadata,
    )

    return {
        "metadata": metadata,
        "summary": summary,
        "json_output": str(json_out),
        "markdown_output": str(md_out),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare RAG vs Mistral vs Llama3 baselines")
    parser.add_argument("--runs", type=int, default=3, help="Number of repeated runs")
    parser.add_argument("--max-scenarios", type=int, default=50, help="Limit number of scenarios")
    parser.add_argument(
        "--target-environment",
        type=str,
        default="Enterprise Windows Active Directory network",
        help="Target environment text passed to generators",
    )
    parser.add_argument(
        "--groq-model",
        type=str,
        default=__import__("os").getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
        help="Groq model for Llama3 baseline and RAG generation",
    )
    parser.add_argument(
        "--mistral-model",
        type=str,
        default=__import__("os").getenv("MISTRAL_MODEL", "mistral-small-latest"),
        help="Mistral API model for no-RAG baseline",
    )
    parser.add_argument(
        "--balanced-classes",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="When limiting scenarios, sample single_step and multi_step more evenly (default: enabled)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)

    result = run_comparison(
        n_runs=args.runs,
        max_scenarios=args.max_scenarios,
        target_environment=args.target_environment,
        groq_model=args.groq_model,
        mistral_model=args.mistral_model,
        balanced_classes=args.balanced_classes,
    )

    print("Comparison complete")
    print(f"JSON: {result['json_output']}")
    print(f"Markdown: {result['markdown_output']}")


if __name__ == "__main__":
    main()
