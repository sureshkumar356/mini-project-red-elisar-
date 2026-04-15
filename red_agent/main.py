"""
Usage:
  python main.py --scenario "APT targeting financial institution"
  python main.py --index-only
  python main.py --predefined apt_phishing_to_exfil
  python main.py --batch
  python main.py --health
  python main.py --interactive
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure sibling modules (config, rag_engine, etc.) are importable
# regardless of how this file is launched.
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

import config
from rag.mitre_parser import MITREParser
from rag.vector_store_faiss import FAISSVectorStore
from rag.rag_engine import RAGEngine
from llm.attack_chain_generator import AttackChainGenerator, PREDEFINED_SCENARIOS
from rag.chunking import chunk_techniques
from reporting.diagram_generator import generate_diagram
from comparison.compare_rag_vs_baselines import run_comparison as run_rag_baseline_comparison


def setup_logging(level: str = None, log_file: bool = True):
    config.ensure_directories()
    generate_diagram(quiet=True)
    log_level = getattr(logging, (level or config.LOG_LEVEL).upper(), logging.INFO)
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        file_handler = logging.FileHandler(config.LOG_FILE, encoding='utf-8', mode='a')
        handlers.append(file_handler)
    logging.basicConfig(level=log_level, format=config.LOG_FORMAT, handlers=handlers, force=True)
    logging.getLogger("chromadb").setLevel(logging.WARNING)
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def parse_and_index(force_reindex: bool = False) -> tuple[FAISSVectorStore, dict]:
    logger = logging.getLogger("red_elisar.main")

    logger.info("=" * 60)
    logger.info("STEP 1: Parsing MITRE ATT&CK STIX 2.1 Bundle")
    logger.info("=" * 60)
    parser = MITREParser()
    techniques = parser.parse()
    logger.info(f"Parsed {len(techniques)} techniques")
    for tactic, count in parser.get_tactics_summary().items():
        logger.info(f"  {tactic:<35} {count:>4}")

    logger.info("=" * 60)
    logger.info("STEP 2: Chunking Techniques (512/128 tokens)")
    logger.info("=" * 60)
    chunks = chunk_techniques(techniques)
    logger.info(f"Generated {len(chunks)} chunks from {len(techniques)} techniques")

    logger.info("=" * 60)
    logger.info("STEP 3: Building FAISS HNSW Vector Index (M=48, efSearch=32)")
    logger.info("=" * 60)
    store = FAISSVectorStore()
    stats = store.index_chunks(chunks, force_reindex=force_reindex)
    logger.info(f"Indexing complete: {json.dumps(stats, indent=2)}")

    return store, stats


def run_generation(
    store: FAISSVectorStore,
    scenario: str,
    target_env: str = "Enterprise Windows Active Directory network",
    chain_length: int = None,
    top_k: int = None,
    export_json: bool = True,
    export_md: bool = True,
    target_url: str = None,
) -> dict:
    logger = logging.getLogger("red_elisar.main")
    generator = AttackChainGenerator(store)

    # Verify system is ready before generating
    health = generator.health_check()
    if not health["system_ready"]:
        logger.error(f"System not ready: {health.get('action_required', 'Unknown issue')}")
        logger.error(f"Health status: {json.dumps(health, indent=2)}")
        groq_key = getattr(config, "LLAMA3_API_KEY", None)
        if not groq_key:
            print("\n[X] LLAMA3_API_KEY is not set!")
            print("    Run: $env:LLAMA3_API_KEY = 'gsk_xxxxxxxxxxxxxxxxxxxx'")
            sys.exit(1)
        else:
            logger.info("Groq API key is configured — system is ready.")

    # ── Live vulnerability probe (if --target-url given) ───────────
    probe_result = None
    if target_url:
        from vuln_checks.targeted_attack_scanner import detect_attack_type, probe_target
        attack_type  = detect_attack_type(scenario)
        print(f"\n  [PROBE] Probing {target_url} for [{attack_type.replace('_',' ').title()}]...")
        probe_result = probe_target(target_url, attack_type)
        status = '[OK] CONFIRMED' if probe_result['found'] else '[WARN] Not auto-confirmed'
        print(f"     -> {status} | Severity: {probe_result['severity']}")
        for ev in probe_result.get('evidence', []):
            if ev.get('confirmed'):
                print(f"     -> {ev['detail'][:90]}")

    logger.info("=" * 60)
    logger.info("STEP 3: Generating Attack Chain (RAG Pipeline)")
    logger.info("=" * 60)
    result = generator.generate(
        scenario=scenario,
        target_environment=target_env,
        chain_length=chain_length,
        top_k=top_k,
    )

    # Attach probe result to the result dict so export_markdown can use it
    if probe_result:
        result["probe_result"] = probe_result

    if export_json:
        json_path = generator.export_json(result)
        logger.info(f"JSON exported: {json_path}")
    if export_md:
        md_path = generator.export_markdown(result)
        logger.info(f"Markdown exported: {md_path}")

    print_result_summary(result)
    return result


def run_interactive(store: FAISSVectorStore):
    logger = logging.getLogger("red_elisar.main")
    generator = AttackChainGenerator(store)

    print("\n" + "=" * 60)
    print("  Red ELISAR — Interactive Mode")
    print("  Type 'quit' to exit, 'scenarios' to list predefined")
    print("=" * 60)

    while True:
        print()
        scenario = input("Enter attack scenario (or command): ").strip()
        if not scenario:
            continue
        if scenario.lower() in ("quit", "exit", "q"):
            print("Exiting.")
            break
        if scenario.lower() == "scenarios":
            print("\nPredefined scenarios:")
            for key, val in generator.list_scenarios().items():
                print(f"  {key}: {val['scenario_preview']}")
            continue
        if scenario.lower() == "health":
            health = generator.health_check()
            print(json.dumps(health, indent=2))
            continue

        # Run predefined scenario if key matches
        if scenario in PREDEFINED_SCENARIOS:
            print(f"Using predefined scenario: {scenario}")
            try:
                result = generator.generate_predefined(scenario)
                print_result_summary(result)
                export = input("Export? (json/md/both/no): ").strip().lower()
                if export in ("json", "both"):
                    generator.export_json(result)
                if export in ("md", "both"):
                    generator.export_markdown(result)
            except Exception as e:
                print(f"Error: {e}")
            continue

        # Custom scenario
        target_env = input("Target environment [Enter=default]: ").strip()
        if not target_env:
            target_env = "Enterprise Windows Active Directory network"
        chain_len = input(f"Chain length [Enter={config.DEFAULT_CHAIN_LENGTH}]: ").strip()
        chain_len = int(chain_len) if chain_len.isdigit() else config.DEFAULT_CHAIN_LENGTH

        try:
            result = generator.generate(
                scenario=scenario,
                target_environment=target_env,
                chain_length=chain_len,
            )
            print_result_summary(result)
            export = input("Export? (json/md/both/no): ").strip().lower()
            if export in ("json", "both"):
                generator.export_json(result)
            if export in ("md", "both"):
                generator.export_markdown(result)
        except Exception as e:
            logger.error(f"Generation failed: {e}", exc_info=True)
            print(f"Error: {e}")


def print_result_summary(result: dict):
    print("\n" + "=" * 60)
    print("  ATTACK CHAIN RESULT")
    print("=" * 60)

    chain = result.get("attack_chain", {}).get("attack_chain", [])
    if not chain:
        print("  No attack chain generated.")
        return

    for step in chain:
        hallucinated = " [!HALLUCINATED]" if step.get("_hallucination_flag") else ""
        print(
            f"\n  Step {step.get('step', '?')}: "
            f"[{step.get('technique_id', '???')}] {step.get('technique_name', 'Unknown')}"
            f"{hallucinated}"
        )
        print(f"    Tactic: {step.get('tactic', 'N/A')}")
        print(f"    {step.get('description', 'N/A')[:120]}...")

    analysis = result.get("analysis", {})
    latency = result.get("latency", {})

    print(f"\n{'-' * 60}")
    print(f"  Faithfulness Score: {result.get('faithfulness_score', 0):.0%}")
    print(f"  Tactical Coverage:  {analysis.get('tactical_coverage', {}).get('coverage_ratio', 0):.0%}")
    print(f"  Unique Techniques:  {analysis.get('unique_techniques', 0)}")
    print(f"  Pipeline Latency:   {latency.get('pipeline_total_s', 0):.2f}s")
    print(f"  LLM Latency:        {latency.get('llm_latency_s', 0):.2f}s")
    print(f"  Tokens/sec:         {latency.get('tokens_per_second', 0):.1f}")

    if result.get("warnings"):
        print(f"\n  [WARN] Warnings ({len(result['warnings'])}):")
        for w in result["warnings"]:
            print(f"    - {w[:100]}")

    print("=" * 60)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Red ELISAR — Privacy-Preserving Autonomous Offensive Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scenario "APT phishing campaign targeting finance"
  python main.py --predefined apt_phishing_to_exfil
  python main.py --batch
  python main.py --interactive
  python main.py --index-only
  python main.py --health
  python main.py --assess-url http://127.0.0.1:5000
  python main.py --assess-url http://127.0.0.1:5000 --no-llm
        """,
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--scenario", type=str, help="Custom attack scenario description")
    mode_group.add_argument("--predefined", type=str, choices=list(PREDEFINED_SCENARIOS.keys()), help="Use a predefined scenario")
    mode_group.add_argument("--batch", action="store_true", help="Run all predefined scenarios")
    mode_group.add_argument("--interactive", action="store_true", help="Interactive mode")
    mode_group.add_argument("--index-only", action="store_true", help="Parse and index only, no generation")
    mode_group.add_argument("--health", action="store_true", help="System health check")
    mode_group.add_argument("--reconstruct-log", type=str, metavar="LOG_FILE", help="Reconstruct attack chain from partial log file")
    mode_group.add_argument(
        "--assess-url",
        type=str,
        metavar="URL",
        help="Autonomously assess a website for vulnerabilities using MITRE ATT&CK"
    )

    parser.add_argument("--target-env", type=str, default="Enterprise Windows Active Directory network")
    parser.add_argument("--target-url", type=str, default=None,
                        help="Live URL to probe for the specific vulnerability (e.g. http://127.0.0.1:5000)")
    parser.add_argument("--chain-length", type=int, default=None)
    parser.add_argument("--top-k", type=int, default=None)
    parser.add_argument("--force-reindex", action="store_true")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--no-export", action="store_true")
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip LLM analysis in --assess-url mode (faster)")
    parser.add_argument(
        "--with-comparison",
        action="store_true",
        help="After scenario generation, also run RAG vs Mistral/Llama3 comparison",
    )
    parser.add_argument(
        "--comparison-runs",
        type=int,
        default=3,
        help="Number of repeated runs for --with-comparison (default: 3)",
    )
    parser.add_argument(
        "--comparison-max-scenarios",
        type=int,
        default=50,
        help="Scenario count for --with-comparison (default: 50)",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(level=args.log_level)
    logger = logging.getLogger("red_elisar.main")

    print("\n" + "=" * 60)
    print("  Red ELISAR")
    print("  Privacy-Preserving Autonomous Offensive Security Agent")
    print("  Using Edge AI and Retrieval-Augmented Generation")
    print("=" * 60)

    total_start = time.perf_counter()

    try:
        if args.health:
            store = FAISSVectorStore()
            generator = AttackChainGenerator(store)
            health = generator.health_check()
            print("\nSystem Health:")
            print(json.dumps(health, indent=2))
            return

        store, index_stats = parse_and_index(force_reindex=args.force_reindex)

        if args.index_only:
            print("\nIndexing complete. Exiting.")
            return

        if args.scenario:
            run_generation(
                store=store,
                scenario=args.scenario,
                target_env=args.target_env,
                chain_length=args.chain_length,
                top_k=args.top_k,
                export_json=not args.no_export,
                export_md=not args.no_export,
                target_url=getattr(args, "target_url", None),
            )

            if args.with_comparison:
                print("\n" + "=" * 60)
                print("  RUNNING COMPARISON (RAG vs MISTRAL/LLaMA3)")
                print("=" * 60)
                try:
                    comparison_result = run_rag_baseline_comparison(
                        n_runs=args.comparison_runs,
                        max_scenarios=args.comparison_max_scenarios,
                        target_environment=args.target_env,
                        groq_model=getattr(config, "GROQ_MODEL", "llama-3.1-8b-instant"),
                        mistral_model="mistral-small-latest",
                    )
                    print("[OK] Comparison complete")
                    print(f"[JSON] {comparison_result['json_output']}")
                    print(f"[MD]   {comparison_result['markdown_output']}")
                except Exception as e:
                    print(f"[WARN] Comparison skipped/failed: {e}")
                    print("       Ensure MISTRAL_API_KEY and LLAMA3_API_KEY are set in this terminal.")

        elif args.predefined:
            generator = AttackChainGenerator(store)
            result = generator.generate_predefined(args.predefined)
            print_result_summary(result)
            if not args.no_export:
                generator.export_json(result)
                generator.export_markdown(result)

        elif args.batch:
            generator = AttackChainGenerator(store)
            results = generator.generate_batch()
            for r in results:
                if "error" not in r:
                    print_result_summary(r)
            if not args.no_export:
                generator.export_batch(results)

        elif args.interactive:
            run_interactive(store)

        elif args.reconstruct_log:
            from log_reconstructor import LogReconstructor
            log_path = Path(args.reconstruct_log)
            if not log_path.exists():
                print(f"\n[X] Log file not found: {log_path}")
                sys.exit(1)
            raw_log = log_path.read_text(encoding='utf-8')
            reconstructor = LogReconstructor(store)
            result = reconstructor.reconstruct(raw_log)

            print("\n" + "=" * 60)
            print("  LOG RECONSTRUCTION RESULT")
            print("=" * 60)
            print(f"  Parsed entries:  {result.get('parsed_entries', 0)}")
            gaps = result.get('gap_analysis', {})
            print(f"  Kill chain coverage: {gaps.get('coverage', 0):.0%}")
            print(f"  Observed tactics: {', '.join(gaps.get('observed_tactics', []))}")
            print(f"  Missing tactics:  {', '.join(gaps.get('missing_tactics', []))}")

            if not args.no_export:
                out_path = config.OUTPUT_DIR / f"reconstruction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(out_path, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, default=str)
                print(f"\n  Result exported: {out_path}")
            print("=" * 60)

        elif args.assess_url:
            # ── Autonomous Web Vulnerability Assessment ──────────
            from vuln_checks.web_vuln_agent import WebVulnAgent
            agent  = WebVulnAgent(force_reindex=args.force_reindex)
            result = agent.assess(args.assess_url, use_llm=not args.no_llm)
            print(f"\n  Markdown report : {result['md_path']}")
            print(f"  JSON report     : {result['json_path']}")

        else:
            # Default: run the flagship APT scenario
            logger.info("No mode specified. Running default APT scenario.")
            generator = AttackChainGenerator(store)
            result = generator.generate_predefined("apt_phishing_to_exfil")
            print_result_summary(result)
            if not args.no_export:
                generator.export_json(result)
                generator.export_markdown(result)

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        print(f"\n {e}")
        sys.exit(1)
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        print(f"\n {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\nS Unexpected error: {e}")
        sys.exit(1)
    finally:
        logger.info(f"Total execution time: {time.perf_counter() - total_start:.2f}s")


if __name__ == "__main__":
    main()
