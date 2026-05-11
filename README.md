# Red ELISAR

Red ELISAR is a research-oriented, retrieval-augmented security workflow that turns MITRE ATT&CK knowledge into structured attack-chain generation, evaluation, and log-reconstruction outputs. The main pipeline uses FAISS HNSW retrieval, local Ollama models, and MITRE ATT&CK STIX data to produce grounded JSON and Markdown reports.

## What this repository does

- Parses MITRE ATT&CK Enterprise data from `enterprise-attack.json`
- Chunks techniques for retrieval and indexes them with FAISS HNSW
- Generates attack chains from user scenarios using RAG + Ollama
- Compares RAG against baseline no-RAG generation
- Evaluates retrieval, faithfulness, tactical coverage, and latency
- Reconstructs likely attack chains from partial security logs
- Exports plots, reports, and run artifacts for analysis

## Repository layout

- `main.py` — primary CLI for indexing, generation, interactive mode, health checks, and log reconstruction
- `attack_chain_generator.py` — wraps RAG generation, exports, and scenario presets
- `rag_engine.py` — retrieval, prompt construction, validation, and Ollama chat calls
- `vector_store_faiss.py` — FAISS HNSW vector store used by the main pipeline
- `mitre_parser.py` — parses and exports MITRE ATT&CK techniques
- `chunking.py` — token-based chunk creation for retrieval
- `baseline_runner.py` — baseline vs RAG comparison suite
- `evaluate.py` — retrieval and generation evaluation metriacs
- `run_experiment.py` — end-to-end experiment orchestrator
- `feedback_loop.py` — reward tracking and tactic-weight updates
- `log_reconstructor.py` — infers missing attack steps from partial logs
- `plot_generator.py` — publication-style comparison charts
- `diagram_generator.py` — auto-generates the runtime flow diagram
- `vector_store.py` — legacy ChromaDB implementation kept for compatibility

## Requirements

- Python 3.10 or newer recommended
- Ollama installed locally and running at `http://localhost:11434`
- An Ollama model available, default: `mistral`
- Python dependencies from `requirements.txt`

Install Ollama model examples:

- `ollama serve`
- `ollama pull mistral`
- `ollama pull llama3`

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Make sure Ollama is running and the default model is available.
4. Run the main script once to build the local index and required folders.

## Quick start

Run the default scenario from the main CLI:

```bash
python main.py
```

This will:

1. Parse MITRE ATT&CK data
2. Chunk techniques
3. Build or load the FAISS index
4. Generate the default predefined scenario
5. Export JSON and Markdown reports unless disabled

## Main CLI usage

```bash
python main.py --scenario "APT phishing campaign targeting finance"
python main.py --predefined apt_phishing_to_exfil
python main.py --batch
python main.py --interactive
python main.py --index-only
python main.py --health
python main.py --reconstruct-log data/sample_partial_log.txt
```

Useful options:

- `--target-env` — set the target environment description
- `--chain-length` — control generated attack-chain length
- `--top-k` — adjust retrieval depth
- `--force-reindex` — rebuild the FAISS index from scratch
- `--no-export` — skip JSON and Markdown exports

If no generation mode is supplied, `main.py` runs the default predefined scenario `apt_phishing_to_exfil`.

## Predefined scenarios

The generator ships with five built-in scenarios:

- `apt_phishing_to_exfil`
- `insider_threat`
- `ransomware_attack`
- `supply_chain`
- `cloud_hybrid`

These are defined in `attack_chain_generator.py` and reused by the baseline, evaluation, and experiment scripts.

## Experiment and evaluation

For the full paper-style workflow:

```bash
python run_experiment.py --full
```

Other useful modes:

- `python run_experiment.py --quick` — smaller validation run
- `python run_experiment.py --plots-only --results-file output/results.json`
- `python run_experiment.py --demo-plots`

You can also run the evaluation module or baseline comparison script directly to inspect retrieval metrics, generation quality, or latency.

## Outputs

Generated artifacts are written to these folders:

- `output/` — attack-chain JSON, Markdown reports, experiment results
- `faiss_index/` — persisted FAISS index, chunk metadata, and chunk text
- `figures/` — publication-style charts
- `logs/` — runtime logs
- `diagrams/` — Mermaid flow diagram
- `feedback_store.json` — feedback history and tactic weights

Example outputs already in the repository include attack-chain reports under `output/` and the runtime diagram in `diagrams/red_elisar_flow.md`.

## Data files

The `data/` folder contains the offline inputs used by the project:

- `enterprise-attack.json` — MITRE ATT&CK Enterprise STIX bundle
- `exploit_tools.json` — tool mapping data
- `mitre_mitigations.json` — mitigation mapping data
- `offensive_logs.json` — sample offensive log data
- `sample_partial_log.txt` — example partial log for reconstruction

## Notes

- The main pipeline uses `FAISSVectorStore` from `vector_store_faiss.py`; `vector_store.py` is retained as a legacy ChromaDB implementation.
- The project is designed for local/offline execution once dependencies and the Ollama model are installed.
- This repository is for research, evaluation, and defensive analysis workflows around MITRE ATT&CK and should be used responsibly.

## Regenerating the diagram

The flow diagram is generated automatically during normal runs, or manually with:

```bash
python diagram_generator.py
```

This writes `diagrams/red_elisar_flow.md`.
