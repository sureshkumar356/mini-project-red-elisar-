# Red ELISAR

Red ELISAR is a Python red-team assistant that uses MITRE ATT&CK data and a
RAG pipeline to generate attack chains, validate scenarios, and produce reports.
It includes an interactive CLI and a Flask web UI with live streaming output.

## Features
- MITRE ATT&CK STIX ingestion with FAISS indexing
- Scenario-to-attack-chain generation with LLMs
- Web recon and vulnerability scanning
- Report exports in JSON/Markdown (PDF when available)
- Optional vulnerable demo target for local testing

## Requirements
- Python 3.8+
- API keys in the environment:
  - `LLAMA3_API_KEY`
  - `MISTRAL_API_KEY`

## Setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r red_agent/requirements.txt
```

## Usage
### CLI
```bash
python run.py
```
Choose from the interactive menu: full scan, generate scenario, validate
scenario on a URL, or analyze scenario only.

### Web UI
```bash
python app.py
```
Open http://127.0.0.1:7860 (separate from the demo target on port 5000).

### Demo target (optional)
```bash
python vulnerable_app/app.py
```
Open http://127.0.0.1:5000 (separate service from the web UI).

## Outputs
- Reports and logs: `red_agent/output`, `red_agent/logs`
- FAISS index: `red_agent/faiss_index`

## Safety
Use only against systems you own or have explicit authorization to test.
