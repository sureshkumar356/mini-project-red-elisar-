# Source Code Paste Guide (Report)

Project: Red ELISAR
Date: 2026-04-30

This file tells you exactly what code to paste into your academic report, in order, with heading names.
Use this as your "Source Code Appendix" plan.

## Important Rule
- Do not paste full files.
- Paste only the listed class/function blocks.
- Keep each pasted block about 30-120 lines.
- For very large functions, paste the key part and add: "Full implementation available in repository file path".

## Suggested Appendix Flow (From RAG to Final Output)

### 1) RAG Data Preparation
Heading: `A. MITRE ATT&CK Parsing and Cleaning`
- File: `red_agent/rag/mitre_parser.py`
- Paste:
  - `class AttackTechnique`
  - `def clean_description(...)`
  - `class MITREParser` (constructor + parse flow)

Heading: `B. Technique Chunking for Retrieval`
- File: `red_agent/rag/chunking.py`
- Paste:
  - `def chunk_text(...)`
  - `def chunk_techniques(...)`
- Optional:
  - `def chunk_offensive_logs(...)` (only if logs are part of your method chapter)

### 2) Vector Store and Indexing
Heading: `C. FAISS Vector Store Construction`
- File: `red_agent/rag/vector_store_faiss.py`
- Paste:
  - `class FAISSVectorStore` (init, index, save/load, search methods)

Heading: `D. Vector Interface Layer`
- File: `red_agent/rag/vector_store.py`
- Paste:
  - `class VectorStore` (if you want to show abstraction/design)

### 3) RAG Retrieval Engine
Heading: `E. Retrieval-Augmented Generation Engine`
- File: `red_agent/rag/rag_engine.py`
- Paste:
  - `class RAGEngine`
- Focus on methods that do:
  - query embedding
  - top-k retrieval
  - relevance filtering
  - context assembly

### 4) MITRE Mapping Layer
Heading: `F. MITRE Technique Mapping`
- File: `red_agent/mappings/mitre_mapper.py`
- Paste:
  - `class MITREMapper`
- Include the method that maps scenario/vulnerability text to technique IDs.

Heading: `G. Tool and Mitigation Enrichment`
- Files:
  - `red_agent/mappings/exploit_tool_mapper.py`
  - `red_agent/mappings/mitigation_mapper.py`
- Paste:
  - `_load_tools`, `get_tools`, `get_tools_for_chain`
  - `_load_mitigations`, `get_mitigation`, `get_mitigations_for_chain`

### 5) LLM Attack Chain Generation
Heading: `H. LLM Client with Retry and JSON Enforcement`
- File: `red_agent/llm/llm_client.py`
- Paste:
  - `class LLMResult`
  - `def _post_with_retry(...)`
  - `def groq_chat_json(...)`
  - `def mistral_chat_json(...)`

Heading: `I. Attack Chain Generator`
- File: `red_agent/llm/attack_chain_generator.py`
- Paste:
  - `class AttackChainGenerator`
- Show prompt construction + chain post-processing.

### 6) Validation and Vulnerability Checks
Heading: `J. Scenario Input Sanitization`
- File: `red_agent/vuln_checks/input_sanitizer.py`
- Paste:
  - `def sanitize_scenario(...)`

Heading: `K. Live Vulnerability Validation`
- File: `red_agent/vuln_checks/live_vuln_checker.py`
- Paste:
  - `class LiveVulnChecker`
  - `def render_markdown_report(...)` (optional)

Heading: `L. Targeted Attack Probing`
- File: `red_agent/vuln_checks/targeted_attack_scanner.py`
- Paste:
  - `def detect_attack_type(...)`
  - `def probe_target(...)`
  - one or two specific probe functions only (example: `_probe_sqli`, `_probe_xss`)

Heading: `M. Automated Scanner and Recon`
- Files:
  - `red_agent/vuln_checks/vuln_scanner.py`
  - `red_agent/vuln_checks/web_recon.py`
- Paste:
  - `class VulnerabilityScanner`
  - `class WebReconAgent`

### 7) Report Generation
Heading: `N. Security Report Generation`
- File: `red_agent/reporting/report_generator.py`
- Paste:
  - `class ReportGenerator`

Heading: `O. PDF Rendering Pipeline`
- File: `red_agent/reporting/pdf_reporter.py`
- Paste:
  - `def render_markdown_to_pdf(...)`

### 8) End-to-End Orchestration (Last Section)
Heading: `P. Runtime Orchestration and CLI Workflow`
- File: `run.py`
- Paste only these high-value parts:
  - `class RuntimeContext`
  - `def discover_attack_surface(...)`
  - `def _build_dynamic_chain_from_mapping(...)`
  - `def run_full_web_scan(...)`
  - `def run_scenario_generation(...)`
  - `def run_scenario_url_validation(...)`
  - `def run_scenario_only_analysis(...)`
  - `def menu_loop(...)` and `def main(...)`

### 9) Configuration
Heading: `Q. Runtime Configuration`
- File: `red_agent/config.py`
- Paste:
  - constants used by retrieval, thresholds, output paths
  - `def ensure_directories(...)`

## What NOT to Paste
- `enterprise-attack.json` (too large dataset)
- `faiss_index/*` binary/index files
- `output/*` generated reports
- `__pycache__/*`
- full logs

## Suggested Appendix Chapter Order (One-line format)
1. MITRE Parsing
2. Chunking
3. FAISS Indexing
4. RAG Retrieval
5. MITRE Mapping
6. Tool/Mitigation Mapping
7. LLM Client
8. Attack Chain Generation
9. Input Sanitization
10. Validation and Probing
11. Vulnerability Scanner and Recon
12. Report Generator
13. Runtime Orchestration (`run.py`)
14. Config

## Quick Length Target (for clean report)
- Main report body source code section: 8-12 pages
- Full appendix source code: 20-35 pages
- Keep each section with: heading + 1 paragraph explanation + selected code block.
