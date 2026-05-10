import os
from pathlib import Path

# Paths
AGENT_ROOT   = Path(__file__).parent.resolve()
PROJECT_ROOT = AGENT_ROOT.parent

MITRE_STIX_PATH     = PROJECT_ROOT / "enterprise-attack.json"
FAISS_INDEX_DIR     = AGENT_ROOT / "faiss_index"
CHROMA_PERSIST_DIR  = AGENT_ROOT / "chroma_db"
OUTPUT_DIR          = AGENT_ROOT / "output"
LOG_DIR             = AGENT_ROOT / "logs"
FIGURES_DIR         = AGENT_ROOT / "figures"
DATA_DIR            = AGENT_ROOT / "data"
DIAGRAMS_DIR        = AGENT_ROOT / "diagrams"
FEEDBACK_STORE_PATH = AGENT_ROOT / "feedback_store.json"

# Embedding model
EMBEDDING_MODEL_NAME  = "all-MiniLM-L6-v2"
EMBEDDING_DIMENSION   = 384
EMBEDDING_BATCH_SIZE  = 64

# Chunking - 512 tokens, 128 overlap
CHUNK_SIZE_TOKENS    = 512
CHUNK_OVERLAP_TOKENS = 128
CHUNK_TOKENIZER      = EMBEDDING_MODEL_NAME

# FAISS HNSW - M=48, efSearch=32
FAISS_HNSW_M               = 48
FAISS_HNSW_EF_SEARCH       = 32
FAISS_HNSW_EF_CONSTRUCTION = 200
RAG_TOP_K                  = 8
RELEVANCE_THRESHOLD        = 2.0
DIVERSITY_TOP_K_WIDE       = 20

# Retrieve a wider candidate set, then select a small context budget for the prompt.
# This keeps prompts small while improving multi-step coverage.
RAG_RETRIEVAL_TOP_K_WIDE   = 18
DIVERSITY_KEY_TACTICS = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# ChromaDB (legacy)
CHROMA_COLLECTION_NAME = "mitre_attack_techniques"
CHROMA_DISTANCE_METRIC = "cosine"

# ── LLM API Keys ────────────────────────────────────────────────────
# Red ELISAR uses TWO cloud APIs — NO local Ollama required.
#
#  Set these in your terminal before running:
#    $env:LLAMA3_API_KEY   = "gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#    $env:MISTRAL_API_KEY = "WkMxgW8nDReEYNv6dVezTvh28VMcVcGn"
#
LLAMA3_API_KEY    = os.getenv("LLAMA3_API_KEY", "")          # LLaMA 3 via Groq
MISTRAL_API_KEY   = os.getenv("MISTRAL_API_KEY", "")       # Mistral via Mistral.ai

# Model names sent to the respective APIs
GROQ_MODEL        = os.getenv("GROQ_MODEL",    "llama-3.1-8b-instant")   # LLaMA 3 on Groq
MISTRAL_MODEL     = os.getenv("MISTRAL_MODEL", "mistral-small-latest")   # Mistral on Mistral.ai

# Models used during benchmarking comparison
BENCHMARK_MODELS  = ["llama-3.1-8b-instant", "mistral-small-latest"]

# LLM generation hyperparameters
LLM_TEMPERATURE   = 0.2
LLM_TOP_P         = 0.9
LLM_MAX_TOKENS    = 2048
LLM_TIMEOUT       = 60
LLM_CONTEXT_WINDOW = 8192     # kept for schema compatibility

# LLM reliability / pacing
LLM_REQUEST_SPACING_S = 1.2
LLM_MAX_RETRIES = 6
LLM_RETRY_BASE_BACKOFF_S = 2.0
LLM_RETRY_MAX_BACKOFF_S = 90.0
LLM_RETRY_JITTER_S = 0.5

# If a provider asks us to wait longer than this on 429 (e.g., token/day exhausted),
# stop the run instead of sleeping for a very long time.
LLM_MAX_429_WAIT_S = 900.0

# RAG prompt budget controls
RAG_MAX_CONTEXT_TECHNIQUES = 14
RAG_TECHNIQUE_SUMMARY_MAX_CHARS = 420

# Context selection strategy
RAG_DIVERSIFY_CONTEXT = True
RAG_CONTEXT_TOP_N_SIMILAR = 3

# Retrieval variants (balanced speed/quality)
RAG_MAX_QUERY_VARIANTS = 2

# Optional lightweight reranking (no external model)
RAG_ENABLE_RERANK = True
RAG_RERANK_WEIGHT = 0.35

# Retrieval mode
RAG_USE_DIVERSE_RETRIEVAL = True

# ── Ollama (NOT USED — kept only so legacy imports don't crash) ──────
OLLAMA_BASE_URL   = ""         # Ollama is NOT used in this project
OLLAMA_MODEL      = GROQ_MODEL  # alias — do not rely on this

# RAG pipeline
MAX_DESCRIPTION_LENGTH = 1500
DEFAULT_CHAIN_LENGTH   = 14
MAX_CHAIN_LENGTH       = 14

# Evaluation
N_EVALUATION_RUNS        = 5
N_TOTAL_SCENARIOS        = 50
N_SINGLE_STEP_SCENARIOS  = 18
N_MULTI_STEP_SCENARIOS   = 32

# Performance
AGGRESSIVE_GC            = True
CHROMA_INSERT_BATCH_SIZE = 100
EMBEDDING_WORKERS        = 0

# Web UI performance tuning (keeps real integrations but with tighter timeouts)
WEB_UI_DISCOVERY_MAX_PAGES = 18
WEB_UI_DISCOVERY_TIMEOUT_S = 6.0
WEB_UI_RECON_TIMEOUT_S      = 6.0
WEB_UI_FORM_TIMEOUT_S       = 5.0
WEB_UI_LIVE_TIMEOUT_S       = 6.0
WEB_UI_PROBE_TIMEOUT_S      = 5.0
WEB_UI_STREAM_HEARTBEAT_S   = 12.0

# Logging
LOG_LEVEL  = "INFO"
LOG_FORMAT = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
LOG_FILE   = LOG_DIR / "red_elisar.log"


def ensure_directories():
    for directory in [
        FAISS_INDEX_DIR, CHROMA_PERSIST_DIR, OUTPUT_DIR,
        LOG_DIR, FIGURES_DIR, DATA_DIR, DIAGRAMS_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
