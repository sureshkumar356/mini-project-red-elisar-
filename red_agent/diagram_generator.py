"""
Red ELISAR — Mermaid Diagram Generator
========================================
Generates the runtime execution flow diagram automatically on every run.
Output: diagrams/red_elisar_flow.md  (Mermaid flowchart TD)

Usage:
    python diagram_generator.py          # generate diagram only
    from diagram_generator import generate_diagram  # call from other modules
"""

import logging
from pathlib import Path
from datetime import datetime

try:
    import config
    DIAGRAM_DIR = config.DIAGRAMS_DIR
except Exception:
    DIAGRAM_DIR = Path(__file__).parent / "diagrams"

logger = logging.getLogger("red_elisar.diagram")

DIAGRAM_PATH = DIAGRAM_DIR / "red_elisar_flow.md"

# ---------------------------------------------------------------------------
# Mermaid source — complete runtime execution flow
# ---------------------------------------------------------------------------
MERMAID_DIAGRAM = """
```mermaid
flowchart TD
    subgraph InputLayer["① INPUT LAYER"]
        A["Analyst enters scenario query\\nSet: retry_count = 0\\nchain_length, target_environment"]
        B["Tokenize query\\nEncode → all-MiniLM-L6-v2\\n384-dim · L2 normalize"]
        A --> B
    end

    subgraph RetrievalLayer["② RETRIEVAL LAYER"]
        C["Search FAISS HNSW Index\\nM=48 · efSearch=32\\nReturn top-5 neighbors"]
        D{"avg_relevance_score\\n< 0.35\\nAND retry_count < 2 ?"}
        E["Expand query\\nPrepend: cybersecurity attack\\ntechnique MITRE ATT&CK\\nretry_count += 1"]
        C --> D
        D -->|"No — score OK"| F
        D -->|"Yes — low relevance"| E
        E -.->|"retry loop"| C
    end

    subgraph ContextLayer["③ CONTEXT LAYER"]
        F["Extract per chunk:\\ntechnique_id · name · tactic\\ndescription ≤ 1500 chars"]
        G["Apply EMA tactic weight\\nmultipliers from feedback loop\\nAssemble prompt context block"]
        H["Inject SYSTEM_PROMPT\\nInject context + scenario\\nInject JSON schema template\\nCheck: prompt ≤ 4096 tokens"]
        F --> G --> H
    end

    subgraph GenerationLayer["④ GENERATION LAYER"]
        I["Ollama LLM Generation\\nmistral / llama3\\ntemp=0.2 · top_p=0.9\\nmax_tokens=512"]
        J["Strip think blocks\\nStrip markdown fences\\nExtract first JSON object"]
        K{"JSON extraction\\nsuccessful ?"}
        I --> J --> K
        K -->|"No — parse fail"| RC1["retry_count += 1\\nmark invalid"]
        RC1 -.->|"retry if count < 2"| RG["Re-generate\\n← STEP 6"]
        RG -.->|"retry loop"| H
    end

    subgraph ValidationLayer["⑤ VALIDATION LAYER"]
        L{"Schema valid ?\\nRequired: scenario\\ntarget_env · attack_chain[]"}
        M["Each step must have:\\nstep_number · technique_id\\ntactic · detection_opportunity"]
        N{"faithfulness_score\\n≥ 0.6 ?"}
        O["Compute:\\nmatched / total_techniques\\nLog hallucinated IDs"]
        P["Filter hallucinated\\nchunks from context\\nretry_count += 1"]
        Q{"retry_count ≥ 2\\nAND still invalid ?"}
        R["Accept with warning\\nis_valid = False"]
        S["Mark output VALID\\nis_valid = True"]
        L -->|"Invalid schema"| RC2["retry_count += 1"]
        RC2 -.->|"retry loop"| RG
        L -->|"Valid"| M --> O --> N
        N -->|"Yes — faithful"| S
        N -->|"No — hallucinated"| P
        P -.->|"retry loop"| H
        S --> Q
        Q -->|"Yes — max retries"| R
        Q -->|"No — valid"| T
        R --> T
    end

    subgraph PolicyLayer["⑥ POLICY LAYER  Πi"]
        T["Compute Reward:\\nR = 0.4·faith + 0.3·precision\\n+ 0.3·coverage"]
        U["Update tactic weights EMA\\nα = 0.3\\nw_new = 0.7·w_old + 0.3·adj\\ncap=3.0 · floor=0.1"]
        V["Persist feedback_store.json\\nRecord per-phase latency:\\nretrieval · generation\\nvalidation · total ms"]
        T --> U --> V
    end

    subgraph OutputLayer["⑦ OUTPUT LAYER"]
        W["Return structured JSON:\\nscenario · model_used\\nattack_chain[]\\nfaithfulness · latency\\nretry_count · is_valid"]
        X["Display formatted\\nattack chain summary\\nto analyst console"]
        W --> X
    end

    B --> C
    K -->|"Yes — extracted"| L
    V --> W
    U -.->|"weight update\\nnext query"| F
```
"""


def generate_diagram(quiet: bool = False) -> Path:
    """
    Write the Mermaid flowchart to diagrams/red_elisar_flow.md.

    Parameters
    ----------
    quiet : bool
        If True, suppress console output (used when called from main pipeline).

    Returns
    -------
    Path
        Absolute path to the generated diagram file.
    """
    DIAGRAM_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    content = f"""# Red ELISAR — Runtime Execution Flow

> Auto-generated on {timestamp}
> Source: `diagram_generator.py`

## System: RAG-based Offensive Security Agent (Single Query Flow)

The diagram below shows the **complete step-by-step runtime execution** for
a single analyst query — from input through retrieval, generation, validation,
policy feedback, and final JSON output.

**Layers:**
1. Input — query tokenization & embedding
2. Retrieval — FAISS HNSW top-5 search with relevance gate
3. Context — chunk extraction + EMA weight application
4. Generation — Ollama LLM with JSON extraction
5. Validation — schema + faithfulness gating with retry loops
6. Policy (Πi) — reward computation + EMA tactic weight update
7. Output — structured JSON attack chain

---

{MERMAID_DIAGRAM.strip()}

---

**Key Parameters:**
| Parameter | Value |
|---|---|
| FAISS HNSW M | 48 |
| efSearch | 32 |
| top-k retrieval | 5 |
| Relevance threshold | 0.35 |
| Faithfulness threshold | 0.6 |
| Max retries | 2 |
| LLM temperature | 0.2 |
| LLM top_p | 0.9 |
| LLM max_tokens | 512 |
| EMA α | 0.3 |
| Weight floor / cap | 0.1 / 3.0 |
| Embedding dim | 384 |
| Chunk size (tokens) | 512 |
| Chunk overlap (tokens) | 128 |
"""

    DIAGRAM_PATH.write_text(content, encoding="utf-8")

    if not quiet:
        print(f"[diagram] Flowchart written → {DIAGRAM_PATH}")
    else:
        logger.debug("Diagram written → %s", DIAGRAM_PATH)

    return DIAGRAM_PATH


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    path = generate_diagram(quiet=False)
    print(f"Open in VS Code: code \"{path}\"")
