# Red ELISAR — Runtime Execution Flow

> Auto-generated on 2026-04-15 19:30:21
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

```mermaid
flowchart TD
    subgraph InputLayer["① INPUT LAYER"]
        A["Analyst enters scenario query\nSet: retry_count = 0\nchain_length, target_environment"]
        B["Tokenize query\nEncode → all-MiniLM-L6-v2\n384-dim · L2 normalize"]
        A --> B
    end

    subgraph RetrievalLayer["② RETRIEVAL LAYER"]
        C["Search FAISS HNSW Index\nM=48 · efSearch=32\nReturn top-5 neighbors"]
        D{"avg_relevance_score\n< 0.35\nAND retry_count < 2 ?"}
        E["Expand query\nPrepend: cybersecurity attack\ntechnique MITRE ATT&CK\nretry_count += 1"]
        C --> D
        D -->|"No — score OK"| F
        D -->|"Yes — low relevance"| E
        E -.->|"retry loop"| C
    end

    subgraph ContextLayer["③ CONTEXT LAYER"]
        F["Extract per chunk:\ntechnique_id · name · tactic\ndescription ≤ 1500 chars"]
        G["Apply EMA tactic weight\nmultipliers from feedback loop\nAssemble prompt context block"]
        H["Inject SYSTEM_PROMPT\nInject context + scenario\nInject JSON schema template\nCheck: prompt ≤ 4096 tokens"]
        F --> G --> H
    end

    subgraph GenerationLayer["④ GENERATION LAYER"]
        I["Ollama LLM Generation\nmistral / llama3\ntemp=0.2 · top_p=0.9\nmax_tokens=512"]
        J["Strip think blocks\nStrip markdown fences\nExtract first JSON object"]
        K{"JSON extraction\nsuccessful ?"}
        I --> J --> K
        K -->|"No — parse fail"| RC1["retry_count += 1\nmark invalid"]
        RC1 -.->|"retry if count < 2"| RG["Re-generate\n← STEP 6"]
        RG -.->|"retry loop"| H
    end

    subgraph ValidationLayer["⑤ VALIDATION LAYER"]
        L{"Schema valid ?\nRequired: scenario\ntarget_env · attack_chain[]"}
        M["Each step must have:\nstep_number · technique_id\ntactic · detection_opportunity"]
        N{"faithfulness_score\n≥ 0.6 ?"}
        O["Compute:\nmatched / total_techniques\nLog hallucinated IDs"]
        P["Filter hallucinated\nchunks from context\nretry_count += 1"]
        Q{"retry_count ≥ 2\nAND still invalid ?"}
        R["Accept with warning\nis_valid = False"]
        S["Mark output VALID\nis_valid = True"]
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
        T["Compute Reward:\nR = 0.4·faith + 0.3·precision\n+ 0.3·coverage"]
        U["Update tactic weights EMA\nα = 0.3\nw_new = 0.7·w_old + 0.3·adj\ncap=3.0 · floor=0.1"]
        V["Persist feedback_store.json\nRecord per-phase latency:\nretrieval · generation\nvalidation · total ms"]
        T --> U --> V
    end

    subgraph OutputLayer["⑦ OUTPUT LAYER"]
        W["Return structured JSON:\nscenario · model_used\nattack_chain[]\nfaithfulness · latency\nretry_count · is_valid"]
        X["Display formatted\nattack chain summary\nto analyst console"]
        W --> X
    end

    B --> C
    K -->|"Yes — extracted"| L
    V --> W
    U -.->|"weight update\nnext query"| F
```

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
