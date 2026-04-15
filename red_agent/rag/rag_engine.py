import json
import time
import logging
import re
from typing import Optional
from datetime import datetime, timezone

import requests
import jsonschema

import config
from .vector_store_faiss import FAISSVectorStore
from vuln_checks.input_sanitizer import sanitize_scenario
from mappings.mitigation_mapper import get_mitigation
from mappings.exploit_tool_mapper import get_tools
from llm.llm_client import groq_chat_json, mistral_chat_json

logger = logging.getLogger("red_elisar.rag_engine")


ATTACK_CHAIN_SCHEMA = {
    "type": "object",
    "required": ["steps"],
    "properties": {
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["step", "description"],
                "anyOf": [
                    {"required": ["technique"]},
                    {"required": ["technique_id"]},
                ],
                "properties": {
                    "step": {"type": "integer", "minimum": 1},
                    "technique": {"type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$"},
                    "technique_id": {"type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$"},
                    "description": {"type": "string", "minLength": 1},
                },
            },
        },
        "metadata": {
            "type": "object",
            "properties": {
                "scenario": {"type": "string"},
                "target_environment": {"type": "string"},
                "chain_length": {"type": "integer"},
                "techniques_used": {"type": "integer"},
            },
        },
    },
}


SYSTEM_PROMPT = (
    "You are an expert red team cybersecurity analyst using the MITRE ATT&CK framework.\n\n"
    "Your task is to generate a realistic, context-aware attack chain strictly aligned with the given scenario."
)

USER_PROMPT_TEMPLATE = """========================
INPUT
=====

* Attack scenario description: {scenario}
* Retrieved MITRE ATT&CK techniques (context):
{context}

========================
STRICT INSTRUCTIONS
===================

1. RELEVANCE (CRITICAL RULE)

* ONLY use techniques that are directly relevant to the scenario.
* DO NOT include unrelated techniques.

Examples:

* If scenario is SQL Injection → DO NOT use brute force (T1110)
* If scenario is CSRF → focus on session hijacking, cookies, user execution
* If scenario is file exposure → focus on credential access, discovery

2. CONTEXT USAGE

* You MUST use at least 3 techniques from the retrieved context
* Prefer highest relevance score techniques
* Do NOT invent unrelated techniques outside context

3. ATTACK FLOW (LOGICAL CHAIN)

* Generate {min_steps}–{max_steps} steps
* Each step MUST logically follow the previous step
* Ensure cause → effect relationship

4. TACTIC ALIGNMENT

* Use only necessary tactics (do NOT force all 14 MITRE tactics)
* Typical flow:
  Initial Access → Execution → Credential Access → Persistence → (Optional) Exfiltration

5. REALISM RULE

* Each step must reflect how a real attacker would proceed
* Avoid redundant or repeated techniques
* Avoid vague or generic steps

6. STRICT FILTERING
   Before output:

* Remove any step not directly tied to the scenario
* Ensure every step contributes to attack progression

========================
GOOD vs BAD EXAMPLES
====================
BAD (irrelevant):
Step 1: Brute Force (T1110) ❌
Step 2: SQL Injection ❌

GOOD (relevant):
Step 1: Exploit Public-Facing Application (T1190)
Step 2: Data Extraction via SQL Injection
Step 3: Credential Access (T1078)
Step 4: Persistence via Valid Accounts

========================
OUTPUT FORMAT (STRICT JSON ONLY)
================================

{{
"steps": [
{{
"step": 1,
"technique": "Txxxx",
"tactic": "initial-access",
"description": "..."
}},
{{
"step": 2,
"technique": "Txxxx",
"tactic": "execution",
"description": "..."
}},
{{
"step": 3,
"technique": "Txxxx",
"tactic": "credential-access",
"description": "..."
}},
{{
"step": 4,
"technique": "Txxxx",
"tactic": "persistence",
"description": "..."
}}
]
}}

========================
CONSTRAINTS
===========

* Minimum {min_steps} steps, maximum {max_steps} steps
* No irrelevant techniques
* No duplicate steps
* No explanation outside JSON
* Every step must match the scenario context
"""


USER_PROMPT_TEMPLATE_SINGLE = """ATTACK SCENARIO:
{scenario}

RETRIEVED TECHNIQUES (5 concise entries):
{context}

INSTRUCTIONS:
- Generate exactly 1 technique step.
- Use ONLY techniques from the retrieved list above.
- Choose the FIRST technique in the retrieved list (highest relevance).

OUTPUT FORMAT (STRICT JSON ONLY):
{{
    "steps": [
        {{"step": 1, "technique": "Txxxx", "tactic": "...", "description": "...", "rationale": "...", "prerequisites": ["..."], "detection_considerations": "...", "mitigation": "..."}}
    ]
}}
"""
class RAGEngine:

    MITRE_TACTICS = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]

    def __init__(self, vector_store: FAISSVectorStore, model: str = None):
        self.vector_store = vector_store
        # Model used for generation — always the Groq/Mistral API model, never Ollama
        self.model = model or config.GROQ_MODEL

    def retrieve(
        self,
        scenario: str,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> list[dict]:
        if top_k is None:
            top_k = config.RAG_TOP_K
        results = self.vector_store.query(
            query_text=scenario,
            top_k=top_k,
            tactic_filter=tactic_filter,
            platform_filter=platform_filter,
        )
        logger.info(f"Retrieved {len(results)} techniques for scenario: '{scenario[:60]}...'")
        return results

    @staticmethod
    def _clean_ws(text: str) -> str:
        return re.sub(r"\s+", " ", str(text or "")).strip()

    def _count_grounded_steps(
        self,
        chain_steps: list[dict],
        retrieved_techniques: list[dict],
    ) -> int:
        retrieved_ids = {
            str(t.get("technique_id", "")).strip().upper()
            for t in (retrieved_techniques or [])
            if t.get("technique_id")
        }
        retrieved_bases = {tid.split(".")[0] for tid in retrieved_ids if tid}
        grounded = 0
        for step in chain_steps or []:
            if not isinstance(step, dict):
                continue
            tid = str(step.get("technique_id") or "").strip().upper()
            if not tid:
                continue
            if tid in retrieved_ids or tid.split(".")[0] in retrieved_bases:
                grounded += 1
        return grounded

    def _summarize_technique_for_prompt(self, tech: dict) -> str:
        tid = self._clean_ws(tech.get("technique_id", ""))
        name = self._clean_ws(tech.get("name", ""))
        return f"{tid} – {name}" if name else tid

    def _dedupe_limit_techniques(self, techniques: list[dict], top_k: int) -> list[dict]:
        # Prefer highest relevance per technique_id; avoid base+sub-technique duplicates when possible.
        by_id: dict[str, dict] = {}
        for t in techniques:
            tid = self._clean_ws(t.get("technique_id", ""))
            if not tid:
                continue
            prev = by_id.get(tid)
            if prev is None or float(t.get("relevance_score", 0.0) or 0.0) > float(prev.get("relevance_score", 0.0) or 0.0):
                by_id[tid] = t

        # Drop sub-techniques if the base technique is already present.
        selected: list[dict] = []
        seen_bases: set[str] = set()
        for tid, t in sorted(by_id.items(), key=lambda kv: float(kv[1].get("relevance_score", 0.0) or 0.0), reverse=True):
            base = tid.split(".")[0]
            if "." in tid and base in by_id:
                continue
            if base in seen_bases and base != tid:
                continue
            selected.append(t)
            seen_bases.add(base)
            if len(selected) >= top_k:
                break
        return selected

    def _select_context_techniques(
        self,
        scenario: str,
        techniques: list[dict],
        desired_count: int,
        chain_length: int,
    ) -> list[dict]:
        if desired_count <= 0:
            return []

        # Optional reranking first.
        techniques = self._rerank_optional(scenario, techniques)

        # Dedupe while keeping a relevance-sorted list.
        deduped = self._dedupe_limit_techniques(techniques, top_k=max(desired_count, len(techniques) or desired_count))
        if len(deduped) <= desired_count:
            return deduped

        diversify = bool(getattr(config, "RAG_DIVERSIFY_CONTEXT", True)) and int(chain_length or 1) > 1
        if not diversify:
            return deduped[:desired_count]

        top_n_similar = int(getattr(config, "RAG_CONTEXT_TOP_N_SIMILAR", 3))
        top_n_similar = max(0, min(top_n_similar, desired_count))

        selected: list[dict] = []
        selected_ids: set[str] = set()
        covered_tactics: set[str] = set()

        def _norm_tactics(t: dict) -> set[str]:
            tactics = t.get("tactics", [])
            if isinstance(tactics, str):
                tactics = [x.strip() for x in tactics.split(",") if x.strip()]
            return {self._normalize_tactic(x) for x in (tactics or []) if x}

        # 1) Always keep the most similar items.
        for t in deduped[:top_n_similar]:
            tid = self._clean_ws(t.get("technique_id", ""))
            if not tid or tid in selected_ids:
                continue
            selected.append(t)
            selected_ids.add(tid)
            covered_tactics |= _norm_tactics(t)
            if len(selected) >= desired_count:
                return selected

        # 2) Then add tactic coverage (from key tactics) using remaining candidates.
        for key_tactic in getattr(config, "DIVERSITY_KEY_TACTICS", []):
            kt = self._normalize_tactic(key_tactic)
            if kt in covered_tactics:
                continue
            for t in deduped[top_n_similar:]:
                tid = self._clean_ws(t.get("technique_id", ""))
                if not tid or tid in selected_ids:
                    continue
                tt = _norm_tactics(t)
                if kt in tt:
                    selected.append(t)
                    selected_ids.add(tid)
                    covered_tactics |= tt
                    break
            if len(selected) >= desired_count:
                return selected

        # 3) Fill remaining slots by relevance.
        for t in deduped:
            if len(selected) >= desired_count:
                break
            tid = self._clean_ws(t.get("technique_id", ""))
            if not tid or tid in selected_ids:
                continue
            selected.append(t)
            selected_ids.add(tid)

        return selected[:desired_count]

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        tokens = re.findall(r"[a-zA-Z0-9_-]{2,}", (text or "").lower())
        stop = {
            "the",
            "and",
            "for",
            "with",
            "from",
            "that",
            "this",
            "into",
            "over",
            "via",
            "using",
            "uses",
            "used",
            "attack",
            "attacker",
            "malware",
        }
        return {t for t in tokens if t not in stop}

    def _rerank_optional(self, query: str, techniques: list[dict]) -> list[dict]:
        if not bool(getattr(config, "RAG_ENABLE_RERANK", False)):
            return techniques

        q = self._tokenize(query)
        if not q:
            return techniques

        weight = float(getattr(config, "RAG_RERANK_WEIGHT", 0.25))
        rescored = []
        for t in techniques:
            text = f"{t.get('name','')} {t.get('description_preview','')} {t.get('document','')}"
            tt = self._tokenize(text)
            overlap = len(q & tt) / max(1, len(q))
            base = float(t.get("relevance_score", 0.0) or 0.0)
            combined = (1.0 - weight) * base + weight * overlap
            t2 = dict(t)
            t2["_rerank_overlap"] = round(overlap, 4)
            t2["_combined_score"] = round(combined, 4)
            rescored.append(t2)

        rescored.sort(key=lambda x: float(x.get("_combined_score", 0.0) or 0.0), reverse=True)
        return rescored

    def build_prompt(
        self,
        scenario: str,
        target_environment: str,
        retrieved_techniques: list[dict],
        chain_length: int = None,
    ) -> tuple[str, str]:
        if chain_length is None:
            chain_length = config.DEFAULT_CHAIN_LENGTH

        # Enforce a small context budget (prompt stays small), but ALWAYS include
        # up to 12 unique techniques in the prompt context.
        max_ctx = int(getattr(config, "RAG_MAX_CONTEXT_TECHNIQUES", 12))
        desired = min(max_ctx, 12)
        retrieved_techniques = self._select_context_techniques(
            scenario=scenario,
            techniques=retrieved_techniques,
            desired_count=desired,
            chain_length=chain_length,
        )

        context = "\n".join(f"- {self._summarize_technique_for_prompt(t)}" for t in retrieved_techniques)

        system = SYSTEM_PROMPT
        if int(chain_length or 1) <= 1:
            user = USER_PROMPT_TEMPLATE_SINGLE.format(
                scenario=scenario,
                context=context,
            )
        else:
            user = USER_PROMPT_TEMPLATE.format(
                scenario=scenario,
                context=context,
                min_steps=8,
                max_steps=10,
            )

        total_chars = len(system) + len(user)
        logger.info(f"Prompt constructed: {total_chars} chars, {len(retrieved_techniques)} techniques in context")
        return system, user

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature_override: Optional[float] = None,
        max_tokens_override: Optional[int] = None,
    ) -> tuple[str, dict]:
        latency = {
            "llm_request_start": time.perf_counter(),
            "llm_model": self.model,
            "prompt_chars": len(system_prompt) + len(user_prompt),
        }

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        max_tokens = int(max_tokens_override if max_tokens_override is not None else getattr(config, "LLM_MAX_TOKENS", 512))
        temperature = float(temperature_override if temperature_override is not None else getattr(config, "LLM_TEMPERATURE", 0.2))
        top_p = float(getattr(config, "LLM_TOP_P", 0.9))

        logger.info("Sending request to %s (%s)...", "Mistral" if "mistral" in self.model.lower() else "Groq", self.model)
        try:
            if "mistral" in self.model.lower():
                result = mistral_chat_json(
                    messages=messages,
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=top_p,
                )
            else:
                result = groq_chat_json(
                    messages=messages,
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=top_p,
                )

            raw_text = result.content
            total_tokens = (result.usage or {}).get("total_tokens") or 0
            prompt_tokens = (result.usage or {}).get("prompt_tokens") or 0

            if self._extract_json(raw_text) is None:
                logger.warning("Model returned malformed JSON. Retrying once with stricter instruction.")
                strict = user_prompt + "\n\nIMPORTANT: Return exactly one valid JSON object and nothing else."
                messages[-1] = {"role": "user", "content": strict}
                if "mistral" in self.model.lower():
                    retry = mistral_chat_json(
                        messages=messages,
                        model=self.model,
                        max_tokens=max_tokens,
                        temperature=0.0,
                        top_p=top_p,
                    )
                else:
                    retry = groq_chat_json(
                        messages=messages,
                        model=self.model,
                        max_tokens=max_tokens,
                        temperature=0.0,
                        top_p=top_p,
                    )
                if self._extract_json(retry.content) is not None:
                    raw_text = retry.content
                    total_tokens = (retry.usage or {}).get("total_tokens") or total_tokens

        except Exception as e:
            raise ConnectionError(f"LLM API error: {e}")

        # ── OLD Ollama code (commented out for reference) ────────
        # payload = {
        #     "model": self.model,
        #     "messages": [
        #         {"role": "system", "content": system_prompt},
        #         {"role": "user",   "content": user_prompt},
        #     ],
        #     "stream": True,
        #     "options": {
        #         "temperature": config.LLM_TEMPERATURE,
        #         "num_predict": config.LLM_MAX_TOKENS,
        #         "num_ctx": config.LLM_CONTEXT_WINDOW,
        #         "top_k": 40,
        #         "top_p": config.LLM_TOP_P,
        #         "repeat_penalty": 1.1,
        #     },
        #     "format": "json",
        # }
        # logger.info(f"Sending request to Ollama ({self.model})...")
        # try:
        #     response = requests.post(
        #         f"{self.ollama_url}/api/chat",
        #         json=payload, timeout=config.LLM_TIMEOUT, stream=True,
        #     )
        #     response.raise_for_status()
        #     import json as _json
        #     full_content = ""
        #     for line in response.iter_lines():
        #         if line:
        #             try:
        #                 chunk = _json.loads(line.decode("utf-8"))
        #                 delta = chunk.get("message", {}).get("content", "")
        #                 full_content += delta
        #                 if chunk.get("done", False):
        #                     break
        #             except Exception:
        #                 continue
        #     raw_text     = full_content
        #     total_tokens = 0
        # except requests.ConnectionError:
        #     raise ConnectionError(f"Cannot connect to Ollama at {self.ollama_url}.")
        # except requests.Timeout:
        #     raise TimeoutError(f"LLM timed out after {config.LLM_TIMEOUT}s.")
        # ── END Ollama code ──────────────────────────────────────

        latency["llm_request_end"]    = time.perf_counter()
        latency["llm_latency_s"]      = latency["llm_request_end"] - latency["llm_request_start"]
        latency["eval_count"]         = total_tokens
        latency["eval_duration_ns"]   = 0
        latency["tokens_per_second"]  = (
            total_tokens / latency["llm_latency_s"]
            if latency["llm_latency_s"] > 0 else 0
        )

        logger.info(
            f"LLM response: {len(raw_text)} chars in {latency['llm_latency_s']:.2f}s "
            f"({latency['tokens_per_second']:.1f} tok/s)"
        )
        return raw_text, latency

    def validate_response(
        self,
        raw_response: str,
        retrieved_techniques: list[dict],
    ) -> tuple[dict, list[str]]:
        warnings = []

        # Layer 1: JSON parsing
        parsed = self._extract_json(raw_response)
        if parsed is None:
            raise ValueError(
                f"LLM response is not valid JSON. Raw response:\n{raw_response[:500]}"
            )

        # Layer 2: Normalize output to {steps: [...]}
        if "steps" not in parsed and "attack_chain" in parsed:
            parsed = {"steps": parsed.get("attack_chain", []), "metadata": parsed.get("metadata", {})}

        # Mandatory: steps must exist for downstream evaluation.
        if not isinstance(parsed, dict) or "steps" not in parsed or not isinstance(parsed.get("steps"), list):
            raise ValueError("Missing or invalid 'steps' in model output")

        # Normalize: allow model to emit {technique: "Txxxx"} and convert to technique_id.
        normalized_steps: list[dict] = []
        for step in parsed.get("steps", []):
            if not isinstance(step, dict):
                continue
            out = dict(step)
            tid = str(out.get("technique_id") or out.get("technique") or "").strip().upper()
            if tid:
                out["technique_id"] = tid
            normalized_steps.append(out)
        parsed["steps"] = normalized_steps

        # Mandatory: every step must have a valid technique id.
        bad = 0
        for s in parsed.get("steps", []):
            tid = str(s.get("technique_id", "")).strip().upper()
            if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
                bad += 1
        if bad:
            raise ValueError(f"Invalid or missing technique IDs in steps: {bad}")

        # Layer 3: Schema validation (non-fatal warning)
        try:
            jsonschema.validate(instance=parsed, schema=ATTACK_CHAIN_SCHEMA)
        except jsonschema.ValidationError as e:
            warnings.append(f"Schema validation warning: {e.message}")
            logger.warning(f"Schema validation issue: {e.message}")

        # Layer 4: Grounding signal (informational, not a hard fail)
        retrieved_ids = {t.get("technique_id", "") for t in retrieved_techniques}
        steps = parsed.get("steps", []) if isinstance(parsed, dict) else []
        grounded = 0
        total = 0
        for step in steps if isinstance(steps, list) else []:
            cited_id = str(step.get("technique_id") or step.get("technique") or "").strip().upper()
            if not cited_id:
                continue
            total += 1
            if cited_id in retrieved_ids or cited_id.split(".")[0] in {x.split(".")[0] for x in retrieved_ids if x}:
                grounded += 1
        if total:
            grounded_ratio = grounded / total
            logger.info("Grounded steps: %d/%d (%.0f%%)", grounded, total, grounded_ratio * 100)

        # Convert to legacy-compatible shape for downstream consumers.
        legacy_chain = []
        for s in steps if isinstance(steps, list) else []:
            legacy_chain.append(
                {
                    "step": int(s.get("step", len(legacy_chain) + 1) or (len(legacy_chain) + 1)),
                    "technique_id": str(s.get("technique_id") or s.get("technique") or "").strip().upper(),
                    "technique_name": str(s.get("technique_name", "")).strip(),
                    "tactic": str(s.get("tactic", "")).strip(),
                    "description": str(s.get("description", "")).strip(),
                    "rationale": str(s.get("rationale", "")).strip() if isinstance(s, dict) else "",
                    "prerequisites": s.get("prerequisites", []) if isinstance(s, dict) else [],
                    "detection_considerations": str(s.get("detection_considerations", "")).strip() if isinstance(s, dict) else "",
                    "mitigation": str(s.get("mitigation", "")).strip() if isinstance(s, dict) else "",
                    "tool_commands": s.get("tool_commands", []) if isinstance(s, dict) else [],
                }
            )
        legacy_chain.sort(key=lambda x: x.get("step", 0) or 0)
        for i, step in enumerate(legacy_chain, 1):
            step["step"] = i

        metadata = parsed.get("metadata", {}) if isinstance(parsed, dict) else {}
        return {"attack_chain": legacy_chain, "metadata": metadata}, warnings

    def _extract_json(self, text: str) -> Optional[dict]:
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try markdown code block
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try first { to last }
        first_brace = text.find('{')
        last_brace = text.rfind('}')
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(text[first_brace:last_brace + 1])
            except json.JSONDecodeError:
                pass

        # Strip <think>...</think> blocks (DeepSeek-R1 reasoning traces)
        cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
        if cleaned != text:
            return self._extract_json(cleaned)

        logger.error(f"Failed to extract JSON from response: {text[:300]}...")
        return None

    @staticmethod
    def _normalize_tactic(tactic: str) -> str:
        return str(tactic or "").lower().strip().replace(" ", "-")

    def _rebalance_tactic_coverage(
        self,
        parsed_chain: dict,
        retrieved_techniques: list[dict],
        chain_length: int,
    ) -> tuple[dict, list[str]]:
        warnings = []
        if chain_length < len(self.MITRE_TACTICS):
            return parsed_chain, warnings

        chain = parsed_chain.get("attack_chain", [])
        if not isinstance(chain, list) or not chain:
            return parsed_chain, warnings

        tactic_counts: dict[str, int] = {}
        for step in chain:
            t = self._normalize_tactic(step.get("tactic", ""))
            if t:
                tactic_counts[t] = tactic_counts.get(t, 0) + 1

        missing_tactics = [
            t for t in self.MITRE_TACTICS
            if t not in tactic_counts
        ]
        if not missing_tactics:
            return parsed_chain, warnings

        by_tactic: dict[str, dict] = {}
        for tech in retrieved_techniques:
            tactics = tech.get("tactics", [])
            if isinstance(tactics, str):
                tactics = [x.strip() for x in tactics.split(",") if x.strip()]
            for tactic in tactics:
                t = self._normalize_tactic(tactic)
                if t in self.MITRE_TACTICS and t not in by_tactic:
                    by_tactic[t] = tech

        duplicate_indices = []
        seen: dict[str, int] = {}
        for idx, step in enumerate(chain):
            t = self._normalize_tactic(step.get("tactic", ""))
            seen[t] = seen.get(t, 0) + 1
            if not t or t not in self.MITRE_TACTICS or seen[t] > 1:
                duplicate_indices.append(idx)

        used_ids = {step.get("technique_id", "") for step in chain}

        for missing in missing_tactics:
            candidate = by_tactic.get(missing)
            if not candidate:
                continue
            if duplicate_indices:
                idx = duplicate_indices.pop(0)
                step = chain[idx]
                step["technique_id"] = candidate.get("technique_id", step.get("technique_id", ""))
                step["technique_name"] = candidate.get("name", step.get("technique_name", ""))
                step["tactic"] = missing
                step["description"] = candidate.get("description_preview", step.get("description", ""))
                step["rationale"] = step.get("rationale") or f"Adjusted to ensure full tactic coverage for {missing}."
                used_ids.add(step.get("technique_id", ""))

        # Re-number steps after any replacements/appends.
        for i, step in enumerate(chain, 1):
            step["step"] = i

        final_tactics = {
            self._normalize_tactic(step.get("tactic", ""))
            for step in chain
            if step.get("tactic")
        }
        final_covered = len(final_tactics & set(self.MITRE_TACTICS))
        if final_covered < len(self.MITRE_TACTICS):
            warnings.append(
                f"Tactic coverage after balancing is {final_covered}/{len(self.MITRE_TACTICS)}. "
                "Scenario relevance may naturally omit some tactics."
            )

        return parsed_chain, warnings

    def generate_attack_chain(
        self,
        scenario: str,
        target_environment: str = "Enterprise Windows Active Directory network",
        chain_length: int = None,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> dict:
        if chain_length is None:
            chain_length = config.DEFAULT_CHAIN_LENGTH

        # Required bounds for multi-step prompts.
        if int(chain_length or 1) <= 1:
            chain_length = 1
        else:
            chain_length = max(4, min(6, int(chain_length)))

        pipeline_start = time.perf_counter()
        latency_metrics = {"pipeline_start": pipeline_start}

        # Sanitize user input
        try:
            scenario = sanitize_scenario(scenario)
        except ValueError as e:
            raise ValueError(f"Input sanitization failed: {e}")

        # Phase 1: Retrieve
        logger.info(f"{'='*60}")
        logger.info(f"PHASE 1: RETRIEVAL")
        logger.info(f"{'='*60}")

        retrieve_start = time.perf_counter()
        use_diverse = bool(getattr(config, "RAG_USE_DIVERSE_RETRIEVAL", False))
        if use_diverse and not tactic_filter and not platform_filter:
            retrieved = self.vector_store.query_diverse(query_text=scenario, top_k=top_k)
        else:
            wide_k = top_k
            if wide_k is None:
                wide_k = int(getattr(config, "RAG_RETRIEVAL_TOP_K_WIDE", getattr(config, "DIVERSITY_TOP_K_WIDE", 30)))
            retrieved = self.retrieve(
                scenario=scenario,
                top_k=wide_k,
                tactic_filter=tactic_filter,
                platform_filter=platform_filter,
            )
        latency_metrics["retrieval_time_s"] = time.perf_counter() - retrieve_start

        if not retrieved:
            raise ValueError(
                "No techniques retrieved. Check that the vector store is indexed "
                "and the query is relevant."
            )

        # Phase 2: Augment prompt
        logger.info(f"{'='*60}")
        logger.info(f"PHASE 2: PROMPT AUGMENTATION")
        logger.info(f"{'='*60}")

        augment_start = time.perf_counter()
        system_prompt, user_prompt = self.build_prompt(
            scenario=scenario,
            target_environment=target_environment,
            retrieved_techniques=retrieved,
            chain_length=chain_length,
        )
        latency_metrics["augmentation_time_s"] = time.perf_counter() - augment_start

        # Phase 3: Generate
        logger.info(f"{'='*60}")
        logger.info(f"PHASE 3: LLM GENERATION")
        logger.info(f"{'='*60}")

        # Phase 4: Validate + mandatory retries (max 2 retries)
        logger.info(f"{'='*60}")
        logger.info(f"PHASE 4: VALIDATION & FAITHFULNESS CHECK")
        logger.info(f"{'='*60}")

        validate_start = time.perf_counter()
        max_attempts = 3
        last_error: Optional[BaseException] = None
        parsed_chain: Optional[dict] = None
        warnings: list[str] = []
        gen_latency: dict = {}

        for attempt in range(1, max_attempts + 1):
            try:
                retry_note = ""
                if attempt > 1:
                    retry_note = (
                        "\n\nRETRY: Your previous output was invalid or too short. "
                        "Return STRICT JSON only and include 4 to 6 steps."
                    )

                raw_response, gen_latency = self.generate(
                    system_prompt,
                    user_prompt + retry_note,
                    temperature_override=(0.0 if attempt > 1 else None),
                    max_tokens_override=int(getattr(config, "LLM_MAX_TOKENS", 512)),
                )

                if raw_response is None or not str(raw_response).strip():
                    raise ValueError("Empty model output")

                parsed_chain, warnings = self.validate_response(raw_response, retrieved)

                chain = parsed_chain.get("attack_chain", []) if isinstance(parsed_chain, dict) else []
                if not isinstance(chain, list):
                    raise ValueError("Invalid attack_chain shape")

                min_steps_required = 1 if chain_length <= 1 else 4
                if len(chain) < min_steps_required:
                    raise ValueError(f"Generated chain too short: {len(chain)} < {min_steps_required}")

                if chain_length > 1:
                    grounded_steps = self._count_grounded_steps(chain, retrieved)
                    if grounded_steps < 3:
                        raise ValueError(f"Not enough context-grounded steps: {grounded_steps} < 3")

                break
            except Exception as e:  # noqa: BLE001
                last_error = e
                parsed_chain = None
                warnings = []
                if attempt >= max_attempts:
                    raise
                logger.warning("Validation failed (attempt %d/%d): %s", attempt, max_attempts, str(e)[:300])

        latency_metrics.update(gen_latency)

        # Enforce step count constraints (stability + multi-step quality).
        chain = parsed_chain.get("attack_chain", [])
        if isinstance(chain, list) and chain_length:
            if len(chain) > chain_length:
                parsed_chain["attack_chain"] = chain[:chain_length]
            min_steps = 1 if chain_length <= 1 else 4
            if len(parsed_chain.get("attack_chain", [])) < min_steps:
                raise ValueError(
                    f"Generated chain too short: {len(parsed_chain.get('attack_chain', []))} < {min_steps}"
                )
        parsed_chain, coverage_warnings = self._rebalance_tactic_coverage(
            parsed_chain=parsed_chain,
            retrieved_techniques=retrieved,
            chain_length=chain_length,
        )
        warnings.extend(coverage_warnings)
        latency_metrics["validation_time_s"] = time.perf_counter() - validate_start

        # Calculate faithfulness score
        retrieved_ids = {t.get("technique_id", "") for t in retrieved}
        retrieved_bases = {tid.split(".")[0] for tid in retrieved_ids if tid}
        chain_steps = parsed_chain.get("attack_chain", [])
        total_steps = len(chain_steps)
        grounded_steps = 0
        for step in chain_steps:
            tid = str(step.get("technique_id", "")).strip()
            if not tid:
                continue
            if tid in retrieved_ids or tid.split(".")[0] in retrieved_bases:
                grounded_steps += 1
        faithfulness_score = grounded_steps / total_steps if total_steps else 0.0

        # Enrich each step with mitigations and tool commands
        for step in parsed_chain.get("attack_chain", []):
            tid = step.get("technique_id", "")
            if not step.get("mitigation"):
                mit = get_mitigation(tid)
                step["mitigation"] = f"{mit['name']}: {mit['description']}"
            if not step.get("tool_commands"):
                tools_info = get_tools(tid)
                step["tool_commands"] = tools_info.get("commands", [])[:3]

        latency_metrics["pipeline_total_s"] = time.perf_counter() - pipeline_start

        logger.info(f"{'='*60}")
        logger.info(f"PIPELINE COMPLETE")
        logger.info(
            f"Total: {latency_metrics['pipeline_total_s']:.2f}s | "
            f"Retrieval: {latency_metrics['retrieval_time_s']*1000:.0f}ms | "
            f"Generation: {latency_metrics.get('llm_latency_s', 0):.2f}s | "
            f"Faithfulness: {faithfulness_score:.0%}"
        )
        logger.info(f"{'='*60}")

        return {
            "attack_chain": parsed_chain,
            "retrieval_results": [
                {
                    "technique_id": r["technique_id"],
                    "name": r["name"],
                    "relevance_score": r.get("relevance_score"),
                    "tactics": r.get("tactics"),
                }
                for r in retrieved
            ],
            "latency": latency_metrics,
            "warnings": warnings,
            "faithfulness_score": faithfulness_score,
            "scenario": scenario,
            "target_environment": target_environment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def check_api_health(self) -> dict:
        """
        Verify that the required API keys are configured.
        Returns a status dict compatible with the old 'check_ollama_health' shape
        so all callers continue to work without changes.
        """
        groq_key    = getattr(config, "LLAMA3_API_KEY", "")
        mistral_key = getattr(config, "MISTRAL_API_KEY", "")

        groq_valid    = bool(groq_key    and groq_key.strip())
        mistral_valid = bool(mistral_key and mistral_key.strip())

        issues = []
        if not groq_valid:
            issues.append(
                "LLAMA3_API_KEY is not set.  "
                "Run: $env:LLAMA3_API_KEY = 'gsk_xxxxxxxxxxxxx'"
            )
        if not mistral_valid:
            issues.append(
                "MISTRAL_API_KEY is not set.  "
                "Run: $env:MISTRAL_API_KEY = 'WkMxgW8nDReEYNv6dVezTvh28VMcVcGn'"
            )

        return {
            # Keep old key names so callers (attack_chain_generator, main.py) work
            "ollama_url":       "Groq Cloud API + Mistral API (Ollama NOT used)",
            "model":            config.GROQ_MODEL,
            "ollama_reachable": groq_valid,   # renamed semantics but same key
            "model_available":  groq_valid,
            "error":            "; ".join(issues) if issues else None,
            "note":             (
                f"Groq API key: {'SET' if groq_valid else 'MISSING'} | "
                f"Mistral API key: {'SET' if mistral_valid else 'MISSING'}"
            ),
        }

    # Keep old name as an alias so older callers don't break
    def check_ollama_health(self) -> dict:
        return self.check_api_health()
