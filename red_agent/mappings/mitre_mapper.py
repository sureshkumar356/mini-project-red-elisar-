"""
mitre_mapper.py — MITRE ATT&CK Vulnerability Mapper for Red ELISAR
===================================================================
Maps scanner findings to real MITRE ATT&CK techniques using:
  1. Direct technique ID lookup (from mitre_hint field)
  2. RAG semantic search (your existing FAISS vector store)
  3. Attack chain ordering by tactic kill-chain sequence

Integration: Fully compatible with your existing RAGEngine and FAISSVectorStore.
"""

import logging
from typing import Optional

logger = logging.getLogger("red_elisar.mitre_mapper")

# Standard MITRE ATT&CK tactic kill-chain order
TACTIC_KILL_CHAIN_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "exfiltration",
    "impact",
]

# Direct map: MITRE technique ID → search query for RAG
TECHNIQUE_SEARCH_QUERIES = {
    "T1592":    "gathering victim host information server fingerprinting reconnaissance",
    "T1190":    "exploit public-facing application web server vulnerability",
    "T1059.007":"JavaScript execution browser scripting cross-site scripting XSS",
    "T1557":    "adversary in the middle man-in-the-middle MITM network interception",
    "T1185":    "browser session hijacking clickjacking iframe",
    "T1204":    "user execution malicious link phishing redirect",
    "T1552":    "unsecured credentials exposed configuration files secrets",
    "T1562":    "impair defenses disable security controls bypass",
    "T1078":    "valid accounts credential access unauthorized admin access",
    "T1213":    "data from information repositories exposed source code",
    "T1499":    "endpoint denial of service web server resource exhaustion",
    "T1110":    "brute force password spraying credential stuffing",
}


class MITREMapper:
    """
    Maps vulnerability scanner findings to MITRE ATT&CK techniques
    and orders them into a realistic attack chain.
    """

    def __init__(self, rag_engine):
        """
        Args:
            rag_engine: Your existing RAGEngine instance.
        """
        self.rag = rag_engine

    # ─── Main Entry Points ────────────────────────────────────────

    def map_vulnerabilities(self, vulnerabilities: list) -> list:
        """
        For each vulnerability, retrieve matching MITRE ATT&CK techniques
        from the FAISS vector store via the RAG engine.

        Returns a list of dicts: {vulnerability, mitre_techniques}
        """
        mapped = []
        retrieval_cache: dict[str, list] = {}
        logger.info(f"[MITREMapper] Mapping {len(vulnerabilities)} vulnerabilities to MITRE ATT&CK...")

        for vuln in vulnerabilities:
            mitre_hint = vuln.get("mitre_hint", "")
            vuln_type  = vuln.get("type", "")
            detail     = vuln.get("detail", "")
            evidence   = vuln.get("evidence", "")
            recommendation = vuln.get("recommendation", "")

            # Build a semantic search query from the vulnerability
            # Prefer the direct technique query if available
            if mitre_hint in TECHNIQUE_SEARCH_QUERIES:
                query = TECHNIQUE_SEARCH_QUERIES[mitre_hint]
            else:
                query = f"{vuln_type} {detail} {evidence} {recommendation} web application attack behavior"

            query_key = " ".join(str(query or "").split()).strip().lower()

            try:
                if query_key in retrieval_cache:
                    techniques = retrieval_cache[query_key]
                else:
                    # Fast mapping mode: one query variant is usually enough for per-step mapping.
                    techniques = self.rag.retrieve(
                        query,
                        top_k=8,
                        max_query_variants=1,
                        use_cache=True,
                    )
                    retrieval_cache[query_key] = techniques
            except Exception as e:
                logger.warning(f"[MITREMapper] RAG retrieval failed for '{query[:50]}': {e}")
                techniques = []

            # Drop weak matches to reduce irrelevant tactics.
            filtered = []
            for t in techniques:
                score = float(t.get("relevance_score", 0.0) or 0.0)
                if score >= 0.2:
                    filtered.append(t)
            techniques = filtered[:8]

            # Add direct hint technique if it's not already retrieved
            retrieved_ids = {t.get("technique_id") for t in techniques}
            if mitre_hint and mitre_hint not in retrieved_ids:
                direct = None
                try:
                    if hasattr(self.rag, "vector_store") and hasattr(self.rag.vector_store, "query_by_technique_id"):
                        direct = self.rag.vector_store.query_by_technique_id(mitre_hint)
                except Exception:
                    direct = None

                if direct:
                    techniques.insert(0, {
                        "technique_id": mitre_hint,
                        "name": direct.get("name", f"Technique {mitre_hint}"),
                        "tactics": direct.get("tactics", []) or ["unknown"],
                        "relevance_score": 1.0,
                        "description_preview": direct.get("description_preview", f"Technique {mitre_hint} from ATT&CK dataset."),
                    })

            mapped.append({
                "vulnerability":     vuln,
                "mitre_techniques":  techniques,
                "primary_technique": techniques[0] if techniques else None,
            })
            logger.info(
                f"[MITREMapper] '{vuln_type}' → "
                f"{[t.get('technique_id') for t in techniques[:2]]}"
            )

        return mapped

    def build_attack_chain(self, mapped_vulns: list, target_url: str = "") -> list:
        """
        Orders mapped techniques into a realistic kill-chain attack sequence.

        Logic:
          1. Group all retrieved techniques by tactic
          2. Walk the kill-chain tactic order
          3. At each tactic position, pick the best matching technique
          4. Attach the source vulnerability for context

        Returns an ordered list of attack steps.
        """
        # Collect all technique→vulnerability pairs, grouped by tactic
        tactic_bucket: dict[str, list] = {t: [] for t in TACTIC_KILL_CHAIN_ORDER}

        for mv in mapped_vulns:
            vuln = mv["vulnerability"]
            techniques = mv.get("mitre_techniques") or []
            if not techniques:
                continue

            # Include multiple mapped techniques per vulnerability so the chain
            # reflects broader attack behavior instead of only one primary pick.
            for rank, tech in enumerate(techniques[:5]):
                tactics = tech.get("tactics", [])
                if isinstance(tactics, str):
                    tactics = [tactics]

                for tactic in tactics:
                    tactic_clean = tactic.lower().replace(" ", "-")
                    if tactic_clean in tactic_bucket:
                        tactic_bucket[tactic_clean].append({
                            "technique": tech,
                            "vulnerability": vuln,
                            "rank": rank,
                        })

        # Build the ordered chain (one step per tactic where possible)
        chain = []
        step_num = 1
        used_techniques = set()
        for tactic in TACTIC_KILL_CHAIN_ORDER:
            entries = tactic_bucket.get(tactic, [])
            if not entries:
                # Pull a direct tactic-focused candidate when this stage is missing.
                try:
                    extra = self.rag.retrieve(
                        f"{target_url} attack behavior for tactic {tactic.replace('-', ' ')}",
                        top_k=6,
                        tactic_filter=tactic,
                    )
                except Exception:
                    extra = []

                if extra:
                    entries = [
                        {
                            "technique": extra[0],
                            "vulnerability": {"type": "Lifecycle Coverage", "detail": f"Coverage-added tactic step: {tactic}", "severity": "INFO"},
                        }
                    ]
                else:
                    continue

            # Prefer highest cosine similarity score; avoid reusing the same technique across steps.
            available = [
                e for e in entries
                if e["technique"].get("technique_id") not in used_techniques
            ]
            pool = available if available else entries
            best = max(
                pool,
                key=lambda e: (
                    float(e["technique"].get("relevance_score", -1.0) or -1.0),
                    -int(e.get("rank", 99)),
                ),
            )
            tech = best["technique"]
            vuln = best["vulnerability"]
            used_techniques.add(tech.get("technique_id"))

            chain.append({
                "step":            step_num,
                "tactic":          tactic,
                "technique_id":    tech.get("technique_id", "Unknown"),
                "technique_name":  tech.get("name", "Unknown"),
                "relevance_score": tech.get("relevance_score"),
                "description":     tech.get("description_preview", tech.get("document", ""))[:300],
                "source_vulnerability": {
                    "type":     vuln.get("type"),
                    "detail":   vuln.get("detail"),
                    "severity": vuln.get("severity"),
                },
                "recommendation": vuln.get("recommendation"),
            })
            step_num += 1

        # Second pass: guarantee broader per-vulnerability representation.
        # This ensures each vulnerability contributes multiple mapped techniques
        # (when available), not just a single extracted one.
        seen_vuln_multi: set[str] = set()
        for mv in mapped_vulns:
            vuln = mv.get("vulnerability", {}) or {}
            techniques = mv.get("mitre_techniques") or []
            if not techniques:
                continue
            vuln_key = (
                f"{vuln.get('type', '')}|{vuln.get('detail', '')}|"
                f"{vuln.get('endpoint', vuln.get('url', ''))}"
            ).strip().lower()
            if vuln_key in seen_vuln_multi:
                continue
            seen_vuln_multi.add(vuln_key)

            added_for_vuln = 0
            for tech in techniques:
                if len(chain) >= 12 or added_for_vuln >= 3:
                    break
                tid = tech.get("technique_id")
                if not tid or tid in used_techniques:
                    continue
                tactics = tech.get("tactics", [])
                if isinstance(tactics, str):
                    tactics = [tactics]
                tactic_clean = "unknown"
                for t in tactics:
                    tc = str(t).lower().replace(" ", "-")
                    if tc in tactic_bucket:
                        tactic_clean = tc
                        break

                used_techniques.add(tid)
                chain.append({
                    "step":            step_num,
                    "tactic":          tactic_clean,
                    "technique_id":    tech.get("technique_id", "Unknown"),
                    "technique_name":  tech.get("name", "Unknown"),
                    "relevance_score": tech.get("relevance_score"),
                    "description":     tech.get("description_preview", tech.get("document", ""))[:300],
                    "source_vulnerability": {
                        "type":     vuln.get("type"),
                        "detail":   vuln.get("detail"),
                        "severity": vuln.get("severity"),
                    },
                    "recommendation": vuln.get("recommendation"),
                })
                step_num += 1
                added_for_vuln += 1

        # Third pass: include additional high-confidence techniques even if
        # they share tactics, so users can see fuller attack-chain coverage.
        extra_candidates = []
        for tactic, entries in tactic_bucket.items():
            for entry in entries:
                tid = entry["technique"].get("technique_id")
                if not tid or tid in used_techniques:
                    continue
                extra_candidates.append((tactic, entry))

        extra_candidates.sort(
            key=lambda x: (
                float(x[1]["technique"].get("relevance_score", 0.0) or 0.0),
                -int(x[1].get("rank", 99)),
            ),
            reverse=True,
        )

        for tactic, best in extra_candidates:
            if len(chain) >= 12:
                break
            tech = best["technique"]
            vuln = best["vulnerability"]
            tid = tech.get("technique_id")
            if not tid or tid in used_techniques:
                continue
            used_techniques.add(tid)
            chain.append({
                "step":            step_num,
                "tactic":          tactic,
                "technique_id":    tech.get("technique_id", "Unknown"),
                "technique_name":  tech.get("name", "Unknown"),
                "relevance_score": tech.get("relevance_score"),
                "description":     tech.get("description_preview", tech.get("document", ""))[:300],
                "source_vulnerability": {
                    "type":     vuln.get("type"),
                    "detail":   vuln.get("detail"),
                    "severity": vuln.get("severity"),
                },
                "recommendation": vuln.get("recommendation"),
            })
            step_num += 1

        # Normalize step numbering after multi-pass appends.
        for idx, step in enumerate(chain, 1):
            step["step"] = idx

        logger.info(f"[MITREMapper] Built attack chain with {len(chain)} steps "
                    f"across {len(set(s['tactic'] for s in chain))} tactics")
        return chain

    def build_scenario_description(self, target_url: str, scan_result: dict,
                                   mapped_vulns: list) -> str:
        """
        Builds a natural-language scenario description for the RAG engine
        to generate the final LLM-powered attack narrative.
        """
        risk    = scan_result.get("overall_risk", "UNKNOWN")
        counts  = scan_result.get("severity_counts", {})
        total   = scan_result.get("total_vulns", 0)
        tech    = scan_result.get("tech_stack", {})

        server   = tech.get("server", "Unknown web server")
        language = tech.get("language", "Unknown backend")

        vuln_types = list({mv["vulnerability"]["type"] for mv in mapped_vulns})
        vuln_str   = ", ".join(vuln_types[:5])

        scenario = (
            f"Web application attack targeting {target_url} "
            f"({server}, {language}). "
            f"Discovered vulnerabilities: {vuln_str}. "
            f"Overall risk: {risk}. "
            f"Critical:{counts.get('CRITICAL',0)}, "
            f"High:{counts.get('HIGH',0)}, "
            f"Medium:{counts.get('MEDIUM',0)} findings. "
            f"Attacker can exploit SQL injection, exposed credentials, "
            f"missing security controls, and debug mode to achieve full compromise."
        )
        return scenario


# ─── Standalone Test ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys, json, logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    print("MITREMapper requires RAGEngine. Run via web_vuln_agent.py instead.")
    print("  python web_vuln_agent.py http://127.0.0.1:5000")
