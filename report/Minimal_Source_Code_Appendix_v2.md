# Minimal Source Code Appendix (Result-Producing Blocks)

Generated on: 2026-04-30 19:59:59

This file includes only the essential code that produces system results end-to-end.


## 1) Core Pipeline Orchestration - RuntimeContext

Source: `run.py`

`python
class RuntimeContext:
    """Lazy-loaded shared runtime components."""

    def __init__(self) -> None:
        self.store: FAISSVectorStore | None = None
        self.rag: RAGEngine | None = None
        self.mapper: MITREMapper | None = None
        self.generator: AttackChainGenerator | None = None
        self.mitre_db: MitreAttackDatabase | None = None

    def ensure_rag(self, force_reindex: bool = False) -> None:
        if self.store and self.rag and self.mapper and self.generator:
            return

        store = FAISSVectorStore()
        if not force_reindex and store.is_ready():
            print("\n[INFO] Loading existing FAISS index...")
            store.load()
        else:
            print("\n[INFO] Building FAISS index from MITRE ATT&CK bundle...")
            parser = MITREParser()
            techniques = parser.parse()
            chunks = chunk_techniques(techniques)
            store.index_chunks(chunks, force_reindex=force_reindex)
            print(f"[OK] Indexed {len(techniques)} techniques.")

        self.store = store
        self.rag = RAGEngine(store)
        self.mapper = MITREMapper(self.rag)
        self.generator = AttackChainGenerator(store)
        self.ensure_mitre_db()

    def ensure_mitre_db(self) -> None:
        if self.mitre_db is None:
            self.mitre_db = MitreAttackDatabase(config.MITRE_STIX_PATH)


```

## 2) Core Pipeline Orchestration - discover_attack_surface

Source: `run.py`

`python
def discover_attack_surface(base_url: str, max_pages: int = 30, timeout: int = 8) -> dict[str, Any]:
    """Discover routes dynamically via crawl + form detection + common-path probing."""
    session = requests.Session()
    visited: set[str] = set()
    discovered_routes: set[str] = set()
    discovered_forms: list[dict[str, Any]] = []
    params_by_route: dict[str, set[str]] = {}
    queue = deque([base_url])

    while queue and len(visited) < max_pages:
        current = canonicalize(queue.popleft())
        if current in visited:
            continue
        visited.add(current)

        try:
            resp = session.get(current, timeout=timeout, allow_redirects=True)
        except Exception:
            continue

        if resp.status_code >= 500:
            continue

        discovered_routes.add(canonicalize(resp.url))

        parsed = urlparse(resp.url)
        if parsed.query:
            params_by_route.setdefault(canonicalize(resp.url.split("?")[0]), set()).update(
                [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            )

        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "text/html" not in content_type:
            continue

        links, forms = parse_html_links_and_forms(resp.url, resp.text)
        for form in forms:
            form_action = canonicalize(form["action"])
            discovered_routes.add(form_action)
            discovered_forms.append(form)
            params_by_route.setdefault(form_action, set()).update(form.get("params", []))

        for candidate in links:
            if not candidate.startswith(("http://", "https://")):
                continue
            if same_host(base_url, candidate):
                c = canonicalize(candidate)
                discovered_routes.add(c)
                if c not in visited:
                    queue.append(c)

    # Common path probing for additional reachable endpoints.
    for path in COMMON_PATHS:
        test_url = canonicalize(urljoin(base_url + "/", path.lstrip("/")))
        if test_url in discovered_routes:
            continue
        try:
            r = session.get(test_url, timeout=timeout, allow_redirects=False)
            if r.status_code < 400:
                discovered_routes.add(test_url)
        except Exception:
            continue

    route_params: dict[str, list[str]] = {
        route: sorted(v) for route, v in params_by_route.items() if v
    }

    return {
        "base_url": base_url,
        "visited_pages": sorted(visited),
        "routes": sorted(discovered_routes),
        "forms": discovered_forms,
        "params_by_route": route_params,
    }


```

## 3) Core Pipeline Orchestration - dynamic attack chain builder

Source: `run.py`

`python
def _build_dynamic_chain_from_mapping(
    vuln: dict[str, Any],
    mapping: dict[str, Any],
    mitre_db: MitreAttackDatabase | None,
    rag_engine: RAGEngine | None,
    top_k: int = 20,
    avoid_primary_ids: set[str] | None = None,
    avoid_chain_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    avoid_primary_ids = avoid_primary_ids or set()
    avoid_chain_ids = avoid_chain_ids or set()

    techniques = mapping.get("mitre_techniques") or []
    records = [_resolve_technique_record(t, vuln, mitre_db) for t in techniques]

    profile = _context_profile(vuln)
    query = str(profile.get("context_text", ""))
    strict_context_text = str(profile.get("strict_context_text", query))
    focus_terms = set(profile.get("focus_terms", set()))
    allows_cloud = bool(profile.get("allows_cloud", False))
    allows_phishing = bool(profile.get("allows_phishing", False))
    mitre_hint = str(profile.get("mitre_hint", ""))
    expected_primary = str(profile.get("expected_primary", ""))

    if rag_engine is not None:
        try:
            broad = rag_engine.retrieve(query, top_k=top_k)
            records.extend(_resolve_technique_record(t, vuln, mitre_db) for t in broad)
        except Exception:
            pass

    # Deduplicate and keep highest relevance per technique.
    dedup: dict[str, dict[str, Any]] = {}
    for r in records:
        tid = str(r.get("technique_id", "")).strip()
        if not tid or tid == "N/A":
            continue
        prev = dedup.get(tid)
        if prev is None or float(r.get("relevance", 0.0)) > float(prev.get("relevance", 0.0)):
            dedup[tid] = r

    records = list(dedup.values())

    # Force tactic diversity by querying for missing lifecycle tactics.
    tactic_order = ATTACK_FLOW_TACTICS
    covered = {t for r in records for t in r.get("tactics", [])}
    missing = [t for t in tactic_order if t not in covered]

    if rag_engine is not None:
        for tactic in missing:
            try:
                tactic_query = f"{query} techniques for tactic {tactic.replace('-', ' ')}"
                extra = rag_engine.retrieve(tactic_query, top_k=8)
                for t in extra:
                    rec = _resolve_technique_record(t, vuln, mitre_db)
                    tid = str(rec.get("technique_id", "")).strip()
                    if not tid or tid == "N/A":
                        continue
                    prev = dedup.get(tid)
                    if prev is None or float(rec.get("relevance", 0.0)) > float(prev.get("relevance", 0.0)):
                        dedup[tid] = rec
            except Exception:
                continue

    records = list(dedup.values())
    if not records:
        return []

    if expected_primary and expected_primary not in {str(r.get("technique_id", "")).strip() for r in records} and mitre_db:
        forced = mitre_db.get_technique(expected_primary)
        if forced:
            records.append(
                {
                    "technique_id": forced.get("technique_id", expected_primary),
                    "technique_name": forced.get("technique_name", "Unknown Technique"),
                    "tactics": forced.get("tactics", []) or ["execution"],
                    "tools": [],
                    "relevance": 1.0,
                    "description": forced.get("description", ""),
                }
            )

    context_text = query

    # Context-aware filtering and ranking to reduce irrelevant noise.
    filtered: list[dict[str, Any]] = []
    for r in records:
        if not _is_contextually_relevant(
            r,
            context_text=context_text,
            focus_terms=focus_terms,
            allows_cloud=allows_cloud,
            allows_phishing=allows_phishing,
        ):
            continue

        overlap = _text_overlap_score(
            context_text,
            f"{r.get('technique_name', '')} {r.get('description', '')} {' '.join(r.get('tactics', []))}",
        )
        relevance = float(r.get("relevance", 0.0))
        score = (0.55 * relevance) + (0.45 * overlap)
        if str(r.get("technique_id", "")) in avoid_chain_ids:
            score -= 0.06
        enriched = dict(r)
        enriched["_score"] = score
        filtered.append(enriched)

    records = filtered
    if not records:
        return []

    primary_candidates = sorted(
        records,
        key=lambda r: _primary_score(
            r,
            context_text=context_text,
            focus_terms=focus_terms,
            mitre_hint=mitre_hint,
            expected_primary=expected_primary,
            avoid_primary_ids=set(),
        ),
        reverse=True,
    )
    primary = primary_candidates[0]
    if expected_primary:
        for candidate in primary_candidates:
            if str(candidate.get("technique_id", "")).strip() == expected_primary:
                primary = candidate
                break
    elif avoid_primary_ids:
        for candidate in primary_candidates:
            tid = str(candidate.get("technique_id", "")).strip()
            if tid and tid not in avoid_primary_ids:
                primary = candidate
                break
    primary_id = str(primary.get("technique_id", "")).strip()
    primary_tactics = primary.get("tactics", []) or []
    primary_tactic = next((t for t in primary_tactics if t in ATTACK_FLOW_TACTICS), "execution")
    primary_rank = _flow_rank(primary_tactic)

    # Group by tactic and sort each tactic bucket by relevance.
    tactic_groups: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        tactics = r.get("tactics", []) or ["unknown"]
        for tactic in tactics:
            tactic_groups.setdefault(tactic, []).append(r)

    for tactic in tactic_groups:
        tactic_groups[tactic].sort(key=lambda x: -float(x.get("_score", x.get("relevance", 0.0))))

    chain: list[dict[str, Any]] = []
    used_techniques: set[str] = set()
    used_tactics: set[str] = set()

    # Follow requested lifecycle order first for logical progression.
    ordered_tactics = [t for t in ATTACK_FLOW_TACTICS if t in tactic_groups]

    for tactic in ordered_tactics:
        rank = _flow_rank(tactic)
        if rank < primary_rank - 1 or rank > primary_rank + 4:
            continue
        bucket = tactic_groups.get(tactic, [])
        if not bucket:
            continue
        selected = None
        if primary_id:
            for candidate in bucket:
                if str(candidate.get("technique_id", "")) == primary_id:
                    selected = candidate
                    break
        if selected is None:
            for candidate in bucket:
                tid = str(candidate.get("technique_id", ""))
                if tid and tid not in used_techniques:
                    selected = candidate
                    break
        if selected is None:
            continue
        used_techniques.add(str(selected.get("technique_id", "")))
        used_tactics.add(tactic)
        step_tools = _select_context_tools(selected.get("tools", []), strict_context_text, max_tools=3)
        if not step_tools:
            step_tools = _fallback_web_tools(vuln, tactic)
        chain.append(
            {
                "step": len(chain) + 1,
                "technique_id": selected.get("technique_id", "N/A"),
                "technique_name": selected.get("technique_name", "Unknown Technique"),
                "tactic": tactic,
                "tools": step_tools,
                "description": selected.get("description", "No description available."),
                "is_primary": str(selected.get("technique_id", "")) == primary_id,
            }
        )
        if len(chain) >= 6:
            break

    # Add remaining non-duplicate techniques, prioritizing tactics not yet covered.
    remaining = sorted(records, key=lambda x: -float(x.get("_score", x.get("relevance", 0.0))))
    remaining_unique_tactics = []
    remaining_repeat_tactics = []
    for rec in remaining:
        tid = str(rec.get("technique_id", ""))
        if not tid or tid in used_techniques:
            continue
        tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
        if tactic not in ATTACK_FLOW_TACTICS:
            continue
        rank = _flow_rank(tactic)
        if rank < primary_rank - 1 or rank > primary_rank + 4:
            continue
        if tactic in used_tactics:
            remaining_repeat_tactics.append(rec)
        else:
            remaining_unique_tactics.append(rec)

    for rec in remaining_unique_tactics:
        if len(chain) >= 6:
            break
        tid = str(rec.get("technique_id", ""))
        tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
        step_tools = _select_context_tools(rec.get("tools", []), strict_context_text, max_tools=3)
        if not step_tools:
            step_tools = _fallback_web_tools(vuln, tactic)
        chain.append(
            {
                "step": len(chain) + 1,
                "technique_id": rec.get("technique_id", "N/A"),
                "technique_name": rec.get("technique_name", "Unknown Technique"),
                "tactic": tactic,
                "tools": step_tools,
                "description": rec.get("description", "No description available."),
                "is_primary": str(rec.get("technique_id", "")) == primary_id,
            }
        )
        used_techniques.add(tid)
        used_tactics.add(tactic)

    # Keep output concise and useful: 5-7 logical steps.
    if len(chain) < 5:
        # Allow repeated tactics only when needed to reach minimum depth.
        fallback = [c for c in remaining_repeat_tactics if str(c.get("technique_id", "")) not in used_techniques]
        for rec in fallback:
            tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
            chain.append(
                {
                    "step": len(chain) + 1,
                    "technique_id": rec.get("technique_id", "N/A"),
                    "technique_name": rec.get("technique_name", "Unknown Technique"),
                    "tactic": tactic,
                    "tools": (_select_context_tools(rec.get("tools", []), strict_context_text, max_tools=3) or _fallback_web_tools(vuln, tactic)),
                    "description": rec.get("description", "No description available."),
                    "is_primary": str(rec.get("technique_id", "")) == primary_id,
                }
            )
            used_techniques.add(str(rec.get("technique_id", "")))
            if len(chain) >= 5 or len(chain) >= 7:
                break

    if len(chain) < 5:
        # Last-resort fill: keep flow-compatible, non-duplicate techniques to hit minimum depth.
        final_fill = [
            r
            for r in remaining
            if str(r.get("technique_id", "")) not in used_techniques
            and (r.get("tactics", ["unknown"]) or ["unknown"])[0] in ATTACK_FLOW_TACTICS
        ]
        for rec in final_fill:
            tactic = (rec.get("tactics", ["unknown"]) or ["unknown"])[0]
            chain.append(
                {
                    "step": len(chain) + 1,
                    "technique_id": rec.get("technique_id", "N/A"),
                    "technique_name": rec.get("technique_name", "Unknown Technique"),
                    "tactic": tactic,
                    "tools": (_select_context_tools(rec.get("tools", []), strict_context_text, max_tools=3) or _fallback_web_tools(vuln, tactic)),
                    "description": rec.get("description", "No description available."),
                    "is_primary": str(rec.get("technique_id", "")) == primary_id,
                }
            )
            used_techniques.add(str(rec.get("technique_id", "")))
            if len(chain) >= 5:
                break

    # Ensure primary technique is always included even if it fell outside flow picks.
    if primary_id and all(str(step.get("technique_id", "")) != primary_id for step in chain):
        chain.insert(
            0,
            {
                "step": 1,
                "technique_id": primary.get("technique_id", "N/A"),
                "technique_name": primary.get("technique_name", "Unknown Technique"),
                "tactic": primary_tactic,
                "tools": (_select_context_tools(primary.get("tools", []), strict_context_text, max_tools=3) or _fallback_web_tools(vuln, primary_tactic)),
                "description": primary.get("description", "No description available."),
                "is_primary": True,
            },
        )

    chain = _downsample_chain_preserve_order(chain, max_steps=6)
    for i, step in enumerate(chain, 1):
        step["step"] = i
    return chain


@contextlib.contextmanager
```

## 4) Core Pipeline Orchestration - full web scan flow

Source: `run.py`

`python
def run_full_web_scan(ctx: RuntimeContext) -> None:
    try:
        target_url = normalize_url(input("Target URL: ").strip())
    except ValueError:
        return

    with _silent_execution():
        discovery = discover_attack_surface(target_url)
        routes = discovery.get("routes", [])

        # Fallback rule: if crawl yields nothing useful, scan the base URL directly.
        if len(routes) <= 1:
            routes = [target_url]

        recon_data = WebReconAgent(target_url).run()
        if not recon_data.get("reachable"):
            return

        passive = VulnerabilityScanner(recon_data).scan()
        passive_vulns = passive.get("vulnerabilities", [])

        live_vulns: list[dict[str, Any]] = []
        try:
            report = LiveVulnChecker(target_url).run_full_check()
            for finding in report.get("vulnerabilities", []):
                if finding.get("confirmed_live"):
                    live_vulns.append(finding)
        except Exception as e:  # noqa: BLE001
            logger.warning("Live scan failed for %s: %s", target_url, e)

        form_vulns = _probe_discovered_forms(target_url, discovery.get("forms", []))

        merged_vulns = _merge_vulnerabilities(passive_vulns, live_vulns, form_vulns)
        counts = _severity_counts(merged_vulns)
        scan_result = {
            "target_url": target_url,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_vulns": len(merged_vulns),
            "severity_counts": counts,
            "overall_risk": _overall_risk(counts),
            "vulnerabilities": merged_vulns,
            "tech_stack": recon_data.get("tech_stack", {}),
        }

        ctx.ensure_rag(force_reindex=False)
        assert ctx.mapper is not None
        assert ctx.mitre_db is not None
        mapped = ctx.mapper.map_vulnerabilities(merged_vulns)
        chain = ctx.mapper.build_attack_chain(mapped, target_url=target_url)

        # Keep existing report generation behavior (JSON + MD standard report).
        report = ReportGenerator().generate(
            target_url=target_url,
            recon_data=recon_data,
            scan_result=scan_result,
            attack_chain=chain,
            llm_analysis=(
                "LLM analysis skipped in interactive full-scan mode. "
                "Use web_vuln_agent.py directly for narrative generation."
            ),
        )

        # Keep existing interactive_web_scan enriched JSON + MD generation.
        enriched = {
            "target_url": target_url,
            "discovery": discovery,
            "vulnerabilities": merged_vulns,
            "vuln_mappings": [
                {
                    "vulnerability": m.get("vulnerability"),
                    "top_techniques": [
                        {
                            "technique_id": t.get("technique_id"),
                            "name": t.get("name"),
                        }
                        for t in (m.get("mitre_techniques") or [])[:3]
                    ],
                }
                for m in mapped
            ],
            "attack_chain": chain,
            "standard_report_paths": {
                "json": report.get("json_path"),
                "markdown": report.get("md_path"),
            },
        }
        _save_enriched_report("interactive_web_scan", enriched)

        # Extra text report for option 1.
        _write_scan_text_report(
            target_url=target_url,
            discovery=discovery,
            vulnerabilities=merged_vulns,
            mapped=mapped,
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


```

## 5) Core Pipeline Orchestration - scenario generation flow

Source: `run.py`

`python
def run_scenario_generation(ctx: RuntimeContext) -> None:
    raw = input("Scenario text: ").strip()
    if not raw:
        return

    try:
        scenario = sanitize_scenario(raw)
    except Exception:  # noqa: BLE001
        return

    target_env = input(
        "Target environment [Enter=Enterprise Windows Active Directory network]: "
    ).strip() or "Enterprise Windows Active Directory network"
    chain_len_raw = input(f"Chain length [Enter={config.DEFAULT_CHAIN_LENGTH}]: ").strip()
    chain_len = int(chain_len_raw) if chain_len_raw.isdigit() else config.DEFAULT_CHAIN_LENGTH

    try:
        with _silent_execution():
            ctx.ensure_rag(force_reindex=False)
            assert ctx.generator is not None
            result = ctx.generator.generate(
                scenario=scenario,
                target_environment=target_env,
                chain_length=chain_len,
            )
            ctx.generator.export_json(result)
            ctx.generator.export_markdown(result)

            chain = result.get("attack_chain", {}).get("attack_chain", [])
            vulnerabilities = []
            for step in chain:
                vulnerabilities.append(
                    {
                        "type": "Scenario Attack Step",
                        "severity": "MEDIUM",
                        "detail": step.get("description", step.get("technique_name", "Scenario step")),
                        "evidence": step.get("rationale", "Generated from scenario and RAG context."),
                        "recommendation": step.get("mitigation", "Apply layered security controls and ATT&CK-aligned mitigations."),
                        "mitre_hint": step.get("technique_id", ""),
                    }
                )

            assert ctx.mapper is not None
            assert ctx.mitre_db is not None
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _write_option_text_report(
                option_slug="scenario",
                mode_name="Generate Attack Scenario (No URL)",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
    except Exception as e:  # noqa: BLE001
        _write_option_text_report(
            option_slug="scenario",
            mode_name="Generate Attack Scenario (No URL)",
            scenario=scenario,
            target_url=None,
            vulnerabilities=[
                {
                    "type": "Execution Failure",
                    "severity": "LOW",
                    "detail": "Scenario generation failed during execution.",
                    "evidence": str(e),
                    "recommendation": "Verify API keys and environment setup, then retry.",
                    "mitre_hint": "",
                }
            ],
            mapped=[],
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


```

## 6) Core Pipeline Orchestration - scenario URL validation flow

Source: `run.py`

`python
def run_scenario_url_validation(ctx: RuntimeContext) -> None:
    raw = input("Scenario text: ").strip()
    url_raw = input("Target URL: ").strip()
    if not raw or not url_raw:
        return

    try:
        scenario = sanitize_scenario(raw)
        target_url = normalize_url(url_raw)
    except Exception:  # noqa: BLE001
        return

    try:
        with _silent_execution():
            attack_type = detect_attack_type(scenario)
            probe = probe_target(target_url, attack_type)
            status = "FOUND" if probe.get("found") else "NOT FOUND"

            ctx.ensure_rag(force_reindex=False)
            assert ctx.mapper is not None
            assert ctx.mitre_db is not None

            evidence = probe.get("evidence", [])
            vuln_items: list[dict[str, Any]] = []
            for ev in evidence:
                if not ev.get("confirmed"):
                    continue
                vuln_items.append(
                    {
                        "type": f"Targeted Validation ({attack_type})",
                        "detail": ev.get("detail", "Targeted evidence detected"),
                        "severity": probe.get("severity", "MEDIUM"),
                        "cwe_id": "CWE-20",
                        "mitre_hint": "",
                        "recommendation": probe.get("recommendation", "Review and patch issue."),
                        "evidence": f"{ev.get('url', target_url)} | {ev.get('payload', 'probe')}",
                        "confirmed_live": bool(ev.get("confirmed")),
                    }
                )

            if not vuln_items:
                vuln_items.append(
                    {
                        "type": f"Targeted Validation ({attack_type})",
                        "detail": "No automatic confirmation; manual verification recommended.",
                        "severity": "LOW",
                        "cwe_id": "CWE-200",
                        "mitre_hint": "",
                        "recommendation": probe.get("recommendation", "Perform manual validation."),
                        "evidence": probe.get("manual_test", target_url),
                        "confirmed_live": False,
                    }
                )

            mapped = ctx.mapper.map_vulnerabilities(vuln_items)
            chain = ctx.mapper.build_attack_chain(mapped, target_url=target_url)

            recon = WebReconAgent(target_url).run()
            counts = _severity_counts(vuln_items)
            report = ReportGenerator().generate(
                target_url=target_url,
                recon_data=recon,
                scan_result={
                    "target_url": target_url,
                    "total_vulns": len(vuln_items),
                    "severity_counts": counts,
                    "overall_risk": _overall_risk(counts),
                    "vulnerabilities": vuln_items,
                    "tech_stack": recon.get("tech_stack", {}),
                },
                attack_chain=chain,
                llm_analysis=(
                    f"Scenario-driven validation completed for attack type '{attack_type}'. "
                    f"Status: {status}."
                ),
            )

            enriched = {
                "target_url": target_url,
                "scenario": scenario,
                "attack_type": attack_type,
                "probe_result": probe,
                "vulnerabilities": vuln_items,
                "vuln_mappings": [
                    {
                        "vulnerability": m.get("vulnerability"),
                        "top_techniques": [
                            {
                                "technique_id": t.get("technique_id"),
                                "name": t.get("name"),
                            }
                            for t in (m.get("mitre_techniques") or [])[:3]
                        ],
                    }
                    for m in mapped
                ],
                "attack_chain": chain,
                "standard_report_paths": {
                    "json": report.get("json_path"),
                    "markdown": report.get("md_path"),
                },
            }
            _save_enriched_report("scenario_url_validation", enriched)

            _write_option_text_report(
                option_slug="validation",
                mode_name="Validate Scenario on Target URL",
                scenario=scenario,
                target_url=target_url,
                vulnerabilities=vuln_items,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
    except Exception as e:  # noqa: BLE001
        _write_option_text_report(
            option_slug="validation",
            mode_name="Validate Scenario on Target URL",
            scenario=scenario,
            target_url=target_url,
            vulnerabilities=[
                {
                    "type": "Execution Failure",
                    "severity": "LOW",
                    "detail": "Scenario+URL validation failed during execution.",
                    "evidence": str(e),
                    "recommendation": "Verify target reachability and API credentials, then retry.",
                    "mitre_hint": "",
                }
            ],
            mapped=[],
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


```

## 7) Core Pipeline Orchestration - scenario analysis only

Source: `run.py`

`python
def run_scenario_only_analysis(ctx: RuntimeContext) -> None:
    raw = input("Scenario text: ").strip()
    if not raw:
        return

    try:
        scenario = sanitize_scenario(raw)
    except Exception:  # noqa: BLE001
        return

    try:
        with _silent_execution():
            ctx.ensure_rag(force_reindex=False)
            assert ctx.generator is not None

            result = ctx.generator.generate(
                scenario=scenario,
                target_environment="General enterprise environment",
                chain_length=config.DEFAULT_CHAIN_LENGTH,
            )

            ctx.generator.export_json(result)
            ctx.generator.export_markdown(result)

            chain = result.get("attack_chain", {}).get("attack_chain", [])
            vulnerabilities = []
            for step in chain:
                vulnerabilities.append(
                    {
                        "type": "Scenario Analysis Step",
                        "severity": "MEDIUM",
                        "detail": step.get("description", step.get("technique_name", "Analysis step")),
                        "evidence": step.get("rationale", "Derived from scenario-only analysis."),
                        "recommendation": step.get("mitigation", "Apply ATT&CK-aligned defensive controls."),
                        "mitre_hint": step.get("technique_id", ""),
                    }
                )

            assert ctx.mapper is not None
            assert ctx.mitre_db is not None
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _write_option_text_report(
                option_slug="analysis",
                mode_name="Analyze Scenario Only",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
    except Exception as e:  # noqa: BLE001
        _write_option_text_report(
            option_slug="analysis",
            mode_name="Analyze Scenario Only",
            scenario=scenario,
            target_url=None,
            vulnerabilities=[
                {
                    "type": "Execution Failure",
                    "severity": "LOW",
                    "detail": "Scenario-only analysis failed during execution.",
                    "evidence": str(e),
                    "recommendation": "Verify LLM/RAG environment and retry.",
                    "mitre_hint": "",
                }
            ],
            mapped=[],
            mitre_db=ctx.mitre_db,
            rag_engine=ctx.rag,
        )


```

## 8) Core Pipeline Orchestration - main entry

Source: `run.py`

`python
def main() -> int:
    setup_logging()
    print("\nRed ELISAR Interactive Red Agent CLI")
    print("Use only against systems you own or are authorized to test.")
    menu_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## 9) RAG Retrieval Core

Source: `red_agent/rag/rag_engine.py`

`python
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
        # Model used for generation â€” always the Groq/Mistral API model, never Ollama
        self.model = model or config.GROQ_MODEL
        # Fast in-memory cache for repeated retrieval calls in the same runtime.
        self._retrieve_cache: dict[tuple, list[dict]] = {}

    def retrieve(
        self,
        scenario: str,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
        max_query_variants: Optional[int] = None,
        use_cache: bool = True,
    ) -> list[dict]:
        if top_k is None:
            top_k = config.RAG_TOP_K
        if max_query_variants is None:
            max_query_variants = int(getattr(config, "RAG_MAX_QUERY_VARIANTS", 0)) or None

        scenario_clean = self._clean_ws(scenario)
        cache_key = (
            scenario_clean.lower(),
            int(top_k),
            (tactic_filter or "").lower(),
            (platform_filter or "").lower(),
            int(max_query_variants) if max_query_variants else 0,
        )
        if use_cache and cache_key in self._retrieve_cache:
            cached = self._retrieve_cache[cache_key]
            logger.debug(
                "RAG retrieve cache hit: top_k=%s variants=%s query='%s...'",
                top_k,
                max_query_variants or "all",
                scenario_clean[:60],
            )
            return [dict(x) for x in cached]

        variants = self._build_query_variants(scenario_clean)
        if max_query_variants is not None and max_query_variants > 0:
            variants = variants[:max_query_variants]

        merged: dict[str, dict] = {}
        for q in variants:
            hits = self.vector_store.query(
                query_text=q,
                top_k=top_k,
                tactic_filter=tactic_filter,
                platform_filter=platform_filter,
            )
            for h in hits:
                tid = str(h.get("technique_id") or "").strip().upper()
                if not tid:
                    continue
                prev = merged.get(tid)
                if prev is None or float(h.get("relevance_score", 0.0) or 0.0) > float(prev.get("relevance_score", 0.0) or 0.0):
                    merged[tid] = h

        results = list(merged.values())
        results = self._rerank_optional(scenario, results)
        results.sort(
            key=lambda r: float(r.get("_combined_score", r.get("relevance_score", 0.0)) or 0.0),
            reverse=True,
        )
        results = results[:top_k]

        if use_cache:
            self._retrieve_cache[cache_key] = [dict(x) for x in results]

        logger.info(f"Retrieved {len(results)} techniques for scenario: '{scenario[:60]}...' using {len(variants)} query variants")
        return results

    def _build_query_variants(self, scenario: str) -> list[str]:
        text = self._clean_ws(scenario)
        low = text.lower()
        variants = [text]

        web_tokens = ["web", "http", "url", "endpoint", "form", "session", "cookie"]
        id_tokens = ["credential", "password", "token", "account", "login", "auth"]
        sql_tokens = ["sql", "database", "query", "injection", "union", "blind"]
        xss_tokens = ["xss", "script", "javascript", "browser"]

        if any(t in low for t in web_tokens):
            variants.append(f"{text} web application attack technique mapping")
        if any(t in low for t in id_tokens):
            variants.append(f"{text} credential access valid accounts lateral movement")
        if any(t in low for t in sql_tokens):
            variants.append(f"{text} exploit public-facing application sql injection database")
        if any(t in low for t in xss_tokens):
            variants.append(f"{text} script execution browser credential theft session hijack")

        # Keep unique order.
        seen = set()
        uniq = []
        for q in variants:
            if not q or q in seen:
                continue
            uniq.append(q)
            seen.add(q)
        return uniq

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
        return f"{tid} â€“ {name}" if name else tid

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
            max_steps = min(chain_length, 14)
            min_steps = max(8, max_steps - 2)
            user = USER_PROMPT_TEMPLATE.format(
                scenario=scenario,
                context=context,
                min_steps=min_steps,
                max_steps=max_steps,
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

        # â”€â”€ OLD Ollama code (commented out for reference) â”€â”€â”€â”€â”€â”€â”€â”€
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
        # â”€â”€ END Ollama code â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

        # Pull additional candidates for missing tactics if not present.
        for missing in missing_tactics:
            if missing in by_tactic:
                continue
            try:
                extra = self.retrieve(
                    scenario=f"MITRE ATT&CK techniques for tactic {missing.replace('-', ' ')}",
                    top_k=8,
                    tactic_filter=missing,
                )
                if extra:
                    by_tactic[missing] = extra[0]
            except Exception:
                continue

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
            elif len(chain) < chain_length:
                chain.append(
                    {
                        "step": len(chain) + 1,
                        "technique_id": candidate.get("technique_id", ""),
                        "technique_name": candidate.get("name", "Unknown"),
                        "tactic": missing,
                        "description": candidate.get("description_preview", "Coverage-added tactic step."),
                        "rationale": f"Added to maintain complete ATT&CK lifecycle coverage for {missing}.",
                        "prerequisites": [],
                        "detection_considerations": "",
                        "mitigation": "",
                        "tool_commands": [],
                    }
                )
                used_ids.add(candidate.get("technique_id", ""))

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
            chain_length = max(8, min(int(getattr(config, "MAX_CHAIN_LENGTH", 14)), int(chain_length)))

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
                max_query_variants=int(getattr(config, "RAG_MAX_QUERY_VARIANTS", 0)) or None,
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
                        f"Return STRICT JSON only and include {max(8, min(chain_length, 14))} to {min(chain_length, 14)} steps."
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

                min_steps_required = 1 if chain_length <= 1 else max(8, min(chain_length, 14))
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
            min_steps = 1 if chain_length <= 1 else max(8, min(chain_length, 14))
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
                    "description": r.get("description_preview", ""),
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

    def generate_attack_chain_fast(
        self,
        scenario: str,
        target_environment: str = "Enterprise Windows Active Directory network",
        chain_length: int = None,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> dict:
        pipeline_start = time.perf_counter()
        latency_metrics = {"pipeline_start": pipeline_start}

        try:
            scenario = sanitize_scenario(scenario)
        except ValueError as e:
            raise ValueError(f"Input sanitization failed: {e}")

        retrieve_start = time.perf_counter()
        normalized_len = None
        if chain_length is not None:
            try:
                normalized_len = int(chain_length)
            except Exception:
                normalized_len = None

        if normalized_len is not None:
            normalized_len = max(1, min(int(getattr(config, "MAX_CHAIN_LENGTH", 14)), normalized_len))

        wide_k = top_k
        if wide_k is None:
            base = normalized_len or int(getattr(config, "DEFAULT_CHAIN_LENGTH", 10))
            wide_k = max(int(getattr(config, "RAG_RETRIEVAL_TOP_K_WIDE", 18)), base * 2)

        use_diverse = bool(getattr(config, "RAG_USE_DIVERSE_RETRIEVAL", False))
        if use_diverse and not tactic_filter and not platform_filter:
            retrieved = self.vector_store.query_diverse(query_text=scenario, top_k=wide_k)
        else:
            retrieved = self.retrieve(
                scenario=scenario,
                top_k=wide_k,
                tactic_filter=tactic_filter,
                platform_filter=platform_filter,
                max_query_variants=int(getattr(config, "RAG_MAX_QUERY_VARIANTS", 0)) or None,
            )

        latency_metrics["retrieval_time_s"] = time.perf_counter() - retrieve_start
        if not retrieved:
            raise ValueError("No techniques retrieved. Check that the vector store is indexed.")

        if normalized_len is None:
            normalized_len = min(8, len(retrieved))
            normalized_len = max(1, normalized_len)

        candidates = self._select_context_techniques(
            scenario=scenario,
            techniques=retrieved,
            desired_count=min(len(retrieved), max(normalized_len * 2, 12)),
            chain_length=normalized_len,
        )

        def _tactics_for(tech: dict) -> list[str]:
            tactics = tech.get("tactics", [])
            if isinstance(tactics, str):
                tactics = [x.strip() for x in tactics.split(",") if x.strip()]
            return [self._normalize_tactic(t) for t in (tactics or []) if t]

        def _score(tech: dict) -> float:
            return float(tech.get("_combined_score", tech.get("relevance_score", 0.0)) or 0.0)

        ranked = sorted(candidates, key=_score, reverse=True)
        selected: list[dict] = []
        used_ids: set[str] = set()

        # Favor kill-chain ordering where possible.
        for tactic in self.MITRE_TACTICS:
            for tech in ranked:
                tid = str(tech.get("technique_id") or "").strip().upper()
                if not tid or tid in used_ids:
                    continue
                if tactic in _tactics_for(tech):
                    selected.append({"tech": tech, "tactic": tactic})
                    used_ids.add(tid)
                    break
            if len(selected) >= normalized_len:
                break

        # Fill remaining slots by relevance.
        for tech in ranked:
            if len(selected) >= normalized_len:
                break
            tid = str(tech.get("technique_id") or "").strip().upper()
            if not tid or tid in used_ids:
                continue
            tactics = _tactics_for(tech)
            selected.append({"tech": tech, "tactic": tactics[0] if tactics else "unknown"})
            used_ids.add(tid)

        chain_steps = []
        for i, item in enumerate(selected, 1):
            tech = item["tech"]
            tid = str(tech.get("technique_id") or "").strip().upper()
            tactic = item.get("tactic") or "unknown"
            description = tech.get("description_preview") or tech.get("document") or "Retrieved ATT&CK technique aligned to scenario."
            step = {
                "step": i,
                "technique_id": tid,
                "technique_name": tech.get("name", "Unknown"),
                "tactic": tactic,
                "description": description,
                "rationale": "Derived from RAG retrieval for the provided scenario.",
                "prerequisites": [],
                "detection_considerations": "",
                "mitigation": "",
                "tool_commands": [],
            }
            mit = get_mitigation(tid)
            if mit.get("name"):
                step["mitigation"] = f"{mit['name']}: {mit.get('description', '')}".strip()
            tools_info = get_tools(tid)
            step["tool_commands"] = (tools_info.get("commands", []) or [])[:3]
            chain_steps.append(step)

        warnings: list[str] = []
        if len(chain_steps) < normalized_len:
            warnings.append(
                f"Only {len(chain_steps)} techniques available for fast mode; requested {normalized_len}."
            )

        latency_metrics["pipeline_total_s"] = time.perf_counter() - pipeline_start
        latency_metrics["llm_latency_s"] = 0.0

        parsed_chain = {
            "attack_chain": chain_steps,
            "metadata": {
                "scenario": scenario,
                "target_environment": target_environment,
                "chain_length": normalized_len,
                "techniques_used": len(chain_steps),
                "generation_mode": "fast",
            },
        }

        return {
            "attack_chain": parsed_chain,
            "retrieval_results": [
                {
                    "technique_id": r["technique_id"],
                    "name": r["name"],
                    "relevance_score": r.get("relevance_score"),
                    "tactics": r.get("tactics"),
                    "description": r.get("description_preview", ""),
                }
                for r in retrieved
            ],
            "latency": latency_metrics,
            "warnings": warnings,
            "faithfulness_score": 1.0,
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
```

## 10) Vector Search Backend

Source: `red_agent/rag/vector_store_faiss.py`

`python
class FAISSVectorStore:

    def __init__(
        self,
        index_dir: Optional[Path] = None,
        model_name: Optional[str] = None,
    ):
        self.index_dir = index_dir or config.FAISS_INDEX_DIR
        self.model_name = model_name or config.EMBEDDING_MODEL_NAME
        self.dimension = config.EMBEDDING_DIMENSION

        # Persistence file paths
        self._index_path    = self.index_dir / "hnsw_index.faiss"
        self._metadata_path = self.index_dir / "metadata.json"
        self._chunks_path   = self.index_dir / "chunks.json"

        # Lazy-loaded components
        self._model: Optional[SentenceTransformer] = None
        self._index: Optional[faiss.Index] = None
        self._metadata: list[dict] = []
        self._documents: list[str] = []

    @property
    def model(self) -> SentenceTransformer:
        if self._model is None:
            logger.info(f"Loading embedding model: {self.model_name}")
            start = time.perf_counter()
            self._model = SentenceTransformer(self.model_name, device="cpu")
            logger.info(f"Embedding model loaded in {time.perf_counter() - start:.2f}s")
        return self._model

    @property
    def index(self) -> faiss.Index:
        if self._index is None:
            if self._index_path.exists():
                self._load_index()
            else:
                self._create_index()
        return self._index

    def _create_index(self):
        logger.info(
            f"Creating FAISS HNSWFlat index: dim={self.dimension}, "
            f"M={config.FAISS_HNSW_M}, efConstruction={config.FAISS_HNSW_EF_CONSTRUCTION}"
        )
        self._index = faiss.IndexHNSWFlat(self.dimension, config.FAISS_HNSW_M)
        self._index.hnsw.efConstruction = config.FAISS_HNSW_EF_CONSTRUCTION
        self._index.hnsw.efSearch = config.FAISS_HNSW_EF_SEARCH
        logger.info("FAISS HNSW index created")

    def index_chunks(self, chunks: list[dict], force_reindex: bool = False) -> dict:
        stats = {
            "total_chunks": len(chunks),
            "indexed": 0,
            "skipped": 0,
            "embedding_time_s": 0.0,
            "indexing_time_s": 0.0,
            "total_time_s": 0.0,
        }
        total_start = time.perf_counter()

        # Skip if already indexed
        if self._index_path.exists() and not force_reindex:
            self._load_index()
            if self._index.ntotal > 0:
                logger.info(
                    f"Index already contains {self._index.ntotal} vectors. "
                    f"Skipping. Use force_reindex=True to rebuild."
                )
                stats["skipped"] = self._index.ntotal
                stats["total_time_s"] = time.perf_counter() - total_start
                return stats

        # Rebuild from scratch
        self._create_index()
        self._metadata = []
        self._documents = []

        texts     = [c["text"] for c in chunks]
        metadatas = [c["metadata"] for c in chunks]

        # Generate embeddings in batches
        logger.info(f"Generating embeddings for {len(texts)} chunks...")
        embed_start = time.perf_counter()
        all_embeddings = []
        batch_size = config.EMBEDDING_BATCH_SIZE

        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            batch_embeddings = self.model.encode(
                batch,
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,  # L2-normalize for cosine similarity
            )
            all_embeddings.append(batch_embeddings)
            logger.debug(
                f"Embedded batch {i // batch_size + 1}/"
                f"{(len(texts) + batch_size - 1) // batch_size}"
            )

        embeddings = np.vstack(all_embeddings).astype(np.float32)
        stats["embedding_time_s"] = time.perf_counter() - embed_start
        logger.info(f"Embeddings generated in {stats['embedding_time_s']:.2f}s")

        # Add vectors to FAISS index
        index_start = time.perf_counter()
        self._index.add(embeddings)
        stats["indexing_time_s"] = time.perf_counter() - index_start

        self._metadata = metadatas
        self._documents = texts
        stats["indexed"] = len(texts)

        self._save_index()
        stats["total_time_s"] = time.perf_counter() - total_start
        logger.info(
            f"Indexed {stats['indexed']} chunks in {stats['total_time_s']:.2f}s "
            f"(embed: {stats['embedding_time_s']:.2f}s, "
            f"index: {stats['indexing_time_s']:.2f}s)"
        )

        # Free embedding memory
        del embeddings, all_embeddings
        if config.AGGRESSIVE_GC:
            gc.collect()

        return stats

    def query(
        self,
        query_text: str,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> list[dict]:
        if top_k is None:
            top_k = config.RAG_TOP_K

        if self.index.ntotal == 0:
            logger.warning("FAISS index is empty. Index chunks first.")
            return []

        start = time.perf_counter()

        # Embed query (normalized for cosine similarity via L2)
        query_embedding = self.model.encode(
            [query_text],
            convert_to_numpy=True,
            normalize_embeddings=True,
        ).astype(np.float32)

        # Over-retrieve when filters are active
        search_k = (
            min(top_k * 3, self.index.ntotal)
            if tactic_filter or platform_filter
            else min(top_k, self.index.ntotal)
        )
        distances, indices = self.index.search(query_embedding, search_k)
        elapsed = time.perf_counter() - start

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < 0 or idx >= len(self._metadata):
                continue

            # Convert L2 distance â†’ cosine similarity (normalized vectors)
            cosine_sim = 1.0 - (float(dist) / 2.0)
            cosine_sim = max(0.0, min(1.0, cosine_sim))
            metadata = self._metadata[idx]
            document = self._documents[idx] if idx < len(self._documents) else ""

            if tactic_filter:
                if tactic_filter.lower() not in metadata.get("tactics", "").lower():
                    continue
            if platform_filter:
                if platform_filter.lower() not in metadata.get("platforms", "").lower():
                    continue

            results.append({
                "technique_id": metadata.get("technique_id", ""),
                "name": metadata.get("name", ""),
                "tactics": metadata.get("tactics", "").split(",") if isinstance(metadata.get("tactics"), str) else metadata.get("tactics", []),
                "platforms": metadata.get("platforms", "").split(",") if isinstance(metadata.get("platforms"), str) else metadata.get("platforms", []),
                "description_preview": metadata.get("description_preview", ""),
                "distance": round(float(dist), 4),
                "relevance_score": round(cosine_sim, 4),
                "document": document,
                "chunk_index": int(idx),
                "stix_id": metadata.get("stix_id", ""),
                "url": metadata.get("url", ""),
            })

            if len(results) >= top_k:
                break

        logger.info(
            f"FAISS query completed in {elapsed * 1000:.1f}ms: "
            f"'{query_text[:50]}...' â†’ {len(results)} results"
        )
        return results

    def query_diverse(self, query_text: str, top_k: int = None) -> list[dict]:
        if top_k is None:
            top_k = config.RAG_TOP_K

        # Wide retrieval for diversity
        wide_results = self.query(query_text, top_k=config.DIVERSITY_TOP_K_WIDE)
        if len(wide_results) <= top_k:
            return wide_results

        # Group techniques by tactic
        tactic_groups: dict[str, list[dict]] = {}
        for r in wide_results:
            tactics = r.get("tactics", [])
            if isinstance(tactics, str):
                tactics = [t.strip() for t in tactics.split(",")]
            for tactic in tactics:
                tactic_lower = tactic.lower().strip()
                if tactic_lower not in tactic_groups:
                    tactic_groups[tactic_lower] = []
                tactic_groups[tactic_lower].append(r)

        # Pick best from each key kill chain tactic
        selected = []
        selected_ids = set()
        for key_tactic in config.DIVERSITY_KEY_TACTICS:
            if key_tactic in tactic_groups:
                for candidate in tactic_groups[key_tactic]:
                    if candidate["technique_id"] not in selected_ids:
                        selected.append(candidate)
                        selected_ids.add(candidate["technique_id"])
                        break
            if len(selected) >= top_k:
                break

        # Fill remaining slots with highest-scoring remaining techniques
        for r in wide_results:
            if len(selected) >= top_k:
                break
            if r["technique_id"] not in selected_ids:
                selected.append(r)
                selected_ids.add(r["technique_id"])

        logger.info(
            f"Diverse retrieval: {len(selected)} techniques from "
            f"{len(set(t for s in selected for t in (s.get('tactics', []) if isinstance(s.get('tactics'), list) else [s.get('tactics', '')])))} tactics"
        )
        return selected[:top_k]

    def query_by_technique_id(self, technique_id: str) -> Optional[dict]:
        for i, meta in enumerate(self._metadata):
            if meta.get("technique_id") == technique_id:
                return {
                    "technique_id": technique_id,
                    "name": meta.get("name", ""),
                    "tactics": meta.get("tactics", "").split(",") if isinstance(meta.get("tactics"), str) else meta.get("tactics", []),
                    "platforms": meta.get("platforms", "").split(",") if isinstance(meta.get("platforms"), str) else meta.get("platforms", []),
                    "description_preview": meta.get("description_preview", ""),
                    "document": self._documents[i] if i < len(self._documents) else "",
                    "stix_id": meta.get("stix_id", ""),
                    "url": meta.get("url", ""),
                }
        return None

    def _save_index(self):
        config.ensure_directories()
        self.index_dir.mkdir(parents=True, exist_ok=True)
        # Save FAISS index
        faiss.write_index(self._index, str(self._index_path))
        # Save metadata sidecar
        with open(self._metadata_path, "w", encoding="utf-8") as f:
            json.dump(self._metadata, f, ensure_ascii=False)
        # Save document texts
        with open(self._chunks_path, "w", encoding="utf-8") as f:
            json.dump(self._documents, f, ensure_ascii=False)
        logger.info(f"Index persisted: {self._index.ntotal} vectors â†’ {self._index_path}")

    def _load_index(self):
        logger.info(f"Loading FAISS index from {self._index_path}")
        start = time.perf_counter()
        self._index = faiss.read_index(str(self._index_path))
        # Restore efSearch (not persisted by FAISS)
        self._index.hnsw.efSearch = config.FAISS_HNSW_EF_SEARCH
        with open(self._metadata_path, "r", encoding="utf-8") as f:
            self._metadata = json.load(f)
        if self._chunks_path.exists():
            with open(self._chunks_path, "r", encoding="utf-8") as f:
                self._documents = json.load(f)
        else:
            self._documents = [""] * len(self._metadata)
        logger.info(f"FAISS index loaded: {self._index.ntotal} vectors in {time.perf_counter() - start:.2f}s")

    def get_collection_stats(self) -> dict:
        return {
            "total_documents": self.index.ntotal,
            "total_metadata_entries": len(self._metadata),
            "embedding_model": self.model_name,
            "embedding_dimension": self.dimension,
            "hnsw_M": config.FAISS_HNSW_M,
            "hnsw_efSearch": config.FAISS_HNSW_EF_SEARCH,
            "hnsw_efConstruction": config.FAISS_HNSW_EF_CONSTRUCTION,
            "index_path": str(self._index_path),
            "index_exists": self._index_path.exists(),
        }

    def is_ready(self) -> bool:
        """Compatibility helper for callers expecting a readiness check."""
        if not self._index_path.exists() or not self._metadata_path.exists():
            return False
        try:
            self._load_index()
            return self._index is not None and self._index.ntotal > 0
        except Exception:
            return False

    def load(self):
        """Compatibility helper for callers expecting an explicit load method."""
        self._load_index()
        return self

    def reset(self):
        logger.warning("Resetting FAISS index â€” all indexed data will be lost")
        for path in [self._index_path, self._metadata_path, self._chunks_path]:
            if path.exists():
                path.unlink()
        self._index = None
        self._metadata = []
        self._documents = []

    def unload_model(self):
        if self._model is not None:
            del self._model
            self._model = None
            if config.AGGRESSIVE_GC:
                gc.collect()
            logger.info("Embedding model unloaded")


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)
    from mitre_parser import MITREParser
    from chunking import chunk_techniques

    parser = MITREParser()
    techniques = parser.parse()
    chunks = chunk_techniques(techniques)
    print(f"Generated {len(chunks)} chunks from {len(techniques)} techniques")

    store = FAISSVectorStore()
    stats = store.index_chunks(chunks, force_reindex=True)
    print(f"\nIndexing Stats: {stats}")
    print(f"Collection Stats: {store.get_collection_stats()}")

    test_query = "initial access via phishing with malicious attachment"
    results = store.query(test_query, top_k=5)
    print(f"\nQuery: '{test_query}'")
    print(f"Results (top-5):")
    for r in results:
        print(
            f"  [{r['technique_id']}] {r['name']} "
            f"(score: {r['relevance_score']:.4f}, tactics: {r['tactics']})"
        )
```

## 11) MITRE Mapping Logic

Source: `red_agent/mappings/mitre_mapper.py`

`python
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

    # â”€â”€â”€ Main Entry Points â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
                f"[MITREMapper] '{vuln_type}' â†’ "
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
        # Collect all techniqueâ†’vulnerability pairs, grouped by tactic
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


# â”€â”€â”€ Standalone Test â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if __name__ == "__main__":
    import sys, json, logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    print("MITREMapper requires RAGEngine. Run via web_vuln_agent.py instead.")
    print("  python web_vuln_agent.py http://127.0.0.1:5000")
```

## 12) Attack Chain Generation

Source: `red_agent/llm/attack_chain_generator.py`

`python
class AttackChainGenerator:

    def __init__(self, vector_store: FAISSVectorStore, model: str = None):
        self.rag_engine = RAGEngine(vector_store, model=model)
        self.vector_store = vector_store
        self.generation_history: list[dict] = []

    def generate(
        self,
        scenario: str,
        target_environment: str = "Enterprise Windows Active Directory network",
        chain_length: int = None,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> dict:
        result = self.rag_engine.generate_attack_chain(
            scenario=scenario,
            target_environment=target_environment,
            chain_length=chain_length,
            top_k=top_k,
            tactic_filter=tactic_filter,
            platform_filter=platform_filter,
        )
        result["analysis"] = self.analyze_chain(result)
        self.generation_history.append(result)
        return result

    def generate_fast(
        self,
        scenario: str,
        target_environment: str = "Enterprise Windows Active Directory network",
        chain_length: int = None,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> dict:
        result = self.rag_engine.generate_attack_chain_fast(
            scenario=scenario,
            target_environment=target_environment,
            chain_length=chain_length,
            top_k=top_k,
            tactic_filter=tactic_filter,
            platform_filter=platform_filter,
        )
        result["analysis"] = self.analyze_chain(result)
        self.generation_history.append(result)
        return result

    def generate_predefined(self, scenario_key: str) -> dict:
        if scenario_key not in PREDEFINED_SCENARIOS:
            available = ", ".join(PREDEFINED_SCENARIOS.keys())
            raise KeyError(f"Unknown scenario '{scenario_key}'. Available: {available}")
        params = dict(PREDEFINED_SCENARIOS[scenario_key])
        # Respect the predefined scenario length; fall back to DEFAULT_CHAIN_LENGTH only when missing.
        params["chain_length"] = int(params.get("chain_length") or config.DEFAULT_CHAIN_LENGTH)
        logger.info(f"Generating predefined scenario: {scenario_key}")
        return self.generate(**params)

    def generate_batch(self, scenario_keys: Optional[list[str]] = None) -> list[dict]:
        if scenario_keys is None:
            scenario_keys = list(PREDEFINED_SCENARIOS.keys())
        results = []
        for i, key in enumerate(scenario_keys, 1):
            logger.info(f"\n{'#'*60}")
            logger.info(f"BATCH {i}/{len(scenario_keys)}: {key}")
            logger.info(f"{'#'*60}")
            try:
                result = self.generate_predefined(key)
                result["scenario_key"] = key
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to generate {key}: {e}")
                results.append({
                    "scenario_key": key,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        return results

    def analyze_chain(self, result: dict) -> dict:
        chain = result.get("attack_chain", {}).get("attack_chain", [])
        if not chain:
            return {"error": "No attack chain to analyze"}

        # Standard MITRE kill chain phases
        mitre_tactics = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]

        chain_tactics = [step.get("tactic", "").lower().replace(" ", "-") for step in chain]
        covered_tactics = set(chain_tactics) & set(mitre_tactics)

        technique_ids = [step.get("technique_id", "") for step in chain]
        unique_techniques = set(technique_ids)

        steps_with_detection = sum(
            1 for step in chain if step.get("detection_considerations", "").strip()
        )
        hallucinated_steps = sum(
            1 for step in chain if step.get("_hallucination_flag", False)
        )

        return {
            "total_steps": len(chain),
            "unique_techniques": len(unique_techniques),
            "technique_reuse": len(chain) - len(unique_techniques),
            "tactical_coverage": {
                "covered": sorted(covered_tactics),
                "total_mitre_tactics": len(mitre_tactics),
                "coverage_ratio": len(covered_tactics) / len(mitre_tactics),
            },
            "detection_coverage": {
                "steps_with_detection": steps_with_detection,
                "coverage_ratio": steps_with_detection / len(chain) if chain else 0,
            },
            "hallucination_metrics": {
                "hallucinated_steps": hallucinated_steps,
                "total_steps": len(chain),
                "faithfulness_score": result.get("faithfulness_score", 0),
            },
            "latency_summary": {
                "total_pipeline_s": result.get("latency", {}).get("pipeline_total_s", 0),
                "retrieval_ms": result.get("latency", {}).get("retrieval_time_s", 0) * 1000,
                "generation_s": result.get("latency", {}).get("llm_latency_s", 0),
                "tokens_per_second": result.get("latency", {}).get("tokens_per_second", 0),
            },
        }

    def export_json(self, result: dict, output_path: Optional[Path] = None) -> Path:
        config.ensure_directories()
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = config.OUTPUT_DIR / f"attack_chain_{timestamp}.json"
        # Serialize, stripping non-JSON-serializable fields
        clean_result = json.loads(json.dumps(result, default=str))
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(clean_result, f, indent=2, ensure_ascii=False)
        logger.info(f"Attack chain exported to: {output_path}")
        return output_path

    def export_markdown(self, result: dict, output_path: Optional[Path] = None) -> Path:
        config.ensure_directories()
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = config.OUTPUT_DIR / f"attack_chain_report_{timestamp}.md"

        chain    = result.get("attack_chain", {}).get("attack_chain", [])
        analysis = result.get("analysis", {})
        latency  = result.get("latency", {})

        lines = [
            "# Red ELISAR â€” Attack Chain Report",
            "",
            f"**Generated:** {result.get('timestamp', 'N/A')}",
            f"**Scenario:** {result.get('scenario', 'N/A')}",
            f"**Target Environment:** {result.get('target_environment', 'N/A')}",
            f"**Faithfulness Score:** {result.get('faithfulness_score', 0):.0%}",
            "",
            "---",
            "",
        ]

        # â”€â”€ Inject live vulnerability probe results if available â”€â”€
        probe = result.get("probe_result")
        if probe:
            from vuln_checks.targeted_attack_scanner import format_probe_result_markdown
            lines.append(format_probe_result_markdown(probe))

        lines += [
            "## Attack Chain",
            "",
        ]

        for step in chain:
            hallucinated = " [WARN HALLUCINATED]" if step.get("_hallucination_flag") else ""
            lines.extend([
                f"### Step {step.get('step', '?')}: {step.get('technique_name', 'Unknown')}{hallucinated}",
                "",
                f"- **Technique ID:** `{step.get('technique_id', 'N/A')}`",
                f"- **Tactic:** {step.get('tactic', 'N/A')}",
                f"- **Description:** {step.get('description', 'N/A')}",
                f"- **Rationale:** {step.get('rationale', 'N/A')}",
                f"- **Prerequisites:** {', '.join(step.get('prerequisites', ['None']))}",
                f"- **Detection:** {step.get('detection_considerations', 'N/A')}",
                f"- **Mitigation:** {step.get('mitigation', 'N/A')}",
            ])
            tool_cmds = step.get('tool_commands', [])
            if tool_cmds:
                lines.append(f"- **Tool Commands:**")
                for cmd in tool_cmds[:3]:
                    lines.append(f"  - `{cmd}`")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## Retrieved Techniques (Context)",
            "",
            "| Technique ID | Name | Relevance Score | Tactics |",
            "|:---|:---|:---|:---|",
        ])

        for tech in result.get("retrieval_results", []):
            tactics = ", ".join(tech.get("tactics", [])) if isinstance(tech.get("tactics"), list) else str(tech.get("tactics", ""))
            lines.append(
                f"| `{tech['technique_id']}` | {tech['name']} | "
                f"{tech.get('relevance_score', 'N/A')} | {tactics} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## Performance Metrics",
            "",
            f"- **Total Pipeline Latency:** {latency.get('pipeline_total_s', 0):.2f}s",
            f"- **Retrieval Latency:** {latency.get('retrieval_time_s', 0)*1000:.0f}ms",
            f"- **LLM Generation Latency:** {latency.get('llm_latency_s', 0):.2f}s",
            f"- **Tokens/Second:** {latency.get('tokens_per_second', 0):.1f}",
            "",
            "## Analysis",
            "",
            f"- **Tactical Coverage:** {analysis.get('tactical_coverage', {}).get('coverage_ratio', 0):.0%} "
            f"({len(analysis.get('tactical_coverage', {}).get('covered', []))} / "
            f"{analysis.get('tactical_coverage', {}).get('total_mitre_tactics', 14)} tactics)",
            f"- **Unique Techniques:** {analysis.get('unique_techniques', 0)}",
            f"- **Detection Coverage:** {analysis.get('detection_coverage', {}).get('coverage_ratio', 0):.0%}",
            f"- **Hallucinated Steps:** {analysis.get('hallucination_metrics', {}).get('hallucinated_steps', 0)}",
            "",
            "---",
            "",
            "*Generated by Red ELISAR â€” Privacy-Preserving Autonomous Offensive Security Agent*",
        ])

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        logger.info(f"Markdown report exported to: {output_path}")
        return output_path

    def export_batch(self, results: list[dict], output_dir: Optional[Path] = None) -> Path:
        config.ensure_directories()
        if output_dir is None:
            output_dir = config.OUTPUT_DIR
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"batch_results_{timestamp}.json"
        clean_results = json.loads(json.dumps(results, default=str))
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "batch_timestamp": datetime.now(timezone.utc).isoformat(),
                "total_scenarios": len(results),
                "results": clean_results,
            }, f, indent=2, ensure_ascii=False)
        logger.info(f"Batch results exported to: {output_path}")
        return output_path

    def list_scenarios(self) -> dict:
        return {
            key: {
                "scenario_preview": val["scenario"][:100] + "...",
                "target_environment": val["target_environment"],
                "chain_length": val["chain_length"],
            }
            for key, val in PREDEFINED_SCENARIOS.items()
        }

    def health_check(self) -> dict:
        status = {
            "vector_store": self.vector_store.get_collection_stats(),
            "ollama": self.rag_engine.check_ollama_health(),
            "system_ready": False,
        }
        vs_ready = status["vector_store"]["total_documents"] > 0
        ollama_ready = (
            status["ollama"]["ollama_reachable"]
            and status["ollama"]["model_available"]
        )
        status["system_ready"] = vs_ready and ollama_ready
        if not vs_ready:
            status["action_required"] = "Index MITRE ATT&CK techniques first"
        elif not ollama_ready:
            status["action_required"] = status["ollama"].get("error", "Start Ollama")
        return status
```

## 13) Final Report Generation

Source: `red_agent/reporting/report_generator.py`

`python
class ReportGenerator:
    """Generates Markdown and JSON vulnerability assessment reports."""

    def __init__(self):
        config.ensure_directories()
        self.output_dir = config.OUTPUT_DIR

    def generate(
        self,
        target_url:   str,
        recon_data:   dict,
        scan_result:  dict,
        attack_chain: list,
        llm_analysis: str,
    ) -> dict:
        """
        Generate both Markdown and JSON reports.
        Returns dict with report paths and summary.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"vuln_report_{timestamp}"

        # Build full report data structure
        report = self._build_report(target_url, recon_data, scan_result,
                                    attack_chain, llm_analysis)

        # Save JSON
        json_path = self.output_dir / f"{base_name}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"[Report] JSON saved: {json_path}")

        # Save Markdown
        md_path = self.output_dir / f"{base_name}.md"
        md_content = self._render_markdown(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"[Report] Markdown saved: {md_path}")

        pdf_path = ""
        if render_markdown_to_pdf:
            try:
                pdf_path = str(render_markdown_to_pdf(md_path, self.output_dir / f"{base_name}.pdf"))
                logger.info(f"[Report] PDF saved: {pdf_path}")
            except Exception as exc:
                logger.warning("[Report] PDF generation failed: %s", exc)

        # Print summary to console
        self._print_console_summary(report)

        return {
            "report_data":  report,
            "json_path":    str(json_path),
            "md_path":      str(md_path),
            "overall_risk": report["overall_risk"],
            "total_vulns":  report["total_vulns"],
            "pdf_path":     pdf_path,
        }

    # â”€â”€â”€ Build Report Data â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _build_report(self, target_url, recon_data, scan_result,
                      attack_chain, llm_analysis) -> dict:
        tech  = recon_data.get("tech_stack", {})
        vulns = scan_result.get("vulnerabilities", [])

        return {
            "report_title":    "Red ELISAR â€” Autonomous Web Vulnerability Assessment",
            "target_url":      target_url,
            "scan_date":       datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "overall_risk":    scan_result.get("overall_risk", "UNKNOWN"),
            "total_vulns":     scan_result.get("total_vulns", 0),
            "severity_counts": scan_result.get("severity_counts", {}),
            "tech_stack": {
                "server":   tech.get("server", "Unknown"),
                "language": tech.get("language", "Unknown"),
                "versions": tech.get("versions", {}),
            },
            "recon_summary": {
                "domain":           recon_data.get("domain"),
                "status_code":      recon_data.get("status_code"),
                "ssl_enabled":      recon_data.get("ssl", {}).get("enabled", False),
                "exposed_paths":    len(recon_data.get("exposed_paths", [])),
                "missing_headers":  len(recon_data.get("missing_security_headers", {})),
                "leaked_headers":   len(recon_data.get("leaked_info_headers", {})),
            },
            "vulnerabilities": vulns,
            "attack_chain":    attack_chain,
            "llm_analysis":    llm_analysis,
            "disclaimer": (
                "EDUCATIONAL USE ONLY. This assessment was performed on a "
                "deliberately vulnerable application for learning purposes. "
                "Unauthorized use of this tool against real systems is illegal."
            ),
        }

    # â”€â”€â”€ Render Markdown Report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _render_markdown(self, report: dict) -> str:
        risk      = report["overall_risk"]
        risk_icon = SEVERITY_ICONS.get(risk, "[UNK]")
        vulns     = report["vulnerabilities"]
        chain     = report["attack_chain"]
        counts    = report["severity_counts"]
        tech      = report["tech_stack"]

        lines = []

        # Title
        lines += [
            "# Red ELISAR â€” Autonomous Web Vulnerability Assessment Report",
            "",
            f"> **Generated by:** Red ELISAR (Privacy-Preserving Autonomous Offensive Security Agent)",
            f"> **Framework:** MITRE ATT&CK Enterprise v14",
            "",
            "---",
            "",
        ]

        # Summary box
        lines += [
            "## Executive Summary",
            "",
            f"| Field              | Value                          |",
            f"|-------------------|-------------------------------|",
            f"| **Target URL**    | `{report['target_url']}`      |",
            f"| **Scan Date**     | {report['scan_date']}          |",
            f"| **Overall Risk**  | {risk_icon} **{risk}**         |",
            f"| **Server**        | {tech['server']}               |",
            f"| **Language**      | {tech['language']}             |",
            f"| **Total Vulns**   | **{report['total_vulns']}**    |",
            f"| Critical         | {counts.get('CRITICAL', 0)}    |",
            f"| High             | {counts.get('HIGH', 0)}        |",
            f"| Medium           | {counts.get('MEDIUM', 0)}      |",
            f"| Low              | {counts.get('LOW', 0)}         |",
            "",
            "---",
            "",
        ]

        # Reconnaissance Summary
        recon = report["recon_summary"]
        lines += [
            "## Reconnaissance Summary",
            "",
            f"- **Domain:** `{recon['domain']}`",
            f"- **HTTP Status:** {recon['status_code']}",
            f"- **SSL/HTTPS:** {'Enabled' if recon['ssl_enabled'] else 'Not Enabled (HTTP only)'}",
            f"- **Missing Security Headers:** {recon['missing_headers']}",
            f"- **Leaky Info Headers:** {recon['leaked_headers']}",
            f"- **Exposed Sensitive Paths:** {recon['exposed_paths']}",
            "",
            "---",
            "",
        ]

        # Vulnerability Findings Table
        lines += [
            "## Vulnerability Findings",
            "",
            "| # | Severity | Type | MITRE Hint | CWE |",
            "|---|----------|------|------------|-----|",
        ]
        for i, v in enumerate(vulns, 1):
            icon = SEVERITY_ICONS.get(v["severity"], "[UNK]")
            lines.append(
                f"| {i} | {icon} {v['severity']} | {v['type']} "
                f"| `{v.get('mitre_hint', '-')}` | {v.get('cwe_id', '-')} |"
            )

        lines += ["", "### Detailed Findings", ""]
        for i, v in enumerate(vulns, 1):
            icon = SEVERITY_ICONS.get(v["severity"], "[UNK]")
            lines += [
                f"#### {i}. {icon} {v['severity']} â€” {v['type']}",
                "",
                f"**Detail:** {v['detail']}",
                "",
                f"**Evidence:** `{v.get('evidence', 'N/A')}`",
                "",
                f"**MITRE ATT&CK:** `{v.get('mitre_hint', 'N/A')}` | "
                f"**CWE:** `{v.get('cwe_id', 'N/A')}`",
                "",
                f"**Recommendation:** {v.get('recommendation', 'N/A')}",
                "",
            ]

        lines += ["---", ""]

        # MITRE ATT&CK Attack Chain
        lines += [
            "## MITRE ATT&CK Attack Chain",
            "",
            f"*Based on discovered vulnerabilities, a realistic attack chain for `{report['target_url']}`:*",
            "",
        ]
        for step in chain:
            tactic_icon = TACTIC_ICONS.get(step["tactic"], "[STEP]")
            vuln_info   = step.get("source_vulnerability", {})
            lines += [
                f"### Step {step['step']}: {tactic_icon} [{step['technique_id']}] {step['technique_name']}",
                f"**Tactic:** `{step['tactic']}`",
                "",
                f"**Description:** {step.get('description', 'N/A')[:250]}",
                "",
                f"**Source Vulnerability:** {vuln_info.get('severity', '')} â€” {vuln_info.get('type', '')}",
                f"> {vuln_info.get('detail', '')}",
                "",
                f"**Mitigation:** {step.get('recommendation', 'N/A')}",
                "",
            ]

        lines += ["---", ""]

        # LLM Analysis
        if report.get("llm_analysis"):
            lines += [
                "## LLM Attack Narrative (Ollama / Red ELISAR)",
                "",
                report["llm_analysis"],
                "",
                "---",
                "",
            ]

        # Disclaimer
        lines += [
            "## Disclaimer",
            "",
            f"> {report['disclaimer']}",
            "",
        ]

        return "\n".join(lines)

    # â”€â”€â”€ Console Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _print_console_summary(self, report: dict):
        risk      = report["overall_risk"]
        risk_icon = SEVERITY_ICONS.get(risk, "[UNK]")
        counts    = report["severity_counts"]
        chain     = report["attack_chain"]
        vulns     = report["vulnerabilities"]

        print("\n" + "=" * 65)
        print("  RED ELISAR â€” VULNERABILITY ASSESSMENT REPORT")
        print("=" * 65)
        print(f"  Target     : {report['target_url']}")
        print(f"  Scan Date  : {report['scan_date']}")
        print(f"  Server     : {report['tech_stack']['server']}")
        print(f"  Language   : {report['tech_stack']['language']}")
        print(f"  Risk Level : {risk_icon} {risk}")
        print(f"  Vulns Found: {report['total_vulns']}  "
              f"(CRIT={counts.get('CRITICAL',0)} HIGH={counts.get('HIGH',0)} "
              f"MED={counts.get('MEDIUM',0)} LOW={counts.get('LOW',0)})")
        print("-" * 65)

        print("\n  VULNERABILITIES:")
        for i, v in enumerate(vulns[:10], 1):
            icon = SEVERITY_ICONS.get(v["severity"], "[UNK]")
            print(f"  {i:2}. {icon} [{v['severity']:<8}] {v['type']}")
            print(f"       {v['detail'][:70]}...")

        print("\n  MITRE ATT&CK ATTACK CHAIN:")
        for step in chain:
            tac_icon = TACTIC_ICONS.get(step["tactic"], "[STEP]")
            print(
                f"  Step {step['step']}: {tac_icon} [{step['technique_id']}] "
                f"{step['technique_name']} ({step['tactic']})"
            )

        print("=" * 65)
```

## 14) Vulnerable Application (Demo Target)

Source: `vulnerable_app/app.py`

`python
"""
VULNERABLE TEST TARGET - For Red ELISAR demo only.
THIS APP IS INTENTIONALLY INSECURE - DO NOT DEPLOY PUBLICLY.

Run: python app.py
Access: http://127.0.0.1:5000
"""

from flask import Flask, request, render_template_string, redirect, jsonify, session
import sqlite3

app = Flask(__name__)

# VULNERABILITY 15: Weak, hardcoded secret key
app.secret_key = "secret123"

# Database setup
DB_PATH = "vuln_app.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    """)
    # Seed data
    c.execute("DELETE FROM users")
    c.execute("DELETE FROM products")
    c.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "admin",   "admin123",      "admin@vuln-shop.local"),
        (2, "alice",   "password",      "alice@vuln-shop.local"),
        (3, "bob",     "bob123",        "bob@vuln-shop.local"),
    ])
    c.executemany("INSERT INTO products VALUES (?,?,?,?)", [
        (1, "Laptop",  999.99,  "High performance laptop"),
        (2, "Phone",   499.99,  "Latest smartphone"),
        (3, "Tablet",  299.99,  "Compact tablet"),
    ])
    conn.commit()
    conn.close()

# Middleware: add insecure headers
@app.after_request
def add_insecure_headers(response):
    # VULNERABILITY 6: Expose technology stack in headers
    response.headers["X-Powered-By"] = "PHP/7.2.1"        # fake but realistic
    response.headers["Server"]       = "Apache/2.2.8 (Ubuntu)"  # old version
    response.headers["X-App-Version"] = "1.0.0-dev"

    # VULNERABILITY 14: CORS wildcard
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

    # NOT SET (intentionally missing):
    # Content-Security-Policy
    # Strict-Transport-Security
    # X-Frame-Options
    # X-Content-Type-Options
    # Referrer-Policy
    # Permissions-Policy

    return response

# HTML template â€” light professional ecommerce theme
BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnShop â€” Deliberately Vulnerable App</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<style>
/* â”€â”€ Reset & Base â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
  --bg:#F2EDF8;--surface:#FFFFFF;--card:#FFFFFF;--border:#DDD2E8;
  --red:#7A264F;--red2:#662041;--green:#10B981;--yellow:#8B5E74;
  --blue:#B65B84;--purple:#334155;--cyan:#0EA5E9;
  --text:#2E2A43;--muted:#655D79;--font:Inter,system-ui,sans-serif;
}}
body{{background:linear-gradient(180deg,#F7F4FB 0%,var(--bg) 100%);color:var(--text);font-family:var(--font);min-height:100vh;font-size:15px;line-height:1.6}}

/* â”€â”€ Hero â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.hero{{
  background:linear-gradient(120deg,#FFFFFF 0%,#F2EAF8 100%);
  border:1px solid var(--border);border-radius:16px;
  padding:3rem 2.5rem;margin-bottom:2rem;position:relative;overflow:hidden;
  box-shadow:0 8px 20px rgba(15,23,42,.06);
}}
.hero::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 70% 50%,rgba(122,38,79,.08),transparent 60%);
  pointer-events:none;
}}
.hero-tag{{
  display:inline-block;background:#F6ECF2;
  border:1px solid #D8B5C9;color:var(--red);
  padding:4px 14px;border-radius:20px;font-size:.72rem;
  font-weight:700;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:1.2rem;
}}
.hero h1{{font-size:2.2rem;font-weight:800;line-height:1.2;margin-bottom:.75rem}}
.hero h1 span{{color:var(--red)}}
.hero p{{color:var(--muted);font-size:1rem;max-width:560px;line-height:1.7}}
.hero-actions{{display:flex;gap:1rem;margin-top:1.75rem;flex-wrap:wrap}}
.hero-btn{{
  padding:.65rem 1.6rem;border-radius:8px;font-weight:600;font-size:.875rem;
  text-decoration:none;transition:all .2s;letter-spacing:.3px;
}}
.hero-btn-primary{{
  background:var(--blue);color:#fff;
  border:none;
}}
.hero-btn-primary:hover{{transform:translateY(-1px);box-shadow:0 4px 18px rgba(122,38,79,.28)}}
.hero-btn-secondary{{
  background:#fff;color:var(--text);border:1px solid var(--border);
}}
.hero-btn-secondary:hover{{border-color:#CBD5E1;background:#F8FAFC}}

/* â”€â”€ Feature grid â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.feature-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}}
.feature-card{{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:1.25rem;transition:border-color .2s,transform .2s;
  box-shadow:0 1px 2px rgba(15,23,42,.05);
}}
.feature-card:hover{{border-color:#D8B5C9;transform:translateY(-2px)}}
.feature-card .fc-label{{
  font-size:.68rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  color:var(--blue);margin-bottom:.5rem;
}}
.feature-card h3{{font-size:.95rem;font-weight:600;margin-bottom:.4rem}}
.feature-card p{{font-size:.78rem;color:var(--muted);line-height:1.5}}

/* â”€â”€ Header / Nav â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
header{{
  background:var(--red2);
  border-bottom:1px solid #5B1D3B;
  padding:0 2rem;
  display:flex;align-items:center;justify-content:space-between;
  height:60px;
  position:sticky;top:0;z-index:100;
}}
.logo{{display:flex;align-items:center;gap:10px;text-decoration:none}}
.logo-icon{{
  width:34px;height:34px;
  background:var(--blue);
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-size:.7rem;font-weight:800;color:#fff;letter-spacing:.5px;box-shadow:0 4px 12px rgba(122,38,79,.28);
}}
.logo-text{{font-size:1.1rem;font-weight:700;color:#FDF7FB}}
.logo-text span{{color:#F4CFE1}}
.logo-sub{{font-size:.65rem;color:#E8D0DE;letter-spacing:1.5px;text-transform:uppercase}}
nav{{display:flex;gap:4px;align-items:center}}
nav a{{
  color:#F5E8EF;text-decoration:none;padding:6px 14px;border-radius:6px;
  font-size:.85rem;font-weight:500;transition:all .18s;
}}
nav a:hover{{background:rgba(255,255,255,.14);color:#FFFFFF}}
nav a.danger{{color:#FFFFFF;border:1px solid #C68DAA}}
nav a.danger:hover{{background:rgba(255,255,255,.18);border-color:#E2B8CC}}

/* â”€â”€ Layout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
main{{max-width:1100px;margin:2rem auto;padding:0 1.5rem}}

/* â”€â”€ Vuln Badge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.vuln-badge{{
  display:inline-flex;align-items:center;gap:6px;
  background:#F6ECF2;border:1px solid #D8B5C9;
  color:var(--red);padding:4px 12px;border-radius:20px;
  font-size:.72rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  margin-bottom:1rem;
}}

/* â”€â”€ Cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.card{{
  background:var(--card);border:1px solid var(--border);
  border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;
  box-shadow:0 1px 2px rgba(15,23,42,.05);
}}
.card h2{{font-size:1.25rem;font-weight:700;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}}
.card h3{{font-size:1rem;font-weight:600;margin:1rem 0 .5rem;color:var(--muted)}}
.card p{{color:var(--muted);margin-bottom:.5rem}}
.card ul{{padding-left:1.2rem;color:var(--muted)}}
.card ul li{{margin-bottom:.35rem}}
.card ul li a{{color:var(--blue);text-decoration:none;font-weight:500}}
.card ul li a:hover{{text-decoration:underline}}

/* â”€â”€ Forms â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
form{{display:flex;flex-direction:column;gap:.75rem;max-width:480px}}
label{{font-size:.8rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}}
input[type=text],input[type=password],input[type=search]{{
  background:#FFFFFF;border:1px solid var(--border);color:var(--text);
  border-radius:8px;padding:.6rem .9rem;font-family:var(--font);font-size:.9rem;
  transition:border-color .2s;outline:none;width:100%;
}}
input:focus{{border-color:#C98BA8;box-shadow:0 0 0 3px rgba(122,38,79,.14)}}
button[type=submit],.btn{{
  background:var(--blue);
  color:#fff;border:none;border-radius:8px;
  padding:.6rem 1.4rem;font-weight:600;font-size:.875rem;
  cursor:pointer;transition:all .2s;letter-spacing:.3px;
  display:inline-flex;align-items:center;gap:6px;width:fit-content;
}}
button[type=submit]:hover,.btn:hover{{
  transform:translateY(-1px);box-shadow:0 4px 18px rgba(122,38,79,.28);
}}
.hint-box{{
  background:#FFFBEB;border:1px solid #FDE68A;
  border-radius:8px;padding:.75rem 1rem;font-size:.82rem;color:var(--yellow);
  margin-top:.5rem;
}}
.hint-box code{{
  background:#FEF3C7;padding:1px 6px;border-radius:4px;
  font-family:'Courier New',monospace;font-size:.85em;
}}

/* â”€â”€ Tables â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
table{{width:100%;border-collapse:collapse;font-size:.875rem;margin-top:.75rem}}
th{{
  background:var(--red);padding:.65rem 1rem;text-align:left;
  font-size:.75rem;text-transform:uppercase;letter-spacing:.5px;color:#FFFFFF;
  border-bottom:1px solid var(--border);font-weight:600;
}}
td{{
  padding:.6rem 1rem;border-bottom:1px solid #E7DCEF;
  color:var(--text);vertical-align:top;
}}
tr:last-child td{{border:none}}
tr:hover td{{background:#F8F2FA}}

/* â”€â”€ Code / Pre â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
pre{{
  background:#F8F2FA;border:1px solid var(--border);border-radius:10px;
  padding:1.25rem;font-family:'Courier New',monospace;font-size:.8rem;
  color:#1E293B;line-height:1.7;overflow-x:auto;
}}
code{{
  background:#F4EAF4;color:#5B1F3C;
  padding:2px 6px;border-radius:4px;font-family:'Courier New',monospace;font-size:.85em;
}}

/* â”€â”€ Messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.msg-ok{{
  background:#ECFDF5;border:1px solid #A7F3D0;
  color:var(--green);border-radius:8px;padding:.65rem 1rem;font-weight:500;font-size:.875rem;
}}
.msg-err{{
  background:#FEF2F2;border:1px solid #FECACA;
  color:#B91C1C;border-radius:8px;padding:.65rem 1rem;font-weight:500;font-size:.875rem;font-family:'Courier New',monospace;
}}

/* â”€â”€ Home grid â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.route-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem;margin-top:1rem}}
.route-item{{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:1rem 1.2rem;transition:border-color .2s;
}}
.route-item:hover{{border-color:var(--red)}}
.route-item a{{color:var(--blue);font-weight:600;text-decoration:none;font-size:.9rem}}
.route-item a:hover{{text-decoration:underline}}
.route-item p{{font-size:.78rem;color:var(--muted);margin-top:4px}}
.vuln-tag{{
  display:inline-block;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700;
  letter-spacing:.5px;text-transform:uppercase;margin-top:4px;
}}
.tag-sqli{{background:rgba(230,57,70,.15);color:var(--red2)}}
.tag-xss{{background:rgba(230,126,34,.15);color:#e67e22}}
.tag-auth{{background:rgba(155,89,182,.15);color:var(--purple)}}
.tag-info{{background:rgba(52,152,219,.15);color:var(--blue)}}
.tag-redirect{{background:rgba(26,188,156,.15);color:var(--cyan)}}

/* â”€â”€ Footer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
footer{{
  text-align:center;padding:2rem;color:var(--muted);font-size:.78rem;
  border-top:1px solid var(--border);margin-top:3rem;
}}
footer span{{color:var(--red)}}
</style>
</head>
<body>

<header>
  <a class="logo" href="/">
    <div class="logo-icon">VS</div>
    <div>
      <div class="logo-text">Vuln<span>Shop</span></div>
      <div class="logo-sub">Modern Demo Store</div>
    </div>
  </a>
  <nav>
    <a href="/products">Products</a>
    <a href="/search">Search</a>
    <a href="/greet">Greet</a>
    <a href="/account">Account</a>
    <a href="/cart">Cart</a>
    <a href="/admin" class="danger">Admin Panel</a>
  </nav>
</header>

<main>
  {content}
</main>

<footer>
  VulnShop &nbsp;|&nbsp; Built for <span>Red ELISAR</span> Security Testing
</footer>

</body>
</html>
"""

# Routes

@app.route("/")
def index():
    content = """
    <div class="hero">
      <div class="hero-tag">Featured Storefront</div>
      <h1>Simple and Modern <span>Shopping Experience</span></h1>
      <p>Discover curated products with a clean browsing flow, seamless search, and a lightweight checkout-ready interface for demo environments.</p>
      <div class="hero-actions">
        <a href="/products" class="hero-btn hero-btn-primary">Browse Products</a>
        <a href="/search" class="hero-btn hero-btn-secondary">Search</a>
        <a href="/account" class="hero-btn hero-btn-secondary">My Account</a>
      </div>
    </div>
    <div class="feature-grid">
      <div class="feature-card">
        <div class="fc-label">Catalogue</div>
        <h3>Products Grid</h3>
        <p>Browse category-ready product cards with clear pricing and purchase actions.</p>
      </div>
      <div class="feature-card">
        <div class="fc-label">Account</div>
        <h3>Account Center</h3>
        <p>Access profile information, order history, and saved payment preferences.</p>
      </div>
      <div class="feature-card">
        <div class="fc-label">Management</div>
        <h3>Admin Dashboard</h3>
        <p>Review system stats and a simple operations table in one place.</p>
      </div>
      <div class="feature-card">
        <div class="fc-label">Developer</div>
        <h3>Search Experience</h3>
        <p>Find products quickly using compact, responsive search controls.</p>
      </div>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/account")
def account():
    content = """
    <div class="card">
      <h2>Account Overview</h2>
      <p>Welcome back. Manage your profile, security settings, and purchase preferences.</p>
    </div>
    <div class="card">
      <table>
        <tr><th>Section</th><th>Status</th><th>Notes</th></tr>
        <tr><td>Profile</td><td>Complete</td><td>Basic details are up to date.</td></tr>
        <tr><td>Orders</td><td>3 recent</td><td>Latest order delivered successfully.</td></tr>
        <tr><td>Saved Cards</td><td>1 card</td><td>Primary payment method available.</td></tr>
      </table>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/cart")
def cart():
    content = """
    <div class="card">
      <h2>Cart</h2>
      <p>Review selected products before checkout.</p>
    </div>
    <div class="card">
      <table>
        <tr><th>Product</th><th>Qty</th><th>Price</th><th>Total</th></tr>
        <tr><td>Laptop</td><td>1</td><td>$999.99</td><td>$999.99</td></tr>
        <tr><td>Phone</td><td>1</td><td>$499.99</td><td>$499.99</td></tr>
      </table>
      <p style="margin-top:1rem"><b>Subtotal: $1499.98</b></p>
      <a class="btn" href="/login">Continue to Checkout</a>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/search")
def search():
    """VULNERABILITY 8: SQL Injection â€” user input goes directly into SQL query."""
    query   = request.args.get("q", "")
    results = []
    error   = None

    if query:
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            # VULNERABLE: Direct string interpolation â€” DO NOT DO THIS IN REAL CODE
            sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
            c.execute(sql)
            results = c.fetchall()
            conn.close()
        except Exception as e:
            # VULNERABILITY 13: Expose error details including SQL query
            error = f"Database error: {str(e)} | Query was: {sql}"

    content = f"""
    <div class="card">
      <h2>Product Search</h2>
      <form method="GET" style="flex-direction:row;align-items:center;gap:.5rem;max-width:600px">
        <input name="q" value="{query}" placeholder="Search products..." type="text" style="flex:1">
        <button type="submit">Search</button>
      </form>
      <div class="hint-box" style="margin-top:1rem">
        Try: <code>Laptop</code> &nbsp;|&nbsp;
        <code>' OR '1'='1</code> &nbsp;|&nbsp;
        <code>' UNION SELECT id,username,password,email FROM users--</code>
      </div>
      {"<div class='msg-err' style='margin-top:.75rem'>" + error + "</div>" if error else ""}
    </div>
    <div class="card">
      <h3>Results</h3>
      <table>
        <tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>
        {"".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in results) if results else "<tr><td colspan=4 style='color:var(--muted);text-align:center;padding:1.5rem'>No results found.</td></tr>"}
      </table>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))



@app.route("/greet")
def greet():
    """VULNERABILITY 9: Reflected XSS â€” user input echoed without sanitization."""
    # VULNERABLE: name parameter echoed directly into HTML without escaping
    name = request.args.get("name", "Guest")
    content = f"""
    <div class="card">
      <h2>Greeting</h2>
      <form method="GET" style="flex-direction:row;align-items:center;gap:.5rem;max-width:480px">
        <input name="name" value="{name}" placeholder="Your name" type="text" style="flex:1">
        <button type="submit">Greet Me</button>
      </form>
      <div class="hint-box" style="margin-top:1rem">
        Try payload: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
      </div>
    </div>
    <div class="card">
      <h3 style="color:var(--text)">Hello, {name}! Welcome to VulnShop.</h3>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/login", methods=["GET", "POST"])
def login():
    """VULNERABILITY 10: Hardcoded credentials (admin/admin123)."""
    message = ""
    msg_cls = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Also SQL injectable version
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            # VULNERABLE: hardcoded + SQL injectable
            sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            c.execute(sql)
            user = c.fetchone()
            conn.close()
            if user:
                session["user"] = username
                message = f"âœ… Logged in as: <b>{username}</b> (ID={user[0]})"
                msg_cls = "msg-ok"
            else:
                message = "âŒ Invalid credentials."
                msg_cls = "msg-err"
        except Exception as e:
            message = f"DB Error: {e}"
            msg_cls = "msg-err"

    content = f"""
    <div class="card">
      <h2>Sign In</h2>
      {f'<div class="{msg_cls}" style="margin-bottom:1rem">{message}</div>' if message else ""}
      <form method="POST">
        <label>Username</label>
        <input name="username" placeholder="Username" type="text">
        <label>Password</label>
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
      </form>
      <div class="hint-box" style="margin-top:1.25rem">
        Credentials: <code>admin</code> / <code>admin123</code> &nbsp;|&nbsp;
        SQLi bypass: <code>' OR '1'='1'--</code>
      </div>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/admin")
def admin():
    """VULNERABILITY: Admin panel accessible without authentication."""
    content = """
    <div class="card">
      <h2>Admin Panel</h2>
      <p style="color:var(--muted)">System administration and configuration.</p>
    </div>
    <div class="card">
      <h3>System Information</h3>
      <table>
        <tr><th>Key</th><th>Value</th></tr>
        <tr><td>App Secret Key</td><td><code>secret123</code></td></tr>
        <tr><td>Database</td><td><code>vuln_app.db (SQLite)</code></td></tr>
        <tr><td>Server</td><td><code>Apache/2.2.8 (Ubuntu)</code></td></tr>
        <tr><td>PHP Version</td><td><code>7.2.1</code></td></tr>
        <tr><td>Debug Mode</td><td style="color:var(--red2)"><b>ON</b></td></tr>
        <tr><td>CORS</td><td style="color:var(--red2)">Wildcard (*)</td></tr>
      </table>
    </div>
    <div class="card">
      <h3>User Management</h3>
      <p><a href="/api/users" style="color:var(--blue)">View all users</a></p>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/redirect")
def open_redirect():
    """VULNERABILITY 11: Open Redirect â€” no validation on destination URL."""
    url = request.args.get("url", "/")
    # VULNERABLE: No validation â€” can redirect to any external site
    return redirect(url)


@app.route("/backup")
def backup():
    """VULNERABILITY 12: Exposed backup/sensitive file."""
    content = """
    <div class="card">
      <h2>Backup File</h2>
      <p style="color:var(--muted)">Database backup configuration and credentials.</p>
    </div>
    <div class="card">
      <pre>
# VulnShop Database Backup â€” 2024-01-15
# DO NOT SHARE

DB_HOST=localhost
DB_NAME=vulnshop_prod
DB_USER=root
DB_PASS=rootpassword123

ADMIN_USER=admin
ADMIN_PASS=admin123

STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXXXXXXXXXX
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

-- User table dump:
INSERT INTO users VALUES (1,'admin','admin123','admin@vuln-shop.local');
INSERT INTO users VALUES (2,'alice','password','alice@vuln-shop.local');
INSERT INTO users VALUES (3,'bob','bob123','bob@vuln-shop.local');
      </pre>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/.env")
def env_file():
    """VULNERABILITY 12: Exposed .env / environment configuration."""
    return """SECRET_KEY=secret123
DATABASE_URL=sqlite:///vuln_app.db
ADMIN_PASSWORD=admin123
DEBUG=True
FLASK_ENV=development
API_KEY=sk-dev-1234567890abcdef
JWT_SECRET=jwt_super_secret_key_123
""", 200, {"Content-Type": "text/plain"}


@app.route("/api/users")
def api_users():
    """VULNERABILITY: Unauthenticated API exposing all user data."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    conn.close()
    return jsonify({
        "status": "ok",
        "count":  len(rows),
        "users":  [{"id": r[0], "username": r[1], "password": r[2], "email": r[3]} for r in rows]
    })


@app.route("/api/products")
def api_products():
    """VULNERABILITY: Unauthenticated API endpoint returning internal product data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM products")
    rows = c.fetchall()
    conn.close()
    return jsonify({
        "status": "ok",
        "count": len(rows),
        "products": [
            {"id": r[0], "name": r[1], "price": r[2], "description": r[3]}
            for r in rows
        ]
    })


@app.route("/products")
def products():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM products")
    rows = c.fetchall()
    conn.close()
    content = """
    <div class="card">
      <h2>All Products</h2>
      <p style="color:var(--muted)">Browse our full product catalogue.</p>
    </div>
    <div class="feature-grid">
        """ + "".join(
            f"""
            <div class='feature-card'>
              <div style='height:120px;border-radius:10px;background:#F1F5F9;border:1px solid var(--border);margin-bottom:.8rem;display:flex;align-items:center;justify-content:center;color:var(--muted)'>Product Image</div>
              <h3>{r[1]}</h3>
              <p style='color:var(--muted)'>{r[3]}</p>
              <p style='margin-top:.5rem;font-weight:700;color:var(--green)'>${r[2]}</p>
              <button class='btn' style='margin-top:.6rem'>Add to Cart</button>
            </div>
            """
            for r in rows
        ) + """
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/error_test")
def error_test():
    """VULNERABILITY: Deliberate unhandled error endpoint for stack-trace/debug exposure."""
    _ = 1 / 0
    return "OK"


@app.route("/config")
def config_dump():
    """VULNERABILITY: Public config disclosure."""
    return """{
  "app_name": "VulnShop",
  "environment": "development",
  "debug": true,
  "database": "sqlite:///vuln_app.db",
  "jwt_secret": "jwt_super_secret_key_123",
  "admin_user": "admin",
  "admin_pass": "admin123"
}""", 200, {"Content-Type": "application/json"}


@app.route("/.git")
def git_metadata():
    """VULNERABILITY: Simulated exposed .git metadata."""
    return """ref: refs/heads/main
commit=9fbc9f1d3aaf1aab9e1f0f3a66f3dc11b9f2a123
author=dev@vuln-shop.local
""", 200, {"Content-Type": "text/plain"}


@app.route("/db")
def db_info():
    """VULNERABILITY: Database diagnostics exposed publicly."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    users_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM products")
    products_count = c.fetchone()[0]
    conn.close()
    return jsonify({
        "db_path": DB_PATH,
        "users_count": users_count,
        "products_count": products_count,
        "note": "diagnostics endpoint left open"
    })


@app.route("/robots.txt")
def robots():
    """Expose sensitive paths in robots.txt."""
    return """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /.env
Disallow: /api/users
Disallow: /config
Disallow: /db
""", 200, {"Content-Type": "text/plain"}


@app.route("/sitemap.xml")
def sitemap():
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:5000/</loc></url>
  <url><loc>http://127.0.0.1:5000/search</loc></url>
  <url><loc>http://127.0.0.1:5000/admin</loc></url>
  <url><loc>http://127.0.0.1:5000/api/users</loc></url>
</urlset>""", 200, {"Content-Type": "application/xml"}


# Main
if __name__ == "__main__":
    init_db()
    print("\n" + "="*60)
    print("  VulnShop â€” Deliberately Vulnerable Web App")
    print("  For Red ELISAR Security Testing ONLY")
    print("  Running at: http://127.0.0.1:5000")
    print("="*60 + "\n")
    # VULNERABILITY 7: Debug mode ON â€” allows remote code execution via debugger
    app.run(debug=True, host="127.0.0.1", port=5000)
```

## 15) Red Agent Web App (Flask UI)

Source: `app.py`

`python
"""
Red ELISAR â€” Flask Web Application
Wraps all 4 run.py menu options in a local browser UI with live streaming output.
Run: python app.py
Then open: http://127.0.0.1:7860
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# â”€â”€ Bootstrap paths (same as run.py) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
PROJECT_DIR = Path(__file__).resolve().parent
AGENT_DIR   = PROJECT_DIR / "red_agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))
os.chdir(AGENT_DIR)

from flask import Flask, Response, abort, jsonify, make_response, render_template, request, send_file, stream_with_context

import config
from llm.attack_chain_generator import AttackChainGenerator
from mappings.mitre_mapper import MITREMapper
from rag.chunking import chunk_techniques
from rag.mitre_parser import MITREParser
from rag.rag_engine import RAGEngine
from rag.vector_store_faiss import FAISSVectorStore
from reporting.report_generator import ReportGenerator
from reporting.pdf_reporter import render_markdown_to_pdf
from vuln_checks.input_sanitizer import sanitize_scenario
from vuln_checks.live_vuln_checker import LiveVulnChecker
from vuln_checks.targeted_attack_scanner import detect_attack_type, probe_target
from vuln_checks.vuln_scanner import VulnerabilityScanner
from vuln_checks.web_recon import WebReconAgent

# Re-import helpers from run.py (since they're defined there)
import run as run_module

app = Flask(__name__)
app.secret_key = "red-elisar-local-only"


@app.route("/api/report/download")
def api_report_download():
    path = (request.args.get("path") or "").strip()
    if not path:
        abort(404)
    report_path = Path(path).expanduser().resolve()
    output_dir = config.OUTPUT_DIR.resolve()
    if output_dir not in report_path.parents and report_path != output_dir:
        abort(403)
    if (not report_path.exists() or not report_path.is_file()) and report_path.suffix.lower() == ".pdf":
        # Auto-heal missing PDF by rendering from sibling markdown when available.
        md_candidate = report_path.with_suffix(".md")
        if md_candidate.exists() and md_candidate.is_file():
            try:
                render_markdown_to_pdf(md_candidate, report_path)
            except Exception as exc:
                return jsonify({"error": f"PDF render failed: {exc}"}), 500
    if not report_path.exists() or not report_path.is_file():
        abort(404)
    return send_file(report_path, as_attachment=True, download_name=report_path.name)

# â”€â”€ Global runtime context (lazy-loaded) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_ctx_lock = threading.Lock()
_runtime_ctx: run_module.RuntimeContext | None = None

_latest_lock = threading.Lock()
_latest_results: dict[str, dict] = {}
_latest_meta: dict[str, str] = {}
_cancel_lock = threading.Lock()
_cancel_events: dict[str, threading.Event] = {}


class RequestCancelledError(Exception):
    pass


def _register_request(request_id: str | None) -> threading.Event | None:
    if not request_id:
        return None
    with _cancel_lock:
        ev = _cancel_events.get(request_id)
        if ev is None:
            ev = threading.Event()
            _cancel_events[request_id] = ev
        return ev


def _cleanup_request(request_id: str | None) -> None:
    if not request_id:
        return
    with _cancel_lock:
        _cancel_events.pop(request_id, None)


def _check_cancel(cancel_event: threading.Event | None):
    if cancel_event is not None and cancel_event.is_set():
        raise RequestCancelledError("Request cancelled by user")


def get_ctx() -> run_module.RuntimeContext:
    global _runtime_ctx
    with _ctx_lock:
        if _runtime_ctx is None:
            _runtime_ctx = run_module.RuntimeContext()
        return _runtime_ctx


def _store_latest(mode: str, payload: dict) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    with _latest_lock:
        _latest_results[mode] = payload
        _latest_results["last"] = payload
        _latest_meta["mode"] = mode
        _latest_meta["timestamp"] = timestamp


def _get_latest(mode: str | None = None) -> tuple[dict | None, dict]:
    with _latest_lock:
        if mode and mode in _latest_results:
            return _latest_results.get(mode), dict(_latest_meta)
        return _latest_results.get("last"), dict(_latest_meta)


# â”€â”€ SSE streaming helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class StreamQueue:
    """Thread-safe queue used to stream log lines back to the browser via SSE."""

    def __init__(self):
        self.q: queue.Queue[str | None] = queue.Queue()

    def put(self, line: str):
        self.q.put(line)

    def done(self):
        self.q.put(None)  # sentinel

    def get(self, timeout: float | None = None):
        return self.q.get(timeout=timeout)

    def __iter__(self):
        while True:
            item = self.q.get()
            if item is None:
                break
            yield item


class QueueHandler(logging.Handler):
    """Redirect log records into the SSE stream queue."""

    def __init__(self, sq: StreamQueue):
        super().__init__()
        self.sq = sq

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.sq.put(msg)
        except Exception:
            pass


def _stream_gen(sq: StreamQueue, heartbeat_s: float | None = None):
    """Generator that yields SSE-formatted events from the queue with keepalive."""
    heartbeat = heartbeat_s or float(getattr(config, "WEB_UI_STREAM_HEARTBEAT_S", 12.0))
    while True:
        try:
            line = sq.get(timeout=heartbeat)
        except queue.Empty:
            yield ": keepalive\n\n"
            continue
        if line is None:
            break
        safe = str(line).replace("\n", "\\n")
        yield f"data: {safe}\n\n"
    yield "data: __DONE__\n\n"


def _prewarm_runtime():
    """Warm up RAG + MITRE context in the background for faster first responses."""
    try:
        ctx = get_ctx()
        ctx.ensure_rag(force_reindex=False)
    except Exception as exc:
        app.logger.warning("Runtime prewarm failed: %s", exc)


def _enrich_chain(chain_steps: list, rag) -> list:
    """Replace 'Unknown' technique names using available technique lookup sources."""
    enriched = []
    for step in chain_steps:
        s = dict(step)
        tid = str(s.get("technique_id") or "").strip().upper()
        name = str(s.get("technique_name") or s.get("name") or "").strip()
        if (not name or name.lower() == "unknown") and tid and rag:
            try:
                record = None
                if hasattr(rag, "vector_store") and hasattr(rag.vector_store, "query_by_technique_id"):
                    record = rag.vector_store.query_by_technique_id(tid)
                elif hasattr(rag, "get_technique"):
                    record = rag.get_technique(tid)
                if record:
                    s["technique_name"] = record.get("name") or record.get("technique_name") or tid
                    if not s.get("tactic") and record.get("tactic"):
                        s["tactic"] = record["tactic"]
                else:
                    s["technique_name"] = tid  # fallback: show ID itself
            except Exception:
                s["technique_name"] = tid
        enriched.append(s)
    return enriched


def _coerce_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _build_step_attribution(chain_steps: list, retrieval_results: list | None = None) -> list:
    """Build explainable retrieval attribution for each generated chain step."""
    retrieval_results = retrieval_results or []
    by_tid = {}
    for rank, r in enumerate(retrieval_results, start=1):
        tid = str(r.get("technique_id") or "").strip().upper()
        if not tid or tid in by_tid:
            continue
        by_tid[tid] = (rank, r)

    attributions = []
    for i, step in enumerate(chain_steps, start=1):
        tid = str(step.get("technique_id") or "").strip().upper()
        tname = str(step.get("technique_name") or step.get("name") or tid or f"Step {i}")
        rationale = str(step.get("rationale") or "").strip()
        rank, source = by_tid.get(tid, (None, None))

        similarity = 0.0
        evidence = []
        flags = []

        if source:
            similarity = _coerce_float(source.get("relevance_score"), 0.0)
            snippet = str(source.get("description") or "").strip()
            evidence.append(
                {
                    "source_type": "faiss_hit",
                    "source_id": str(source.get("technique_id") or tid),
                    "rank": rank,
                    "similarity_score": round(similarity, 4),
                    "snippet": snippet[:280],
                    "matched_terms": [],
                }
            )
            if similarity < 0.35:
                flags.append("low_similarity")
        else:
            evidence.append(
                {
                    "source_type": "fallback",
                    "source_id": tid or f"step-{i}",
                    "rank": None,
                    "similarity_score": 0.0,
                    "snippet": "No direct retrieval evidence found; used generated step context.",
                    "matched_terms": [],
                }
            )
            flags.append("fallback_used")

        confidence = max(0.15, min(0.98, 0.4 + (similarity * 0.6)))
        if not rationale:
            flags.append("sparse_evidence")

        attributions.append(
            {
                "step_id": i,
                "technique_id": tid,
                "technique_name": tname,
                "confidence_score": round(confidence, 4),
                "evidence": evidence,
                "rationale_summary": (rationale[:240] if rationale else "Generated from scenario context and mapped ATT&CK behavior."),
                "attribution_flags": sorted(set(flags)),
            }
        )

    return attributions


def _build_causal_attack_graph(chain_steps: list, vulnerabilities: list | None = None) -> dict:
    """Convert linear chain into a lightweight causal graph with branch edges."""
    vulnerabilities = vulnerabilities or []
    nodes = []
    edges = []
    entry_nodes = []
    objective_nodes = []

    for i, step in enumerate(chain_steps, start=1):
        sid = f"tech-{i}"
        tactic = str(step.get("tactic") or step.get("phase") or "unknown")
        prob = max(0.15, 0.72 - (0.03 * (i - 1)))
        cost = 2 + i
        nodes.append(
            {
                "id": sid,
                "type": "technique",
                "label": str(step.get("technique_name") or step.get("name") or step.get("technique_id") or f"Step {i}"),
                "technique_id": str(step.get("technique_id") or ""),
                "tactic": tactic,
                "base_probability": round(prob, 3),
                "base_cost": cost,
                "detectability": round(min(0.9, 0.25 + (0.05 * i)), 3),
            }
        )

        if i == 1:
            entry_nodes.append(sid)
        if i == len(chain_steps):
            objective_nodes.append(sid)
        if i > 1:
            edges.append(
                {
                    "source": f"tech-{i-1}",
                    "target": sid,
                    "relation": "enables",
                    "weight": 1.0,
                    "explanation": "Prior technique establishes conditions for next stage.",
                }
            )

        if i > 2 and (i % 2 == 0):
            edges.append(
                {
                    "source": f"tech-{i-2}",
                    "target": sid,
                    "relation": "alternative_path",
                    "weight": 0.55,
                    "explanation": "Alternative attacker path inferred from tactic-level continuity.",
                }
            )

    for vi, vuln in enumerate(vulnerabilities[:6], start=1):
        vid = f"vuln-{vi}"
        vlabel = str(vuln.get("type") or "Vulnerability")
        sev = str(vuln.get("severity") or "MEDIUM").upper()
        sev_weight = {"CRITICAL": 0.85, "HIGH": 0.75, "MEDIUM": 0.6, "LOW": 0.45}.get(sev, 0.5)
        nodes.append(
            {
                "id": vid,
                "type": "condition",
                "label": vlabel,
                "tactic": "initial-access",
                "base_probability": sev_weight,
                "base_cost": 1,
                "detectability": 0.35,
            }
        )
        if entry_nodes:
            edges.append(
                {
                    "source": vid,
                    "target": entry_nodes[0],
                    "relation": "requires",
                    "weight": round(sev_weight, 2),
                    "explanation": "Discovered weakness can enable initial attacker foothold.",
                }
            )

    return {
        "nodes": nodes,
        "edges": edges,
        "entry_nodes": entry_nodes,
        "objective_nodes": objective_nodes,
    }


def _simulate_defense_what_if(graph: dict, controls: list[dict] | None = None) -> dict:
    """Run a lightweight what-if simulation over attack graph nodes."""
    controls = controls or [
        {
            "control_id": "waf_strict_mode",
            "name": "Strict WAF Rules",
            "target_tactics": ["initial-access", "execution"],
            "effect": "weaken",
            "probability_multiplier": 0.65,
            "cost_multiplier": 1.2,
            "enabled": True,
        },
        {
            "control_id": "mfa_everywhere",
            "name": "MFA Everywhere",
            "target_tactics": ["credential-access", "lateral-movement"],
            "effect": "block",
            "probability_multiplier": 0.4,
            "cost_multiplier": 1.35,
            "enabled": True,
        },
        {
            "control_id": "edr_behavioral",
            "name": "EDR Behavioral Detection",
            "target_tactics": ["execution", "persistence", "impact"],
            "effect": "detect",
            "probability_multiplier": 0.75,
            "cost_multiplier": 1.5,
            "enabled": True,
        },
    ]

    technique_nodes = [n for n in graph.get("nodes", []) if n.get("type") == "technique"]
    if not technique_nodes:
        return {
            "active_controls": controls,
            "path_results": [],
            "global_metrics": {
                "best_attack_path_probability": 0.0,
                "mean_time_to_objective": 0.0,
                "residual_risk_score": 0.0,
                "control_effectiveness_delta": 0.0,
            },
        }

    baseline_prob = 1.0
    baseline_cost = 0.0
    adjusted_prob = 1.0
    adjusted_cost = 0.0

    per_step = []
    for n in technique_nodes:
        p = _coerce_float(n.get("base_probability"), 0.5)
        c = _coerce_float(n.get("base_cost"), 1.0)
        baseline_prob *= p
        baseline_cost += c

        p_adj = p
        c_adj = c
        tactic = str(n.get("tactic") or "")
        blockers = []
        for ctrl in controls:
            if not ctrl.get("enabled"):
                continue
            if tactic not in (ctrl.get("target_tactics") or []):
                continue
            p_adj *= _coerce_float(ctrl.get("probability_multiplier"), 1.0)
            c_adj *= _coerce_float(ctrl.get("cost_multiplier"), 1.0)
            blockers.append(ctrl.get("name", "Control"))

        adjusted_prob *= max(0.01, p_adj)
        adjusted_cost += c_adj
        per_step.append(
            {
                "node_id": n.get("id"),
                "technique_id": n.get("technique_id", ""),
                "tactic": tactic,
                "base_probability": round(p, 4),
                "adjusted_probability": round(max(0.01, p_adj), 4),
                "base_cost": round(c, 2),
                "adjusted_cost": round(c_adj, 2),
                "affected_by": blockers,
            }
        )

    delta = 0.0
    if baseline_prob > 0:
        delta = max(0.0, min(1.0, 1.0 - (adjusted_prob / baseline_prob)))

    return {
        "active_controls": controls,
        "path_results": [
            {
                "path_id": "primary_path",
                "success_probability": round(adjusted_prob, 6),
                "expected_cost": round(adjusted_cost, 2),
                "expected_time": round(adjusted_cost * 0.85, 2),
                "blocked_by_controls": sorted({b for s in per_step for b in s.get("affected_by", [])}),
            }
        ],
        "per_step_effects": per_step,
        "global_metrics": {
            "baseline_path_probability": round(baseline_prob, 6),
            "best_attack_path_probability": round(adjusted_prob, 6),
            "mean_time_to_objective": round(adjusted_cost * 0.85, 2),
            "residual_risk_score": round(min(1.0, adjusted_prob * 2.0), 4),
            "control_effectiveness_delta": round(delta, 4),
        },
    }


def _attach_novelty(result_payload: dict, chain_steps: list, vulnerabilities: list | None = None, retrieval_results: list | None = None):
    """Attach explainability and what-if simulation artifacts to API result payload."""
    attributions = _build_step_attribution(chain_steps=chain_steps, retrieval_results=retrieval_results)
    graph = _build_causal_attack_graph(chain_steps=chain_steps, vulnerabilities=vulnerabilities)
    simulation = _simulate_defense_what_if(graph)
    result_payload["attack_chain_attribution"] = attributions
    result_payload["attack_graph"] = graph
    result_payload["what_if_simulation"] = simulation


def _build_readable_scenario_text(scenario: str, target_env: str | None, chain_steps: list) -> dict:
    """Create readable, user-focused narrative paragraphs from LLM-generated chain steps."""
    steps = chain_steps or []
    top_steps = steps[:8]
    names = [str(s.get("technique_name") or s.get("name") or s.get("technique_id") or "attack step").strip() for s in top_steps]
    tactics = [str(s.get("tactic") or s.get("phase") or "unknown").strip().replace("-", " ") for s in top_steps]
    env = (target_env or "enterprise environment").strip()

    if names:
        attack_flow = ", then ".join(names[:5])
        if len(names) > 5:
            attack_flow += ", followed by additional chained stages"
    else:
        attack_flow = "multi-stage behavior mapped from your scenario"

    intent_para = (
        f"This scenario models a realistic multi-step security pathway in the {env}, "
        f"aligned to your stated objective and likely progression points."
    )
    flow_para = (
        f"The generated chain indicates a practical progression: {attack_flow}. "
        f"This sequence is modeled from your scenario context and ATT&CK-grounded LLM reasoning."
    )
    workflow_para = (
        "Use this chain as a structured execution and validation workflow: confirm prerequisites, verify each transition, "
        "capture evidence at each stage, and record outcome quality before moving to the next step."
    )
    actions = []
    detailed_flow = []
    proceed_guidance = []
    for idx, step in enumerate(top_steps[:8], start=1):
        name = str(step.get("technique_name") or step.get("name") or step.get("technique_id") or f"Step {idx}")
        tactic = str(step.get("tactic") or step.get("phase") or "unknown").replace("-", " ")
        desc = str(step.get("description") or "No detailed description provided by the chain.").strip()
        rationale = str(step.get("rationale") or "Mapped from scenario context and ATT&CK behavior.").strip()
        mitigation = str(step.get("mitigation") or "Apply layered controls, detection, and hardening for this step.").strip()
        actions.append(f"Step {idx}: Focus on {name} under {tactic} with clear success criteria.")
        detailed_flow.append(
            f"Step {idx} ({tactic}) - {name}. "
            f"Process detail: {desc} "
            f"Chain role: {rationale}"
        )
        proceed_guidance.append(
            f"Step {idx} execution guidance: Prepare required conditions for {name}, run controlled validation for this stage, "
            f"collect concrete evidence artifacts, and confirm that outputs satisfy step-specific success criteria. "
            f"Quality note: {mitigation}"
        )

    return {
        "summary": " ".join([intent_para, flow_para]),
        "paragraphs": [intent_para, flow_para, workflow_para],
        "operator_actions": actions,
        "detailed_attack_flow": detailed_flow,
        "how_to_proceed": proceed_guidance,
        "tactic_sequence": tactics,
    }


# â”€â”€ Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/")
def index():
    resp = make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/api/status")
def api_status():
    """Quick health ping."""
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/api/latest")
def api_latest():
    mode = (request.args.get("mode") or "").strip().lower()
    payload, meta = _get_latest(mode or None)
    if not payload:
        return jsonify({"error": "No cached result available"}), 404
    return jsonify({"result": payload, "meta": meta})


@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    data = request.get_json(force=True) or {}
    request_id = str(data.get("request_id") or "").strip()
    if not request_id:
        return jsonify({"error": "request_id is required"}), 400
    with _cancel_lock:
        ev = _cancel_events.get(request_id)
        if ev is None:
            return jsonify({"status": "not_found", "request_id": request_id}), 404
        ev.set()
    return jsonify({"status": "cancelled", "request_id": request_id})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Option 1 â€” Full Web Vulnerability Scan."""
    data = request.get_json(force=True) or {}
    target_url_raw = (data.get("target_url") or "").strip()
    request_id = str(data.get("request_id") or "").strip()

    if not target_url_raw:
        return jsonify({"error": "target_url is required"}), 400

    try:
        target_url = run_module.normalize_url(target_url_raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        # Attach queue handler to root logger
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Starting full web scan on: {target_url}")

            # Step 1 â€“ Attack surface discovery
            sq.put("[STEP 1/5] Discovering attack surface (crawl + common paths)â€¦")
            discovery = run_module.discover_attack_surface(
                target_url,
                max_pages=int(getattr(config, "WEB_UI_DISCOVERY_MAX_PAGES", 18)),
                timeout=float(getattr(config, "WEB_UI_DISCOVERY_TIMEOUT_S", 6.0)),
            )
            routes = discovery.get("routes", [])
            _check_cancel(cancel_event)
            sq.put(f"[OK] Found {len(routes)} routes, {len(discovery.get('forms', []))} forms.")

            # Step 2 â€“ Web Recon
            sq.put("[STEP 2/5] Running web reconâ€¦")
            recon_data = WebReconAgent(
                target_url,
                timeout_s=float(getattr(config, "WEB_UI_RECON_TIMEOUT_S", 6.0)),
            ).run()
            _check_cancel(cancel_event)
            if not recon_data.get("reachable"):
                sq.put(f"[ERROR] Target {target_url} is not reachable. Aborting.")
                return

            # Step 3 â€“ Passive + live vulnerability scan
            sq.put("[STEP 3/5] Scanning for vulnerabilities (passive + live)â€¦")
            passive_result = VulnerabilityScanner(recon_data).scan()
            passive_vulns = passive_result.get("vulnerabilities", [])
            _check_cancel(cancel_event)
            sq.put(f"[OK] Passive scanner found {len(passive_vulns)} issue(s).")

            live_vulns: list = []
            try:
                live_report = LiveVulnChecker(
                    target_url,
                    timeout=int(getattr(config, "WEB_UI_LIVE_TIMEOUT_S", 6.0)),
                ).run_full_check()
                _check_cancel(cancel_event)
                live_vulns = [f for f in live_report.get("vulnerabilities", []) if f.get("confirmed_live")]
                sq.put(f"[OK] Live checker confirmed {len(live_vulns)} issue(s).")
            except Exception as exc:
                sq.put(f"[WARN] Live check failed: {exc}")

            form_vulns = run_module._probe_discovered_forms(
                target_url,
                discovery.get("forms", []),
                timeout=float(getattr(config, "WEB_UI_FORM_TIMEOUT_S", 5.0)),
            )
            _check_cancel(cancel_event)
            sq.put(f"[OK] Form probe found {len(form_vulns)} issue(s).")

            merged_vulns = run_module._merge_vulnerabilities(passive_vulns, live_vulns, form_vulns)
            counts = run_module._severity_counts(merged_vulns)
            risk = run_module._overall_risk(counts)
            sq.put(f"[OK] Merged total: {len(merged_vulns)} vulnerabilities. Overall risk: {risk}")

            # Step 4 â€“ MITRE mapping + RAG
            sq.put("[STEP 4/5] Loading FAISS index and mapping to MITRE ATT&CKâ€¦")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)
            mapped = ctx.mapper.map_vulnerabilities(merged_vulns)
            chain = ctx.mapper.build_attack_chain(mapped, target_url=target_url)
            sq.put(f"[OK] MITRE mapping complete. Attack chain has {len(chain)} steps.")

            # Step 5 â€“ Report generation
            sq.put("[STEP 5/5] Generating reportsâ€¦")
            scan_result = {
                "target_url": target_url,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "total_vulns": len(merged_vulns),
                "severity_counts": counts,
                "overall_risk": risk,
                "vulnerabilities": merged_vulns,
                "tech_stack": recon_data.get("tech_stack", {}),
            }
            report = ReportGenerator().generate(
                target_url=target_url,
                recon_data=recon_data,
                scan_result=scan_result,
                attack_chain=chain,
                llm_analysis="LLM analysis skipped in web UI mode.",
            )
            _check_cancel(cancel_event)
            txt_path = run_module._write_scan_text_report(
                target_url=target_url,
                discovery=discovery,
                vulnerabilities=merged_vulns,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report saved: {txt_path.name}")
            sq.put(f"[OK] JSON report: {Path(report.get('json_path', '')).name}")
            sq.put(f"[OK] Markdown report: {Path(report.get('md_path', '')).name}")

            # Emit structured result for the UI to parse
            chain_with_vuln = []
            for s in chain:
                x = dict(s)
                sv = x.get("source_vulnerability") or {}
                x["vulnerability_name"] = str(sv.get("type") or "")
                x["vulnerability_detail"] = str(sv.get("detail") or "")
                x["vulnerability_severity"] = str(sv.get("severity") or "")
                chain_with_vuln.append(x)

            scenario_summary = (
                f"Full scan for {target_url}. "
                f"Total findings: {len(merged_vulns)}. "
                f"Risk profile: {risk}. "
                f"Primary findings include: {', '.join([str(v.get('type') or 'Finding') for v in merged_vulns[:6]])}."
            )
            result_payload = {
                "type": "result",
                "target_url": target_url,
                "overall_risk": risk,
                "severity_counts": counts,
                "total_vulns": len(merged_vulns),
                "vulnerabilities": merged_vulns,
                "attack_chain": chain_with_vuln,
                "readable_scenario": _build_readable_scenario_text(
                    scenario=scenario_summary,
                    target_env=target_url,
                    chain_steps=chain_with_vuln,
                ),
                "reports": {
                    "txt": str(txt_path),
                    "json": str(report.get("json_path", "")),
                    "md": str(report.get("md_path", "")),
                    "pdf": str(report.get("pdf_path", "")),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=chain,
                vulnerabilities=merged_vulns,
                retrieval_results=[],
            )
            _store_latest("fullscan", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Scan complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/scenario", methods=["POST"])
def api_scenario():
    """Option 2 â€” Generate Attack Scenario (No URL)."""
    data = request.get_json(force=True) or {}
    raw_scenario  = (data.get("scenario") or "").strip()
    request_id = str(data.get("request_id") or "").strip()
    target_env    = (data.get("target_env") or "Enterprise Windows Active Directory network").strip()
    chain_len_raw = str(data.get("chain_length") or config.DEFAULT_CHAIN_LENGTH).strip()

    if not raw_scenario:
        return jsonify({"error": "scenario is required"}), 400

    try:
        scenario = sanitize_scenario(raw_scenario)
    except Exception as exc:
        return jsonify({"error": f"Invalid scenario: {exc}"}), 400

    # Use 14 steps by default for full ATT&CK tactic coverage when possible.
    chain_len = int(chain_len_raw) if chain_len_raw.isdigit() else 14
    chain_len = max(8, min(chain_len, 14))  # clamp 8â€“14

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Generating attack scenario: {scenario[:80]}")
            sq.put(f"[INFO] Target environment: {target_env}")
            sq.put(f"[INFO] Chain length: {chain_len}")

            sq.put("[STEP 1/3] Loading FAISS indexâ€¦")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)
            sq.put("[OK] RAG engine ready.")

            sq.put("[STEP 2/3] Generating attack chain via RAG + LLMâ€¦")
            result = ctx.generator.generate(
                scenario=scenario,
                target_environment=target_env,
                chain_length=chain_len,
            )
            _check_cancel(cancel_event)
            json_path = ctx.generator.export_json(result)
            md_path   = ctx.generator.export_markdown(result)
            pdf_path = ""
            try:
                pdf_path = render_markdown_to_pdf(Path(md_path), Path(md_path).with_suffix(".pdf"))
            except Exception as exc:
                sq.put(f"[WARN] PDF generation failed: {exc}")
            sq.put(f"[OK] Chain generated with {len(result.get('attack_chain', {}).get('attack_chain', []))} steps.")

            sq.put("[STEP 3/3] Building MITRE mapping reportâ€¦")
            chain_steps = result.get("attack_chain", {}).get("attack_chain", [])
            vulnerabilities = [
                {
                    "type": "Scenario Attack Step",
                    "severity": "MEDIUM",
                    "detail": s.get("description", s.get("technique_name", "")),
                    "evidence": s.get("rationale", "Generated from scenario and RAG context."),
                    "recommendation": s.get("mitigation", "Apply layered security controls."),
                    "mitre_hint": s.get("technique_id", ""),
                }
                for s in chain_steps
            ]
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _check_cancel(cancel_event)
            txt_path = run_module._write_option_text_report(
                option_slug="scenario",
                mode_name="Generate Attack Scenario (No URL)",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report: {txt_path.name}")
            sq.put(f"[OK] JSON report: {Path(json_path).name}")
            sq.put(f"[OK] Markdown report: {Path(md_path).name}")

            analysis  = result.get("analysis", {})
            latency   = result.get("latency", {})
            retrieval = result.get("retrieval_results", [])

            # Enrich chain steps â€” replace 'Unknown' names from FAISS
            enriched_chain = _enrich_chain(chain_steps, ctx.rag)

            result_payload = {
                "type": "result",
                "scenario": scenario,
                "target_env": target_env,
                "faithfulness_score": result.get("faithfulness_score", 0),
                "tactical_coverage": analysis.get("tactical_coverage", {}).get("coverage_ratio", 0),
                "unique_techniques": analysis.get("unique_techniques", 0),
                "pipeline_latency_s": latency.get("pipeline_total_s", 0),
                "attack_chain": enriched_chain,
                "readable_scenario": _build_readable_scenario_text(
                    scenario=scenario,
                    target_env=target_env,
                    chain_steps=enriched_chain,
                ),
                "reports": {
                    "txt": str(txt_path),
                    "json": str(json_path),
                    "md": str(md_path),
                    "pdf": str(pdf_path),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=enriched_chain,
                vulnerabilities=vulnerabilities,
                retrieval_results=retrieval,
            )
            _store_latest("scenario", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Scenario generation complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Option 3 â€” Validate Scenario on Target URL."""
    data = request.get_json(force=True) or {}
    raw_scenario  = (data.get("scenario") or "").strip()
    target_url_raw = (data.get("target_url") or "").strip()
    request_id = str(data.get("request_id") or "").strip()

    if not raw_scenario or not target_url_raw:
        return jsonify({"error": "scenario and target_url are required"}), 400

    try:
        scenario   = sanitize_scenario(raw_scenario)
        target_url = run_module.normalize_url(target_url_raw)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Validating scenario on: {target_url}")

            sq.put("[STEP 1/4] Detecting attack type from scenarioâ€¦")
            attack_type = detect_attack_type(scenario)
            _check_cancel(cancel_event)
            sq.put(f"[OK] Detected attack type: {attack_type}")

            sq.put(f"[STEP 2/4] Probing target for {attack_type}â€¦")
            probe = probe_target(
                target_url,
                attack_type,
                timeout=float(getattr(config, "WEB_UI_PROBE_TIMEOUT_S", 5.0)),
            )
            _check_cancel(cancel_event)
            status = "CONFIRMED" if probe.get("found") else "NOT CONFIRMED"
            sq.put(f"[OK] Probe result: {status} | Severity: {probe.get('severity', 'N/A')}")

            sq.put("[STEP 3/4] Loading RAG engine and mapping MITRE techniquesâ€¦")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)

            evidence = probe.get("evidence", [])
            vuln_items = []
            for ev in evidence:
                if not ev.get("confirmed"):
                    continue
                vuln_items.append({
                    "type": f"Targeted Validation ({attack_type})",
                    "detail": ev.get("detail", "Targeted evidence detected"),
                    "severity": probe.get("severity", "MEDIUM"),
                    "cwe_id": "CWE-20",
                    "mitre_hint": "",
                    "recommendation": probe.get("recommendation", "Review and patch issue."),
                    "evidence": f"{ev.get('url', target_url)} | {ev.get('payload', 'probe')}",
                    "confirmed_live": True,
                })
            if not vuln_items:
                vuln_items.append({
                    "type": f"Targeted Validation ({attack_type})",
                    "detail": "No automatic confirmation; manual verification recommended.",
                    "severity": "LOW",
                    "cwe_id": "CWE-200",
                    "mitre_hint": "",
                    "recommendation": probe.get("recommendation", "Perform manual validation."),
                    "evidence": probe.get("manual_test", target_url),
                    "confirmed_live": False,
                })

            mapped = ctx.mapper.map_vulnerabilities(vuln_items)
            _check_cancel(cancel_event)
            chain  = ctx.mapper.build_attack_chain(mapped, target_url=target_url)
            sq.put(f"[OK] MITRE mapping: {len(chain)} attack chain steps.")

            sq.put("[STEP 4/4] Generating reportsâ€¦")
            recon  = WebReconAgent(target_url).run()
            counts = run_module._severity_counts(vuln_items)
            risk   = run_module._overall_risk(counts)
            report = ReportGenerator().generate(
                target_url=target_url,
                recon_data=recon,
                scan_result={
                    "target_url": target_url,
                    "total_vulns": len(vuln_items),
                    "severity_counts": counts,
                    "overall_risk": risk,
                    "vulnerabilities": vuln_items,
                    "tech_stack": recon.get("tech_stack", {}),
                },
                attack_chain=chain,
                llm_analysis=(
                    f"Scenario-driven validation for attack type '{attack_type}'. Status: {status}."
                ),
            )
            _check_cancel(cancel_event)
            txt_path = run_module._write_option_text_report(
                option_slug="validation",
                mode_name="Validate Scenario on Target URL",
                scenario=scenario,
                target_url=target_url,
                vulnerabilities=vuln_items,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report: {txt_path.name}")

            result_payload = {
                "type": "result",
                "scenario": scenario,
                "target_url": target_url,
                "attack_type": attack_type,
                "probe_status": status,
                "probe_severity": probe.get("severity", "N/A"),
                "overall_risk": risk,
                "severity_counts": counts,
                "vulnerabilities": vuln_items,
                "attack_chain": chain,
                "reports": {
                    "txt": str(txt_path),
                    "json": str(report.get("json_path", "")),
                    "md": str(report.get("md_path", "")),
                    "pdf": str(report.get("pdf_path", "")),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=chain,
                vulnerabilities=vuln_items,
                retrieval_results=[],
            )
            _store_latest("validate", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Validation complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Option 4 â€” Analyze Scenario Only (RAG + MITRE, no LLM call)."""
    data = request.get_json(force=True) or {}
    raw_scenario = (data.get("scenario") or "").strip()
    chain_len_raw = str(data.get("chain_length") or config.DEFAULT_CHAIN_LENGTH).strip()
    request_id = str(data.get("request_id") or "").strip()

    if not raw_scenario:
        return jsonify({"error": "scenario is required"}), 400

    try:
        scenario = sanitize_scenario(raw_scenario)
    except Exception as exc:
        return jsonify({"error": f"Invalid scenario: {exc}"}), 400

    sq = StreamQueue()
    cancel_event = _register_request(request_id)

    def worker():
        ctx = get_ctx()
        handler = QueueHandler(sq)
        handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _check_cancel(cancel_event)
            sq.put(f"[INFO] Analyzing scenario: {scenario[:80]}")

            sq.put("[STEP 1/3] Loading FAISS indexâ€¦")
            ctx.ensure_rag(force_reindex=False)
            _check_cancel(cancel_event)
            sq.put("[OK] RAG engine ready.")

            chain_len = int(chain_len_raw) if chain_len_raw.isdigit() else config.DEFAULT_CHAIN_LENGTH
            chain_len = max(8, min(chain_len, 14))

            sq.put("[STEP 2/3] Generating attack chain via RAG + LLM...")
            result = ctx.generator.generate(
                scenario=scenario,
                target_environment="General enterprise environment",
                chain_length=chain_len,
            )
            _check_cancel(cancel_event)
            json_path = ctx.generator.export_json(result)
            md_path = ctx.generator.export_markdown(result)
            pdf_path = ""
            try:
                pdf_path = render_markdown_to_pdf(Path(md_path), Path(md_path).with_suffix(".pdf"))
            except Exception as exc:
                sq.put(f"[WARN] PDF generation failed: {exc}")
            chain_steps = result.get("attack_chain", {}).get("attack_chain", [])
            sq.put(f"[OK] {len(chain_steps)} steps generated.")

            sq.put("[STEP 3/3] Building MITRE mapping and text reportâ€¦")
            vulnerabilities = [
                {
                    "type": "Scenario Analysis Step",
                    "severity": "MEDIUM",
                    "detail": s.get("description", s.get("technique_name", "")),
                    "evidence": s.get("rationale", "Derived from scenario-only analysis."),
                    "recommendation": s.get("mitigation", "Apply ATT&CK-aligned defensive controls."),
                    "mitre_hint": s.get("technique_id", ""),
                }
                for s in chain_steps
            ]
            mapped = ctx.mapper.map_vulnerabilities(vulnerabilities)
            _check_cancel(cancel_event)
            txt_path = run_module._write_option_text_report(
                option_slug="analysis",
                mode_name="Analyze Scenario Only",
                scenario=scenario,
                target_url=None,
                vulnerabilities=vulnerabilities,
                mapped=mapped,
                mitre_db=ctx.mitre_db,
                rag_engine=ctx.rag,
            )
            sq.put(f"[OK] Text report: {txt_path.name}")

            analysis = result.get("analysis", {})
            latency  = result.get("latency", {})
            retrieval = result.get("retrieval_results", [])

            # Enrich chain steps â€” replace 'Unknown' names from MITRE DB
            enriched_chain = _enrich_chain(chain_steps, ctx.mitre_db)

            result_payload = {
                "type": "result",
                "scenario": scenario,
                "faithfulness_score": result.get("faithfulness_score", 0),
                "tactical_coverage": analysis.get("tactical_coverage", {}).get("coverage_ratio", 0),
                "unique_techniques": analysis.get("unique_techniques", 0),
                "pipeline_latency_s": latency.get("pipeline_total_s", 0),
                "attack_chain": enriched_chain,
                "readable_scenario": _build_readable_scenario_text(
                    scenario=scenario,
                    target_env="General enterprise environment",
                    chain_steps=enriched_chain,
                ),
                "reports": {
                    "txt": str(txt_path),
                    "json": str(json_path),
                    "md": str(md_path),
                    "pdf": str(pdf_path),
                },
            }
            _attach_novelty(
                result_payload,
                chain_steps=enriched_chain,
                vulnerabilities=vulnerabilities,
                retrieval_results=retrieval,
            )
            _store_latest("analyze", result_payload)
            sq.put("__RESULT__:" + json.dumps(result_payload, default=str))
            sq.put("[DONE] Analysis complete.")
        except RequestCancelledError:
            sq.put("[INFO] Request cancelled. Backend worker stopped.")
        except Exception as exc:
            sq.put(f"[ERROR] {exc}")
        finally:
            root.removeHandler(handler)
            _cleanup_request(request_id)
            sq.done()

    threading.Thread(target=worker, daemon=True).start()

    return Response(
        stream_with_context(_stream_gen(sq)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# â”€â”€ Server entry point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

if __name__ == "__main__":
    config.ensure_directories()
    run_module.setup_logging()
    threading.Thread(target=_prewarm_runtime, daemon=True).start()
    print("\n" + "=" * 60)
    print("  Red ELISAR â€” Web Application")
    print("  Open your browser at: http://127.0.0.1:7860")
    print("  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=7860, debug=False, threaded=True)
```
