import json
import logging
from typing import Optional
import config

logger = logging.getLogger("red_elisar.mitigations")

_MITIGATIONS_PATH = config.DATA_DIR / "mitre_mitigations.json"
_CACHE: Optional[dict] = None


def _load_mitigations() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if not _MITIGATIONS_PATH.exists():
        logger.warning(f"Mitigations file not found: {_MITIGATIONS_PATH}")
        _CACHE = {}
        return _CACHE
    with open(_MITIGATIONS_PATH, "r", encoding="utf-8") as f:
        _CACHE = json.load(f)
    logger.info(f"Loaded {len(_CACHE)} mitigation entries")
    return _CACHE


def get_mitigation(technique_id: str) -> dict:
    data = _load_mitigations()

    # 1. Exact match
    if technique_id in data:
        return data[technique_id]

    # 2. Parent technique fallback (T1566.001 → T1566)
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        if parent_id in data:
            entry = data[parent_id].copy()
            entry["_fallback"] = f"Parent technique {parent_id}"
            return entry

    # 3. Generic default
    return {
        "mitigation_id": "M0000",
        "name": "General Best Practices",
        "description": (
            "Apply defense-in-depth principles: network segmentation, "
            "least-privilege access, endpoint detection and response (EDR), "
            "security awareness training, regular patching, and monitoring."
        ),
        "nist_controls": ["AC-6", "SI-4", "AT-2", "CM-7"],
        "_fallback": "Default generic mitigation",
    }


def get_mitigations_for_chain(attack_chain: list[dict]) -> list[dict]:
    results = []
    for step in attack_chain:
        tid = step.get("technique_id", "")
        mitigation = get_mitigation(tid)
        results.append({
            "step": step.get("step", 0),
            "technique_id": tid,
            "technique_name": step.get("technique_name", ""),
            "mitigation": mitigation,
        })
    return results
