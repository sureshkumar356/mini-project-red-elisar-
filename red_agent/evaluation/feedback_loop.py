import json
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
from collections import defaultdict
import config

logger = logging.getLogger("red_elisar.feedback")


class FeedbackStore:

    def __init__(self, store_path: Path = None):
        self.store_path = store_path or config.FEEDBACK_STORE_PATH
        self._entries: list[dict] = []
        self._weights: dict[str, float] = {}
        self._load()

    def _load(self):
        if self.store_path.exists():
            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._entries = data.get("entries", [])
                self._weights = data.get("weights", {})
                logger.info(f"Loaded {len(self._entries)} feedback entries")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load feedback store: {e}")
                self._entries = []
                self._weights = {}
        else:
            self._entries = []
            self._weights = {}

    def _save(self):
        data = {
            "entries": self._entries,
            "weights": self._weights,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(self._entries),
        }
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def add_entry(self, entry: dict):
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        entry["entry_id"] = len(self._entries) + 1
        self._entries.append(entry)
        self._save()

    @property
    def entries(self) -> list[dict]:
        return self._entries

    @property
    def weights(self) -> dict[str, float]:
        return self._weights

    @weights.setter
    def weights(self, new_weights: dict[str, float]):
        self._weights = new_weights
        self._save()


class FeedbackLoop:

    ALPHA         = 0.3   # EMA learning rate
    MIN_WEIGHT    = 0.1
    MAX_WEIGHT    = 3.0
    DEFAULT_WEIGHT = 1.0

    TACTICS = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]

    def __init__(self, store: FeedbackStore = None):
        self.store = store or FeedbackStore()
        if not self.store.weights:
            self.store.weights = {t: self.DEFAULT_WEIGHT for t in self.TACTICS}

    def record_outcome(
        self,
        scenario: str,
        retrieved_techniques: list[dict],
        generated_chain: dict,
        faithfulness_score: float,
        expected_techniques: list[str] = None,
    ) -> dict:
        # Extract tactic usage from generated chain steps
        tactic_usage = defaultdict(int)
        generated_ids = []
        chain_steps = generated_chain.get("attack_chain", [])
        if isinstance(chain_steps, dict):
            chain_steps = chain_steps.get("attack_chain", [])
        for step in chain_steps:
            tactic_usage[step.get("tactic", "unknown").lower()] += 1
            tid = step.get("technique_id", "")
            if tid:
                generated_ids.append(tid)

        # Tactic distribution from retrieved techniques
        retrieved_tactics = defaultdict(int)
        for tech in retrieved_techniques:
            tactics = tech.get("tactics", [])
            if isinstance(tactics, str):
                tactics = [t.strip() for t in tactics.split(",")]
            for tactic in tactics:
                retrieved_tactics[tactic.lower()] += 1

        reward = self._compute_reward(
            faithfulness_score=faithfulness_score,
            generated_ids=generated_ids,
            expected_techniques=expected_techniques or [],
            tactic_usage=dict(tactic_usage),
        )

        entry = {
            "scenario": scenario[:200],
            "faithfulness_score": faithfulness_score,
            "reward": reward,
            "generated_technique_count": len(generated_ids),
            "generated_techniques": generated_ids,
            "retrieved_technique_count": len(retrieved_techniques),
            "tactic_usage": dict(tactic_usage),
            "retrieved_tactics": dict(retrieved_tactics),
        }
        if expected_techniques:
            entry["expected_techniques"] = expected_techniques

        self.store.add_entry(entry)
        self._update_weights(reward, dict(tactic_usage), dict(retrieved_tactics))

        logger.info(f"Feedback recorded: reward={reward:.3f}, faithfulness={faithfulness_score:.3f}")
        return entry

    def _compute_reward(
        self,
        faithfulness_score: float,
        generated_ids: list[str],
        expected_techniques: list[str],
        tactic_usage: dict[str, int],
    ) -> float:
        # Component 1: Faithfulness (weight 0.4)
        faith_component = faithfulness_score

        # Component 2: Technique precision (weight 0.3)
        if expected_techniques and generated_ids:
            expected_set = set(expected_techniques)
            generated_set = set(generated_ids)
            correct = 0
            for gid in generated_set:
                base_gid = gid.split(".")[0]
                if gid in expected_set or base_gid in expected_set:
                    correct += 1
                else:
                    for eid in expected_set:
                        if eid.split(".")[0] == base_gid:
                            correct += 1
                            break
            precision_component = correct / len(generated_set)
        else:
            precision_component = 0.5  # neutral when no ground truth

        # Component 3: Tactical coverage (weight 0.3)
        total_tactics = max(len(self.TACTICS), 1)
        coverage_component = min(len(tactic_usage) / float(total_tactics), 1.0)

        reward = (
            0.4 * faith_component
            + 0.3 * precision_component
            + 0.3 * coverage_component
        )
        return round(min(max(reward, 0.0), 1.0), 4)

    def _update_weights(
        self,
        reward: float,
        tactic_usage: dict[str, int],
        retrieved_tactics: dict[str, int],
    ):
        # EMA update: w_new = (1 - α) * w_old + α * adjustment
        current_weights = dict(self.store.weights)
        for tactic in self.TACTICS:
            old_weight = current_weights.get(tactic, self.DEFAULT_WEIGHT)
            if tactic in tactic_usage and reward > 0.5:
                # Tactic used in successful generation → boost weight
                adjustment = old_weight * (1.0 + reward * 0.5)
            elif tactic in retrieved_tactics and tactic not in tactic_usage:
                # Retrieved but unused → reduce weight
                adjustment = old_weight * (1.0 - (1.0 - reward) * 0.3)
            else:
                adjustment = old_weight

            new_weight = (1 - self.ALPHA) * old_weight + self.ALPHA * adjustment
            new_weight = max(self.MIN_WEIGHT, min(self.MAX_WEIGHT, new_weight))
            current_weights[tactic] = round(new_weight, 4)

        self.store.weights = current_weights
        logger.debug(f"Updated weights: {current_weights}")

    def get_current_weights(self) -> dict[str, float]:
        return dict(self.store.weights)

    def get_weight_for_tactic(self, tactic: str) -> float:
        return self.store.weights.get(tactic.lower(), self.DEFAULT_WEIGHT)

    def get_feedback_summary(self) -> dict:
        entries = self.store.entries
        if not entries:
            return {
                "total_entries": 0,
                "avg_reward": 0,
                "avg_faithfulness": 0,
                "current_weights": self.get_current_weights(),
            }
        import statistics as stats
        rewards = [e.get("reward", 0) for e in entries]
        faithfulness = [e.get("faithfulness_score", 0) for e in entries]
        return {
            "total_entries": len(entries),
            "avg_reward": round(stats.mean(rewards), 4),
            "avg_faithfulness": round(stats.mean(faithfulness), 4),
            "reward_trend": rewards[-10:],
            "current_weights": self.get_current_weights(),
            "weight_range": {
                "min": round(min(self.store.weights.values()), 4),
                "max": round(max(self.store.weights.values()), 4),
            },
        }

    def reset(self):
        self.store._entries = []
        self.store.weights = {t: self.DEFAULT_WEIGHT for t in self.TACTICS}
        logger.info("Feedback loop reset")


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)

    loop = FeedbackLoop()

    loop.record_outcome(
        scenario="APT phishing campaign targeting enterprise",
        retrieved_techniques=[
            {"technique_id": "T1566.001", "tactics": "initial-access"},
            {"technique_id": "T1059.001", "tactics": "execution"},
            {"technique_id": "T1003.001", "tactics": "credential-access"},
        ],
        generated_chain={
            "attack_chain": [
                {"step": 1, "technique_id": "T1566.001", "tactic": "initial-access"},
                {"step": 2, "technique_id": "T1059.001", "tactic": "execution"},
                {"step": 3, "technique_id": "T1003.001", "tactic": "credential-access"},
            ]
        },
        faithfulness_score=1.0,
        expected_techniques=["T1566.001", "T1059.001", "T1003.001"],
    )

    summary = loop.get_feedback_summary()
    print(f"\nFeedback Summary:")
    print(json.dumps(summary, indent=2))
