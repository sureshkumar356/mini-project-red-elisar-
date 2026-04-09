import json
import re
import logging
import gc
from pathlib import Path
from typing import Optional
import config

logger = logging.getLogger("red_elisar.parser")


class AttackTechnique:
    __slots__ = [
        "technique_id", "name", "description", "tactics",
        "platforms", "data_sources", "is_subtechnique",
        "stix_id", "url"
    ]

    def __init__(
        self,
        technique_id: str,
        name: str,
        description: str,
        tactics: list[str],
        platforms: list[str],
        data_sources: list[str],
        is_subtechnique: bool,
        stix_id: str,
        url: str
    ):
        self.technique_id = technique_id
        self.name = name
        self.description = description
        self.tactics = tactics
        self.platforms = platforms
        self.data_sources = data_sources
        self.is_subtechnique = is_subtechnique
        self.stix_id = stix_id
        self.url = url

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "tactics": self.tactics,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
            "is_subtechnique": self.is_subtechnique,
            "stix_id": self.stix_id,
            "url": self.url,
        }

    def to_embedding_text(self) -> str:
        tactics_str = ", ".join(self.tactics) if self.tactics else "unknown"
        desc = self.description[:config.MAX_DESCRIPTION_LENGTH]
        return (
            f"{self.technique_id}: {self.name} | "
            f"Tactics: {tactics_str} | "
            f"{desc}"
        )

    def __repr__(self) -> str:
        return f"AttackTechnique({self.technique_id}: {self.name})"


def clean_description(raw_description: str) -> str:
    if not raw_description:
        return ""
    text = raw_description
    # Remove citation references
    text = re.sub(r'\(Citation:[^)]+\)', '', text)
    # Remove markdown links, keep text
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Remove bold/italic markers
    text = re.sub(r'\*{1,3}([^*]+)\*{1,3}', r'\1', text)
    # Remove code blocks
    text = re.sub(r'```[^`]*```', '', text, flags=re.DOTALL)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Remove markdown headers
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    # Normalize whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r'[ \t]+', ' ', text)
    return text.strip()


class MITREParser:

    def __init__(self, stix_path: Optional[Path] = None):
        self.stix_path = stix_path or config.MITRE_STIX_PATH
        self.techniques: list[AttackTechnique] = []
        self._raw_bundle = None

    def parse(self) -> list[AttackTechnique]:
        logger.info(f"Loading STIX bundle from: {self.stix_path}")

        if not self.stix_path.exists():
            raise FileNotFoundError(
                f"MITRE ATT&CK STIX file not found: {self.stix_path}\n"
                f"Download from: https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack.json"
            )

        # Load JSON bundle
        with open(self.stix_path, 'r', encoding='utf-8') as f:
            self._raw_bundle = json.load(f)

        self._validate_bundle()

        # Extract attack-pattern objects
        attack_patterns = [
            obj for obj in self._raw_bundle.get("objects", [])
            if obj.get("type") == "attack-pattern"
        ]
        logger.info(f"Found {len(attack_patterns)} attack-pattern objects")

        valid_count = 0
        skipped_deprecated = 0
        skipped_revoked = 0

        for obj in attack_patterns:
            if obj.get("x_mitre_deprecated", False):
                skipped_deprecated += 1
                continue
            if obj.get("revoked", False):
                skipped_revoked += 1
                continue
            technique = self._extract_technique(obj)
            if technique:
                self.techniques.append(technique)
                valid_count += 1

        logger.info(
            f"Extracted {valid_count} valid techniques "
            f"(skipped {skipped_deprecated} deprecated, {skipped_revoked} revoked)"
        )

        # Free raw bundle memory
        self._raw_bundle = None
        if config.AGGRESSIVE_GC:
            gc.collect()

        return self.techniques

    def _validate_bundle(self):
        bundle_type = self._raw_bundle.get("type", "")
        if bundle_type != "bundle":
            raise ValueError(f"Expected STIX bundle type 'bundle', got '{bundle_type}'")
        spec_version = self._raw_bundle.get("spec_version", "")
        if spec_version and not spec_version.startswith("2."):
            logger.warning(f"Expected STIX 2.x spec_version, got '{spec_version}'. Attempting anyway.")
        objects = self._raw_bundle.get("objects", [])
        if not objects:
            raise ValueError("STIX bundle contains no objects")
        logger.info(
            f"STIX bundle validated: {len(objects)} total objects, "
            f"ID: {self._raw_bundle.get('id', 'unknown')}"
        )

    def _extract_technique(self, obj: dict) -> Optional[AttackTechnique]:
        try:
            technique_id = ""
            url = ""
            # Extract ID from external references
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break

            if not technique_id:
                logger.warning(f"No technique ID found for object: {obj.get('id')}")
                return None

            name = obj.get("name", "Unknown Technique")
            description = clean_description(obj.get("description", ""))

            # Extract tactics from kill chain phases
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name", ""))

            platforms = obj.get("x_mitre_platforms", [])
            data_sources = obj.get("x_mitre_data_sources", [])
            is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
            stix_id = obj.get("id", "")

            return AttackTechnique(
                technique_id=technique_id,
                name=name,
                description=description,
                tactics=tactics,
                platforms=platforms,
                data_sources=data_sources,
                is_subtechnique=is_subtechnique,
                stix_id=stix_id,
                url=url,
            )
        except Exception as e:
            logger.error(f"Failed to extract technique from {obj.get('id')}: {e}")
            return None

    def get_tactics_summary(self) -> dict[str, int]:
        tactic_counts: dict[str, int] = {}
        for tech in self.techniques:
            for tactic in tech.tactics:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        return dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True))

    def export_json(self, output_path: Optional[Path] = None) -> Path:
        if output_path is None:
            config.ensure_directories()
            output_path = config.OUTPUT_DIR / "techniques.json"
        data = {
            "total_techniques": len(self.techniques),
            "tactics_summary": self.get_tactics_summary(),
            "techniques": [t.to_dict() for t in self.techniques],
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Exported {len(self.techniques)} techniques to {output_path}")
        return output_path


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)

    parser = MITREParser()
    techniques = parser.parse()

    print(f"\n{'='*60}")
    print(f"MITRE ATT&CK Enterprise Parser Results")
    print(f"{'='*60}")
    print(f"Total techniques extracted: {len(techniques)}")
    print(f"\nTactics Summary:")
    for tactic, count in parser.get_tactics_summary().items():
        print(f"  {tactic:<35} {count:>4} techniques")

    export_path = parser.export_json()
    print(f"\nExported to: {export_path}")
