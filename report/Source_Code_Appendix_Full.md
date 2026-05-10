# Source Code Appendix (Full)

Project: Red ELISAR  
Generated on: 2026-04-30 19:50:37

This document contains the actual source code blocks requested for the report, from RAG module to final implementation, plus vulnerable app and web app.


## A. RAG MITRE Parser

File: $(System.Collections.Hashtable.Path)

```python
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
```

## B. RAG Chunking

File: $(System.Collections.Hashtable.Path)

```python
import logging
from typing import Optional
from transformers import AutoTokenizer
import config

logger = logging.getLogger("red_elisar.chunking")

_tokenizer: Optional[AutoTokenizer] = None


def _get_tokenizer() -> AutoTokenizer:
    global _tokenizer
    if _tokenizer is None:
        logger.info(f"Loading tokenizer for: {config.CHUNK_TOKENIZER}")
        _tokenizer = AutoTokenizer.from_pretrained(
            f"sentence-transformers/{config.CHUNK_TOKENIZER}"
        )
        logger.info("Tokenizer loaded")
    return _tokenizer


def chunk_text(
    text: str,
    metadata: dict,
    chunk_size: int = None,
    chunk_overlap: int = None,
) -> list[dict]:
    if chunk_size is None:
        chunk_size = config.CHUNK_SIZE_TOKENS
    if chunk_overlap is None:
        chunk_overlap = config.CHUNK_OVERLAP_TOKENS

    if not text or not text.strip():
        return []

    tokenizer = _get_tokenizer()
    stride = chunk_size - chunk_overlap  # 512 - 128 = 384

    # Tokenize full text
    encoded = tokenizer.encode(text, add_special_tokens=False)
    total_tokens = len(encoded)

    # Single chunk if text fits
    if total_tokens <= chunk_size:
        chunk_meta = {
            **metadata,
            "chunk_index": 0,
            "total_chunks": 1,
            "is_chunked": False,
            "token_count": total_tokens,
        }
        return [{"text": text.strip(), "metadata": chunk_meta}]

    # Sliding window chunking
    chunks = []
    start = 0
    chunk_index = 0

    while start < total_tokens:
        end = min(start + chunk_size, total_tokens)
        chunk_token_ids = encoded[start:end]

        chunk_text_str = tokenizer.decode(
            chunk_token_ids,
            skip_special_tokens=True,
            clean_up_tokenization_spaces=True,
        ).strip()

        if chunk_text_str:
            chunk_meta = {
                **metadata,
                "chunk_index": chunk_index,
                "total_chunks": -1,
                "is_chunked": True,
                "token_count": len(chunk_token_ids),
            }
            chunks.append({"text": chunk_text_str, "metadata": chunk_meta})
            chunk_index += 1

        start += stride

        # Merge tiny trailing chunk into last chunk
        if start < total_tokens and (total_tokens - start) < chunk_size // 4:
            remaining_ids = encoded[start:total_tokens]
            remaining_text = tokenizer.decode(
                remaining_ids,
                skip_special_tokens=True,
                clean_up_tokenization_spaces=True,
            ).strip()
            if remaining_text and chunks:
                last_chunk = chunks[-1]
                last_chunk["text"] += " " + remaining_text
                last_chunk["metadata"]["token_count"] += len(remaining_ids)
            break

    # Set total_chunks on all chunks
    total_chunks = len(chunks)
    for c in chunks:
        c["metadata"]["total_chunks"] = total_chunks

    return chunks


def chunk_techniques(techniques: list) -> list[dict]:
    all_chunks = []
    stats = {
        "total_techniques": len(techniques),
        "total_chunks": 0,
        "single_chunk_techniques": 0,
        "multi_chunk_techniques": 0,
        "max_chunks_per_technique": 0,
    }

    for tech in techniques:
        text = tech.to_embedding_text()
        metadata = {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactics": ", ".join(tech.tactics) if tech.tactics else "",
            "platforms": ", ".join(tech.platforms) if tech.platforms else "",
            "is_subtechnique": tech.is_subtechnique,
            "stix_id": tech.stix_id,
            "url": tech.url,
            "description_preview": tech.description[:200] if tech.description else "",
        }

        chunks = chunk_text(text, metadata)
        all_chunks.extend(chunks)

        n_chunks = len(chunks)
        if n_chunks == 1:
            stats["single_chunk_techniques"] += 1
        else:
            stats["multi_chunk_techniques"] += 1
        if n_chunks > stats["max_chunks_per_technique"]:
            stats["max_chunks_per_technique"] = n_chunks

    stats["total_chunks"] = len(all_chunks)

    logger.info(
        f"Chunking complete: {stats['total_techniques']} techniques â†’ "
        f"{stats['total_chunks']} chunks "
        f"({stats['single_chunk_techniques']} single, "
        f"{stats['multi_chunk_techniques']} multi, "
        f"max {stats['max_chunks_per_technique']} chunks/technique)"
    )

    return all_chunks


def chunk_offensive_logs(logs: list[dict]) -> list[dict]:
    all_chunks = []

    for log in logs:
        text = log.get("query", log.get("description", ""))
        if not text:
            continue

        metadata = {
            "scenario_id": log.get("scenario_id", ""),
            "scenario_type": log.get("scenario_type", "unknown"),
            "expected_techniques": ", ".join(log.get("expected_techniques", [])),
            "source": "offensive_log",
        }

        chunks = chunk_text(text, metadata)
        all_chunks.extend(chunks)

    logger.info(f"Chunked {len(logs)} offensive logs â†’ {len(all_chunks)} chunks")
    return all_chunks


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)
    from mitre_parser import MITREParser

    parser = MITREParser()
    techniques = parser.parse()
    print(f"Parsed {len(techniques)} techniques")

    chunks = chunk_techniques(techniques)
    print(f"Generated {len(chunks)} total chunks")

    if chunks:
        print(f"\n--- Sample Chunk 0 ---")
        print(f"Metadata: {chunks[0]['metadata']}")
        print(f"Text (first 200 chars): {chunks[0]['text'][:200]}...")
```

## C. FAISS Vector Store

File: $(System.Collections.Hashtable.Path)

```python
import json
import logging
import time
import gc
import numpy as np
from pathlib import Path
from typing import Optional

import faiss
from sentence_transformers import SentenceTransformer

import config

logger = logging.getLogger("red_elisar.faiss_store")


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

## D. RAG Engine

File: $(System.Collections.Hashtable.Path)

```python
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

* If scenario is SQL Injection â†’ DO NOT use brute force (T1110)
* If scenario is CSRF â†’ focus on session hijacking, cookies, user execution
* If scenario is file exposure â†’ focus on credential access, discovery

2. CONTEXT USAGE

* You MUST use at least 3 techniques from the retrieved context
* Prefer highest relevance score techniques
* Do NOT invent unrelated techniques outside context

3. ATTACK FLOW (LOGICAL CHAIN)

* Generate {min_steps}â€“{max_steps} steps
* Each step MUST logically follow the previous step
* Ensure cause â†’ effect relationship

4. TACTIC ALIGNMENT

* Use only necessary tactics (do NOT force all 14 MITRE tactics)
* Typical flow:
  Initial Access â†’ Execution â†’ Credential Access â†’ Persistence â†’ (Optional) Exfiltration

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
Step 1: Brute Force (T1110) âŒ
Step 2: SQL Injection âŒ

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

## E. MITRE Mapper

File: $(System.Collections.Hashtable.Path)

```python
"""
mitre_mapper.py â€” MITRE ATT&CK Vulnerability Mapper for Red ELISAR
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

# Direct map: MITRE technique ID â†’ search query for RAG
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

## F. Tool Mapper

File: $(System.Collections.Hashtable.Path)

```python
import json
import logging
from typing import Optional
import config

logger = logging.getLogger("red_elisar.exploit_tools")

_TOOLS_PATH = config.DATA_DIR / "exploit_tools.json"
_CACHE: Optional[dict] = None


def _load_tools() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if not _TOOLS_PATH.exists():
        logger.warning(f"Exploit tools file not found: {_TOOLS_PATH}")
        _CACHE = {}
        return _CACHE
    with open(_TOOLS_PATH, "r", encoding="utf-8") as f:
        _CACHE = json.load(f)
    logger.info(f"Loaded {len(_CACHE)} exploit tool entries")
    return _CACHE


def get_tools(technique_id: str) -> dict:
    data = _load_tools()

    # 1. Exact match
    if technique_id in data:
        return data[technique_id]

    # 2. Parent technique fallback
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        if parent_id in data:
            entry = data[parent_id].copy()
            entry["_fallback"] = f"Parent technique {parent_id}"
            return entry

    # 3. Empty default
    return {
        "tools": [],
        "commands": [],
        "platforms": [],
        "_fallback": "No specific tools mapped",
    }


def get_tools_for_chain(attack_chain: list[dict]) -> list[dict]:
    results = []
    for step in attack_chain:
        tid = step.get("technique_id", "")
        tools = get_tools(tid)
        results.append({
            "step": step.get("step", 0),
            "technique_id": tid,
            "technique_name": step.get("technique_name", ""),
            "tools": tools,
        })
    return results
```

## G. Mitigation Mapper

File: $(System.Collections.Hashtable.Path)

```python
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

    # 2. Parent technique fallback (T1566.001 â†’ T1566)
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
```

## H. LLM Client

File: $(System.Collections.Hashtable.Path)

```python
"""
llm_client.py â€” Unified LLM API Client for Red ELISAR
=======================================================
Provides groq_chat_json() and mistral_chat_json() as thin,
retry-aware wrappers over the Groq and Mistral REST APIs.

Both functions return an LLMResult dataclass with:
  .content    â€” raw text from the model
  .usage      â€” {"prompt_tokens": int, "total_tokens": int, ...}
  .latency_s  â€” end-to-end request wall-clock time in seconds

Usage:
    from llm_client import groq_chat_json, mistral_chat_json

    result = groq_chat_json(messages=..., model=..., ...)
    print(result.content)
    print(result.latency_s)
"""

import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

import config

logger = logging.getLogger("red_elisar.llm_client")

# â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

GROQ_API_BASE    = "https://api.groq.com/openai/v1/chat/completions"
MISTRAL_API_BASE = "https://api.mistral.ai/v1/chat/completions"

# HTTP status codes that are retriable
_RETRY_STATUSES = {429, 500, 502, 503, 504}


# â”€â”€ Result dataclass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@dataclass
class LLMResult:
    """Returned by groq_chat_json / mistral_chat_json."""
    content:   str
    usage:     dict = field(default_factory=dict)
    latency_s: float = 0.0
    model:     str = ""
    raw:       Any = None          # full JSON response (for debugging)


# â”€â”€ Internal retry helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _post_with_retry(
    url: str,
    headers: dict,
    payload: dict,
    max_retries: int,
    base_backoff: float,
    max_backoff: float,
    jitter: float,
    max_429_wait: float,
    timeout: int,
) -> requests.Response:
    """POST with exponential backoff, honouring Retry-After on 429."""
    last_exc: Optional[Exception] = None
    for attempt in range(1, max_retries + 2):   # +1 for the initial attempt
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)

            if resp.status_code not in _RETRY_STATUSES:
                return resp   # success or non-retriable error

            # 429 â€” respect Retry-After if present
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", 0) or 0)
                if retry_after > max_429_wait:
                    raise RuntimeError(
                        f"API rate-limit retry-after={retry_after}s exceeds "
                        f"max_429_wait={max_429_wait}s â€” aborting."
                    )
                if retry_after > 0:
                    logger.warning("Rate-limited (429). Waiting %.1fs (Retry-After).", retry_after)
                    time.sleep(retry_after)
                    continue

            sleep = min(base_backoff * (2 ** (attempt - 1)), max_backoff)
            sleep += random.uniform(0, jitter)
            logger.warning(
                "HTTP %s â€” retrying in %.1fs (attempt %d/%d).",
                resp.status_code, sleep, attempt, max_retries + 1,
            )
            time.sleep(sleep)

        except requests.exceptions.RequestException as exc:
            last_exc = exc
            sleep = min(base_backoff * (2 ** (attempt - 1)), max_backoff)
            sleep += random.uniform(0, jitter)
            logger.warning("Request error: %s â€” retrying in %.1fs.", exc, sleep)
            time.sleep(sleep)

    if last_exc:
        raise last_exc
    raise RuntimeError(f"All {max_retries + 1} attempts to {url} failed.")


# â”€â”€ Groq (LLaMA 3) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def groq_chat_json(
    messages: list[dict],
    model: str = None,
    max_tokens: int = None,
    temperature: float = None,
    top_p: float = None,
    api_key: str = None,
    timeout: int = None,
    max_retries: int = None,
) -> LLMResult:
    """
    Call the Groq OpenAI-compatible chat endpoint.

    API key resolution order:
        1. api_key argument
        2. LLAMA3_API_KEY env var  (via config.LLAMA3_API_KEY)
        3. GROQ_API_KEY env var    (legacy fallback)

    Returns an LLMResult with .content, .usage, .latency_s.
    """
    _model       = model       or config.GROQ_MODEL
    _max_tokens  = max_tokens  if max_tokens  is not None else config.LLM_MAX_TOKENS
    _temperature = temperature if temperature is not None else config.LLM_TEMPERATURE
    _top_p       = top_p       if top_p       is not None else config.LLM_TOP_P
    _timeout     = timeout     if timeout     is not None else config.LLM_TIMEOUT
    _max_retries = max_retries if max_retries is not None else config.LLM_MAX_RETRIES

    _api_key = (
        api_key
        or config.LLAMA3_API_KEY
        or os.getenv("GROQ_API_KEY", "")
    ).strip()
    if not _api_key:
        raise RuntimeError(
            "Groq API key not set. "
            "Run: $env:LLAMA3_API_KEY = 'gsk_...'"
        )

    headers = {
        "Authorization": f"Bearer {_api_key}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":       _model,
        "messages":    messages,
        "max_tokens":  _max_tokens,
        "temperature": _temperature,
        "top_p":       _top_p,
    }

    logger.debug("Groq request: model=%s tokens=%s temp=%s", _model, _max_tokens, _temperature)
    t0 = time.perf_counter()

    resp = _post_with_retry(
        url           = GROQ_API_BASE,
        headers       = headers,
        payload       = payload,
        max_retries   = _max_retries,
        base_backoff  = config.LLM_RETRY_BASE_BACKOFF_S,
        max_backoff   = config.LLM_RETRY_MAX_BACKOFF_S,
        jitter        = config.LLM_RETRY_JITTER_S,
        max_429_wait  = config.LLM_MAX_429_WAIT_S,
        timeout       = _timeout,
    )
    latency = time.perf_counter() - t0

    if not resp.ok:
        raise RuntimeError(
            f"Groq API error {resp.status_code}: {resp.text[:400]}"
        )

    data    = resp.json()
    content = data["choices"][0]["message"]["content"]
    usage   = data.get("usage") or {}

    logger.debug(
        "Groq response: %d chars in %.2fs | tokens=%s",
        len(content), latency, usage.get("total_tokens"),
    )
    return LLMResult(content=content, usage=usage, latency_s=latency, model=_model, raw=data)


# â”€â”€ Mistral â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def mistral_chat_json(
    messages: list[dict],
    model: str = None,
    max_tokens: int = None,
    temperature: float = None,
    top_p: float = None,
    api_key: str = None,
    timeout: int = None,
    max_retries: int = None,
) -> LLMResult:
    """
    Call the Mistral AI chat endpoint.

    API key resolution order:
        1. api_key argument
        2. MISTRAL_API_KEY env var (via config.MISTRAL_API_KEY)

    Returns an LLMResult with .content, .usage, .latency_s.
    """
    _model       = model       or config.MISTRAL_MODEL
    _max_tokens  = max_tokens  if max_tokens  is not None else config.LLM_MAX_TOKENS
    _temperature = temperature if temperature is not None else config.LLM_TEMPERATURE
    _top_p       = top_p       if top_p       is not None else config.LLM_TOP_P
    _timeout     = timeout     if timeout     is not None else config.LLM_TIMEOUT
    _max_retries = max_retries if max_retries is not None else config.LLM_MAX_RETRIES

    _api_key = (
        api_key
        or config.MISTRAL_API_KEY
        or os.getenv("MISTRAL_API_KEY", "")
    ).strip()
    if not _api_key:
        raise RuntimeError(
            "Mistral API key not set. "
            "Run: $env:MISTRAL_API_KEY = 'WkMx...'"
        )

    headers = {
        "Authorization": f"Bearer {_api_key}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
    payload = {
        "model":       _model,
        "messages":    messages,
        "max_tokens":  _max_tokens,
        "temperature": _temperature,
        "top_p":       _top_p,
    }

    logger.debug("Mistral request: model=%s tokens=%s temp=%s", _model, _max_tokens, _temperature)
    t0 = time.perf_counter()

    resp = _post_with_retry(
        url           = MISTRAL_API_BASE,
        headers       = headers,
        payload       = payload,
        max_retries   = _max_retries,
        base_backoff  = config.LLM_RETRY_BASE_BACKOFF_S,
        max_backoff   = config.LLM_RETRY_MAX_BACKOFF_S,
        jitter        = config.LLM_RETRY_JITTER_S,
        max_429_wait  = config.LLM_MAX_429_WAIT_S,
        timeout       = _timeout,
    )
    latency = time.perf_counter() - t0

    if not resp.ok:
        raise RuntimeError(
            f"Mistral API error {resp.status_code}: {resp.text[:400]}"
        )

    data    = resp.json()
    content = data["choices"][0]["message"]["content"]
    usage   = data.get("usage") or {}

    logger.debug(
        "Mistral response: %d chars in %.2fs | tokens=%s",
        len(content), latency, usage.get("total_tokens"),
    )
    return LLMResult(content=content, usage=usage, latency_s=latency, model=_model, raw=data)
```

## I. Attack Chain Generator

File: $(System.Collections.Hashtable.Path)

```python
import json
import time
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import config
from rag.vector_store_faiss import FAISSVectorStore
from rag.rag_engine import RAGEngine

logger = logging.getLogger("red_elisar.chain_generator")


PREDEFINED_SCENARIOS = {
    "apt_phishing_to_exfil": {
        "scenario": (
            "Advanced persistent threat group targets a corporate enterprise network. "
            "The attack begins with spear-phishing emails containing weaponized Office documents, "
            "establishes persistence through scheduled tasks and registry modifications, "
            "escalates privileges via token manipulation, performs Active Directory reconnaissance, "
            "moves laterally using pass-the-hash, and exfiltrates sensitive data over encrypted C2 channels."
        ),
        "target_environment": "Enterprise Windows Active Directory network with Exchange email servers",
        "chain_length": 7,
    },
    "insider_threat": {
        "scenario": (
            "A malicious insider with valid credentials attempts to escalate access, "
            "disable security monitoring, access restricted file shares, "
            "and exfiltrate intellectual property while evading detection."
        ),
        "target_environment": "Corporate Windows environment with DLP and SIEM monitoring",
        "chain_length": 5,
    },
    "ransomware_attack": {
        "scenario": (
            "Ransomware operator gains initial access through exposed RDP service, "
            "disables antivirus and endpoint detection, deploys ransomware across the network "
            "using PsExec and Group Policy, and encrypts critical data for extortion."
        ),
        "target_environment": "Healthcare organization with Windows servers and workstations",
        "chain_length": 6,
    },
    "supply_chain": {
        "scenario": (
            "Adversary compromises a software supply chain by injecting malicious code into "
            "a trusted software update mechanism, achieving code execution on downstream targets, "
            "establishing covert persistence, and collecting sensitive data."
        ),
        "target_environment": "Enterprise environment with automated software deployment pipeline",
        "chain_length": 5,
    },
    "cloud_hybrid": {
        "scenario": (
            "Attacker targets a hybrid cloud environment by exploiting web application vulnerabilities, "
            "stealing cloud credentials, moving from on-premises to cloud infrastructure, "
            "and accessing cloud storage containing sensitive data."
        ),
        "target_environment": "Hybrid enterprise with on-premises Active Directory and cloud services",
        "chain_length": 6,
    },
}


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

## J. Input Sanitizer

File: $(System.Collections.Hashtable.Path)

```python
import re
import logging

logger = logging.getLogger("red_elisar.sanitizer")

MAX_INPUT_LENGTH = 2000

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?(previous|prior|above)",
    r"you\s+are\s+now\s+a",
    r"act\s+as\s+(a|an)\s+",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*",
    r"<\s*/?script",
    r"<\s*/?iframe",
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"override\s+(system|instructions?)",
    r"jailbreak",
    r"DAN\s+mode",
    r"developer\s+mode",
]

# Compile patterns once for performance
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
_HTML_TAG_RE       = re.compile(r"<[^>]+>")
_CONTROL_CHAR_RE   = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_scenario(text: str) -> str:
    if not text or not text.strip():
        raise ValueError("Scenario input cannot be empty.")

    original_length = len(text)

    # 1. Truncate if too long
    if len(text) > MAX_INPUT_LENGTH:
        text = text[:MAX_INPUT_LENGTH]
        logger.warning(f"Input truncated: {original_length} -> {MAX_INPUT_LENGTH} chars")

    # 2. Remove control characters
    text = _CONTROL_CHAR_RE.sub("", text)

    # 3. Strip HTML/XML tags
    cleaned = _HTML_TAG_RE.sub("", text)
    if cleaned != text:
        logger.warning("HTML tags stripped from input")
        text = cleaned

    # 4. Detect and redact injection patterns
    detected = []
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(text)
        if match:
            detected.append(match.group())
            text = pattern.sub("[REDACTED]", text)

    if detected:
        logger.warning(f"Prompt injection patterns detected and redacted: {detected}")

    # Final validation
    text = text.strip()
    if not text:
        raise ValueError("Scenario input is empty after sanitization.")

    return text
```

## K. Live Vulnerability Checker

File: $(System.Collections.Hashtable.Path)

```python
"""
live_vuln_checker.py â€” Real-Time Live Vulnerability Checker for Red ELISAR
============================================================================
Actively probes a running web application to discover vulnerabilities IN REAL
TIME. Unlike the static vuln_scanner.py which analyses recon data, this module
sends actual HTTP payloads and observes live responses to confirm whether a
vulnerability really exists in the running application.

Checks performed (all dynamic, runtime-confirmed):
  1.  SQL Injection â€” injects classic SQLi payloads and inspects responses
  2.  Reflected XSS â€” tests script injection payloads and looks for reflection
  3.  Blind XSS markers â€” sends canary strings and watches for them in output
  4.  Open Redirect â€” feeds external URLs to redirect parameters
  5.  Sensitive File Disclosure â€” probes well-known dangerous paths
  6.  Authentication Bypass (SQLi login) â€” tests auth bypass via SQLi
  7.  Unauthenticated Admin Access â€” tries admin-panel paths without credentials
  8.  HTTP Security Header Audit â€” live header capture and gap analysis
  9.  Information Disclosure via Errors â€” triggers 500 errors and inspects leaks
 10.  CORS Wildcard Misconfiguration â€” sends custom Origin and checks response
 11.  Server / Technology Banner Leakage â€” fingerprints from live response headers
 12.  Session Fixation / Cookie Flags â€” checks cookie security attributes

Every finding is confirmed from a LIVE HTTP response â€” nothing is assumed.
Results are suitable for feeding into the MITRE ATT&CK mapper and report generator.

Usage:
  python live_vuln_checker.py http://127.0.0.1:5000
  python live_vuln_checker.py http://127.0.0.1:5000 --output-json my_results.json
    python live_vuln_checker.py http://127.0.0.1:5000 --output-md my_results.md
"""

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# â”€â”€ ensure parent package is importable â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
sys.path.insert(0, str(Path(__file__).parent.resolve()))

logger = logging.getLogger("red_elisar.live_vuln_checker")

# â”€â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# SQLi payloads: (payload, description)
SQLI_PAYLOADS = [
    ("' OR '1'='1", "Classic OR tautology"),
    ("' OR 1=1--",  "Commenting remainder with OR tautology"),
    ("' UNION SELECT NULL--", "UNION probe (1 column)"),
    ("' UNION SELECT NULL,NULL--", "UNION probe (2 columns)"),
    ("' UNION SELECT id,username,password,email FROM users--",
     "UNION dump users (4 col)"),
    ("1; DROP TABLE users--", "Stacked query attempt"),
    ("' AND SLEEP(0)--", "Time-based injection probe (SQLite)"),
    ("' OR SUBSTR(username,1,1)='a'--", "Boolean-based blind injection"),
]

# XSS payloads: (payload, marker_to_look_for)
XSS_PAYLOADS = [
    ("<script>alert('XSS_1')</script>",   "XSS_1"),
    ("<img src=x onerror=alert('XSS_2')>", "XSS_2"),
    ("<svg onload=alert('XSS_3')>",        "XSS_3"),
    ("javascript:alert('XSS_4')",          "XSS_4"),
    ("\"><script>alert('XSS_5')</script>",  "XSS_5"),
    ("'><script>prompt('XSS_6')</script>",  "XSS_6"),
]

# Sensitive paths (probed live and observed for actual HTTP 200/302)
SENSITIVE_PATHS = [
    ("/.env",          "CRITICAL", "CWE-312", "T1552.001", "Exposed .env file with credentials"),
    ("/backup",        "CRITICAL", "CWE-312", "T1552",     "Exposed backup file/directory"),
    ("/.git/config",   "CRITICAL", "CWE-312", "T1213",     "Exposed .git repository config"),
    ("/admin",         "HIGH",     "CWE-284", "T1078",     "Unauthenticated admin panel access"),
    ("/api/users",     "CRITICAL", "CWE-306", "T1078",     "Unauthenticated user data API"),
    ("/phpinfo.php",   "HIGH",     "CWE-200", "T1592",     "phpinfo() information disclosure"),
    ("/server-status", "MEDIUM",   "CWE-200", "T1592",     "Apache server-status page"),
    ("/.htaccess",     "MEDIUM",   "CWE-200", "T1592",     ".htaccess configuration exposed"),
    ("/debug",         "CRITICAL", "CWE-94",  "T1190",     "Debug endpoint enabled"),
    ("/actuator",      "HIGH",     "CWE-284", "T1190",     "Spring Boot actuator exposed"),
    ("/swagger.json",  "MEDIUM",   "CWE-200", "T1592",     "Swagger API documentation exposed"),
    ("/robots.txt",    "INFO",     "CWE-200", "T1592",     "robots.txt reveals hidden paths"),
    ("/sitemap.xml",   "INFO",     "CWE-200", "T1592",     "sitemap.xml reveals all endpoints"),
    ("/config",        "HIGH",     "CWE-200", "T1552",     "Config directory accessible"),
]

# Required security headers
REQUIRED_HEADERS = {
    "Content-Security-Policy":   ("HIGH",   "CWE-79",   "T1059.007"),
    "Strict-Transport-Security": ("HIGH",   "CWE-311",  "T1557"),
    "X-Frame-Options":           ("MEDIUM", "CWE-1021", "T1185"),
    "X-Content-Type-Options":    ("MEDIUM", "CWE-430",  "T1204"),
    "Referrer-Policy":           ("LOW",    "CWE-200",  "T1592"),
    "Permissions-Policy":        ("LOW",    "CWE-693",  "T1562"),
}

# Open redirect test vectors
REDIRECT_PARAMS = [
    ("url",    "http://evil-attacker.example.com"),
    ("next",   "http://evil-attacker.example.com"),
    ("return", "//evil-attacker.example.com"),
    ("redirect", "https://evil-attacker.example.com"),
]


# â”€â”€â”€ Session Helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_session(timeout: int = 10) -> requests.Session:
    """Create a resilient requests session with retry logic."""
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "RedELISAR-LiveVulnChecker/2.0"})
    session.timeout = timeout
    return session


def render_markdown_report(report: dict) -> str:
    """Render a clear Markdown report from a live scan report dict."""
    vulnerabilities = report.get("vulnerabilities", [])
    severity_counts = report.get("severity_counts", {})

    lines = []
    lines.append("# Red ELISAR - Live Vulnerability Scan Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Target URL: {report.get('target_url', 'N/A')}")
    lines.append(f"- Scan Timestamp (UTC): {report.get('scan_timestamp', 'N/A')}")
    lines.append(f"- Elapsed Seconds: {report.get('elapsed_seconds', 'N/A')}")
    lines.append(f"- Total Findings: {report.get('total_findings', 0)}")
    lines.append(f"- Overall Risk: {report.get('overall_risk', 'N/A')}")
    lines.append(f"- Scan Method: {report.get('method', 'N/A')}")
    lines.append("")

    if "error" in report:
        lines.append("## Error")
        lines.append("")
        lines.append(f"{report['error']}")
        lines.append("")

    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {severity_counts.get(sev, 0)} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not vulnerabilities:
        lines.append("No vulnerabilities found.")
        lines.append("")
    else:
        for i, v in enumerate(vulnerabilities, 1):
            lines.append(f"### {i}. {v.get('type', 'Unknown')} [{v.get('severity', 'N/A')}]")
            lines.append("")
            lines.append(f"- Detail: {v.get('detail', 'N/A')}")
            lines.append(f"- CWE: {v.get('cwe_id', 'N/A')}")
            lines.append(f"- MITRE Hint: {v.get('mitre_hint', 'N/A')}")
            lines.append(f"- Confirmed Live: {v.get('confirmed_live', False)}")
            lines.append(f"- Evidence: {v.get('evidence', 'N/A')}")
            lines.append(f"- Recommendation: {v.get('recommendation', 'N/A')}")
            lines.append("")

    return "\n".join(lines)


# â”€â”€â”€ Core Live Vulnerability Checker â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class LiveVulnChecker:
    """
    Real-time, active vulnerability checker for a live web application.

    Every finding is confirmed from an actual live HTTP response; there are
    no hard-coded or assumed results. The checker adapts to whatever the
    target returns.
    """

    def __init__(self, target_url: str, timeout: int = 10):
        self.target   = target_url.rstrip("/")
        self.timeout  = timeout
        self.session  = _make_session(timeout)
        self.findings: list[dict] = []
        self.scan_start = datetime.now(timezone.utc).isoformat()
        self._parse_target()

    def _parse_target(self):
        parsed = urlparse(self.target)
        self.scheme = parsed.scheme
        self.host   = parsed.netloc
        self.path   = parsed.path or "/"

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Public API
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def run_full_check(self) -> dict:
        """
        Execute all real-time vulnerability checks and return a structured
        report. Nothing is assumed â€” every finding is confirmed live.
        """
        t_start = time.perf_counter()
        print(f"\n{'='*65}")
        print(f"  RED ELISAR â€” LIVE VULNERABILITY CHECKER")
        print(f"  Target : {self.target}")
        print(f"  Time   : {self.scan_start}")
        print(f"{'='*65}\n")

        # Verify reachability first
        if not self._verify_reachable():
            return self._build_report(elapsed=time.perf_counter() - t_start,
                                       error="Target not reachable")

        # Run all checks in sequence
        checks = [
            ("[1/12] Security Headers",          self._check_security_headers),
            ("[2/12] Server Banner Leakage",      self._check_server_banners),
            ("[3/12] CORS Misconfiguration",      self._check_cors),
            ("[4/12] Sensitive File Disclosure",  self._check_sensitive_paths),
            ("[5/12] SQL Injection",              self._check_sql_injection),
            ("[6/12] Reflected XSS",             self._check_xss),
            ("[7/12] Open Redirect",             self._check_open_redirect),
            ("[8/12] Auth Bypass (SQLi Login)",  self._check_auth_bypass),
            ("[9/12] Unauthenticated Admin",     self._check_unauth_admin),
            ("[10/12] Error Information Leakage", self._check_error_leakage),
            ("[11/12] Cookie Security Flags",    self._check_cookie_flags),
            ("[12/12] HTTP vs HTTPS",            self._check_http_scheme),
        ]

        for label, fn in checks:
            print(f"  {label} ...", end="", flush=True)
            try:
                fn()
                count_for_step = sum(
                    1 for f in self.findings
                    if f.get("_check") == fn.__name__
                )
                print(f" {'FOUND ' + str(count_for_step) if count_for_step else 'clean'}")
            except Exception as e:
                logger.warning(f"Check failed ({label}): {e}")
                print(f" ERROR: {e}")

        elapsed = time.perf_counter() - t_start
        report  = self._build_report(elapsed=elapsed)
        self._print_summary(report)
        return report

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Individual Live Checks
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _verify_reachable(self) -> bool:
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            logger.info(f"Target reachable â€” HTTP {resp.status_code}")
            return True
        except Exception as e:
            logger.error(f"Target unreachable: {e}")
            return False

    # â”€â”€ 1. Security Header Audit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_security_headers(self):
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            headers = resp.headers
            for header, (severity, cwe, mitre) in REQUIRED_HEADERS.items():
                if header not in headers:
                    self._add(
                        vuln_type  = "Missing Security Header",
                        detail     = f"HTTP response is missing the '{header}' header",
                        severity   = severity,
                        cwe        = cwe,
                        mitre      = mitre,
                        evidence   = f"Header '{header}' absent in live response from {self.target}",
                        check      = "_check_security_headers",
                        confirmed  = True,
                        recommendation = (
                            f"Add '{header}' to all HTTP responses. "
                            f"Example config depends on your web server / framework."
                        ),
                    )
        except Exception as e:
            logger.debug(f"Header check error: {e}")

    # â”€â”€ 2. Server Banner Leakage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_server_banners(self):
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            h = resp.headers
            leaky = {
                "Server":       h.get("Server"),
                "X-Powered-By": h.get("X-Powered-By"),
                "X-App-Version":h.get("X-App-Version"),
                "X-AspNet-Version": h.get("X-AspNet-Version"),
            }
            for hname, hval in leaky.items():
                if hval:
                    self._add(
                        vuln_type  = "Information Disclosure (Banner)",
                        detail     = f"Header '{hname}' reveals technology: '{hval}'",
                        severity   = "MEDIUM",
                        cwe        = "CWE-200",
                        mitre      = "T1592",
                        evidence   = f"Live response header â†’ {hname}: {hval}",
                        check      = "_check_server_banners",
                        confirmed  = True,
                        recommendation = f"Remove or generalize the '{hname}' response header.",
                    )
        except Exception as e:
            logger.debug(f"Banner check error: {e}")

    # â”€â”€ 3. CORS Misconfiguration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_cors(self):
        try:
            resp = self.session.get(
                self.target,
                headers={"Origin": "https://evil-attacker.example.com"},
                timeout=self.timeout,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self._add(
                    vuln_type  = "CORS Wildcard Misconfiguration",
                    detail     = "Server allows cross-origin requests from ANY domain (*)",
                    severity   = "HIGH",
                    cwe        = "CWE-942",
                    mitre      = "T1557",
                    evidence   = f"Live response: Access-Control-Allow-Origin: {acao}",
                    check      = "_check_cors",
                    confirmed  = True,
                    recommendation = (
                        "Replace '*' with specific trusted origins. "
                        "Never combine wildcard CORS with cookies/credentials."
                    ),
                )
            elif "evil-attacker.example.com" in acao:
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                self._add(
                    vuln_type  = "CORS Origin Reflection",
                    detail     = "Server reflects attacker Origin back â€” CORS misconfigured",
                    severity   = severity,
                    cwe        = "CWE-942",
                    mitre      = "T1557",
                    evidence   = (f"Sent Origin: evil-attacker.example.com â†’ "
                                  f"Got ACAO: {acao}, ACAC: {acac}"),
                    check      = "_check_cors",
                    confirmed  = True,
                    recommendation = (
                        "Maintain and validate a strict allowlist of trusted origins. "
                        "Reject requests from unknown origins."
                    ),
                )
        except Exception as e:
            logger.debug(f"CORS check error: {e}")

    # â”€â”€ 4. Sensitive File Disclosure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_sensitive_paths(self):
        for path, severity, cwe, mitre, desc in SENSITIVE_PATHS:
            try:
                url  = f"{self.target}{path}"
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
                if resp.status_code == 200:
                    preview = resp.text[:300].strip().replace("\n", " ")
                    self._add(
                        vuln_type  = "Sensitive File / Path Disclosure",
                        detail     = f"Path '{path}' returned HTTP 200 â€” {desc}",
                        severity   = severity,
                        cwe        = cwe,
                        mitre      = mitre,
                        evidence   = f"GET {url} â†’ 200 OK | Preview: {preview[:120]}...",
                        check      = "_check_sensitive_paths",
                        confirmed  = True,
                        recommendation = (
                            f"Remove or protect '{path}'. Ensure sensitive files are "
                            f"outside the web root and access-controlled."
                        ),
                    )
                elif resp.status_code in (301, 302):
                    loc = resp.headers.get("Location", "")
                    self._add(
                        vuln_type  = "Sensitive Path Redirect",
                        detail     = (f"Path '{path}' redirects (may be accessible): "
                                      f"â†’ {loc}"),
                        severity   = "LOW",
                        cwe        = cwe,
                        mitre      = mitre,
                        evidence   = f"GET {url} â†’ {resp.status_code} â†’ Location: {loc}",
                        check      = "_check_sensitive_paths",
                        confirmed  = True,
                        recommendation = f"Verify whether '{path}' is accessible after redirect.",
                    )
            except Exception:
                continue

    # â”€â”€ 5. SQL Injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_sql_injection(self):
        """
        Probes GET parameters on known/discovered endpoints with SQLi payloads.
        Detects: error-based, UNION-based, and data-exposure confirmation.
        """
        # Endpoints with known injectable parameters to probe
        probe_targets = [
            (f"{self.target}/search",  "q"),
            (f"{self.target}/login",   None),  # POST â€” handled separately
        ]

        sql_error_patterns = [
            r"sqlite",
            r"syntax error",
            r"unrecognized token",
            r"sql",
            r"mysql",
            r"postgre",
            r"ORA-",
            r"microsoft.*odbc",
            r"query was:",
            r"database error",
        ]

        for endpoint, param in probe_targets:
            if param is None:
                continue
            for payload, payload_desc in SQLI_PAYLOADS:
                try:
                    params = {param: payload}
                    resp   = self.session.get(endpoint, params=params,
                                              timeout=self.timeout)
                    body   = resp.text.lower()

                    # Error-based detection
                    for pattern in sql_error_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            self._add(
                                vuln_type  = "SQL Injection (Error-Based)",
                                detail     = (
                                    f"SQLi payload '{payload}' on {endpoint}?{param}=... "
                                    f"triggered SQL error pattern '{pattern}' in live response"
                                ),
                                severity   = "CRITICAL",
                                cwe        = "CWE-89",
                                mitre      = "T1190",
                                evidence   = (
                                    f"GET {endpoint}?{param}={payload[:60]} â†’ "
                                    f"HTTP {resp.status_code} | Matched: {pattern}"
                                ),
                                check      = "_check_sql_injection",
                                confirmed  = True,
                                recommendation = (
                                    "Use parameterised queries / prepared statements. "
                                    "NEVER concatenate user input into SQL strings."
                                ),
                            )
                            break  # One finding per payload is enough

                    # Data-exfiltration confirmation (UNION dump)
                    if "UNION SELECT" in payload.upper():
                        if re.search(r"admin\d*@", body) or "admin123" in body:
                            self._add(
                                vuln_type  = "SQL Injection (UNION â€” Data Exfiltrated)",
                                detail     = (
                                    f"UNION payload successfully retrieved user table data "
                                    f"via {endpoint}?{param}"
                                ),
                                severity   = "CRITICAL",
                                cwe        = "CWE-89",
                                mitre      = "T1190",
                                evidence   = (
                                    f"Live response contains user credentials extracted from DB. "
                                    f"Payload: {payload[:80]}"
                                ),
                                check      = "_check_sql_injection",
                                confirmed  = True,
                                recommendation = (
                                    "Immediate remediation: parameterise all queries. "
                                    "Rotate all credentials exposed in this database."
                                ),
                            )
                except Exception:
                    continue

    # â”€â”€ 6. Reflected XSS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_xss(self):
        """
        Sends XSS payloads to endpoints and confirms reflection in the live
        HTTP response body.
        """
        probe_targets = [
            (f"{self.target}/greet",  "name"),
            (f"{self.target}/search", "q"),
        ]
        for endpoint, param in probe_targets:
            for payload, marker in XSS_PAYLOADS:
                try:
                    params = {param: payload}
                    resp   = self.session.get(endpoint, params=params,
                                              timeout=self.timeout)
                    # Check if the raw payload (or a significant part) appears
                    # verbatim in the response â€” confirming reflection
                    if marker in resp.text or payload[:20] in resp.text:
                        self._add(
                            vuln_type  = "Reflected Cross-Site Scripting (XSS)",
                            detail     = (
                                f"XSS payload reflected unescaped on "
                                f"{endpoint}?{param}=<payload>"
                            ),
                            severity   = "HIGH",
                            cwe        = "CWE-79",
                            mitre      = "T1059.007",
                            evidence   = (
                                f"Sent: {payload[:60]} | "
                                f"Marker '{marker}' found verbatim in live HTTP response"
                            ),
                            check      = "_check_xss",
                            confirmed  = True,
                            recommendation = (
                                "HTML-escape all user input before rendering. "
                                "Use template engines with auto-escaping (e.g., Jinja2 with |e)."
                            ),
                        )
                        break  # One XSS per endpoint is enough
                except Exception:
                    continue

    # â”€â”€ 7. Open Redirect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_open_redirect(self):
        for param, evil_url in REDIRECT_PARAMS:
            test_url = f"{self.target}/redirect"
            try:
                resp = self.session.get(
                    test_url,
                    params={param: evil_url},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    # Confirm it actually redirects to the evil URL (or domain)
                    if "evil-attacker" in location or location.startswith("http"):
                        parsed_loc = urlparse(location)
                        if parsed_loc.netloc and parsed_loc.netloc != urlparse(self.target).netloc:
                            self._add(
                                vuln_type  = "Open Redirect",
                                detail     = (
                                    f"Parameter '{param}' on /redirect causes unvalidated "
                                    f"redirect to external domain: {location}"
                                ),
                                severity   = "MEDIUM",
                                cwe        = "CWE-601",
                                mitre      = "T1204",
                                evidence   = (
                                    f"GET /redirect?{param}={evil_url} â†’ "
                                    f"HTTP {resp.status_code} Location: {location}"
                                ),
                                check      = "_check_open_redirect",
                                confirmed  = True,
                                recommendation = (
                                    "Validate redirect destinations against a whitelist. "
                                    "Never redirect to user-supplied external URLs."
                                ),
                            )
                            break
            except Exception:
                continue

    # â”€â”€ 8. Authentication Bypass via SQLi â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_auth_bypass(self):
        """
        Attempts login with SQLi payloads to confirm authentication bypass.
        """
        login_url   = f"{self.target}/login"
        bypass_payloads = [
            ("' OR '1'='1'--",  "Classic tautology bypass"),
            ("admin'--",         "Comment-out password bypass"),
            ("' OR 1=1--",       "Numeric OR tautology"),
        ]
        for username_payload, desc in bypass_payloads:
            try:
                data = {"username": username_payload, "password": "anything"}
                resp = self.session.post(login_url, data=data,
                                         timeout=self.timeout)
                body = resp.text
                # Confirmed if the response shows a successful login message
                if re.search(r"logged in as|welcome.*admin|id=", body, re.IGNORECASE):
                    self._add(
                        vuln_type  = "Authentication Bypass via SQL Injection",
                        detail     = (
                            f"Login form bypassed using SQLi payload: '{username_payload}' "
                            f"â€” {desc}. Response confirms successful login."
                        ),
                        severity   = "CRITICAL",
                        cwe        = "CWE-287",
                        mitre      = "T1078",
                        evidence   = (
                            f"POST /login username='{username_payload}' password='anything' "
                            f"â†’ HTTP {resp.status_code} | Response: "
                            + body[body.lower().find("logged"):body.lower().find("logged")+80]
                        ),
                        check      = "_check_auth_bypass",
                        confirmed  = True,
                        recommendation = (
                            "Use parameterised queries for all authentication checks. "
                            "Implement account lockout and rate limiting."
                        ),
                    )
                    break
            except Exception:
                continue

    # â”€â”€ 9. Unauthenticated Admin Access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_unauth_admin(self):
        admin_paths = ["/admin", "/admin/", "/admin/panel",
                       "/administrator", "/management"]
        for path in admin_paths:
            try:
                resp = self.session.get(
                    f"{self.target}{path}",
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Confirm it's actually an admin panel, not a generic 200
                    admin_keywords = ["admin", "panel", "management",
                                      "system", "dashboard", "user"]
                    if any(kw in body for kw in admin_keywords):
                        self._add(
                            vuln_type  = "Unauthenticated Admin Panel Access",
                            detail     = (
                                f"Admin path '{path}' returns HTTP 200 without any "
                                f"authentication credentials"
                            ),
                            severity   = "CRITICAL",
                            cwe        = "CWE-284",
                            mitre      = "T1078",
                            evidence   = (
                                f"GET {self.target}{path} â†’ HTTP 200 | "
                                f"Admin keywords confirmed in live response body"
                            ),
                            check      = "_check_unauth_admin",
                            confirmed  = True,
                            recommendation = (
                                "Protect all admin routes with strong authentication "
                                "and role-based access control."
                            ),
                        )
                        break
            except Exception:
                continue

    # â”€â”€ 10. Error / Stack Trace Information Leakage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_error_leakage(self):
        error_urls = [
            f"{self.target}/error_test",
            f"{self.target}/nonexistent_path_xyz",
            f"{self.target}/search?q=" + "' AND 1=CONVERT(int,'error')--",
        ]
        leak_patterns = [
            (r"traceback",       "Python traceback exposed"),
            (r"werkzeug",        "Werkzeug/Flask debug info exposed"),
            (r"ZeroDivisionError", "Python exception class name visible"),
            (r"Internal Server Error.*File.*line \d+",
             "Stack frame with file/line info exposed"),
            (r"query was:",      "Raw SQL query exposed in error message"),
            (r"syntax error",    "Database error message exposed"),
        ]
        for url in error_urls:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code in (500, 400, 200):
                    for pattern, desc in leak_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self._add(
                                vuln_type  = "Error / Stack Trace Information Leakage",
                                detail     = f"{desc} at {url}",
                                severity   = "HIGH",
                                cwe        = "CWE-209",
                                mitre      = "T1592",
                                evidence   = (
                                    f"GET {url} â†’ HTTP {resp.status_code} | "
                                    f"Pattern '{pattern}' matched in live response"
                                ),
                                check      = "_check_error_leakage",
                                confirmed  = True,
                                recommendation = (
                                    "Disable debug mode and custom error handlers. "
                                    "Return generic 500 pages in production. "
                                    "Never expose stack traces to end users."
                                ),
                            )
                            break
            except Exception:
                continue

    # â”€â”€ 11. Cookie Security Flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_cookie_flags(self):
        try:
            resp = self.session.get(f"{self.target}/login",
                                     timeout=self.timeout)
            # Make a POST to get a Set-Cookie header
            post_resp = self.session.post(
                f"{self.target}/login",
                data={"username": "admin", "password": "admin123"},
                timeout=self.timeout,
            )
            for r in [resp, post_resp]:
                set_cookie = r.headers.get("Set-Cookie", "")
                if set_cookie:
                    issues = []
                    if "HttpOnly" not in set_cookie:
                        issues.append("Missing HttpOnly flag â€” cookie accessible via JS")
                    if "Secure" not in set_cookie:
                        issues.append("Missing Secure flag â€” cookie sent over HTTP")
                    if "SameSite" not in set_cookie:
                        issues.append("Missing SameSite flag â€” CSRF risk")
                    for issue in issues:
                        self._add(
                            vuln_type  = "Insecure Cookie Configuration",
                            detail     = issue,
                            severity   = "MEDIUM",
                            cwe        = "CWE-614",
                            mitre      = "T1185",
                            evidence   = f"Live Set-Cookie header: {set_cookie[:120]}",
                            check      = "_check_cookie_flags",
                            confirmed  = True,
                            recommendation = (
                                "Set cookies with: HttpOnly; Secure; SameSite=Strict "
                                "(or Lax for SSO)."
                            ),
                        )
                    if issues:
                        break
        except Exception as e:
            logger.debug(f"Cookie flag check error: {e}")

    # â”€â”€ 12. HTTP Scheme Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_http_scheme(self):
        if self.scheme == "http":
            self._add(
                vuln_type  = "Unencrypted HTTP (No TLS)",
                detail     = (
                    "Application is served over plain HTTP â€” all traffic "
                    "including credentials is transmitted in cleartext"
                ),
                severity   = "CRITICAL",
                cwe        = "CWE-319",
                mitre      = "T1557",
                evidence   = f"Target URL scheme is 'http://' â€” confirmed from {self.target}",
                check      = "_check_http_scheme",
                confirmed  = True,
                recommendation = (
                    "Deploy TLS (HTTPS) via a certificate authority (e.g. Let's Encrypt). "
                    "Configure HSTS after enabling HTTPS."
                ),
            )

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Internal helpers
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add(self, vuln_type: str, detail: str, severity: str,
             cwe: str, mitre: str, evidence: str, check: str,
             confirmed: bool, recommendation: str):
        """Add a confirmed finding (de-duplicated by vuln_type + detail)."""
        key = f"{vuln_type}::{detail[:60]}"
        already = any(
            f"{f['type']}::{f['detail'][:60]}" == key
            for f in self.findings
        )
        if not already:
            self.findings.append({
                "type":           vuln_type,
                "detail":         detail,
                "severity":       severity,
                "cwe_id":         cwe,
                "mitre_hint":     mitre,
                "evidence":       evidence,
                "confirmed_live": confirmed,
                "recommendation": recommendation,
                "_check":         check,
            })

    def _build_report(self, elapsed: float, error: str = None) -> dict:
        """Build and return the structured report dict."""
        # Remove internal _check keys for clean output
        clean_findings = [
            {k: v for k, v in f.items() if k != "_check"}
            for f in sorted(
                self.findings,
                key=lambda x: SEVERITY_ORDER.get(x["severity"], 99),
            )
        ]
        stats = {sev: 0 for sev in SEVERITY_ORDER}
        for f in clean_findings:
            stats[f["severity"]] = stats.get(f["severity"], 0) + 1

        overall_risk = "INFO"
        if stats["CRITICAL"] > 0:
            overall_risk = "CRITICAL"
        elif stats["HIGH"] >= 2:
            overall_risk = "HIGH"
        elif stats["HIGH"] >= 1 or stats["MEDIUM"] >= 3:
            overall_risk = "MEDIUM"
        elif stats["MEDIUM"] > 0:
            overall_risk = "LOW"

        report = {
            "target_url":       self.target,
            "scan_timestamp":   self.scan_start,
            "elapsed_seconds":  round(elapsed, 2),
            "total_findings":   len(clean_findings),
            "severity_counts":  stats,
            "overall_risk":     overall_risk,
            "vulnerabilities":  clean_findings,
            "method":           "LIVE_ACTIVE_SCAN",
            "confirmed_live":   True,
        }
        if error:
            report["error"] = error
        return report

    def _print_summary(self, report: dict):
        stats = report["severity_counts"]
        print(f"\n{'='*65}")
        print(f"  LIVE SCAN COMPLETE â€” {report['total_findings']} vulnerabilities found")
        print(f"  Overall Risk : {report['overall_risk']}")
        print(f"  CRITICAL={stats['CRITICAL']}  HIGH={stats['HIGH']}  "
              f"MEDIUM={stats['MEDIUM']}  LOW={stats['LOW']}")
        print(f"  Scan Time    : {report['elapsed_seconds']}s")
        print(f"{'='*65}\n")
        print("  Top Findings:")
        for v in report["vulnerabilities"][:10]:
            icon = {"CRITICAL": "critical", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                    "LOW": "LOW", "INFO": "INFO"}.get(v["severity"], "â€¢")
            print(f"  {icon} [{v['severity']}] {v['type']}")
            print(f"       {v['detail'][:90]}")
            print(f"       Evidence: {v['evidence'][:80]}")
            print()


# â”€â”€â”€ Standalone CLI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def main():
    parser = argparse.ArgumentParser(
        description="Red ELISAR â€” Real-Time Live Vulnerability Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python live_vuln_checker.py http://127.0.0.1:5000
  python live_vuln_checker.py http://127.0.0.1:5000 --output-json results.json
    python live_vuln_checker.py http://127.0.0.1:5000 --output-md results.md
    python live_vuln_checker.py http://127.0.0.1:5000 --output-json results.json --output-md report.md
  python live_vuln_checker.py http://127.0.0.1:5000 --timeout 15
        """,
    )
    parser.add_argument("url",
                        help="Target URL of the running web application")
    parser.add_argument("--output-json", "-o",
                        default=None,
                        help="Path to save JSON results (optional)")
    parser.add_argument("--output-md", "-m",
                        default=None,
                        help="Path to save Markdown report (optional)")
    parser.add_argument("--timeout", "-t",
                        type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )
    # Suppress noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    checker = LiveVulnChecker(args.url, timeout=args.timeout)
    report  = checker.run_full_check()

    if args.output_json:
        out_path = Path(args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\n  âœ… Results saved to: {out_path}")

    md_path = None
    if args.output_md:
        md_path = Path(args.output_md)
    elif args.output_json:
        md_path = Path(args.output_json).with_suffix(".md")

    if md_path is not None:
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown_report(report), encoding="utf-8")
        print(f"  âœ… Markdown report saved to: {md_path}")

    if not args.output_json and md_path is None:
        print("\n  Full JSON Report:")
        print(json.dumps(report, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## L. Targeted Attack Scanner

File: $(System.Collections.Hashtable.Path)

```python
"""
targeted_attack_scanner.py â€” Live Vulnerability Probe for Red ELISAR
=====================================================================
When a --scenario command is run with --target-url, this module:
  1. Reads keywords from the scenario text to detect the attack type
  2. Sends real HTTP probes to the target URL
  3. Returns confirmed vulnerability evidence for the MD report

Supported attack types (auto-detected from scenario keywords):
  xss             â†’ Reflected XSS at /greet?name=
  sql_injection   â†’ SQLi at /search and /login
  exposed_files   â†’ /.env, /backup, /api/users, /admin
  open_redirect   â†’ /redirect?url=
  cors            â†’ Access-Control-Allow-Origin: * header
  missing_headers â†’ Missing CSP, X-Frame-Options, HSTS, etc.
  broken_auth     â†’ Login with admin/admin123
  debug_mode      â†’ Flask Werkzeug debugger enabled
  fingerprinting  â†’ Server version leaking in headers
  mitm_http       â†’ Running plain HTTP, no HTTPS / HSTS
  unauthenticated_api â†’ /api/users accessible without auth
"""

import re
import logging
import requests
from urllib.parse import urljoin, urlparse

import config

logger = logging.getLogger("red_elisar.targeted_scanner")

# â”€â”€ Severity mapping per attack type â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
SEVERITY = {
    "sql_injection":       "CRITICAL",
    "debug_mode":          "CRITICAL",
    "broken_auth":         "HIGH",
    "exposed_files":       "HIGH",
    "unauthenticated_api": "HIGH",
    "xss":                 "HIGH",
    "open_redirect":       "MEDIUM",
    "cors":                "MEDIUM",
    "fingerprinting":      "MEDIUM",
    "missing_headers":     "MEDIUM",
    "mitm_http":           "MEDIUM",
}

# â”€â”€ Keyword sets for auto-detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ATTACK_KEYWORDS = {
    "sql_injection":       ["sql injection", "sqli", "union select", "bypass authentication",
                            "login form", "database dump", "sqlite"],
    "xss":                 ["cross-site scripting", "xss", "javascript inject",
                            "session cookie", "script injection", "reflected xss", "stored xss"],
    "exposed_files":       ["exposed", ".env", "backup", "sensitive file", "configuration file",
                            "api key", "secret key", "hardcoded credential"],
    "unauthenticated_api": ["unauthenticated", "rest api", "api endpoint",
                            "insecure direct", "idor"],
    "open_redirect":       ["open redirect", "redirect", "url manipulation", "phishing redirect"],
    "cors":                ["cors", "cross-origin", "wildcard", "access-control"],
    "missing_headers":     ["clickjacking", "x-frame", "content-security-policy", "csp",
                            "missing header", "security header", "hsts"],
    "broken_auth":         ["broken authentication", "brute force", "hardcoded", "weak credential",
                            "admin password", "weak password", "rate limiting"],
    "debug_mode":          ["debug mode", "werkzeug", "remote code execution", "rce",
                            "python code", "debugger"],
    "fingerprinting":      ["fingerprint", "server version", "apache", "php version",
                            "software version", "cve", "banner grab"],
    "mitm_http":           ["man-in-the-middle", "mitm", "plain http", "no https",
                            "hsts", "tls", "ssl", "network interception"],
}

DEFAULT_TIMEOUT_S = float(getattr(config, "WEB_UI_PROBE_TIMEOUT_S", 5.0))


def detect_attack_type(scenario: str) -> str:
    """Detect attack type from scenario text via keyword matching."""
    s = scenario.lower()
    scores = {}
    for attack, keywords in ATTACK_KEYWORDS.items():
        scores[attack] = sum(1 for kw in keywords if kw in s)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "generic"


def probe_target(target_url: str, attack_type: str, timeout: float | None = None) -> dict:
    """
    Probe the target URL for the specified attack type.
    Returns a dict with: found, evidence, severity, endpoints_tested, recommendation
    """
    target_url = target_url.rstrip("/")
    probers = {
        "xss":                 _probe_xss,
        "sql_injection":       _probe_sqli,
        "exposed_files":       _probe_exposed_files,
        "unauthenticated_api": _probe_unauth_api,
        "open_redirect":       _probe_open_redirect,
        "cors":                _probe_cors,
        "missing_headers":     _probe_missing_headers,
        "broken_auth":         _probe_broken_auth,
        "debug_mode":          _probe_debug_mode,
        "fingerprinting":      _probe_fingerprinting,
        "mitm_http":           _probe_mitm_http,
        "generic":             _probe_generic,
    }
    probe_fn  = probers.get(attack_type, _probe_generic)
    timeout_s = float(timeout) if timeout is not None else DEFAULT_TIMEOUT_S
    result    = probe_fn(target_url, timeout_s)
    result["attack_type"] = attack_type
    result["target_url"]  = target_url
    result["severity"]    = SEVERITY.get(attack_type, "MEDIUM")
    logger.info(f"[TargetedScanner] {attack_type} â†’ found={result['found']}")
    return result


# â”€â”€â”€ Individual Probers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _probe_xss(base: str, timeout_s: float) -> dict:
    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
    ]
    endpoints_tested = []
    evidence = []

    xss_endpoints = [
        ("/greet", "name"),
        ("/search", "q"),
        ("/", "q"),
    ]

    for path, param in xss_endpoints:
        for payload in payloads:
            url = f"{base}{path}?{param}={payload}"
            endpoints_tested.append(url)
            try:
                r = requests.get(url, timeout=timeout_s, allow_redirects=True)
                if payload.lower() in r.text.lower() or "<script>" in r.text.lower():
                    evidence.append({
                        "url":        url,
                        "status":     r.status_code,
                        "payload":    payload,
                        "confirmed":  True,
                        "detail":     f"Payload reflected in response at {path}?{param}=",
                    })
                    break
            except Exception:
                continue

    found = len(evidence) > 0
    return {
        "found":             found,
        "endpoints_tested":  endpoints_tested[:6],
        "evidence":          evidence,
        "vuln_description":  "Reflected XSS: server returns user-supplied JavaScript unescaped, allowing session hijacking.",
        "manual_test":       f"{base}/greet?name=<script>alert(document.cookie)</script>",
        "recommendation":    "Escape all user input on output (use Jinja2 autoescaping). Add Content-Security-Policy header.",
    }


def _probe_sqli(base: str, timeout_s: float) -> dict:
    payloads = [
        ("' OR '1'='1", "shows all results â€” authentication bypass"),
        ("' OR '1'='1'--", "comments out password check"),
        ("' UNION SELECT 1,2,3,4--", "UNION-based data extraction"),
    ]
    evidence  = []
    endpoints = [("/search", "q", "GET"), ("/login", "username", "POST")]
    endpoints_tested = []

    # Test GET /search
    for payload, meaning in payloads[:2]:
        url = f"{base}/search?q={payload}"
        endpoints_tested.append(url)
        try:
            r = requests.get(url, timeout=timeout_s)
            if r.status_code == 200 and len(r.text) > 500:
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   payload,
                    "confirmed": True,
                    "detail":    f"SQLi at /search â€” {meaning}. Response length: {len(r.text)} bytes",
                })
        except Exception:
            pass

    # Test POST /login
    try:
        r = requests.post(
            f"{base}/login",
            data={"username": "' OR '1'='1'--", "password": "x"},
            timeout=timeout_s,
            allow_redirects=False,
        )
        endpoints_tested.append(f"{base}/login [POST SQLi]")
        if r.status_code in (302, 200) and "admin" in r.text.lower():
            evidence.append({
                "url":       f"{base}/login",
                "status":    r.status_code,
                "payload":   "' OR '1'='1'-- (POST login)",
                "confirmed": True,
                "detail":    "SQL injection bypasses login authentication entirely",
            })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "SQL Injection: unsanitised user input is inserted directly into SQL queries, allowing auth bypass and data extraction.",
        "manual_test":       f"{base}/search?q=' OR '1'='1",
        "recommendation":    "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings.",
    }


def _probe_exposed_files(base: str, timeout_s: float) -> dict:
    sensitive_paths = [
        ("/.env",     "Environment file with API keys and secrets"),
        ("/backup",   "Database backup with all records"),
        ("/admin",    "Admin panel without authentication"),
        ("/api/users","User API exposing all passwords"),
        ("/robots.txt","robots.txt listing sensitive paths"),
        ("/.git",     "Git repository metadata"),
        ("/config",   "Configuration endpoint"),
    ]
    evidence         = []
    endpoints_tested = []

    for path, description in sensitive_paths:
        url = f"{base}{path}"
        endpoints_tested.append(url)
        try:
            r = requests.get(url, timeout=timeout_s)
            if r.status_code == 200:
                snippet = r.text[:200].replace("\n", " ")
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   "Direct GET request (no auth)",
                    "confirmed": True,
                    "detail":    f"{description} â€” accessible without authentication. Preview: {snippet}",
                })
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Sensitive File Exposure: configuration files, backups, and admin panels are publicly accessible without authentication.",
        "manual_test":       f"{base}/.env",
        "recommendation":    "Remove sensitive files from web root. Use server-level access controls. Never commit secrets to source code.",
    }


def _probe_unauth_api(base: str, timeout_s: float) -> dict:
    api_endpoints = [
        ("/api/users",    "User database with passwords"),
        ("/api/products", "Product data"),
        ("/admin",        "Admin panel"),
    ]
    evidence         = []
    endpoints_tested = []

    for path, desc in api_endpoints:
        url = f"{base}{path}"
        endpoints_tested.append(url)
        try:
            r = requests.get(url, timeout=timeout_s)
            if r.status_code == 200:
                has_sensitive = any(w in r.text.lower()
                                    for w in ["password", "email", "username", "secret", "token"])
                if has_sensitive:
                    evidence.append({
                        "url":       url,
                        "status":    r.status_code,
                        "payload":   "GET (no Authorization header)",
                        "confirmed": True,
                        "detail":    f"{desc} â€” returns sensitive data without any authentication",
                    })
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Unauthenticated API: sensitive endpoints accessible with no authentication, exposing user credentials and data.",
        "manual_test":       f"{base}/api/users",
        "recommendation":    "Require authentication (JWT/session) on all API endpoints. Apply role-based access control.",
    }


def _probe_open_redirect(base: str, timeout_s: float) -> dict:
    test_url         = f"{base}/redirect?url=http://evil-example.com"
    endpoints_tested = [test_url]
    evidence         = []
    try:
        r = requests.get(test_url, timeout=timeout_s, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if "evil-example.com" in loc or "http://" in loc:
                evidence.append({
                    "url":       test_url,
                    "status":    r.status_code,
                    "payload":   "url=http://evil-example.com",
                    "confirmed": True,
                    "detail":    f"Redirects to attacker-controlled URL: Location: {loc}",
                })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Open Redirect: the /redirect endpoint forwards users to any external URL without validation, enabling phishing.",
        "manual_test":       test_url,
        "recommendation":    "Validate redirect destinations against an allowlist. Reject or encode external URLs.",
    }


def _probe_cors(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    try:
        r = requests.get(
            base,
            timeout=timeout_s,
            headers={"Origin": "http://evil-attacker.com"},
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil-attacker.com" in acao:
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "Origin: http://evil-attacker.com",
                "confirmed": True,
                "detail":    f"Access-Control-Allow-Origin: {acao} â€” any origin allowed to read responses",
            })

        # Also check ACAO on API endpoint
        r2 = requests.get(
            f"{base}/api/users",
            timeout=timeout_s,
            headers={"Origin": "http://evil-attacker.com"},
        )
        acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
        if acao2 == "*":
            evidence.append({
                "url":       f"{base}/api/users",
                "status":    r2.status_code,
                "payload":   "Origin: http://evil-attacker.com",
                "confirmed": True,
                "detail":    f"API endpoint also has CORS wildcard: {acao2}",
            })
    except Exception:
        pass

    endpoints_tested.append(f"{base}/api/users")
    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "CORS Misconfiguration: wildcard Access-Control-Allow-Origin allows any website to read API responses.",
        "manual_test":       f"curl -H 'Origin: http://evil.com' -I {base}",
        "recommendation":    "Restrict Access-Control-Allow-Origin to specific trusted domains only. Never use * on authenticated endpoints.",
    }


def _probe_missing_headers(base: str, timeout_s: float) -> dict:
    required = {
        "Content-Security-Policy":    "Prevents XSS attacks",
        "X-Frame-Options":            "Prevents clickjacking",
        "Strict-Transport-Security":  "Enforces HTTPS",
        "X-Content-Type-Options":     "Prevents MIME sniffing",
        "Referrer-Policy":            "Controls referrer leakage",
        "Permissions-Policy":         "Controls browser features",
    }
    evidence         = []
    endpoints_tested = [base]
    try:
        r = requests.get(base, timeout=timeout_s)
        for header, purpose in required.items():
            if header not in r.headers:
                evidence.append({
                    "url":       base,
                    "status":    r.status_code,
                    "payload":   f"Missing: {header}",
                    "confirmed": True,
                    "detail":    f"Header '{header}' absent â€” {purpose}",
                })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  f"Missing Security Headers: {len(evidence)} required HTTP security headers are absent.",
        "manual_test":       f"curl -I {base}",
        "recommendation":    "Add CSP, X-Frame-Options: DENY, Strict-Transport-Security, X-Content-Type-Options: nosniff to all responses.",
    }


def _probe_broken_auth(base: str, timeout_s: float) -> dict:
    credentials = [
        ("admin", "admin123"),
        ("admin", "admin"),
        ("admin", "password"),
        ("root",  "root"),
    ]
    evidence         = []
    endpoints_tested = []

    for user, pwd in credentials:
        url = f"{base}/login"
        endpoints_tested.append(f"{url} [{user}:{pwd}]")
        try:
            r = requests.post(
                url,
                data={"username": user, "password": pwd},
                timeout=timeout_s,
                allow_redirects=True,
            )
            if (r.status_code == 200 and
                    ("welcome" in r.text.lower() or
                     "dashboard" in r.text.lower() or
                     "admin" in r.text.lower() or
                     "logout" in r.text.lower())):
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   f"username={user}&password={pwd}",
                    "confirmed": True,
                    "detail":    f"Login succeeded with weak credentials {user}/{pwd} â€” no rate limiting or CAPTCHA",
                })
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Broken Authentication: hardcoded/default credentials accepted with no lockout or rate limiting.",
        "manual_test":       f"curl -X POST {base}/login -d 'username=admin&password=admin123'",
        "recommendation":    "Remove hardcoded credentials. Enforce strong passwords, account lockout after 5 failed attempts, and multi-factor authentication.",
    }


def _probe_debug_mode(base: str, timeout_s: float) -> dict:
    test_url         = f"{base}/error_test"
    endpoints_tested = [test_url, f"{base}/nonexistent-page-12345"]
    evidence         = []

    for url in endpoints_tested:
        try:
            r = requests.get(url, timeout=timeout_s)
            body = r.text.lower()
            if any(sig in body for sig in
                   ["traceback", "werkzeug", "debugger", "interactive console",
                    "pin:", "python", "flask"]):
                evidence.append({
                    "url":       url,
                    "status":    r.status_code,
                    "payload":   "Direct GET request",
                    "confirmed": True,
                    "detail":    "Flask/Werkzeug debug mode active â€” full Python stack traces exposed, interactive console possible",
                })
                break
        except Exception:
            pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Debug Mode Enabled: Flask is running with debug=True exposing stack traces and potentially an interactive Python console.",
        "manual_test":       test_url,
        "recommendation":    "Set debug=False in production. Use environment variables: FLASK_ENV=production. Never expose stack traces to users.",
    }


def _probe_fingerprinting(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    try:
        r    = requests.get(base, timeout=timeout_s)
        srv  = r.headers.get("Server", "")
        xpow = r.headers.get("X-Powered-By", "")
        if any(c.isdigit() for c in srv):   # version number in Server
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HTTP response headers",
                "confirmed": True,
                "detail":    f"Server: {srv} â€” version exposed, attackers can look up known CVEs",
            })
        if xpow:
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HTTP response headers",
                "confirmed": True,
                "detail":    f"X-Powered-By: {xpow} â€” technology stack exposed",
            })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Server Fingerprinting: HTTP headers reveal exact server software version, enabling targeted CVE exploitation.",
        "manual_test":       f"curl -I {base}",
        "recommendation":    "Remove or mask Server and X-Powered-By headers in server configuration.",
    }


def _probe_mitm_http(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    parsed           = urlparse(base)
    try:
        r    = requests.get(base, timeout=timeout_s)
        hsts = r.headers.get("Strict-Transport-Security", "")
        if parsed.scheme == "http":
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HTTP scheme check",
                "confirmed": True,
                "detail":    "Site runs over plain HTTP â€” all traffic (cookies, passwords) sent in cleartext",
            })
        if not hsts:
            evidence.append({
                "url":       base,
                "status":    r.status_code,
                "payload":   "HSTS header check",
                "confirmed": True,
                "detail":    "Missing Strict-Transport-Security header â€” browsers won't enforce HTTPS",
            })
    except Exception:
        pass

    return {
        "found":             len(evidence) > 0,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "No HTTPS / Missing HSTS: all traffic is transmitted unencrypted, vulnerable to network interception.",
        "manual_test":       f"Check: {base} (uses http:// not https://)",
        "recommendation":    "Deploy a TLS certificate (Let's Encrypt is free). Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    }


def _probe_generic(base: str, timeout_s: float) -> dict:
    endpoints_tested = [base]
    evidence         = []
    try:
        r = requests.get(base, timeout=timeout_s)
        evidence.append({
            "url":       base,
            "status":    r.status_code,
            "payload":   "GET request",
            "confirmed": False,
            "detail":    f"Target reachable â€” HTTP {r.status_code}. Run specific attack probes for detailed findings.",
        })
    except Exception as e:
        evidence.append({"url": base, "confirmed": False, "detail": str(e)})

    return {
        "found":             False,
        "endpoints_tested":  endpoints_tested,
        "evidence":          evidence,
        "vuln_description":  "Generic probe â€” target is reachable.",
        "manual_test":       base,
        "recommendation":    "Run specific attack scenario commands for targeted vulnerability detection.",
    }


def format_probe_result_markdown(result: dict) -> str:
    """Format probe results as a Markdown section for injection into the report."""
    found     = result.get("found", False)
    atype     = result.get("attack_type", "unknown").replace("_", " ").title()
    sev       = result.get("severity", "MEDIUM")
    evidence  = result.get("evidence", [])
    endpoints = result.get("endpoints_tested", [])
    icons     = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}
    icon      = icons.get(sev, "[UNK]")

    lines = [
        "## Live Vulnerability Verification",
        "",
        f"> **Attack Type Probed:** {atype}",
        f"> **Target:** `{result.get('target_url', 'N/A')}`",
        f"> **Status:** {'[OK] VULNERABILITY CONFIRMED' if found else '[WARN] Not confirmed (may need manual check)'}",
        f"> **Severity:** {icon} {sev}",
        "",
    ]

    if found:
        lines += [
            "### Confirmed Findings",
            "",
        ]
        for i, ev in enumerate(evidence, 1):
            if ev.get("confirmed"):
                lines += [
                    f"#### Finding {i}",
                    f"- **URL Tested:** `{ev.get('url', 'N/A')}`",
                    f"- **HTTP Status:** {ev.get('status', 'N/A')}",
                    f"- **Payload/Method:** `{ev.get('payload', 'N/A')}`",
                    f"- **Evidence:** {ev.get('detail', 'N/A')}",
                    "",
                ]
    else:
        lines += [
            "### Probe Results",
            "",
            f"No automatic confirmation - the vulnerability may require manual testing.",
            f"**Manual Test URL:** `{result.get('manual_test', 'N/A')}`",
            "",
        ]

    lines += [
        "### Endpoints Probed",
        "",
    ]
    for ep in endpoints[:8]:
        lines.append(f"- `{ep}`")

    lines += [
        "",
        f"**Vulnerability Description:** {result.get('vuln_description', 'N/A')}",
        "",
        f"**Recommendation:** {result.get('recommendation', 'N/A')}",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)
```

## M. Vulnerability Scanner

File: $(System.Collections.Hashtable.Path)

```python
"""
vuln_scanner.py â€” Vulnerability Analysis for Red ELISAR
========================================================
Takes reconnaissance data from WebReconAgent and produces a
structured list of vulnerabilities, each with:
  - type, detail, severity, cwe_id, mitre_hint, recommendation

Severity scale: CRITICAL > HIGH > MEDIUM > LOW > INFO

Usage (standalone test):
  python vuln_scanner.py http://127.0.0.1:5000
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger("red_elisar.vuln_scanner")

# â”€â”€â”€ Severity Definitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Header â†’ (severity, CWE, MITRE technique hint, recommendation)
HEADER_VULN_MAP = {
    "Content-Security-Policy": (
        "HIGH",
        "CWE-79",
        "T1059.007",   # Command and Scripting Interpreter: JavaScript
        "Add a Content-Security-Policy header to whitelist trusted content sources. "
        "Example: Content-Security-Policy: default-src 'self'"
    ),
    "Strict-Transport-Security": (
        "HIGH",
        "CWE-311",
        "T1557",       # Adversary-in-the-Middle
        "Enable HSTS to force HTTPS. "
        "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "CWE-1021",
        "T1185",       # Browser Session Hijacking (via clickjacking)
        "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks."
    ),
    "X-Content-Type-Options": (
        "MEDIUM",
        "CWE-430",
        "T1204",       # User Execution
        "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing."
    ),
    "Referrer-Policy": (
        "LOW",
        "CWE-200",
        "T1592",       # Gather Victim Host Info
        "Add Referrer-Policy: no-referrer or strict-origin to limit referrer leakage."
    ),
    "Permissions-Policy": (
        "LOW",
        "CWE-693",
        "T1562",       # Impair Defenses
        "Add Permissions-Policy to restrict browser features (camera, mic, geolocation)."
    ),
}

# Sensitive paths â†’ (severity, CWE, MITRE hint, recommendation)
SENSITIVE_PATH_MAP = {
    "/.env":         ("CRITICAL", "CWE-312", "T1552", "Remove .env from web root. Never expose configuration files publicly."),
    "/backup":       ("CRITICAL", "CWE-312", "T1552", "Remove backup files. Store backups outside the web root."),
    "/.git/config":  ("CRITICAL", "CWE-312", "T1213", "Block .git directory access via web server config."),
    "/admin":        ("HIGH",     "CWE-284", "T1078", "Protect admin routes with authentication and authorization."),
    "/api/users":    ("CRITICAL", "CWE-306", "T1078", "Add authentication to all API endpoints exposing user data."),
    "/phpinfo.php":  ("HIGH",     "CWE-200", "T1592", "Remove phpinfo.php from production environments."),
    "/server-status":("MEDIUM",  "CWE-200", "T1592", "Disable Apache server-status or restrict by IP."),
    "/.htaccess":    ("MEDIUM",  "CWE-200", "T1592", "Block .htaccess access via web server configuration."),
    "/robots.txt":   ("INFO",    "CWE-200", "T1592", "Avoid listing sensitive paths in robots.txt (security by obscurity is not security)."),
    "/debug":        ("CRITICAL", "CWE-94",  "T1190", "Disable debug endpoints in production."),
}

# Leaky header patterns â†’ (severity, CWE, MITRE hint, recommendation)
LEAKY_HEADER_RULES = {
    "Server":       ("MEDIUM", "CWE-200", "T1592", "Remove or genericize the Server header to hide version information."),
    "X-Powered-By": ("MEDIUM", "CWE-200", "T1592", "Remove X-Powered-By header to avoid exposing technology stack."),
    "X-App-Version":("LOW",    "CWE-200", "T1592", "Remove X-App-Version to prevent version enumeration."),
}


class VulnerabilityScanner:
    """
    Analyzes recon data to identify vulnerabilities and
    map them to MITRE ATT&CK technique hints.
    """

    def __init__(self, recon_data: dict):
        self.data           = recon_data
        self.vulnerabilities = []
        self.scan_time       = datetime.now(timezone.utc).isoformat()

    # â”€â”€â”€ Main Entry Point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def scan(self) -> dict:
        """Run all checks and return a structured vulnerability report."""
        logger.info(f"[Scanner] Starting vulnerability scan for: {self.data.get('target_url')}")

        if not self.data.get("reachable"):
            return {"error": "Target not reachable", "vulnerabilities": []}

        self._check_missing_headers()
        self._check_leaky_headers()
        self._check_exposed_paths()
        self._check_cors()
        self._check_open_redirect()
        self._check_ssl()
        self._check_debug_mode()
        self._check_http_only()

        # Sort by severity
        self.vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v["severity"], 99))

        stats = {
            "CRITICAL": sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL"),
            "HIGH":     sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH"),
            "MEDIUM":   sum(1 for v in self.vulnerabilities if v["severity"] == "MEDIUM"),
            "LOW":      sum(1 for v in self.vulnerabilities if v["severity"] == "LOW"),
            "INFO":     sum(1 for v in self.vulnerabilities if v["severity"] == "INFO"),
        }

        logger.info(
            f"[Scanner] Found {len(self.vulnerabilities)} vulnerabilities â€” "
            f"CRITICAL:{stats['CRITICAL']} HIGH:{stats['HIGH']} "
            f"MEDIUM:{stats['MEDIUM']} LOW:{stats['LOW']}"
        )

        return {
            "target_url":      self.data.get("target_url"),
            "scan_timestamp":  self.scan_time,
            "total_vulns":     len(self.vulnerabilities),
            "severity_counts": stats,
            "overall_risk":    self._calculate_overall_risk(stats),
            "vulnerabilities": self.vulnerabilities,
        }

    # â”€â”€â”€ Check: Missing Security Headers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_missing_headers(self):
        missing = self.data.get("missing_security_headers", {})
        for header, description in missing.items():
            if header in HEADER_VULN_MAP:
                severity, cwe, mitre_hint, rec = HEADER_VULN_MAP[header]
                self._add_vuln(
                    vuln_type  = "Missing Security Header",
                    detail     = f"HTTP header '{header}' is not set â€” {description}",
                    severity   = severity,
                    cwe_id     = cwe,
                    mitre_hint = mitre_hint,
                    recommendation = rec,
                    evidence   = f"Response header '{header}': not present",
                )

    # â”€â”€â”€ Check: Information Leakage via Headers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_leaky_headers(self):
        leaked = self.data.get("leaked_info_headers", {})
        for header, value in leaked.items():
            if header in LEAKY_HEADER_RULES:
                severity, cwe, mitre_hint, rec = LEAKY_HEADER_RULES[header]
                self._add_vuln(
                    vuln_type  = "Information Disclosure (HTTP Header)",
                    detail     = f"Header '{header}' exposes technology details: '{value}'",
                    severity   = severity,
                    cwe_id     = cwe,
                    mitre_hint = mitre_hint,
                    recommendation = rec,
                    evidence   = f"{header}: {value}",
                )

    # â”€â”€â”€ Check: Sensitive Exposed Paths â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_exposed_paths(self):
        for path_info in self.data.get("exposed_paths", []):
            path   = path_info["path"]
            status = path_info["status_code"]
            mapped = SENSITIVE_PATH_MAP.get(path)

            if mapped:
                severity, cwe, mitre_hint, rec = mapped
            else:
                severity, cwe, mitre_hint, rec = (
                    "MEDIUM", "CWE-200", "T1592",
                    f"Restrict access to {path} or remove it from the web root."
                )

            self._add_vuln(
                vuln_type  = "Exposed Sensitive Resource",
                detail     = f"Sensitive path '{path}' is publicly accessible (HTTP {status})",
                severity   = severity,
                cwe_id     = cwe,
                mitre_hint = mitre_hint,
                recommendation = rec,
                evidence   = f"GET {path} â†’ {status} ({path_info['size_bytes']} bytes)",
                extra      = {"preview": path_info.get("content_preview", "")[:100]},
            )

    # â”€â”€â”€ Check: CORS Misconfiguration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_cors(self):
        cors = self.data.get("cors", {})
        for issue in cors.get("issues", []):
            self._add_vuln(
                vuln_type  = "CORS Misconfiguration",
                detail     = issue,
                severity   = "HIGH",
                cwe_id     = "CWE-942",
                mitre_hint = "T1557",   # Adversary-in-the-Middle
                recommendation = (
                    "Replace 'Access-Control-Allow-Origin: *' with specific allowed origins. "
                    "Never use wildcard CORS for authenticated endpoints."
                ),
                evidence   = f"Access-Control-Allow-Origin: {cors.get('origin', '*')}",
            )

    # â”€â”€â”€ Check: Open Redirect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_open_redirect(self):
        redirects = self.data.get("redirects", {})
        if redirects.get("open_redirect_likely"):
            for detail in redirects.get("details", []):
                self._add_vuln(
                    vuln_type  = "Open Redirect",
                    detail     = f"URL parameter causes redirect to external site: {detail.get('redirects_to')}",
                    severity   = "MEDIUM",
                    cwe_id     = "CWE-601",
                    mitre_hint = "T1204",   # User Execution (phishing link)
                    recommendation = (
                        "Validate and whitelist redirect destinations. "
                        "Never redirect to user-supplied external URLs."
                    ),
                    evidence   = f"GET {detail.get('test_url')} â†’ 302 â†’ {detail.get('redirects_to')}",
                )

    # â”€â”€â”€ Check: SSL/TLS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_ssl(self):
        ssl = self.data.get("ssl", {})
        if not ssl.get("enabled"):
            self._add_vuln(
                vuln_type  = "No HTTPS / Plain HTTP",
                detail     = "Site is served over HTTP â€” all traffic is unencrypted",
                severity   = "CRITICAL",
                cwe_id     = "CWE-319",
                mitre_hint = "T1557",   # Adversary-in-the-Middle
                recommendation = (
                    "Enable HTTPS with a valid SSL/TLS certificate. "
                    "Use Let's Encrypt for free certificates."
                ),
                evidence   = f"URL scheme: http://",
            )
        elif not ssl.get("valid"):
            self._add_vuln(
                vuln_type  = "Invalid SSL Certificate",
                detail     = f"SSL certificate error: {ssl.get('error')}",
                severity   = "HIGH",
                cwe_id     = "CWE-295",
                mitre_hint = "T1557",
                recommendation = "Renew or correct the SSL certificate.",
                evidence   = ssl.get("error", ""),
            )

    # â”€â”€â”€ Check: Debug Mode Active â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_debug_mode(self):
        indicators = self.data.get("debug_indicators", [])
        if indicators:
            self._add_vuln(
                vuln_type  = "Debug Mode Enabled",
                detail     = f"Application appears to be running in debug mode: {'; '.join(indicators)}",
                severity   = "CRITICAL",
                cwe_id     = "CWE-94",
                mitre_hint = "T1190",   # Exploit Public-Facing Application
                recommendation = (
                    "Disable debug mode in production. "
                    "Set DEBUG=False and FLASK_ENV=production. "
                    "Debug mode in Flask allows arbitrary code execution via the Werkzeug debugger."
                ),
                evidence   = str(indicators),
            )

    # â”€â”€â”€ Check: HTTP site (no HSTS enforcement) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _check_http_only(self):
        if self.data.get("scheme") == "http" or self.data.get("target_url", "").startswith("http://"):
            # Already flagged in SSL check as CRITICAL
            pass

    # â”€â”€â”€ Add Vulnerability â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _add_vuln(self, vuln_type, detail, severity, cwe_id,
                  mitre_hint, recommendation, evidence="", extra=None):
        self.vulnerabilities.append({
            "type":           vuln_type,
            "detail":         detail,
            "severity":       severity,
            "cwe_id":         cwe_id,
            "mitre_hint":     mitre_hint,   # Technique ID hint for MITRE mapper
            "recommendation": recommendation,
            "evidence":       evidence,
            **({"extra": extra} if extra else {}),
        })

    # â”€â”€â”€ Calculate Overall Risk â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _calculate_overall_risk(self, stats: dict) -> str:
        if stats["CRITICAL"] > 0:
            return "CRITICAL"
        elif stats["HIGH"] >= 2:
            return "HIGH"
        elif stats["HIGH"] >= 1 or stats["MEDIUM"] >= 3:
            return "MEDIUM"
        elif stats["MEDIUM"] > 0:
            return "LOW"
        return "INFO"


# â”€â”€â”€ Standalone Test â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if __name__ == "__main__":
    import sys, json, logging
    from web_recon import WebReconAgent

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    recon  = WebReconAgent(target).run()
    result = VulnerabilityScanner(recon).scan()
    print(json.dumps(result, indent=2, default=str))
```

## N. Web Recon Agent

File: $(System.Collections.Hashtable.Path)

```python
"""Passive web reconnaissance for the VulnShop demo.

This module is intentionally lightweight:
- Performs a single baseline GET to the target URL
- Extracts basic tech hints from response headers
- Probes a small set of common sensitive paths
- Records missing security headers and information-leaking headers

It is used by `vuln_checks.web_vuln_agent`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urljoin

import requests

logger = logging.getLogger("red_elisar.web_recon")


_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "Mitigates XSS by restricting allowed content sources",
    "Strict-Transport-Security": "Forces HTTPS to reduce MITM risk",
    "X-Frame-Options": "Mitigates clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Limits referrer leakage",
    "Permissions-Policy": "Restricts browser features",
}

_LEAKY_HEADERS = ["Server", "X-Powered-By", "X-App-Version"]

_DEFAULT_SENSITIVE_PATHS = [
    "/.env",
    "/backup",
    "/.git/config",
    "/admin",
    "/api/users",
    "/phpinfo.php",
    "/server-status",
    "/.htaccess",
    "/robots.txt",
    "/debug",
]


@dataclass
class WebReconAgent:
    """Collects passive recon signals from a target web app."""

    target_url: str
    timeout_s: float = 8.0

    def run(self) -> dict[str, Any]:
        parsed = urlparse(self.target_url)
        domain = parsed.netloc or parsed.path
        base_url = self.target_url.rstrip("/")

        out: dict[str, Any] = {
            "target_url": base_url,
            "domain": domain,
            "reachable": False,
            "status_code": None,
            "tech_stack": {"server": "Unknown", "language": "Unknown", "versions": {}},
            "ssl": {"enabled": parsed.scheme.lower() == "https", "valid": None, "error": None},
            "missing_security_headers": {},
            "leaked_info_headers": {},
            "exposed_paths": [],
            "cors": {"origin": None, "issues": []},
            "redirects": {"open_redirect_likely": False, "details": []},
            "error": None,
        }

        try:
            resp = requests.get(base_url, timeout=self.timeout_s, allow_redirects=True)
            out["reachable"] = True
            out["status_code"] = resp.status_code

            server = resp.headers.get("Server")
            powered = resp.headers.get("X-Powered-By")
            out["tech_stack"]["server"] = server or "Unknown"

            language = "Unknown"
            if powered:
                language = powered
            elif server and "werkzeug" in server.lower():
                language = "Python/Flask"
            out["tech_stack"]["language"] = language

            versions: dict[str, str] = {}
            if server:
                versions["server"] = server
            if powered:
                versions["x_powered_by"] = powered
            out["tech_stack"]["versions"] = versions

            for header, desc in _SECURITY_HEADERS.items():
                if header not in resp.headers:
                    out["missing_security_headers"][header] = desc

            for header in _LEAKY_HEADERS:
                if header in resp.headers and str(resp.headers.get(header, "")).strip():
                    out["leaked_info_headers"][header] = str(resp.headers.get(header, "")).strip()

            # CORS quick check
            acao = resp.headers.get("Access-Control-Allow-Origin")
            if acao:
                out["cors"]["origin"] = acao
                if acao.strip() == "*":
                    out["cors"]["issues"].append("Access-Control-Allow-Origin is wildcard (*)")

            # Probe a small set of sensitive paths (passive-ish GET)
            out["exposed_paths"] = self._probe_paths(base_url)

        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)
            logger.warning("Recon failed for %s: %s", base_url, e)

        # SSL validity (best-effort)
        if out["ssl"]["enabled"]:
            try:
                requests.get(base_url, timeout=self.timeout_s, verify=True)
                out["ssl"]["valid"] = True
            except Exception as e:  # noqa: BLE001
                out["ssl"]["valid"] = False
                out["ssl"]["error"] = str(e)
        else:
            out["ssl"]["valid"] = False

        return out

    def _probe_paths(self, base_url: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for path in _DEFAULT_SENSITIVE_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            try:
                resp = requests.get(url, timeout=self.timeout_s, allow_redirects=False)
                preview = ""
                try:
                    preview = (resp.text or "")[:200]
                except Exception:
                    preview = ""

                # record only interesting statuses to keep output small
                if resp.status_code < 400:
                    results.append(
                        {
                            "path": path,
                            "status_code": resp.status_code,
                            "size_bytes": len(resp.content or b""),
                            "content_preview": preview,
                        }
                    )
            except Exception:
                continue
        return results


if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    ap = argparse.ArgumentParser(description="Passive web reconnaissance (Red ELISAR)")
    ap.add_argument("url", help="Target URL, e.g. http://127.0.0.1:5000")
    ap.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    args = ap.parse_args()

    data = WebReconAgent(args.url, timeout_s=args.timeout).run()
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
```

## O. Report Generator

File: $(System.Collections.Hashtable.Path)

```python
"""
report_generator.py â€” Vulnerability Assessment Report Generator
===============================================================
Produces formatted output reports from Red ELISAR's web assessment:
  - Markdown report (.md) â€” human-readable full report
  - JSON report (.json)   â€” machine-readable for further processing

Both files are saved to red_agent/output/ directory.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import config

try:
    from reporting.pdf_reporter import render_markdown_to_pdf
except Exception:
    render_markdown_to_pdf = None

logger = logging.getLogger("red_elisar.report_generator")

SEVERITY_ICONS = {
    "CRITICAL": "[CRIT]",
    "HIGH":     "[HIGH]",
    "MEDIUM":   "[MED]",
    "LOW":      "[LOW]",
    "INFO":     "[INFO]",
}

TACTIC_ICONS = {
    "reconnaissance":       "[RECON]",
    "resource-development": "[RESOURCE]",
    "initial-access":       "[INITIAL]",
    "execution":            "[EXEC]",
    "persistence":          "[PERSIST]",
    "privilege-escalation": "[PRIV-ESC]",
    "defense-evasion":      "[DEF-EVASION]",
    "credential-access":    "[CRED]",
    "discovery":            "[DISCOVERY]",
    "lateral-movement":     "[LATERAL]",
    "collection":           "[COLLECT]",
    "exfiltration":         "[EXFIL]",
    "impact":               "[IMPACT]",
}


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

## P. Runtime Configuration

File: $(System.Collections.Hashtable.Path)

```python
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

# â”€â”€ LLM API Keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Red ELISAR uses TWO cloud APIs â€” NO local Ollama required.
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

# â”€â”€ Ollama (NOT USED â€” kept only so legacy imports don't crash) â”€â”€â”€â”€â”€â”€
OLLAMA_BASE_URL   = ""         # Ollama is NOT used in this project
OLLAMA_MODEL      = GROQ_MODEL  # alias â€” do not rely on this

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
```

## Q. Final Implementation CLI (run.py)

File: $(System.Collections.Hashtable.Path)

```python
"""Interactive Red Agent CLI entry point.

This runner composes existing modules from red_agent/ without changing
their core logic.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

# Optional parser; fallback regex parsing is used when bs4 is unavailable.
try:
    from bs4 import BeautifulSoup
except Exception:  # noqa: BLE001
    BeautifulSoup = None


# â”€â”€ Bootstrap path/cwd exactly once â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
PROJECT_DIR = Path(__file__).resolve().parent
AGENT_DIR = PROJECT_DIR / "red_agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))
os.chdir(AGENT_DIR)

import config
from llm.attack_chain_generator import AttackChainGenerator
from mappings.mitre_mapper import MITREMapper
from rag.chunking import chunk_techniques
from rag.mitre_parser import MITREParser
from rag.rag_engine import RAGEngine
from rag.vector_store_faiss import FAISSVectorStore
from reporting.report_generator import ReportGenerator
from vuln_checks.input_sanitizer import sanitize_scenario
from vuln_checks.live_vuln_checker import LiveVulnChecker
from vuln_checks.targeted_attack_scanner import detect_attack_type, probe_target
from vuln_checks.vuln_scanner import VulnerabilityScanner
from vuln_checks.web_recon import WebReconAgent

logger = logging.getLogger("red_elisar.run_cli")

COMMON_PATHS = [
    "/admin",
    "/login",
    "/register",
    "/api",
    "/api/users",
    "/search",
    "/redirect",
    "/debug",
    "/backup",
    "/.env",
    "/robots.txt",
    "/sitemap.xml",
]

ATTACK_FLOW_TACTICS = [
    "reconnaissance",
    "initial-access",
    "execution",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "exfiltration",
    "impact",
]

GENERIC_CONTEXT_TOKENS = {
    "http",
    "https",
    "www",
    "com",
    "net",
    "org",
    "url",
    "target",
    "application",
    "web",
    "vulnerability",
    "attack",
    "mitre",
    "technique",
    "endpoint",
}

TOOL_NOISE_KEYWORDS = {
    "agent tesla",
    "astaroth",
    "dridex",
    "emotet",
    "trickbot",
    "nation state",
    "apt",
}

WEB_TOOL_HINTS = {
    "web",
    "http",
    "https",
    "browser",
    "api",
    "cookie",
    "session",
    "credential",
    "password",
    "token",
    "shell",
    "proxy",
}

MALWARE_STYLE_KEYWORDS = {
    "malware",
    "adware",
    "ransomware",
    "trojan",
    "infostealer",
    "worm",
    "botnet",
}

WEB_TOOL_ALLOWLIST = {
    "sqlmap",
    "burp suite",
    "curl",
    "browser",
}

FORM_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
]

FORM_XSS_PAYLOADS = [
    "<script>alert('x')</script>",
    "\"><img src=x onerror=alert('x')>",
]

SQL_ERROR_PATTERNS = [
    r"sqlite",
    r"syntax error",
    r"unrecognized token",
    r"mysql",
    r"postgre",
    r"ORA-",
    r"database error",
]


def setup_logging() -> None:
    config.ensure_directories()
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(config.LOG_FILE, encoding="utf-8", mode="a"))
    except Exception:  # noqa: BLE001
        pass
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
        format=config.LOG_FORMAT,
        handlers=handlers,
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)


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


class MitreAttackDatabase:
    """Minimal MITRE ATT&CK STIX reader for technique/tactic/tools enrichment."""

    def __init__(self, stix_path: Path):
        self.stix_path = stix_path
        self.technique_index: dict[str, dict[str, Any]] = {}
        self.technique_stix_to_external: dict[str, str] = {}
        self.software_index: dict[str, dict[str, str]] = {}
        self.tools_by_technique: dict[str, list[dict[str, str]]] = {}
        self.tactic_id_to_name: dict[str, str] = {}
        self.tactic_order: list[str] = []
        self._loaded = False
        self._load()

    def _load(self) -> None:
        self._loaded = True
        if not self.stix_path.exists():
            return
        try:
            bundle = json.loads(self.stix_path.read_text(encoding="utf-8"))
        except Exception:
            return

        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        software_types = {"tool", "malware"}

        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                self.tactic_id_to_name[obj.get("id", "")] = str(obj.get("name", "")).strip().lower()

        # Build tactic sequence from ATT&CK matrix ordering in STIX (no hardcoded stage order).
        for obj in objects:
            if obj.get("type") != "x-mitre-matrix":
                continue
            refs = obj.get("tactic_refs", [])
            ordered = []
            for ref in refs:
                nm = self.tactic_id_to_name.get(ref)
                if nm:
                    ordered.append(nm)
            if ordered:
                self.tactic_order = ordered
                break

        for obj in objects:
            otype = obj.get("type")
            if otype in software_types:
                self.software_index[obj.get("id", "")] = {
                    "name": obj.get("name", "Unknown Tool"),
                    "description": (obj.get("description", "") or "").strip(),
                }

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = ""
            for ref in obj.get("external_references", []):
                eid = str(ref.get("external_id", "")).strip()
                if eid.startswith("T"):
                    ext_id = eid
                    break
            if not ext_id:
                continue

            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    pname = str(phase.get("phase_name", "")).strip()
                    if pname:
                        tactics.append(pname)

            self.technique_index[ext_id] = {
                "technique_id": ext_id,
                "technique_name": obj.get("name", "Unknown Technique"),
                "description": (obj.get("description", "") or "").strip(),
                "tactics": sorted(set(tactics)),
                "stix_id": obj.get("id", ""),
            }
            self.technique_stix_to_external[obj.get("id", "")] = ext_id

        temp_tools: dict[str, dict[str, dict[str, str]]] = {}
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            target_ref = obj.get("target_ref", "")
            source_ref = obj.get("source_ref", "")
            technique_id = self.technique_stix_to_external.get(target_ref)
            software = self.software_index.get(source_ref)
            if not technique_id or not software:
                continue
            bucket = temp_tools.setdefault(technique_id, {})
            bucket[software.get("name", "Unknown Tool")] = software

        self.tools_by_technique = {
            tid: list(name_map.values()) for tid, name_map in temp_tools.items()
        }

    def get_technique(self, technique_id: str) -> dict[str, Any]:
        return self.technique_index.get(technique_id, {})

    def get_tools_for_technique(self, technique_id: str) -> list[dict[str, str]]:
        return list(self.tools_by_technique.get(technique_id, []))

    def tactic_rank(self, tactic: str) -> int:
        key = str(tactic or "").strip().lower()
        if key in self.tactic_order:
            return self.tactic_order.index(key)
        return 10_000


def normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("URL cannot be empty.")
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return raw.rstrip("/")


def same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc


def canonicalize(url: str) -> str:
    p = urlparse(url)
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", query, ""))


def parse_html_links_and_forms(base_url: str, html: str) -> tuple[set[str], list[dict[str, Any]]]:
    links: set[str] = set()
    forms: list[dict[str, Any]] = []

    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href", "")).strip()
            if not href or href.startswith(("javascript:", "mailto:", "#")):
                continue
            links.add(urljoin(base_url + "/", href))

        for form in soup.find_all("form"):
            action = str(form.get("action") or "").strip() or base_url
            method = str(form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(str(name))
            forms.append(
                {
                    "action": urljoin(base_url + "/", action),
                    "method": method,
                    "params": sorted(set(inputs)),
                }
            )
        return links, forms

    # Regex fallback for environments without bs4.
    for match in re.findall(r"href=[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE):
        href = match.strip()
        if href and not href.startswith(("javascript:", "mailto:", "#")):
            links.add(urljoin(base_url + "/", href))

    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, flags=re.IGNORECASE | re.DOTALL):
        form_attrs = match.group(1) or ""
        form_body = match.group(2) or ""

        method_m = re.search(r"\bmethod\s*=\s*[\"']?([^\"' >]+)", form_attrs, flags=re.IGNORECASE)
        action_m = re.search(r"\baction\s*=\s*[\"']?([^\"' >]+)", form_attrs, flags=re.IGNORECASE)

        method = (method_m.group(1) if method_m else "GET").upper()
        action = (action_m.group(1) if action_m else "").strip() or base_url

        params = sorted(
            {
                p.strip()
                for p in re.findall(
                    r"<(?:input|textarea|select)[^>]*\bname\s*=\s*[\"']?([^\"' >]+)",
                    form_body,
                    flags=re.IGNORECASE,
                )
                if p.strip()
            }
        )

        forms.append(
            {
                "action": urljoin(base_url + "/", action),
                "method": method,
                "params": params,
            }
        )

    return links, forms


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


def _merge_vulnerabilities(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged_by_key: dict[str, dict[str, Any]] = {}
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    def endpoint_key(v: dict[str, Any]) -> str:
        def normalize_endpoint(u: str) -> str:
            p = urlparse(u)
            if p.scheme and p.netloc:
                return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", "", ""))
            return u

        direct = str(v.get("endpoint", "")).strip()
        if direct:
            try:
                return normalize_endpoint(direct)
            except Exception:
                return direct
        inferred = _infer_affected_url(v, "")
        if inferred:
            try:
                return normalize_endpoint(inferred)
            except Exception:
                return inferred
        return "unknown-endpoint"

    def split_evidence(text: str) -> list[str]:
        if not text:
            return []
        return [p.strip() for p in re.split(r"\n|\s+\|\s+|\s*;\s*", text) if p.strip()]

    def normalize_type(vtype: str) -> str:
        t = (vtype or "Unknown").strip()
        t = re.sub(r"\s*\([^)]*\)", "", t).strip()
        low = t.lower()
        if "sql injection" in low:
            return "SQL Injection"
        if "cross-site scripting" in low or "xss" in low:
            return "Reflected Cross-Site Scripting (XSS)"
        if "sensitive file" in low or "exposed sensitive resource" in low:
            return "Exposed Sensitive Resource"
        return t

    for group in groups:
        for v in group:
            vtype = normalize_type(str(v.get("type", "Unknown")))
            endpoint = endpoint_key(v)
            key = f"{endpoint}::{vtype.lower()}"

            if key not in merged_by_key:
                base = dict(v)
                base["type"] = vtype
                base["endpoint"] = endpoint
                base["_evidence_items"] = split_evidence(str(v.get("evidence", "")))
                merged_by_key[key] = base
                continue

            curr = merged_by_key[key]
            evidence_items = curr.get("_evidence_items", [])
            for piece in split_evidence(str(v.get("evidence", ""))):
                if piece not in evidence_items:
                    evidence_items.append(piece)
            curr["_evidence_items"] = evidence_items

            curr_sev = severity_rank.get(str(curr.get("severity", "INFO")).upper(), 0)
            new_sev = severity_rank.get(str(v.get("severity", "INFO")).upper(), 0)
            if new_sev > curr_sev:
                curr["severity"] = v.get("severity", curr.get("severity"))

            if len(str(v.get("detail", ""))) > len(str(curr.get("detail", ""))):
                curr["detail"] = v.get("detail", curr.get("detail"))
            if not curr.get("mitre_hint") and v.get("mitre_hint"):
                curr["mitre_hint"] = v.get("mitre_hint")
            if len(str(v.get("recommendation", ""))) > len(str(curr.get("recommendation", ""))):
                curr["recommendation"] = v.get("recommendation", curr.get("recommendation"))

    merged: list[dict[str, Any]] = []
    for item in merged_by_key.values():
        evidence_items = item.pop("_evidence_items", [])
        if evidence_items:
            item["evidence"] = " | ".join(evidence_items)
        merged.append(item)
    return merged


def _probe_discovered_forms(base_url: str, forms: list[dict[str, Any]], timeout: int = 8) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    session = requests.Session()

    for form in forms:
        action = str(form.get("action", "")).strip()
        method = str(form.get("method", "GET")).upper().strip()
        params = [str(p).strip() for p in (form.get("params", []) or []) if str(p).strip()]
        if not action or not params:
            continue

        url = action if action.startswith(("http://", "https://")) else urljoin(base_url + "/", action)

        for param in params[:6]:
            for payload in FORM_SQLI_PAYLOADS:
                try:
                    data = {param: payload}
                    if method == "POST":
                        resp = session.post(url, data=data, timeout=timeout, allow_redirects=True)
                    else:
                        resp = session.get(url, params=data, timeout=timeout, allow_redirects=True)
                    body = (resp.text or "")[:8000].lower()
                    matched = next((pat for pat in SQL_ERROR_PATTERNS if re.search(pat, body, re.IGNORECASE)), None)
                    if matched:
                        key = f"sqli::{url}::{param}"
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            {
                                "type": "SQL Injection",
                                "detail": f"Form parameter '{param}' at {url} appears SQL injectable.",
                                "severity": "CRITICAL",
                                "cwe_id": "CWE-89",
                                "mitre_hint": "T1190",
                                "recommendation": "Use parameterized queries for all database access and validate input.",
                                "evidence": f"{method} {url} param={param} payload={payload} pattern={matched}",
                                "endpoint": url,
                                "confirmed_live": True,
                            }
                        )
                except Exception:
                    continue

            for payload in FORM_XSS_PAYLOADS:
                try:
                    data = {param: payload}
                    if method == "POST":
                        resp = session.post(url, data=data, timeout=timeout, allow_redirects=True)
                    else:
                        resp = session.get(url, params=data, timeout=timeout, allow_redirects=True)
                    body = resp.text or ""
                    if payload[:20] in body or "alert('x')" in body.lower():
                        key = f"xss::{url}::{param}"
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            {
                                "type": "Reflected Cross-Site Scripting (XSS)",
                                "detail": f"Form parameter '{param}' at {url} reflects unescaped input.",
                                "severity": "HIGH",
                                "cwe_id": "CWE-79",
                                "mitre_hint": "T1059.007",
                                "recommendation": "Apply output encoding and input validation for form parameters.",
                                "evidence": f"{method} {url} param={param} payload={payload}",
                                "endpoint": url,
                                "confirmed_live": True,
                            }
                        )
                except Exception:
                    continue

    return findings


def _severity_counts(vulns: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        sev = str(v.get("severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _overall_risk(counts: dict[str, int]) -> str:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if counts.get("HIGH", 0) >= 2:
        return "HIGH"
    if counts.get("HIGH", 0) >= 1 or counts.get("MEDIUM", 0) >= 3:
        return "MEDIUM"
    if counts.get("MEDIUM", 0) > 0:
        return "LOW"
    return "INFO"


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s|`]+", text or "")


def _infer_affected_url(vuln: dict[str, Any], target_url: str) -> str:
    urls = _extract_urls(str(vuln.get("evidence", "")))
    if urls:
        return urls[0]
    return target_url


def _split_recommendation_lines(recommendation: str) -> list[str]:
    text = (recommendation or "").strip()
    if not text:
        return ["Review and remediate this vulnerability according to secure coding standards."]
    chunks = [c.strip() for c in re.split(r"[.;]\s+", text) if c.strip()]
    return chunks or [text]


def _normalize_tools(raw_tools: list[dict[str, str]], max_items: int = 6) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for t in raw_tools:
        name = str(t.get("name", "Unknown Tool")).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        desc = str(t.get("description", "")).strip()
        if len(desc) > 220:
            desc = desc[:217] + "..."
        normalized.append({"name": name, "description": desc})
        if len(normalized) >= max_items:
            break
    return normalized


def _resolve_technique_record(
    technique: dict[str, Any],
    vuln: dict[str, Any],
    mitre_db: MitreAttackDatabase | None,
) -> dict[str, Any]:
    candidate_id = str(technique.get("technique_id") or vuln.get("mitre_hint") or "").strip()
    db_info = mitre_db.get_technique(candidate_id) if (mitre_db and candidate_id) else {}

    technique_id = db_info.get("technique_id") or candidate_id or "N/A"
    technique_name = db_info.get("technique_name") or str(technique.get("name") or "Unknown Technique")
    tactics = db_info.get("tactics") or technique.get("tactics") or []
    if isinstance(tactics, str):
        tactics = [tactics]

    tools = _normalize_tools(mitre_db.get_tools_for_technique(technique_id) if mitre_db else [])
    relevance = float(technique.get("relevance_score", 0) or 0)
    description = (
        str(technique.get("description_preview") or "").strip()
        or str(technique.get("document") or "").strip()
        or db_info.get("description", "")
        or str(vuln.get("detail", ""))
    )

    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactics": [str(t).strip().lower() for t in tactics if str(t).strip()],
        "tools": tools,
        "relevance": relevance,
        "description": description,
    }


def _vulnerability_rag_query(vuln: dict[str, Any]) -> str:
    vtype = str(vuln.get("type", "")).strip()
    detail = str(vuln.get("detail", "")).strip()
    evidence = str(vuln.get("evidence", "")).strip()
    endpoint = ""
    urls = _extract_urls(evidence)
    if urls:
        try:
            endpoint = urlparse(urls[0]).path or ""
        except Exception:
            endpoint = ""
    endpoint_text = endpoint if endpoint else "unknown endpoint"
    return (
        f"MITRE ATT&CK techniques for {vtype or 'web vulnerability'} in web application. "
        f"Details: {detail or 'no detail provided'}. "
        f"Evidence: {evidence or 'no evidence provided'}. "
        f"Endpoint: {endpoint_text}. "
        "Focus on web exploitation, data exposure, credential access, and realistic post-exploitation progression."
    )


def _tokenize_text(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}", (text or "").lower())}


def _text_overlap_score(a: str, b: str) -> float:
    ta = _tokenize_text(a)
    tb = _tokenize_text(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def _select_context_tools(
    tools: list[dict[str, str]],
    context_text: str,
    max_tools: int = 3,
) -> list[dict[str, str]]:
    if not tools:
        return []
    scored: list[tuple[float, dict[str, str]]] = []
    for t in tools:
        text = f"{t.get('name', '')} {t.get('description', '')}".strip()
        low = text.lower()
        overlap = _text_overlap_score(context_text, text)

        if any(k in low for k in MALWARE_STYLE_KEYWORDS) and "malware" not in context_text.lower():
            continue
        if any(k in low for k in TOOL_NOISE_KEYWORDS) and overlap < 0.04:
            continue
        has_web_hint = any(k in low for k in WEB_TOOL_HINTS)
        if overlap < 0.05 and not (has_web_hint and overlap >= 0.02):
            continue
        scored.append((overlap, t))

    scored.sort(key=lambda x: x[0], reverse=True)
    selected: list[dict[str, str]] = []
    for _, tool in scored:
        name = str(tool.get("name", "")).strip().lower()
        if name in WEB_TOOL_ALLOWLIST:
            selected.append(tool)
        if len(selected) >= max_tools:
            break
    return selected


def _expected_primary_technique(vuln: dict[str, Any]) -> str:
    text = " ".join(
        [
            str(vuln.get("type", "")),
            str(vuln.get("detail", "")),
            str(vuln.get("evidence", "")),
        ]
    ).lower()

    if "sql injection" in text or "cwe-89" in text:
        return "T1190"
    if ".env" in text or "backup" in text or "unsecured credentials" in text:
        return "T1552"
    if "plain http" in text or "no https" in text or "unencrypted http" in text or "no tls" in text:
        return "T1048"
    if "cors" in text:
        return "T1552"
    return str(vuln.get("mitre_hint", "")).strip()


def _fallback_web_tools(vuln: dict[str, Any], tactic: str) -> list[dict[str, str]]:
    text = " ".join(
        [
            str(vuln.get("type", "")),
            str(vuln.get("detail", "")),
            str(vuln.get("evidence", "")),
            str(tactic),
        ]
    ).lower()

    if "sql" in text:
        names = ["sqlmap", "Burp Suite", "curl"]
    elif "xss" in text or "cors" in text:
        names = ["Burp Suite", "browser", "curl"]
    else:
        names = ["curl", "browser"]

    out: list[dict[str, str]] = []
    for n in names[:3]:
        out.append({"name": n, "description": "Relevant web testing tool"})
    return out


def _flow_rank(tactic: str) -> int:
    t = str(tactic or "").strip().lower()
    if t in ATTACK_FLOW_TACTICS:
        return ATTACK_FLOW_TACTICS.index(t)
    return 10_000


def _context_profile(vuln: dict[str, Any]) -> dict[str, Any]:
    vtype = str(vuln.get("type", ""))
    detail = str(vuln.get("detail", ""))
    evidence = str(vuln.get("evidence", ""))
    query = _vulnerability_rag_query(vuln)
    strict_context_text = " ".join([vtype, detail, evidence]).strip()
    context_text = " ".join([strict_context_text, query]).strip()

    terms = _tokenize_text(context_text)
    terms = {t for t in terms if t not in GENERIC_CONTEXT_TOKENS and len(t) >= 3}

    lowered = context_text.lower()
    allows_cloud = any(k in lowered for k in ["cloud", "aws", "azure", "gcp", "s3", "iam"])
    allows_phishing = any(k in lowered for k in ["phish", "email", "inbox", "attachment"])
    return {
        "context_text": context_text,
        "strict_context_text": strict_context_text,
        "focus_terms": terms,
        "allows_cloud": allows_cloud,
        "allows_phishing": allows_phishing,
        "mitre_hint": str(vuln.get("mitre_hint", "")).strip(),
        "expected_primary": _expected_primary_technique(vuln),
    }


def _record_text(record: dict[str, Any]) -> str:
    return " ".join(
        [
            str(record.get("technique_name", "")),
            str(record.get("description", "")),
            " ".join(record.get("tactics", []) or []),
        ]
    )


def _is_contextually_relevant(
    record: dict[str, Any],
    context_text: str,
    focus_terms: set[str],
    allows_cloud: bool,
    allows_phishing: bool,
) -> bool:
    text = _record_text(record)
    low = text.lower()
    overlap = _text_overlap_score(context_text, text)
    relevance = float(record.get("relevance", 0.0))

    if not allows_phishing and any(k in low for k in ["phish", "spearphish", "email attachment", "inbox"]):
        return False
    if not allows_cloud and any(k in low for k in ["aws", "azure", "gcp", "s3", "ec2", "iam", "kubernetes"]):
        return False
    if any(k in low for k in ["malware", "ransomware", "trojan", "rat", "nation-state", "apt"]):
        return False

    # Keep web/data/credential-centric results with clear contextual signal.
    has_focus_term = bool(focus_terms & _tokenize_text(text))
    has_relevant_tactic = any(t in (record.get("tactics", []) or []) for t in ATTACK_FLOW_TACTICS)

    if not has_relevant_tactic:
        return False
    if overlap >= 0.02:
        return True
    if has_focus_term and relevance >= 0.14:
        return True
    return False


def _primary_score(
    record: dict[str, Any],
    context_text: str,
    focus_terms: set[str],
    mitre_hint: str,
    expected_primary: str,
    avoid_primary_ids: set[str],
) -> float:
    tid = str(record.get("technique_id", "")).strip()
    text = _record_text(record)
    overlap = _text_overlap_score(context_text, text)
    relevance = float(record.get("relevance", 0.0))
    direct_term_hits = len(focus_terms & _tokenize_text(text))
    directness = min(1.0, direct_term_hits / 5.0)

    score = (0.5 * overlap) + (0.3 * relevance) + (0.2 * directness)
    if mitre_hint and tid == mitre_hint:
        score += 0.2
    if expected_primary and tid == expected_primary:
        score += 1.5
    elif expected_primary and tid != expected_primary:
        score -= 0.4
    if tid in avoid_primary_ids:
        score -= 0.08
    return score


def _downsample_chain_preserve_order(chain: list[dict[str, Any]], max_steps: int) -> list[dict[str, Any]]:
    if len(chain) <= max_steps:
        return chain
    if max_steps <= 0:
        return []
    if max_steps == 1:
        return [chain[0]]
    idxs = {
        round(i * (len(chain) - 1) / (max_steps - 1))
        for i in range(max_steps)
    }
    selected = [chain[i] for i in sorted(idxs)]
    return selected[:max_steps]


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
def _silent_execution() -> Any:
    """Suppress stdout/stderr and non-critical logs during option execution."""
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    previous_disable = logging.root.manager.disable
    try:
        logging.disable(logging.CRITICAL)
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            yield
    finally:
        logging.disable(previous_disable)


def _write_scan_text_report(
    target_url: str,
    discovery: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    mapped: list[dict[str, Any]],
    mitre_db: MitreAttackDatabase | None,
    rag_engine: RAGEngine | None,
) -> Path:
    config.ensure_directories()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    out_path = config.OUTPUT_DIR / f"scan_report_{ts}.txt"

    lines: list[str] = [
        "===============================",
        "RED AGENT SCAN REPORT",
        "===============================",
        "",
        f"Target: {target_url}",
        f"Scan Time: {scan_time}",
        f"Discovered Routes: {len(discovery.get('routes', []))}",
        f"Discovered Forms: {len(discovery.get('forms', []))}",
        "",
    ]

    used_primary_ids: set[str] = set()
    used_chain_ids: set[str] = set()

    for i, vuln in enumerate(vulnerabilities, 1):
        mapping = mapped[i - 1] if i - 1 < len(mapped) else {}
        chain = _build_dynamic_chain_from_mapping(
            vuln,
            mapping,
            mitre_db,
            rag_engine=rag_engine,
            top_k=25,
            avoid_primary_ids=used_primary_ids,
            avoid_chain_ids=used_chain_ids,
        )
        primary = next((s for s in chain if s.get("is_primary")), chain[0] if chain else {})
        technique_id = str(primary.get("technique_id", "N/A"))
        technique_name = str(primary.get("technique_name", "Unknown Technique"))
        tactics = sorted({str(step.get("tactic", "unknown")) for step in chain}) if chain else []
        tools = _normalize_tools([tool for step in chain for tool in step.get("tools", [])], max_items=4)
        if technique_id and technique_id != "N/A":
            used_primary_ids.add(technique_id)
        for step in chain:
            sid = str(step.get("technique_id", "")).strip()
            if sid:
                used_chain_ids.add(sid)
        affected_url = _infer_affected_url(vuln, target_url)
        evidence_text = str(vuln.get("evidence", "N/A"))
        recommendation = str(vuln.get("recommendation", ""))

        lines.extend(
            [
                "--------------------------------",
                f"[VULNERABILITY #{i}]",
                f"Type: {vuln.get('type', 'Unknown')}",
                f"Severity: {vuln.get('severity', 'N/A')}",
                "",
                "Affected URL:",
                affected_url,
                "",
                "Evidence:",
                f"- {evidence_text}",
                "",
                "--------------------------------",
                "MITRE ATT&CK MAPPING",
                f"Technique ID: {technique_id}",
                f"Technique Name: {technique_name}",
                f"Tactics: {', '.join(tactics) if tactics else 'N/A'}",
                "Tools / Software:",
            ]
        )
        for tool in tools:
            lines.append(f"- {tool.get('name', 'Unknown Tool')}: {tool.get('description', 'N/A')}")
        if not tools:
            lines.append("- No tools found in MITRE dataset")
        lines.extend(["", "--------------------------------", "ATTACK CHAIN:", ""])

        for idx, step in enumerate(chain, 1):
            lines.append(f"{idx}. {str(step.get('tactic', 'unknown')).replace('-', ' ').title()}:")
            lines.append(
                f"   Technique: {step.get('technique_id', 'N/A')} - {step.get('technique_name', 'Unknown')}"
            )
            step_tools = step.get("tools", [])
            lines.append(
                "   Tools: " + (", ".join(t.get("name", "Unknown Tool") for t in step_tools) if step_tools else "No tools found in MITRE dataset")
            )
            lines.append(f"   Description: {step.get('description', 'N/A')}")
            lines.append("")

        lines.extend(
            [
                "--------------------------------",
                "RECOMMENDATION:",
            ]
        )
        for rec in _split_recommendation_lines(recommendation):
            lines.append(f"- {rec}")
        lines.extend(["", "================================", ""])

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def _save_enriched_report(prefix: str, payload: dict[str, Any]) -> tuple[Path, Path]:
    """Keep enriched JSON/Markdown generation for interactive scan outputs."""
    config.ensure_directories()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = config.OUTPUT_DIR / f"{prefix}_{ts}.json"
    md_path = config.OUTPUT_DIR / f"{prefix}_{ts}.md"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    lines = [
        f"# {prefix.replace('_', ' ').title()}",
        "",
        f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- Target URL: {payload.get('target_url', 'N/A')}",
        f"- Total vulnerabilities: {len(payload.get('vulnerabilities', []))}",
        "",
        "## MITRE Mapping Per Vulnerability",
        "",
    ]

    for i, item in enumerate(payload.get("vuln_mappings", []), 1):
        vuln = item.get("vulnerability", {})
        lines.append(f"### {i}. {vuln.get('type', 'Unknown')} [{vuln.get('severity', 'N/A')}]")
        lines.append(f"- Detail: {vuln.get('detail', 'N/A')}")
        techniques = item.get("top_techniques", [])
        if techniques:
            lines.append("- Techniques:")
            for t in techniques:
                lines.append(f"  - [{t.get('technique_id', 'N/A')}] {t.get('name', 'Unknown')}")
        else:
            lines.append("- Techniques: None")
        lines.append("")

    lines += ["## Attack Chain", ""]
    for step in payload.get("attack_chain", []):
        lines.append(
            f"- Step {step.get('step', '?')}: "
            f"[{step.get('technique_id', 'N/A')}] {step.get('technique_name', 'Unknown')} "
            f"({step.get('tactic', 'N/A')})"
        )

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return json_path, md_path


def _write_option_text_report(
    option_slug: str,
    mode_name: str,
    scenario: str | None,
    target_url: str | None,
    vulnerabilities: list[dict[str, Any]],
    mapped: list[dict[str, Any]],
    mitre_db: MitreAttackDatabase | None,
    rag_engine: RAGEngine | None,
) -> Path:
    """Write a structured TXT report for options 2/3/4 (and reusable elsewhere)."""
    config.ensure_directories()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = config.OUTPUT_DIR / f"report_{option_slug}_{ts}.txt"
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    lines: list[str] = [
        "===============================",
        "RED AGENT REPORT",
        "===============================",
        "",
        f"Timestamp: {scan_time}",
        f"Mode: {mode_name}",
        f"Target URL: {target_url or 'N/A'}",
        f"Scenario: {scenario or 'N/A'}",
        "",
    ]

    used_primary_ids: set[str] = set()
    used_chain_ids: set[str] = set()

    if not vulnerabilities:
        vulnerabilities = [
            {
                "type": "Analysis Item",
                "severity": "INFO",
                "detail": "No concrete vulnerability evidence available for this run.",
                "evidence": "N/A",
                "recommendation": "Review scenario assumptions and run with target context if needed.",
                "mitre_hint": "",
            }
        ]

    for i, vuln in enumerate(vulnerabilities, 1):
        mapping = mapped[i - 1] if i - 1 < len(mapped) else {}
        chain = _build_dynamic_chain_from_mapping(
            vuln,
            mapping,
            mitre_db,
            rag_engine=rag_engine,
            top_k=25,
            avoid_primary_ids=used_primary_ids,
            avoid_chain_ids=used_chain_ids,
        )
        primary = next((s for s in chain if s.get("is_primary")), chain[0] if chain else {})
        technique_id = str(primary.get("technique_id", "N/A"))
        technique_name = str(primary.get("technique_name", "Unknown Technique"))
        tactics = sorted({str(step.get("tactic", "unknown")) for step in chain}) if chain else []
        tools = _normalize_tools([tool for step in chain for tool in step.get("tools", [])], max_items=4)
        if technique_id and technique_id != "N/A":
            used_primary_ids.add(technique_id)
        for step in chain:
            sid = str(step.get("technique_id", "")).strip()
            if sid:
                used_chain_ids.add(sid)
        evidence_text = str(vuln.get("evidence", "N/A"))
        recommendation = str(vuln.get("recommendation", ""))
        affected_url = _infer_affected_url(vuln, target_url or "N/A")

        lines.extend(
            [
                "--------------------------------",
                f"[ITEM #{i}]",
                f"Type: {vuln.get('type', 'Unknown')}",
                f"Severity: {vuln.get('severity', 'N/A')}",
                "",
                "Affected URL:",
                affected_url,
                "",
                "Evidence:",
                f"- {evidence_text}",
                "",
                "--------------------------------",
                "MITRE ATT&CK MAPPING",
                f"Technique ID: {technique_id}",
                f"Technique Name: {technique_name}",
                f"Tactics: {', '.join(tactics) if tactics else 'N/A'}",
                "Tools / Software:",
            ]
        )
        for tool in tools:
            lines.append(f"- {tool.get('name', 'Unknown Tool')}: {tool.get('description', 'N/A')}")
        if not tools:
            lines.append("- No tools found in MITRE dataset")
        lines.extend(
            [
                "",
                "--------------------------------",
                "ATTACK CHAIN:",
                "",
            ]
        )

        for idx, step in enumerate(chain, 1):
            lines.append(f"{idx}. {str(step.get('tactic', 'unknown')).replace('-', ' ').title()}:")
            lines.append(
                f"   Technique: {step.get('technique_id', 'N/A')} - {step.get('technique_name', 'Unknown')}"
            )
            step_tools = step.get("tools", [])
            lines.append(
                "   Tools: " + (", ".join(t.get("name", "Unknown Tool") for t in step_tools) if step_tools else "No tools found in MITRE dataset")
            )
            lines.append(f"   Description: {step.get('description', 'N/A')}")
            lines.append("")

        lines.extend(["--------------------------------", "RECOMMENDATION:"])
        for rec in _split_recommendation_lines(recommendation):
            lines.append(f"- {rec}")
        lines.extend(["", "================================", ""])

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


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


def menu_loop() -> None:
    ctx = RuntimeContext()

    while True:
        print("\n=== RED AGENT CLI ===")
        print("1. Full Web Vulnerability Scan (Auto Route Discovery + Attack Chain Output)")
        print("2. Generate Attack Scenario (No URL)")
        print("3. Validate Scenario on Target URL")
        print("4. Analyze Scenario Only")
        print("5. Exit")

        choice = input("Select option [1-5]: ").strip()

        if choice == "1":
            try:
                run_full_web_scan(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Full scan failed")

        elif choice == "2":
            try:
                run_scenario_generation(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Scenario generation failed")

        elif choice == "3":
            try:
                run_scenario_url_validation(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Scenario+URL validation failed")

        elif choice == "4":
            try:
                run_scenario_only_analysis(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Scenario-only analysis failed")

        elif choice == "5":
            print("Exiting Red Agent CLI.")
            break

        else:
            print("Invalid option. Please choose 1, 2, 3, 4, or 5.")


def main() -> int:
    setup_logging()
    print("\nRed ELISAR Interactive Red Agent CLI")
    print("Use only against systems you own or are authorized to test.")
    menu_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## R. Red Agent Web App (Flask UI)

File: $(System.Collections.Hashtable.Path)

```python
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

## S. Vulnerable Application (Demo Target)

File: $(System.Collections.Hashtable.Path)

```python
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
