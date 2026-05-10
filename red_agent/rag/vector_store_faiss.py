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

            # Convert L2 distance → cosine similarity (normalized vectors)
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
            f"'{query_text[:50]}...' → {len(results)} results"
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
        logger.info(f"Index persisted: {self._index.ntotal} vectors → {self._index_path}")

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
        logger.warning("Resetting FAISS index — all indexed data will be lost")
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
