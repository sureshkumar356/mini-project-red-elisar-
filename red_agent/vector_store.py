"""
Red ELISAR — ChromaDB Vector Store
====================================
Manages vector embeddings for MITRE ATT&CK techniques using ChromaDB
with SentenceTransformers for offline embedding generation.

Architecture:
    ┌─────────────────┐    ┌──────────────────┐    ┌─────────────┐
    │ AttackTechnique  │───>│ SentenceTransform │───>│  ChromaDB   │
    │   .to_embed()    │    │  (all-MiniLM-L6)  │    │ (persistent)│
    └─────────────────┘    └──────────────────┘    └─────────────┘

Design Decisions:
    1. ChromaDB is chosen over FAISS because:
       - Built-in persistence (survives restarts without re-embedding)
       - Metadata filtering (filter by tactic, platform)
       - No manual index management
       - Acceptable performance for ATT&CK-scale (~800 techniques)
    
    2. SentenceTransformers 'all-MiniLM-L6-v2' is chosen because:
       - 80MB model size (fits comfortably in 16GB RAM)
       - 384-dim embeddings (compact storage in ChromaDB)
       - Strong semantic similarity for technical text
       - Fully offline after initial download
    
    3. Embedding strategy: technique ID + name + tactics + description
       concatenated into a single text improves retrieval for both
       tactical queries ("initial access techniques") and specific
       queries ("PowerShell exploitation").

Memory Profile:
    - SentenceTransformer model: ~200MB in RAM
    - ChromaDB with ~800 techniques: ~5MB on disk, ~50MB in RAM
    - Peak during batch embedding: ~500MB
    - Steady-state after indexing: ~250MB

Performance:
    - Initial indexing: ~30-60 seconds (CPU-only)
    - Query latency: <50ms per query (including embedding + search)
    - ChromaDB uses HNSW index internally (ANN search)
"""

import logging
import time
import gc
from pathlib import Path
from typing import Optional

import chromadb
from sentence_transformers import SentenceTransformer

import config
from mitre_parser import AttackTechnique

logger = logging.getLogger("red_elisar.vector_store")


class VectorStore:
    """
    Manages ChromaDB vector store for MITRE ATT&CK technique embeddings.
    
    Handles embedding generation, indexing, and similarity search
    with full offline capability.
    """
    
    def __init__(
        self,
        persist_dir: Optional[Path] = None,
        model_name: Optional[str] = None,
    ):
        """
        Initialize the vector store.
        
        Args:
            persist_dir: ChromaDB persistence directory.
            model_name: SentenceTransformer model name.
        """
        self.persist_dir = persist_dir or config.CHROMA_PERSIST_DIR
        self.model_name = model_name or config.EMBEDDING_MODEL_NAME
        
        self._model: Optional[SentenceTransformer] = None
        self._client: Optional[chromadb.ClientAPI] = None
        self._collection = None
    
    # ========================================================================
    # LAZY INITIALIZATION (Memory Optimization)
    # ========================================================================
    # The embedding model and ChromaDB client are loaded lazily to avoid
    # loading ~200MB into RAM until actually needed. This is critical
    # for 16GB systems running multiple processes.
    
    @property
    def model(self) -> SentenceTransformer:
        """Lazy-load the SentenceTransformer embedding model."""
        if self._model is None:
            logger.info(f"Loading embedding model: {self.model_name}")
            start = time.perf_counter()
            
            self._model = SentenceTransformer(
                self.model_name,
                device="cpu",  # Explicit CPU to avoid GPU memory issues
            )
            
            elapsed = time.perf_counter() - start
            logger.info(f"Embedding model loaded in {elapsed:.2f}s")
        
        return self._model
    
    @property
    def client(self) -> chromadb.ClientAPI:
        """Lazy-load the ChromaDB persistent client."""
        if self._client is None:
            config.ensure_directories()
            logger.info(f"Initializing ChromaDB at: {self.persist_dir}")
            
            self._client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=chromadb.Settings(
                    anonymized_telemetry=False,  # Privacy: no telemetry
                    allow_reset=True,
                ),
            )
        
        return self._client
    
    @property
    def collection(self):
        """Get or create the techniques collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=config.CHROMA_COLLECTION_NAME,
                metadata={"hnsw:space": config.CHROMA_DISTANCE_METRIC},
            )
        return self._collection
    
    # ========================================================================
    # INDEXING
    # ========================================================================
    
    def index_techniques(
        self,
        techniques: list[AttackTechnique],
        force_reindex: bool = False,
    ) -> dict:
        """
        Index MITRE ATT&CK techniques into ChromaDB.
        
        If the collection already has data and force_reindex is False,
        skips indexing to avoid redundant computation.
        
        Args:
            techniques: List of parsed AttackTechnique objects.
            force_reindex: If True, deletes existing collection and re-indexes.
        
        Returns:
            Dictionary with indexing statistics.
        """
        stats = {
            "total_techniques": len(techniques),
            "indexed": 0,
            "skipped": 0,
            "embedding_time_s": 0.0,
            "indexing_time_s": 0.0,
            "total_time_s": 0.0,
        }
        
        total_start = time.perf_counter()
        
        # Check if already indexed
        existing_count = self.collection.count()
        if existing_count > 0 and not force_reindex:
            logger.info(
                f"Collection already contains {existing_count} techniques. "
                f"Skipping indexing. Use force_reindex=True to rebuild."
            )
            stats["skipped"] = existing_count
            stats["total_time_s"] = time.perf_counter() - total_start
            return stats
        
        # Clear existing data if re-indexing
        if force_reindex and existing_count > 0:
            logger.info(f"Force re-indexing: deleting {existing_count} existing entries")
            self.client.delete_collection(config.CHROMA_COLLECTION_NAME)
            self._collection = None  # Reset cached reference
        
        # Prepare documents for embedding
        ids = []
        documents = []
        metadatas = []
        
        for tech in techniques:
            ids.append(tech.technique_id)
            documents.append(tech.to_embedding_text())
            metadatas.append({
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactics": ",".join(tech.tactics) if tech.tactics else "unknown",
                "platforms": ",".join(tech.platforms) if tech.platforms else "unknown",
                "is_subtechnique": str(tech.is_subtechnique),
                "stix_id": tech.stix_id,
                "url": tech.url,
                # Store truncated description in metadata for retrieval display
                "description_preview": tech.description[:500],
            })
        
        logger.info(f"Generating embeddings for {len(documents)} techniques...")
        
        # Generate embeddings in batches to control memory
        embed_start = time.perf_counter()
        
        all_embeddings = []
        batch_size = config.EMBEDDING_BATCH_SIZE
        
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            batch_embeddings = self.model.encode(
                batch,
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,  # Cosine similarity optimization
            )
            all_embeddings.extend(batch_embeddings.tolist())
            
            logger.debug(
                f"Embedded batch {i//batch_size + 1}/"
                f"{(len(documents) + batch_size - 1)//batch_size}"
            )
        
        stats["embedding_time_s"] = time.perf_counter() - embed_start
        logger.info(f"Embeddings generated in {stats['embedding_time_s']:.2f}s")
        
        # Insert into ChromaDB in batches
        index_start = time.perf_counter()
        insert_batch = config.CHROMA_INSERT_BATCH_SIZE
        
        for i in range(0, len(ids), insert_batch):
            end = min(i + insert_batch, len(ids))
            self.collection.add(
                ids=ids[i:end],
                embeddings=all_embeddings[i:end],
                documents=documents[i:end],
                metadatas=metadatas[i:end],
            )
        
        stats["indexing_time_s"] = time.perf_counter() - index_start
        stats["indexed"] = len(ids)
        stats["total_time_s"] = time.perf_counter() - total_start
        
        logger.info(
            f"Indexed {stats['indexed']} techniques in {stats['total_time_s']:.2f}s "
            f"(embed: {stats['embedding_time_s']:.2f}s, "
            f"index: {stats['indexing_time_s']:.2f}s)"
        )
        
        # Free embedding memory
        del all_embeddings
        if config.AGGRESSIVE_GC:
            gc.collect()
        
        return stats
    
    # ========================================================================
    # RETRIEVAL
    # ========================================================================
    
    def query(
        self,
        query_text: str,
        top_k: int = None,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> list[dict]:
        """
        Retrieve the most relevant techniques for a query.
        
        Uses semantic similarity search over technique embeddings.
        Optional metadata filters narrow results by tactic or platform.
        
        Args:
            query_text: Natural language query describing the attack scenario.
            top_k: Number of results to return (default: config.RAG_TOP_K).
            tactic_filter: Filter by specific tactic (e.g., "initial-access").
            platform_filter: Filter by platform (e.g., "Windows").
        
        Returns:
            List of result dicts with keys: technique_id, name, description,
            tactics, distance, document.
        """
        if top_k is None:
            top_k = config.RAG_TOP_K
        
        start = time.perf_counter()
        
        # Embed the query
        query_embedding = self.model.encode(
            [query_text],
            convert_to_numpy=True,
            normalize_embeddings=True,
        ).tolist()
        
        # Build metadata filter
        where_filter = None
        if tactic_filter or platform_filter:
            conditions = []
            if tactic_filter:
                # ChromaDB $contains for comma-separated tactics
                conditions.append({"tactics": {"$contains": tactic_filter}})
            if platform_filter:
                conditions.append({"platforms": {"$contains": platform_filter}})
            
            if len(conditions) == 1:
                where_filter = conditions[0]
            else:
                where_filter = {"$and": conditions}
        
        # Execute similarity search
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=min(top_k, self.collection.count()),
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )
        
        elapsed = time.perf_counter() - start
        
        # Format results
        formatted_results = []
        if results and results["ids"] and results["ids"][0]:
            for i, tech_id in enumerate(results["ids"][0]):
                distance = results["distances"][0][i]
                
                # Apply relevance threshold
                if distance > config.RELEVANCE_THRESHOLD:
                    continue
                
                metadata = results["metadatas"][0][i]
                formatted_results.append({
                    "technique_id": tech_id,
                    "name": metadata.get("name", ""),
                    "tactics": metadata.get("tactics", "").split(","),
                    "platforms": metadata.get("platforms", "").split(","),
                    "description_preview": metadata.get("description_preview", ""),
                    "distance": round(distance, 4),
                    "relevance_score": round(1 - distance, 4),  # Convert distance to similarity
                    "document": results["documents"][0][i],
                    "stix_id": metadata.get("stix_id", ""),
                    "url": metadata.get("url", ""),
                })
        
        logger.info(
            f"Query completed in {elapsed*1000:.1f}ms: "
            f"'{query_text[:50]}...' → {len(formatted_results)} results"
        )
        
        return formatted_results
    
    def query_by_technique_id(self, technique_id: str) -> Optional[dict]:
        """
        Retrieve a specific technique by its MITRE ID.
        
        Args:
            technique_id: MITRE technique ID (e.g., "T1059").
        
        Returns:
            Technique dict or None if not found.
        """
        try:
            result = self.collection.get(
                ids=[technique_id],
                include=["documents", "metadatas"],
            )
            if result and result["ids"]:
                metadata = result["metadatas"][0]
                return {
                    "technique_id": technique_id,
                    "name": metadata.get("name", ""),
                    "tactics": metadata.get("tactics", "").split(","),
                    "platforms": metadata.get("platforms", "").split(","),
                    "description_preview": metadata.get("description_preview", ""),
                    "document": result["documents"][0],
                    "stix_id": metadata.get("stix_id", ""),
                    "url": metadata.get("url", ""),
                }
        except Exception as e:
            logger.warning(f"Technique {technique_id} not found: {e}")
        
        return None
    
    # ========================================================================
    # UTILITIES
    # ========================================================================
    
    def get_collection_stats(self) -> dict:
        """Get statistics about the indexed collection."""
        count = self.collection.count()
        return {
            "total_documents": count,
            "collection_name": config.CHROMA_COLLECTION_NAME,
            "embedding_model": self.model_name,
            "embedding_dimension": config.EMBEDDING_DIMENSION,
            "distance_metric": config.CHROMA_DISTANCE_METRIC,
            "persist_directory": str(self.persist_dir),
        }
    
    def reset(self):
        """Delete the collection and reset state. Use with caution."""
        logger.warning("Resetting vector store — all indexed data will be lost")
        try:
            self.client.delete_collection(config.CHROMA_COLLECTION_NAME)
        except ValueError:
            pass  # Collection doesn't exist
        self._collection = None
    
    def unload_model(self):
        """
        Unload the embedding model to free ~200MB RAM.
        
        Useful after indexing is complete and only ChromaDB queries
        are needed (ChromaDB stores embeddings, so the model is only
        needed for new queries).
        
        Note: Model will be reloaded on next query() call.
        """
        if self._model is not None:
            del self._model
            self._model = None
            if config.AGGRESSIVE_GC:
                gc.collect()
            logger.info("Embedding model unloaded to free memory")


# ============================================================================
# STANDALONE EXECUTION
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)
    
    from mitre_parser import MITREParser
    
    # Parse techniques
    parser = MITREParser()
    techniques = parser.parse()
    
    # Index into ChromaDB
    store = VectorStore()
    stats = store.index_techniques(techniques, force_reindex=True)
    
    print(f"\nIndexing Stats: {stats}")
    print(f"Collection Stats: {store.get_collection_stats()}")
    
    # Test query
    test_query = "initial access via phishing with malicious attachment"
    results = store.query(test_query, top_k=5)
    
    print(f"\nQuery: '{test_query}'")
    print(f"Results:")
    for r in results:
        print(f"  [{r['technique_id']}] {r['name']} "
              f"(score: {r['relevance_score']}, tactics: {r['tactics']})")
