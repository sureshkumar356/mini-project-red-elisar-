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
        f"Chunking complete: {stats['total_techniques']} techniques → "
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

    logger.info(f"Chunked {len(logs)} offensive logs → {len(all_chunks)} chunks")
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
