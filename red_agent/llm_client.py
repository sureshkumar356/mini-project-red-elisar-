"""
llm_client.py — Unified LLM API Client for Red ELISAR
=======================================================
Provides groq_chat_json() and mistral_chat_json() as thin,
retry-aware wrappers over the Groq and Mistral REST APIs.

Both functions return an LLMResult dataclass with:
  .content    — raw text from the model
  .usage      — {"prompt_tokens": int, "total_tokens": int, ...}
  .latency_s  — end-to-end request wall-clock time in seconds

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

# ── Constants ─────────────────────────────────────────────────────────────────

GROQ_API_BASE    = "https://api.groq.com/openai/v1/chat/completions"
MISTRAL_API_BASE = "https://api.mistral.ai/v1/chat/completions"

# HTTP status codes that are retriable
_RETRY_STATUSES = {429, 500, 502, 503, 504}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class LLMResult:
    """Returned by groq_chat_json / mistral_chat_json."""
    content:   str
    usage:     dict = field(default_factory=dict)
    latency_s: float = 0.0
    model:     str = ""
    raw:       Any = None          # full JSON response (for debugging)


# ── Internal retry helper ─────────────────────────────────────────────────────

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

            # 429 — respect Retry-After if present
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", 0) or 0)
                if retry_after > max_429_wait:
                    raise RuntimeError(
                        f"API rate-limit retry-after={retry_after}s exceeds "
                        f"max_429_wait={max_429_wait}s — aborting."
                    )
                if retry_after > 0:
                    logger.warning("Rate-limited (429). Waiting %.1fs (Retry-After).", retry_after)
                    time.sleep(retry_after)
                    continue

            sleep = min(base_backoff * (2 ** (attempt - 1)), max_backoff)
            sleep += random.uniform(0, jitter)
            logger.warning(
                "HTTP %s — retrying in %.1fs (attempt %d/%d).",
                resp.status_code, sleep, attempt, max_retries + 1,
            )
            time.sleep(sleep)

        except requests.exceptions.RequestException as exc:
            last_exc = exc
            sleep = min(base_backoff * (2 ** (attempt - 1)), max_backoff)
            sleep += random.uniform(0, jitter)
            logger.warning("Request error: %s — retrying in %.1fs.", exc, sleep)
            time.sleep(sleep)

    if last_exc:
        raise last_exc
    raise RuntimeError(f"All {max_retries + 1} attempts to {url} failed.")


# ── Groq (LLaMA 3) ───────────────────────────────────────────────────────────

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


# ── Mistral ───────────────────────────────────────────────────────────────────

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
