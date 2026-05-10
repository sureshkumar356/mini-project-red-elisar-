"""
Quick connectivity test for Gemma2 2B cloud endpoint.
Run this BEFORE integrating into the kiosk to verify your API key and URL work.

Usage (PowerShell):
    $env:GEMMA2_API_KEY      = "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    $env:GEMMA2_ENDPOINT_URL = "https://YOUR-ID.endpoints.huggingface.cloud/v1/chat/completions"
    python test_gemma2.py
"""

import os
import sys
import time
import requests

# ── Configuration (reads from environment variables) ──────────────────────────
API_KEY      = os.getenv("GEMMA2_API_KEY", "").strip()
ENDPOINT_URL = os.getenv(
    "GEMMA2_ENDPOINT_URL",
    "https://YOUR-ENDPOINT-ID.endpoints.huggingface.cloud/v1/chat/completions"
)
MODEL = os.getenv("GEMMA2_MODEL", "tgi")   # HF Inference Endpoints use "tgi"

# ── Pre-flight checks ─────────────────────────────────────────────────────────
print("=" * 60)
print("  Gemma2 2B Cloud API — Connectivity Test")
print("=" * 60)

if not API_KEY:
    print("❌  GEMMA2_API_KEY is not set.")
    print("    Run: $env:GEMMA2_API_KEY = 'hf_...'")
    sys.exit(1)

if "YOUR-ENDPOINT-ID" in ENDPOINT_URL:
    print("❌  GEMMA2_ENDPOINT_URL is not configured.")
    print("    Run: $env:GEMMA2_ENDPOINT_URL = 'https://<your-id>.endpoints.huggingface.cloud/v1/chat/completions'")
    sys.exit(1)

print(f"✅  API Key    : {API_KEY[:8]}{'*' * (len(API_KEY) - 8)}")
print(f"✅  Endpoint   : {ENDPOINT_URL}")
print(f"✅  Model      : {MODEL}")
print()

# ── Test 1: Basic "Hello" ─────────────────────────────────────────────────────
print("[Test 1] Basic greeting...")

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type":  "application/json",
}
payload = {
    "model": MODEL,
    "messages": [
        {"role": "system",  "content": "You are a helpful assistant. Be very brief."},
        {"role": "user",    "content": "Say hello in exactly one sentence."},
    ],
    "max_tokens":  60,
    "temperature": 0.3,
    "stream":      False,
}

try:
    t0   = time.perf_counter()
    resp = requests.post(ENDPOINT_URL, headers=headers, json=payload, timeout=60)
    ms   = (time.perf_counter() - t0) * 1000

    if resp.status_code == 200:
        data    = resp.json()
        content = data["choices"][0]["message"]["content"]
        tokens  = data.get("usage", {}).get("total_tokens", "n/a")
        print(f"   ✅  Response   : {content.strip()}")
        print(f"   ✅  Latency    : {ms:.0f} ms")
        print(f"   ✅  Tokens used: {tokens}")
    else:
        print(f"   ❌  HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)

except requests.exceptions.ConnectionError as e:
    print(f"   ❌  Cannot connect: {e}")
    print("       • Is the endpoint running? Check HF Endpoints dashboard.")
    print("       • If endpoint is 'Scaled to zero', click Resume and wait ~60s.")
    sys.exit(1)
except requests.exceptions.Timeout:
    print("   ❌  Request timed out (60s).")
    print("       Cold-start can take 30–120s. Try again in a moment.")
    sys.exit(1)

print()

# ── Test 2: Kiosk-style query ─────────────────────────────────────────────────
print("[Test 2] Kiosk assistant query...")

KIOSK_SYSTEM = (
    "You are ARIA, a kiosk assistant at a government service center. "
    "Answer in 2 sentences max. Be warm and helpful."
)
payload["messages"] = [
    {"role": "system", "content": KIOSK_SYSTEM},
    {"role": "user",   "content": "What documents do I need to apply for a ration card?"},
]
payload["max_tokens"] = 120

try:
    t0   = time.perf_counter()
    resp = requests.post(ENDPOINT_URL, headers=headers, json=payload, timeout=60)
    ms   = (time.perf_counter() - t0) * 1000

    if resp.status_code == 200:
        content = resp.json()["choices"][0]["message"]["content"]
        print(f"   ✅  Response   : {content.strip()}")
        print(f"   ✅  Latency    : {ms:.0f} ms")
    else:
        print(f"   ❌  HTTP {resp.status_code}: {resp.text[:300]}")

except Exception as e:
    print(f"   ❌  Error: {e}")

print()
print("=" * 60)
print("  All tests done. Your Gemma2 2B cloud API is ready to use!")
print("  Next: Run the Flask app and visit http://127.0.0.1:5000/chatbot")
print("=" * 60)
