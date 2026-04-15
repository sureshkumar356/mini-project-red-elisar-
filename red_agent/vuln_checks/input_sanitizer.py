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
