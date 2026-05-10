from __future__ import annotations

import re
from pathlib import Path

from fpdf import FPDF


def _soft_wrap_long_tokens(text: str, max_token_len: int = 64) -> str:
    parts = re.split(r"(\s+)", text)
    out: list[str] = []
    for p in parts:
        if not p or p.isspace():
            out.append(p)
            continue
        if len(p) <= max_token_len:
            out.append(p)
            continue
        # Break very long unspaced tokens (URLs, hashes, base64, etc.)
        chunks = [p[i:i + max_token_len] for i in range(0, len(p), max_token_len)]
        out.append(" ".join(chunks))
    return "".join(out)


def _clean_line(text: str) -> str:
    # Keep PDF output ASCII-safe and readable.
    line = str(text or "")
    line = line.replace("`", "")
    line = line.replace("**", "")
    line = line.replace("|", " ")
    line = line.replace("#", "")
    line = line.strip()
    line = line.encode("ascii", "ignore").decode("ascii")
    return _soft_wrap_long_tokens(line)


def render_markdown_to_pdf(md_path: Path, pdf_path: Path, title: str | None = None) -> Path:
    md_path = Path(md_path)
    pdf_path = Path(pdf_path)
    lines = md_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)

    heading = title or "Red Agent Report"
    pdf.multi_cell(0, 8, _clean_line(heading))
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    for line in lines:
        cleaned = _clean_line(line)
        if not cleaned:
            pdf.ln(2)
            continue
        try:
            pdf.multi_cell(0, 5, cleaned)
        except Exception:
            # Last-resort fallback: keep rendering by splitting aggressively.
            safe_line = _soft_wrap_long_tokens(cleaned, max_token_len=32)
            pdf.multi_cell(0, 5, safe_line)

    pdf.output(str(pdf_path))
    return pdf_path
