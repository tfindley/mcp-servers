"""Document -> Markdown conversion with automatic engine routing.

Two backends:
  * markitdown (Microsoft) -- best LLM-targeted Markdown for Office, PDF,
    HTML, images, audio, structured data, archives, email.
  * pandoc (the universal document converter) -- the academic/research
    standard for round-tripping between markup/document formats. Used here
    for formats markitdown does not cover (ODF, LaTeX, RST, RTF, wikis, ...).

The public entry point is `convert_document`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

Engine = Literal["auto", "markitdown", "pandoc"]

# --------------------------------------------------------------------------
# Routing tables (extensions are lower-case, with leading dot)
# --------------------------------------------------------------------------

# Formats we hand to markitdown. It generally produces the cleanest Markdown
# for these and is the preferred engine where both backends overlap.
MARKITDOWN_EXTS = {
    # Office
    ".docx", ".pptx", ".xlsx", ".xls",
    # PDF
    ".pdf",
    # Web / markup
    ".html", ".htm",
    # Structured data (rendered as tables / fenced blocks)
    ".csv", ".tsv", ".json", ".xml",
    # E-book / notebook / email / archive
    ".epub", ".ipynb", ".msg", ".zip",
    # Images (EXIF + optional OCR/captioning)
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp",
    # Audio (metadata + optional transcription)
    ".mp3", ".wav", ".m4a", ".flac", ".ogg",
}

# Formats we hand to pandoc. These are markup/document formats that
# markitdown does not handle but pandoc reads natively.
PANDOC_EXTS = {
    # OpenDocument
    ".odt", ".ods", ".odp",
    # TeX / LaTeX
    ".tex", ".latex", ".ltx",
    # Lightweight markup
    ".rst", ".org", ".textile", ".t2t", ".muse",
    # Rich text / word-processing interchange
    ".rtf",
    # Wikis
    ".mediawiki", ".wiki", ".dokuwiki", ".tikiwiki", ".twiki", ".vimwiki",
    ".creole", ".jira",
    # Docs / publishing
    ".docbook", ".dbk", ".jats", ".tei", ".opml", ".fb2",
    # Roff / man
    ".man", ".ms", ".roff",
    # Bibliography
    ".bib", ".ris", ".json-ld",
    # Typst
    ".typ",
}

# Already text/Markdown -- no conversion needed, just read it.
PASSTHROUGH_EXTS = {".md", ".markdown", ".mdown", ".mkd", ".txt", ".text"}

# pandoc input-format hints for extensions pandoc can't infer from the suffix.
_PANDOC_FORMAT_HINTS = {
    ".wiki": "mediawiki",
    ".dbk": "docbook",
    ".ltx": "latex",
    ".tex": "latex",
    ".t2t": "t2t",
}


@dataclass
class ConversionResult:
    markdown: str
    engine: str
    source: str
    title: Optional[str] = None
    truncated: bool = False
    original_chars: Optional[int] = None


class UnsupportedFormatError(ValueError):
    """Raised when no backend is registered for the given file extension."""


def _ext(path: str) -> str:
    return Path(path).suffix.lower()


def _is_url(path: str) -> bool:
    return path.startswith(("http://", "https://"))


def pick_engine(path: str) -> Engine:
    """Decide which backend handles `path` based on its extension (or URL)."""
    if _is_url(path):
        return "markitdown"  # markitdown fetches and converts remote pages
    ext = _ext(path)
    if ext in MARKITDOWN_EXTS or ext in PASSTHROUGH_EXTS:
        return "markitdown"
    if ext in PANDOC_EXTS:
        return "pandoc"
    # Unknown extension: let markitdown attempt it (it sniffs content types).
    return "markitdown"


def supported_formats() -> dict:
    """Return the routing table, for the `supported_formats` MCP tool."""
    return {
        "markitdown": sorted(MARKITDOWN_EXTS),
        "pandoc": sorted(PANDOC_EXTS),
        "passthrough": sorted(PASSTHROUGH_EXTS),
    }


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------

def _convert_with_markitdown(path: str) -> tuple[str, Optional[str]]:
    from markitdown import MarkItDown

    md = MarkItDown(enable_plugins=False)
    result = md.convert(path)
    title = getattr(result, "title", None)
    return result.text_content, title


def _convert_with_pandoc(path: str) -> tuple[str, Optional[str]]:
    import pypandoc

    extra_args = ["--wrap=none"]  # no hard line wrapping -> cleaner Markdown
    fmt = _PANDOC_FORMAT_HINTS.get(_ext(path))
    kwargs = {"to": "gfm", "extra_args": extra_args}
    if fmt:
        kwargs["format"] = fmt
    text = pypandoc.convert_file(path, **kwargs)
    return text, None


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def convert_document(
    path: str,
    engine: Engine = "auto",
    max_chars: Optional[int] = None,
) -> ConversionResult:
    """Convert a document at `path` to Markdown.

    Args:
        path: Local file path (``~`` is expanded) or an http(s) URL.
        engine: ``"auto"`` (route by extension), ``"markitdown"``, or ``"pandoc"``.
        max_chars: If set, truncate the Markdown to this many characters.

    Raises:
        FileNotFoundError: local path does not exist.
        UnsupportedFormatError: explicit engine can't handle the extension.
        RuntimeError: the backend failed to convert the document.
    """
    if not _is_url(path):
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"No such file: {path}")
        ext = _ext(path)
        # Cheap passthrough for files that are already Markdown/plain text.
        if engine == "auto" and ext in PASSTHROUGH_EXTS:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            return _finalize(text, "passthrough", path, None, max_chars)

    chosen: Engine = pick_engine(path) if engine == "auto" else engine

    # Guard explicit engine choices against formats they can't handle.
    if engine == "pandoc" and not _is_url(path) and _ext(path) in MARKITDOWN_EXTS \
            and _ext(path) not in PANDOC_EXTS:
        raise UnsupportedFormatError(
            f"pandoc does not read '{_ext(path)}'. Use engine='auto' or 'markitdown'."
        )

    try:
        if chosen == "pandoc":
            text, title = _convert_with_pandoc(path)
        else:
            text, title = _convert_with_markitdown(path)
    except Exception as exc:  # surface a clean error to the MCP client
        raise RuntimeError(f"{chosen} failed to convert {path!r}: {exc}") from exc

    return _finalize(text, chosen, path, title, max_chars)


def _finalize(
    text: str,
    engine: str,
    source: str,
    title: Optional[str],
    max_chars: Optional[int],
) -> ConversionResult:
    text = (text or "").strip()
    original = len(text)
    truncated = False
    if max_chars is not None and original > max_chars:
        text = text[:max_chars]
        truncated = True
    return ConversionResult(
        markdown=text,
        engine=engine,
        source=source,
        title=title,
        truncated=truncated,
        original_chars=original,
    )
