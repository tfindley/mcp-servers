"""MCP server exposing document -> Markdown conversion tools.

Run with:  doc-convert-mcp           (after `uv sync`/install)
       or:  uv run doc-convert-mcp   (from the project directory)

Transport is stdio, which is what Claude Code / Desktop expect.
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

from .convert import (
    Engine,
    UnsupportedFormatError,
    convert_document as _convert,
    supported_formats as _supported_formats,
)

mcp = FastMCP("doc-convert")


@mcp.tool()
def convert_document(
    path: str,
    engine: str = "auto",
    max_chars: Optional[int] = None,
) -> str:
    """Convert a non-Markdown document to clean Markdown.

    USE THIS INSTEAD OF READING THE FILE DIRECTLY whenever you need the
    *contents* of a .pdf, .docx, .pptx, .xlsx, .odt, .rtf, .epub, .html,
    .csv, .tex/.rst, or similar document. Reading those raw wastes tokens
    (binary/XML/markup noise); this returns compact Markdown instead.

    Routing is automatic: Office/PDF/HTML/images/audio/data go through
    Microsoft markitdown; OpenDocument/LaTeX/RST/RTF/wiki formats go through
    pandoc. Files that are already Markdown/plain text are returned as-is.

    Args:
        path: Local file path (``~`` expanded) or an http(s) URL.
        engine: "auto" (default), "markitdown", or "pandoc".
        max_chars: Optional cap on returned characters (for very large docs).

    Returns:
        The document rendered as Markdown. If truncated, a trailing notice
        states how many characters were omitted.
    """
    if engine not in ("auto", "markitdown", "pandoc"):
        raise ValueError("engine must be 'auto', 'markitdown', or 'pandoc'")

    try:
        result = _convert(path, engine=engine, max_chars=max_chars)  # type: ignore[arg-type]
    except (FileNotFoundError, UnsupportedFormatError) as exc:
        # Return as a clear error string the model can act on.
        raise ValueError(str(exc)) from exc

    out = result.markdown
    if result.truncated:
        omitted = (result.original_chars or 0) - len(result.markdown)
        out += (
            f"\n\n---\n*[truncated by doc-convert: {omitted} of "
            f"{result.original_chars} characters omitted; "
            f"re-call with a larger max_chars to see more]*"
        )
    return out or "*[doc-convert: conversion produced no text]*"


@mcp.tool()
def supported_formats() -> dict:
    """List which file extensions route to which backend (markitdown vs pandoc)."""
    return _supported_formats()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
