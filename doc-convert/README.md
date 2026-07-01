# doc-convert-mcp

An MCP server that converts non-Markdown documents to **Markdown** so an LLM
reads compact text instead of raw binary/XML/markup — saving tokens.

It auto-routes between two battle-tested converters:

| Backend | Handles |
| --- | --- |
| **[markitdown](https://github.com/microsoft/markitdown)** (Microsoft) | `.pdf` `.docx` `.pptx` `.xlsx` `.xls` `.html` `.csv` `.tsv` `.json` `.xml` `.epub` `.ipynb` `.msg` `.zip` |
| **[pandoc](https://pandoc.org/)** (the universal document converter) | `.odt` `.ods` `.odp` `.tex`/`.latex` `.rst` `.rtf` `.org` `.textile` `.docbook` `.man` `.typ` `.mediawiki` + other wikis, `.fb2` `.opml` `.bib` `.ris` … |

Files that are already Markdown/plain text are returned as-is. `pandoc` ships
bundled via the `pypandoc-binary` package — no system `pandoc` install needed.

## Tools

- **`convert_document(path, engine="auto", max_chars=None)`** → Markdown string.
  `path` is a local file (`~` expanded) or an `http(s)` URL. `engine` is
  `"auto"` (route by extension), `"markitdown"`, or `"pandoc"`.
- **`supported_formats()`** → the routing table (which extension → which backend).

## Install

```bash
cd mcp-servers/doc-convert
uv sync          # creates .venv with all deps (Python 3.13)
```

## Register with Claude Code

```bash
claude mcp add doc-convert -- \
  uv run --directory /absolute/path/to/mcp-servers/doc-convert doc-convert-mcp
```

Or add to `.mcp.json` / `~/.claude.json`:

```json
{
  "mcpServers": {
    "doc-convert": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/absolute/path/to/mcp-servers/doc-convert",
        "doc-convert-mcp"
      ]
    }
  }
}
```

For Claude Desktop, add the same block to its `claude_desktop_config.json`.

## Saving tokens

Because the question was "so I read non-Markdown formats through it
automatically": an MCP server can't *force* interception — the model chooses to
call tools. The `convert_document` tool description steers the model to prefer
it over `Read` for binary/markup documents. To make it stricter, add a line to
your `CLAUDE.md`, e.g.:

> When you need the contents of a `.pdf/.docx/.pptx/.xlsx/.odt/.rtf/.epub/.tex`
> file, call the `doc-convert` MCP's `convert_document` tool instead of `Read`.

## Notes

- Audio transcription and image OCR extras are intentionally omitted (they pull
  heavy ML deps like `onnxruntime`). Add `markitdown[audio-transcription]` etc.
  to `pyproject.toml` if you want them.
