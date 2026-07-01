"""NetBox v3 / v4 compatibility shim — kept small and isolated on purpose.

Tested targets: 3.6.9 and 4.5.4 (SPEC.md sec.4). The REST surface for CI-core
objects is stable across these; only a handful of fields differ in shape. When
all target deployments reach v4, this module can be deleted wholesale and
nothing else changes.

Everything here keys off a detected major version so the rest of the codebase
never branches on it.
"""

from __future__ import annotations


def parse_major(version: str) -> int:
    """'3.6.9' -> 3, '4.5.4' -> 4. Falls back to 4 (the assumed-modern default)
    if the string is unparseable rather than crashing the server."""
    try:
        return int(str(version).split(".", 1)[0])
    except (ValueError, AttributeError):
        return 4


def normalize_record(record: dict, major: int) -> dict:
    """Apply any version-specific field normalizations so callers see one shape.

    Currently a near-passthrough — the v3/v4 CI-core REST representations line up
    closely. This is the single, intended home for divergences as we find them
    while testing against 3.6.9 vs 4.5.4. Examples of the kind of thing that
    belongs here (add as verified, not speculatively):
      * `status` rendered as a bare string (older) vs a {value,label} object.
      * minor key renames between lines.
    """
    # Placeholder for verified divergences. Keep additions data-driven and small.
    return record
