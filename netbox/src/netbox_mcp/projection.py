"""Field projection — trims a serialized NetBox record down to the configured
allow-set before it ever reaches the model (SPEC.md sec.3.3), then redacts any
configured secret keys/paths.

NetBox object permissions filter rows, not columns, so column-limiting MUST
happen here. This is also a token-efficiency win: smaller payloads.

Field families handled here:
  * custom_fields  -- passed through by default; restrictable to named keys.
  * config_context -- OFF by default (secrets vector). The caller only sets
                      include_config_context=True when the config_context gate is
                      enabled; projection retains it only then.
  * redaction      -- redact_keys blank matching key names anywhere; redact_paths
                      blank dotted, list-aware paths. Applied to the whole record
                      (covers config_context, custom_fields and top level).
"""

from __future__ import annotations

CONFIG_CONTEXT_KEY = "config_context"
CUSTOM_FIELDS_KEY = "custom_fields"
REDACTED = "[redacted]"


def project(
    record: dict,
    allowed: list[str],
    *,
    include_config_context: bool,
    custom_field_keys: list[str] | None = None,
    redact_keys: list[str] | None = None,
    redact_paths: list[str] | None = None,
) -> dict:
    """Return a copy of ``record`` reduced to ``allowed`` keys, then redacted.

    Args:
        record: serialized NetBox record (plain dict).
        allowed: the per-object field allow-set.
        include_config_context: if True, retain ``config_context`` even though it
            is not part of ``allowed`` (it is policy-controlled, not field-listed).
        custom_field_keys: if provided, restrict ``custom_fields`` to these keys.
        redact_keys: key names to blank anywhere they appear (recursive).
        redact_paths: dotted, list-aware paths to blank (e.g.
            "config_context.users.password").
    """
    return _apply(
        record,
        _allow_set(allowed, include_config_context),
        set(custom_field_keys) if custom_field_keys is not None else None,
        set(redact_keys or ()),
        _split_paths(redact_paths),
    )


def project_many(
    records: list[dict],
    allowed: list[str],
    *,
    include_config_context: bool,
    custom_field_keys: list[str] | None = None,
    redact_keys: list[str] | None = None,
    redact_paths: list[str] | None = None,
) -> list[dict]:
    # Build the allow-set, keep-set and redaction structures once for the whole
    # list rather than per record — the policy is identical across every row.
    allow = _allow_set(allowed, include_config_context)
    keep_cf = set(custom_field_keys) if custom_field_keys is not None else None
    redact_keyset = set(redact_keys or ())
    redact_pathsegs = _split_paths(redact_paths)
    return [_apply(r, allow, keep_cf, redact_keyset, redact_pathsegs) for r in records]


def _allow_set(allowed: list[str], include_config_context: bool) -> set[str]:
    allow = set(allowed)
    if include_config_context:
        allow.add(CONFIG_CONTEXT_KEY)
    else:
        allow.discard(CONFIG_CONTEXT_KEY)
    return allow


def _split_paths(redact_paths: list[str] | None) -> list[list[str]]:
    return [p.split(".") for p in redact_paths] if redact_paths else []


def _apply(
    record: dict,
    allow: set[str],
    keep_cf: set[str] | None,
    redact_keyset: set[str],
    redact_pathsegs: list[list[str]],
) -> dict:
    out: dict = {k: v for k, v in record.items() if k in allow}

    # Restrict custom field keys if the operator narrowed them in config.
    if keep_cf is not None and isinstance(out.get(CUSTOM_FIELDS_KEY), dict):
        out[CUSTOM_FIELDS_KEY] = {
            k: v for k, v in out[CUSTOM_FIELDS_KEY].items() if k in keep_cf
        }

    # Redaction: key-name matches anywhere, then targeted path blanking.
    if redact_keyset:
        _redact_keys(out, redact_keyset)
    for segs in redact_pathsegs:
        _redact_path(out, segs)

    return out


def _redact_keys(node, keys: set[str]) -> None:
    """Blank any dict key whose name is in ``keys``, recursively (descends dicts
    and lists). The matched value is replaced with the REDACTED marker."""
    if isinstance(node, dict):
        for key in node:
            if key in keys:
                node[key] = REDACTED
            else:
                _redact_keys(node[key], keys)
    elif isinstance(node, list):
        for item in node:
            _redact_keys(item, keys)


def _redact_path(node, segments: list[str]) -> None:
    """Blank the value at a dotted path. List-aware: if a list is encountered
    mid-path, the remaining path is applied to every element (so
    'users.password' blanks password in each list item)."""
    if isinstance(node, list):
        for item in node:
            _redact_path(item, segments)
        return
    if isinstance(node, dict) and segments[0] in node:
        head, rest = segments[0], segments[1:]
        if rest:
            _redact_path(node[head], rest)
        else:
            node[head] = REDACTED
