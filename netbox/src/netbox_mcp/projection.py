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
  * redaction      -- redact_keys blank matching key names anywhere;
                      redact_patterns do the same for compound names via
                      anchored wildcards; redact_paths blank dotted, list-aware
                      paths. Applied to the whole record (covers config_context,
                      custom_fields and top level).

Key matching is CASE-INSENSITIVE and whole-key: "password" blanks `Password` and
`PASSWORD`, but never `password_policy` -- substring matching would blank
`bypass` for `pass`. Compound names that whole-key matching cannot reach
(`storagepass`, `dbPassword`) are the job of redact_patterns, whose defaults are
anchored so "*secret" catches `clientSecret` without blanking `secretary_name`.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

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
    redact_patterns: list[str] | None = None,
    redact_paths: list[str] | None = None,
) -> dict:
    """Return a copy of ``record`` reduced to ``allowed`` keys, then redacted.

    Args:
        record: serialized NetBox record (plain dict).
        allowed: the per-object field allow-set.
        include_config_context: if True, retain ``config_context`` even though it
            is not part of ``allowed`` (it is policy-controlled, not field-listed).
        custom_field_keys: if provided, restrict ``custom_fields`` to these keys.
        redact_keys: key names to blank anywhere they appear (recursive,
            case-insensitive, whole-key).
        redact_patterns: fnmatch wildcards matched against key names, for
            compound names whole-key matching cannot reach ("*secret").
        redact_paths: dotted, list-aware paths to blank (e.g.
            "config_context.users.password").
    """
    return _apply(
        record,
        _allow_set(allowed, include_config_context),
        set(custom_field_keys) if custom_field_keys is not None else None,
        _KeyMatcher(redact_keys, redact_patterns),
        _split_paths(redact_paths),
    )


def project_many(
    records: list[dict],
    allowed: list[str],
    *,
    include_config_context: bool,
    custom_field_keys: list[str] | None = None,
    redact_keys: list[str] | None = None,
    redact_patterns: list[str] | None = None,
    redact_paths: list[str] | None = None,
) -> list[dict]:
    # Build the allow-set, keep-set and redaction structures once for the whole
    # list rather than per record — the policy is identical across every row.
    allow = _allow_set(allowed, include_config_context)
    keep_cf = set(custom_field_keys) if custom_field_keys is not None else None
    matcher = _KeyMatcher(redact_keys, redact_patterns)
    redact_pathsegs = _split_paths(redact_paths)
    return [_apply(r, allow, keep_cf, matcher, redact_pathsegs) for r in records]


def _allow_set(allowed: list[str], include_config_context: bool) -> set[str]:
    allow = set(allowed)
    if include_config_context:
        allow.add(CONFIG_CONTEXT_KEY)
    else:
        allow.discard(CONFIG_CONTEXT_KEY)
    return allow


def _split_paths(redact_paths: list[str] | None) -> list[list[str]]:
    return [p.split(".") for p in redact_paths] if redact_paths else []


class _KeyMatcher:
    """Decides whether a key name should be redacted. Built once per projection
    call, not per record -- the policy is identical across every row."""

    __slots__ = ("keys", "patterns")

    def __init__(self, keys: list[str] | None, patterns: list[str] | None):
        # Lowercased on both sides so `Password`/`PASSWORD` match `password`
        # without the operator having to enumerate spellings.
        self.keys = frozenset(k.lower() for k in (keys or ()))
        self.patterns = tuple(p.lower() for p in (patterns or ()))

    def __bool__(self) -> bool:
        return bool(self.keys or self.patterns)

    def matches(self, key: str) -> bool:
        candidate = key.lower()
        if candidate in self.keys:
            return True
        return any(fnmatchcase(candidate, pat) for pat in self.patterns)


def _apply(
    record: dict,
    allow: set[str],
    keep_cf: set[str] | None,
    matcher: _KeyMatcher,
    redact_pathsegs: list[list[str]],
) -> dict:
    # Deep-copied, not shallow-copied: redaction mutates in place, and a shallow
    # copy shares nested dicts with the caller's record -- projecting the same
    # record twice would otherwise let the first pass poison the second.
    out: dict = {k: _deepcopy(v) for k, v in record.items() if k in allow}

    # Restrict custom field keys if the operator narrowed them in config.
    if keep_cf is not None and isinstance(out.get(CUSTOM_FIELDS_KEY), dict):
        out[CUSTOM_FIELDS_KEY] = {
            k: v for k, v in out[CUSTOM_FIELDS_KEY].items() if k in keep_cf
        }

    # Redaction: key-name matches anywhere, then targeted path blanking.
    if matcher:
        _redact_keys(out, matcher)
    for segs in redact_pathsegs:
        _redact_path(out, segs)

    return out


def _deepcopy(node):
    if isinstance(node, dict):
        return {k: _deepcopy(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_deepcopy(v) for v in node]
    return node


def _redact_keys(node, matcher: _KeyMatcher) -> None:
    """Blank any dict key the matcher accepts, recursively (descends dicts and
    lists). The matched value is replaced wholesale with the REDACTED marker
    rather than element-wise, so a redacted list does not leak its length."""
    if isinstance(node, dict):
        for key in node:
            if matcher.matches(key):
                node[key] = REDACTED
            else:
                _redact_keys(node[key], matcher)
    elif isinstance(node, list):
        for item in node:
            _redact_keys(item, matcher)


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
