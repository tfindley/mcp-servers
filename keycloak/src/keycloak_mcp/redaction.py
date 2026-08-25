"""Attribute redaction and projection — the control that keeps confidential and
GDPR-relevant attribute values away from the model.

Keycloak `attributes` are a free-form `{key: [values]}` bag on both groups and
users. In practice they end up holding a mix of things that are fine to read
(entitlements, cost centres, service tiers) and things that are not (personal
data, and occasionally outright secrets). There is no server-side way to ask
Keycloak for "everything except these keys", so the filtering has to happen
here, on the way out.

Two independent controls, applied in this order:

  1. PROJECTION (allow-list, optional) -- reduce `attributes` to a named set of
     keys. Off by default; the strictest option when you know exactly which
     attributes the agent should ever see.
  2. REDACTION (deny-list, on by default) -- blank matching keys ANYWHERE in the
     record, recursively. Three matchers:
        keys     whole-key names, case-insensitive by default (never substring:
                 substring matching would blank `secretary_name` for `secret`)
        patterns fnmatch wildcards for deliberate prefix/substring matching,
                 e.g. "*secret*" or "urn:ietf:params:scim:*"
        paths    targeted dotted, list-aware paths, e.g. "attributes.homeAddress"

Because redaction walks the WHOLE record, adding `email` to the deny-list also
blanks the top-level UserRepresentation `email` field, not just an attribute of
that name. That is intentional.

`mode` decides what a match becomes:
  "redact" (default)  value -> "[redacted]"; the key stays visible, so the model
                      can see that an attribute exists and say so, without
                      reading it.
  "drop"              the key is removed entirely; use when the mere presence of
                      the attribute is itself sensitive.

This module is called from client.py, not from the tool layer, so no tool can
return an unredacted record by forgetting a call (this is a deliberate
tightening of the netbox-mcp arrangement, where the tools invoke projection).
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

REDACTED = "[redacted]"
ATTRIBUTES_KEY = "attributes"


@dataclass(frozen=True)
class RedactionPolicy:
    """A compiled, reusable redaction policy. Build once per server, not per
    record -- the policy is identical for every row."""

    keys: frozenset[str]
    patterns: tuple[str, ...]
    paths: tuple[tuple[str, ...], ...]
    mode: str
    case_sensitive: bool

    @classmethod
    def build(
        cls,
        *,
        keys: list[str] | None = None,
        patterns: list[str] | None = None,
        paths: list[str] | None = None,
        mode: str = "redact",
        case_sensitive: bool = False,
    ) -> RedactionPolicy:
        norm = (lambda s: s) if case_sensitive else (lambda s: s.lower())
        return cls(
            keys=frozenset(norm(k) for k in (keys or ())),
            patterns=tuple(norm(p) for p in (patterns or ())),
            paths=tuple(tuple(p.split(".")) for p in (paths or ())),
            mode=mode,
            case_sensitive=case_sensitive,
        )

    @property
    def active(self) -> bool:
        return bool(self.keys or self.patterns or self.paths)

    def matches(self, key: str) -> bool:
        """True if this key name should be redacted (exact name or wildcard)."""
        candidate = key if self.case_sensitive else key.lower()
        if candidate in self.keys:
            return True
        return any(fnmatchcase(candidate, pat) for pat in self.patterns)

    def apply(self, record: dict) -> dict:
        """Return a redacted deep copy of ``record``. The input is never mutated,
        so a caller holding the raw representation (e.g. to read `path` before
        redaction) is unaffected."""
        if not self.active:
            return _deepcopy(record)
        out = _walk(record, self)
        for segments in self.paths:
            _redact_path(out, list(segments), self.mode)
        return out

    def redacted_keys(self, record: dict) -> list[str]:
        """Key names in this record that the policy would hide. Reported by the
        effective-attributes tool so the model can tell the difference between
        'no such attribute' and 'attribute withheld'."""
        attrs = record.get(ATTRIBUTES_KEY)
        if not isinstance(attrs, dict):
            return []
        return sorted(k for k in attrs if self.matches(k))


def project_attributes(record: dict, allowed: list[str] | None) -> dict:
    """Reduce ``record['attributes']`` to ``allowed`` keys (allow-list mode).

    A no-op when ``allowed`` is None, which is the default -- most operators want
    a deny-list (redaction), not an allow-list. Matching is exact and
    case-sensitive: an allow-list is an explicit enumeration, so a near-miss
    should fail closed rather than quietly widen.
    """
    if allowed is None:
        return record
    attrs = record.get(ATTRIBUTES_KEY)
    if not isinstance(attrs, dict):
        return record
    keep = set(allowed)
    out = dict(record)
    out[ATTRIBUTES_KEY] = {k: v for k, v in attrs.items() if k in keep}
    return out


# --- internals -------------------------------------------------------------

def _deepcopy(node):
    if isinstance(node, dict):
        return {k: _deepcopy(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_deepcopy(v) for v in node]
    return node


def _walk(node, policy: RedactionPolicy):
    """Recursively copy ``node``, blanking or dropping matching keys.

    A matched value is replaced wholesale with the REDACTED marker rather than
    element-wise, so a multi-valued attribute does not leak its cardinality.
    """
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if policy.matches(key):
                if policy.mode == "drop":
                    continue
                out[key] = REDACTED
            else:
                out[key] = _walk(value, policy)
        return out
    if isinstance(node, list):
        return [_walk(item, policy) for item in node]
    return node


def _redact_path(node, segments: list[str], mode: str) -> None:
    """Blank (or drop) the value at a dotted path, in place. List-aware: a list
    encountered mid-path applies the remaining path to every element."""
    if isinstance(node, list):
        for item in node:
            _redact_path(item, segments, mode)
        return
    if not isinstance(node, dict) or segments[0] not in node:
        return
    head, rest = segments[0], segments[1:]
    if rest:
        _redact_path(node[head], rest, mode)
    elif mode == "drop":
        del node[head]
    else:
        node[head] = REDACTED
