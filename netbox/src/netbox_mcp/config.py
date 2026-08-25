"""Configuration loading.

Split is deliberate (SPEC.md sec.9):
  * Secrets + connection  -> environment variables (never on disk here).
  * Scope / field policy   -> netbox-mcp.toml (diffable, no secrets).

Env vars:
  NETBOX_URL          (required)  base URL, e.g. https://netbox.example.com
  NETBOX_TOKEN_RO     (required)  read-only token (write_enabled=false)
  NETBOX_TOKEN_RW     (optional)  read-write token; absent -> no write tools
  NETBOX_MCP_CONFIG   (optional)  path to netbox-mcp.toml (default: ./netbox-mcp.toml)
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# --- Sensible per-object default field allow-sets (SPEC.md sec.3.3 / sec.8) ---
# Projection keeps these top-level keys from each serialized record. "custom_fields"
# is included by default everywhere; "config_context" is handled separately and is
# OFF BY DEFAULT (it can carry secrets — see the config_context gate below) so it is
# NOT listed here.
DEFAULT_FIELDS: dict[str, list[str]] = {
    "device": [
        "id", "name", "display", "status", "role", "device_type", "serial",
        "asset_tag", "site", "location", "rack", "position", "face", "tenant",
        "platform", "primary_ip", "primary_ip4", "primary_ip6", "description",
        "tags", "custom_fields", "url", "last_updated",
    ],
    "vm": [
        "id", "name", "display", "status", "role", "site", "cluster", "tenant",
        "platform", "vcpus", "memory", "disk", "primary_ip", "primary_ip4",
        "primary_ip6", "description", "tags", "custom_fields", "url", "last_updated",
    ],
    "ip_address": [
        "id", "display", "address", "status", "role", "tenant", "vrf",
        "assigned_object_type", "assigned_object", "dns_name", "description",
        "tags", "custom_fields", "url", "last_updated",
    ],
    "prefix": [
        "id", "display", "prefix", "status", "role", "site", "tenant", "vrf",
        "vlan", "is_pool", "description", "tags", "custom_fields", "url",
        "last_updated",
    ],
    "interface": [
        "id", "display", "name", "device", "virtual_machine", "type", "enabled",
        "mac_address", "mtu", "mode", "description", "connected_endpoints",
        "tags", "custom_fields", "url", "last_updated",
    ],
    "site": [
        "id", "name", "display", "slug", "status", "region", "group", "tenant",
        "facility", "physical_address", "description", "tags", "custom_fields",
        "url", "last_updated",
    ],
    "tenant": [
        "id", "name", "display", "slug", "group", "description", "tags",
        "custom_fields", "url", "last_updated",
    ],
    "rack": [
        "id", "name", "display", "status", "site", "location", "role", "tenant",
        "u_height", "width", "description", "tags", "custom_fields", "url",
        "last_updated",
    ],
}

# High-confidence secret-ish key names redacted anywhere in a returned record by
# default (defense-in-depth after config_context was found to carry password
# hashes). Overridable via [redact].keys in netbox-mcp.toml; set to [] to disable.
# Deliberately conservative — excludes e.g. "sshkeys" (usually public authorized
# keys). Add your own via config rather than widening these defaults.
DEFAULT_REDACT_KEYS: list[str] = [
    "password", "passwd", "secret", "private_key", "privatekey",
    "api_key", "apikey", "token",
]

# Compound key names that whole-key matching cannot reach -- config_context is
# free-form YAML, so real deployments carry things like `storagepass` and
# `dbPassword` that a `password` entry misses entirely.
#
# These wildcards are ANCHORED at one end on purpose: "*secret" catches
# `clientSecret` while leaving `secretary_name` alone, which a bare "*secret*"
# would blank. That keeps the never-substring property of `keys` intact while
# still covering compounds. Over-matching here is fail-safe (a redacted
# `password_policy` boolean is a nuisance; a leaked credential is not), and
# audit_config_context_keys shows exactly what the policy hides.
#
# Setting [redact].patterns in the toml REPLACES this list. `keys` and
# `patterns` are independent controls with independent defaults.
DEFAULT_REDACT_PATTERNS: list[str] = [
    "*password", "password*", "*passwd", "passwd*",
    "*secret", "secret_*",
    "*token", "token_*",
    "*apikey", "*api_key", "*privatekey", "*private_key",
    "*credential", "*credentials",
]

# Key-name fragments that LOOK credential-shaped. Never used to redact anything
# -- audit_config_context_keys uses them to flag keys the active policy does NOT
# cover, so an operator finds the gap deliberately instead of in a transcript.
# Substring matching is fine here precisely because the output is a report.
AUDIT_SUSPECT_FRAGMENTS: list[str] = [
    "pass", "secret", "token", "credential", "auth", "key", "hash", "salt",
    "otp", "seed", "cert", "licen",
    # NB: no bare "pin" -- it matches "mapping" and produced pure noise on a
    # real deployment. Fragments earn their place by finding something.
]


@dataclass(frozen=True)
class Config:
    url: str
    token_ro: str
    token_rw: str | None = None
    # Scope filters applied client-side to EVERY query as defense-in-depth.
    # The authoritative scope is still the NetBox service-user permission
    # constraint (SPEC.md sec.3.2); this is belt-and-suspenders, not the gate.
    scope_tenants: list[str] = field(default_factory=list)   # tenant slugs
    scope_sites: list[str] = field(default_factory=list)     # site slugs
    # Per-object field allow-sets (override DEFAULT_FIELDS where present).
    fields: dict[str, list[str]] = field(default_factory=dict)
    # If set, restrict custom_fields to these named keys (else pass all through).
    custom_field_keys: list[str] | None = None
    # HARD GATE: config_context is OFF by default because it can carry secrets.
    # When False, config_context is never requested from NetBox and always
    # stripped in projection — no get_*/list_* call can return it, regardless of
    # include_config_context or config_context_in_lists.
    config_context_enabled: bool = False
    # Only meaningful when config_context_enabled is True: whether list_* render
    # config_context by default (get_* always do once the gate is on). Per-call
    # include_config_context still overrides on lists.
    config_context_in_lists: bool = False
    # Redaction applied to EVERY returned record (covers config_context AND
    # custom_fields AND top level). redact_keys: key names blanked anywhere they
    # appear (recursive). redact_paths: dotted, list-aware paths (e.g.
    # "config_context.users.password") blanked at that location.
    redact_keys: list[str] = field(default_factory=lambda: list(DEFAULT_REDACT_KEYS))
    redact_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_REDACT_PATTERNS))
    redact_paths: list[str] = field(default_factory=list)
    # TLS trust for the NetBox HTTPS endpoint (common issue: internal NetBox with
    # a self-signed cert). Prefer pointing tls_ca_bundle at the internal CA cert
    # (secure). tls_verify=False disables verification entirely (insecure — test
    # only). ca_bundle takes precedence when both are set.
    tls_verify: bool = True
    tls_ca_bundle: str | None = None

    @property
    def write_enabled(self) -> bool:
        return bool(self.token_rw)

    @property
    def verify(self):
        """The value to hand requests/pynetbox as ``session.verify``:
        a CA-bundle path, or a bool."""
        return self.tls_ca_bundle if self.tls_ca_bundle else self.tls_verify

    def fields_for(self, obj: str) -> list[str]:
        """Allowed field list for an object type (config override or default)."""
        return self.fields.get(obj, DEFAULT_FIELDS.get(obj, []))


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or malformed."""


def _load_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


def load_config() -> Config:
    """Build Config from environment + netbox-mcp.toml. Raises ConfigError on
    missing required values so the server fails fast and loud at startup."""
    url = os.environ.get("NETBOX_URL", "").strip()
    token_ro = os.environ.get("NETBOX_TOKEN_RO", "").strip()
    token_rw = os.environ.get("NETBOX_TOKEN_RW", "").strip() or None

    missing = [name for name, val in (("NETBOX_URL", url), ("NETBOX_TOKEN_RO", token_ro)) if not val]
    if missing:
        raise ConfigError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "NETBOX_URL and NETBOX_TOKEN_RO (a write_enabled=false token) are required."
        )

    cfg_path = Path(os.environ.get("NETBOX_MCP_CONFIG", "netbox-mcp.toml"))
    raw = _load_toml(cfg_path)

    scope = raw.get("scope", {})
    fields_section = raw.get("fields", {})
    cf = raw.get("custom_fields", {})
    tls = raw.get("tls", {})
    cc = raw.get("config_context", {})
    redact = raw.get("redact", {})

    # config_context gate: env overrides toml; default OFF (secrets vector).
    cc_env = os.environ.get("NETBOX_CONFIG_CONTEXT_ENABLED")
    cc_enabled = _as_bool(cc_env) if cc_env is not None else bool(cc.get("enabled", False))

    # TLS: env overrides toml (env is the quick path for a self-signed test box).
    ca_bundle = os.environ.get("NETBOX_CA_BUNDLE", "").strip() or tls.get("ca_bundle")
    verify_env = os.environ.get("NETBOX_TLS_VERIFY")
    tls_verify = _as_bool(verify_env) if verify_env is not None else bool(tls.get("verify", True))

    return Config(
        url=url,
        token_ro=token_ro,
        token_rw=token_rw,
        scope_tenants=scope.get("tenants", []),
        scope_sites=scope.get("sites", []),
        fields=dict(fields_section),
        custom_field_keys=cf.get("keys"),
        config_context_enabled=cc_enabled,
        config_context_in_lists=bool(cc.get("in_lists", False)),
        redact_keys=redact.get("keys", list(DEFAULT_REDACT_KEYS)),
        redact_patterns=redact.get("patterns", list(DEFAULT_REDACT_PATTERNS)),
        redact_paths=redact.get("paths", []),
        tls_verify=tls_verify,
        tls_ca_bundle=ca_bundle or None,
    )


def _as_bool(value: str) -> bool:
    """Parse a truthy/falsey env string. Anything but an explicit false-ish value
    is treated as True, so a typo fails safe (verification stays ON)."""
    return value.strip().lower() not in {"0", "false", "no", "off", ""}
