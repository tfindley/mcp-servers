"""MCP server exposing read-only NetBox CI tools.

Run with:  netbox-mcp              (after `uv sync`/install)
       or:  uv run netbox-mcp      (from the project directory)

Transport is stdio, which is what Claude Code / Desktop expect. The tool layer
is otherwise transport-agnostic (SPEC.md sec.7) so a remote HTTP entrypoint can
be added later without touching these tools.

Every tool is read-only, scope-constrained (via the NetBox service user + the
configured client-side scope) and field-projected before returning. There is
deliberately NO generic "query any endpoint" tool (SPEC.md sec.3.4).
"""

from __future__ import annotations

import functools
from typing import Optional

import requests
from mcp.types import ToolAnnotations

from .client import NetBoxClient
from .config import AUDIT_SUSPECT_FRAGMENTS, Config, load_config
from .projection import CONFIG_CONTEXT_KEY, REDACTED, project, project_many

try:  # mcp SDK >= 2.0 renamed FastMCP to MCPServer
    from mcp.server import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # mcp SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server
    from mcp.server.fastmcp.exceptions import ToolError

mcp = _Server("netbox")

# Advertised on every tool so a client sees the read-only guarantee in the
# protocol, not just in prose. v1 ships no write tools at all (SPEC.md sec.3.1),
# and reads are issued with a NetBox token whose write_enabled flag is false.
# openWorldHint is true because the data lives in an external system.
_READ_ONLY = ToolAnnotations.model_validate({
    "readOnlyHint": True, "destructiveHint": False,
    "idempotentHint": True, "openWorldHint": True,
})


def _tool(fn):
    """Register a read-only tool, translating errors into the SDK's ToolError.

    mcp SDK 2.x replaces the text of any exception that is NOT a ToolError with
    a generic "Error executing tool <name>" and keeps the detail server-side.
    Without this, the messages that make a failure recoverable -- "no device with
    id 42 (or outside configured scope)", a NetBox 403, a TLS trust failure --
    would never reach the model. functools.wraps keeps the signature and
    docstring the SDK reads to build the tool schema.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ValueError as exc:          # raised by the get_* tools on a miss
            raise ToolError(str(exc)) from exc
        except requests.RequestException as exc:
            raise ToolError(f"NetBox request failed: {exc}") from exc
        except RuntimeError as exc:        # client wraps NetBox failures in these
            raise ToolError(str(exc)) from exc

    return mcp.tool(annotations=_READ_ONLY)(wrapper)


# Lazily-built singletons so importing this module never requires live config.
_config: Config | None = None
_client: NetBoxClient | None = None


def _get() -> tuple[Config, NetBoxClient]:
    global _config, _client
    if _config is None:
        _config = load_config()
    if _client is None:
        _client = NetBoxClient(_config)
    return _config, _client


def _filters(**kwargs) -> dict:
    """Drop unset (None) filters so they don't constrain the NetBox query."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _list_cc(include_config_context: bool, cfg: Config) -> bool:
    """Effective config_context inclusion for a list_* call: requires the hard
    gate AND (an explicit per-call request OR the config default)."""
    return cfg.config_context_enabled and (include_config_context or cfg.config_context_in_lists)


def _project_list(records: list[dict], obj: str, cfg: Config, include_cc: bool) -> list[dict]:
    return project_many(
        records, cfg.fields_for(obj),
        include_config_context=include_cc,
        custom_field_keys=cfg.custom_field_keys,
        redact_keys=cfg.redact_keys, redact_patterns=cfg.redact_patterns,
        redact_paths=cfg.redact_paths,
    )


def _project_one(record: dict, obj: str, cfg: Config, include_cc: bool) -> dict:
    return project(
        record, cfg.fields_for(obj),
        include_config_context=include_cc,
        custom_field_keys=cfg.custom_field_keys,
        redact_keys=cfg.redact_keys, redact_patterns=cfg.redact_patterns,
        redact_paths=cfg.redact_paths,
    )


# --- compute / CI ---------------------------------------------------------
@_tool
def list_devices(
    name: Optional[str] = None,
    tenant: Optional[str] = None,
    site: Optional[str] = None,
    status: Optional[str] = None,
    include_config_context: bool = False,
) -> list[dict]:
    """List NetBox devices (physical CIs) within the configured scope.

    Filters (all optional): name, tenant (slug), site (slug), status.
    Custom fields are included. config_context is returned only when the server's
    config_context gate is enabled AND you pass include_config_context=True (it is
    off by default because it can carry secrets).
    """
    cfg, client = _get()
    include_cc = _list_cc(include_config_context, cfg)
    records = client.list_devices(
        include_config_context=include_cc,
        **_filters(name=name, tenant=tenant, site=site, status=status),
    )
    return _project_list(records, "device", cfg, include_cc)


@_tool
def get_device(device_id: int) -> dict:
    """Get a single NetBox device by id. Includes custom_fields. config_context is
    included only when the server's config_context gate is enabled (off by
    default — it can carry secrets)."""
    cfg, client = _get()
    record = client.get_device(device_id)
    if record is None:
        raise ValueError(f"No device with id {device_id} (or outside configured scope).")
    return _project_one(record, "device", cfg, cfg.config_context_enabled)


@_tool
def list_vms(
    name: Optional[str] = None,
    tenant: Optional[str] = None,
    site: Optional[str] = None,
    status: Optional[str] = None,
    include_config_context: bool = False,
) -> list[dict]:
    """List virtual machines (virtual CIs) within the configured scope.
    Same filter/field semantics as list_devices (config_context off by default)."""
    cfg, client = _get()
    include_cc = _list_cc(include_config_context, cfg)
    records = client.list_vms(
        include_config_context=include_cc,
        **_filters(name=name, tenant=tenant, site=site, status=status),
    )
    return _project_list(records, "vm", cfg, include_cc)


@_tool
def get_vm(vm_id: int) -> dict:
    """Get a single virtual machine by id. Includes custom_fields. config_context
    is included only when the server's config_context gate is enabled (off by
    default — it can carry secrets)."""
    cfg, client = _get()
    record = client.get_vm(vm_id)
    if record is None:
        raise ValueError(f"No virtual machine with id {vm_id} (or outside configured scope).")
    return _project_one(record, "vm", cfg, cfg.config_context_enabled)


# --- addressing -----------------------------------------------------------
@_tool
def list_ip_addresses(
    tenant: Optional[str] = None,
    status: Optional[str] = None,
    address: Optional[str] = None,
) -> list[dict]:
    """List IP addresses within the configured scope. Optional filters: tenant
    (slug), status, address (e.g. '10.0.0.0/24' to match within a prefix)."""
    cfg, client = _get()
    records = client.list_ip_addresses(**_filters(tenant=tenant, status=status, address=address))
    return _project_list(records, "ip_address", cfg, False)


@_tool
def list_prefixes(
    tenant: Optional[str] = None,
    site: Optional[str] = None,
    status: Optional[str] = None,
    prefix: Optional[str] = None,
) -> list[dict]:
    """List prefixes/subnets within the configured scope. Optional filters:
    tenant (slug), site (slug), status, prefix."""
    cfg, client = _get()
    records = client.list_prefixes(**_filters(tenant=tenant, site=site, status=status, prefix=prefix))
    return _project_list(records, "prefix", cfg, False)


@_tool
def list_interfaces(
    device: Optional[str] = None,
    name: Optional[str] = None,
) -> list[dict]:
    """List device interfaces within the configured scope. Optional filters:
    device (name), name (interface name)."""
    cfg, client = _get()
    records = client.list_interfaces(**_filters(device=device, name=name))
    return _project_list(records, "interface", cfg, False)


# --- org / placement context ---------------------------------------------
@_tool
def list_sites(name: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    """List sites (org/location context) within the configured scope."""
    cfg, client = _get()
    records = client.list_sites(**_filters(name=name, status=status))
    return _project_list(records, "site", cfg, False)


@_tool
def list_tenants(name: Optional[str] = None) -> list[dict]:
    """List tenants (org context) within the configured scope."""
    cfg, client = _get()
    records = client.list_tenants(**_filters(name=name))
    return _project_list(records, "tenant", cfg, False)


@_tool
def list_racks(
    name: Optional[str] = None,
    site: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict]:
    """List racks (placement context) within the configured scope."""
    cfg, client = _get()
    records = client.list_racks(**_filters(name=name, site=site, status=status))
    return _project_list(records, "rack", cfg, False)


# --- policy audit ---------------------------------------------------------
@_tool
def audit_config_context_keys(sample_size: int = 50,
                              include_all_keys: bool = False) -> dict:
    """Audit whether the redaction policy actually covers what config_context holds.

    Returns dotted KEY PATHS and occurrence counts only — never a value — so
    running the audit cannot leak what it is auditing.

    config_context is free-form YAML and is the documented secrets vector, while
    `keys` matching is whole-key: an entry for `password` does not cover
    `storagepass`, and a `paths` entry covers exactly one location. This walks
    the real data and reports which key paths the policy blanks, which it does
    not, and which of the latter *look* credential-shaped.

    `flagged_not_redacted` is a prompt for operator review, not a verdict: some
    flagged keys are legitimately public (an authorized-keys list, a GPG public
    key), and a secret with an innocuous name will not be flagged at all.

    By default the full list of unredacted key paths is summarised to a count —
    on a real deployment it runs to hundreds of entries and is almost all
    routine config. Set include_all_keys=True to get every one.

    Requires the config_context gate to be enabled.
    """
    cfg, client = _get()
    if not cfg.config_context_enabled:
        raise ValueError(
            "config_context is disabled ([config_context] enabled = false), so there "
            "is nothing for this audit to inspect. It reads key names only, never "
            "values — enable the gate to audit, or audit with it on in a scratch config."
        )

    raw, sampled = client.audit_records(sample_size)

    # Collect dotted key PATHS from the raw records.
    counts: dict[str, int] = {}

    def walk(node, trail: str) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                path = f"{trail}.{key}" if trail else key
                counts[path] = counts.get(path, 0) + 1
                walk(val, path)
        elif isinstance(node, list):
            for item in node:
                walk(item, trail)   # list index is noise; collapse onto the path

    for record in raw:
        walk(record.get(CONFIG_CONTEXT_KEY) or {}, CONFIG_CONTEXT_KEY)
        walk(record.get("custom_fields") or {}, "custom_fields")

    # Compare against what projection ACTUALLY blanks, rather than re-deriving
    # the matching rules here — this way the audit cannot drift from the filter.
    projected = _project_list([dict(r) for r in raw], "device", cfg, True)
    blanked: set[str] = set()

    def walk_projected(node, trail: str) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                path = f"{trail}.{key}" if trail else key
                if val == REDACTED:
                    blanked.add(path)
                else:
                    walk_projected(val, path)
        elif isinstance(node, list):
            for item in node:
                walk_projected(item, trail)

    for record in projected:
        walk_projected(record.get(CONFIG_CONTEXT_KEY) or {}, CONFIG_CONTEXT_KEY)
        walk_projected(record.get("custom_fields") or {}, "custom_fields")

    covered, uncovered, flagged = [], [], []
    for path, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        entry = {"key_path": path, "occurrences": n}
        if path in blanked:
            covered.append(entry)
            continue
        uncovered.append(entry)
        leaf = path.rsplit(".", 1)[-1].lower()
        hits = [f for f in AUDIT_SUSPECT_FRAGMENTS if f in leaf]
        if hits:
            flagged.append({**entry, "matched_fragments": hits})

    out = {
        "sampled": sampled,
        "distinct_key_paths": len(counts),
        "redacted_by_policy": covered,
        "not_redacted_count": len(uncovered),
        "flagged_not_redacted": flagged,
        "policy": {
            "redact_keys": sorted(cfg.redact_keys),
            "redact_patterns": cfg.redact_patterns,
            "redact_paths": cfg.redact_paths,
        },
        "note": ("Key paths and counts only; no values are returned. "
                 "'flagged_not_redacted' is a heuristic prompt for review, not a "
                 "verdict — some flagged keys are legitimately public, and a "
                 "secret with an innocuous name will not be flagged."),
    }
    if include_all_keys:
        out["not_redacted"] = uncovered
    return out


# --- health ---------------------------------------------------------------
@_tool
def netbox_status() -> dict:
    """NetBox health and the detected NetBox version (confirms connectivity, the
    v3/v4 major the server detected, and whether write tools are enabled)."""
    _, client = _get()
    return client.status()


def main() -> None:
    # Fail fast and loud if required config is missing, before serving.
    load_config()
    mcp.run()


if __name__ == "__main__":
    main()
