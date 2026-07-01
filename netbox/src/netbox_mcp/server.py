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

from typing import Optional

from mcp.server.fastmcp import FastMCP

from .client import NetBoxClient
from .config import Config, load_config
from .projection import project, project_many

mcp = FastMCP("netbox")

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
        redact_keys=cfg.redact_keys, redact_paths=cfg.redact_paths,
    )


def _project_one(record: dict, obj: str, cfg: Config, include_cc: bool) -> dict:
    return project(
        record, cfg.fields_for(obj),
        include_config_context=include_cc,
        custom_field_keys=cfg.custom_field_keys,
        redact_keys=cfg.redact_keys, redact_paths=cfg.redact_paths,
    )


# --- compute / CI ---------------------------------------------------------
@mcp.tool()
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


@mcp.tool()
def get_device(device_id: int) -> dict:
    """Get a single NetBox device by id. Includes custom_fields. config_context is
    included only when the server's config_context gate is enabled (off by
    default — it can carry secrets)."""
    cfg, client = _get()
    record = client.get_device(device_id)
    if record is None:
        raise ValueError(f"No device with id {device_id} (or outside configured scope).")
    return _project_one(record, "device", cfg, cfg.config_context_enabled)


@mcp.tool()
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


@mcp.tool()
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
@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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
@mcp.tool()
def list_sites(name: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    """List sites (org/location context) within the configured scope."""
    cfg, client = _get()
    records = client.list_sites(**_filters(name=name, status=status))
    return _project_list(records, "site", cfg, False)


@mcp.tool()
def list_tenants(name: Optional[str] = None) -> list[dict]:
    """List tenants (org context) within the configured scope."""
    cfg, client = _get()
    records = client.list_tenants(**_filters(name=name))
    return _project_list(records, "tenant", cfg, False)


@mcp.tool()
def list_racks(
    name: Optional[str] = None,
    site: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict]:
    """List racks (placement context) within the configured scope."""
    cfg, client = _get()
    records = client.list_racks(**_filters(name=name, site=site, status=status))
    return _project_list(records, "rack", cfg, False)


# --- health ---------------------------------------------------------------
@mcp.tool()
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
