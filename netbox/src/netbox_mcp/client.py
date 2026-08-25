"""NetBoxClient — the single internal interface every tool calls.

The MCP tool layer (server.py) talks ONLY to this class, never to pynetbox
directly. That is what keeps the read engine swappable (SPEC.md sec.5): if
pynetbox's lazy object model ever gets in the way, this one file can be
re-implemented on raw httpx without touching a single tool.

Reads are always issued with the read-only token. The client exposes no write
methods in v1 (SPEC.md sec.3.1 / sec.8).
"""

from __future__ import annotations

import sys
from typing import Any

import pynetbox
import requests
from pynetbox.core.response import Record

from .compat import normalize_record, parse_major
from .config import Config

# pynetbox Record instance attributes that are framework internals, not data.
_INTERNAL_ATTRS = {
    "api", "default_ret", "endpoint", "url", "has_details",
    "object_list_metadata",
}


def _convert(value: Any) -> Any:
    """Recursively turn pynetbox Records into plain, readable dicts.

    Nested related objects (site, tenant, role, ...) are preserved as
    {id, name/display, ...} dicts rather than flattened to bare IDs, because the
    readable names are exactly what's useful to a model reading CI data.
    """
    if isinstance(value, Record):
        out: dict[str, Any] = {}
        for key, val in vars(value).items():
            if key.startswith("_") or key in _INTERNAL_ATTRS:
                continue
            out[key] = _convert(val)
        return out
    if isinstance(value, list):
        return [_convert(v) for v in value]
    return value


class NetBoxClient:
    def __init__(self, config: Config):
        self._config = config
        self._api = pynetbox.api(config.url, token=config.token_ro)
        # Configure TLS trust on the underlying requests session (handles the
        # common internal-NetBox self-signed-cert case). ca_bundle path is the
        # secure fix; verify=False is an insecure test-only escape hatch.
        session = requests.Session()
        session.verify = config.verify
        if config.verify is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            print(
                "netbox-mcp: WARNING — TLS certificate verification is DISABLED "
                "(NETBOX_TLS_VERIFY=false). Connection is not protected against "
                "interception; use a CA bundle instead for anything but testing.",
                file=sys.stderr,
            )
        self._api.http_session = session
        self._major: int | None = None  # lazily detected NetBox major version

    # --- meta -------------------------------------------------------------
    @property
    def major(self) -> int:
        if self._major is None:
            self._major = parse_major(getattr(self._api, "version", "") or "")
        return self._major

    def status(self) -> dict:
        """NetBox health + detected version (drives netbox_status tool)."""
        try:
            raw = self._api.status()
        except Exception as exc:  # surface a clear, actionable error to the model
            raise RuntimeError(f"NetBox status check failed: {exc}") from exc
        return {
            "netbox_version": raw.get("netbox-version"),
            "detected_major": self.major,
            "python_version": raw.get("python-version"),
            "plugins": raw.get("plugins", {}),
            "write_tools_enabled": self._config.write_enabled,
        }

    # --- scope helper -----------------------------------------------------
    def _scoped(self, filters: dict) -> dict:
        """Merge configured scope (tenant/site slugs) into a filter dict as
        client-side defense-in-depth. NetBox permission constraints remain the
        authoritative gate (SPEC.md sec.3.2); this just narrows further and never
        widens. Caller-supplied filters win if they overlap."""
        scoped = dict(filters)
        if self._config.scope_tenants and "tenant" not in scoped:
            scoped["tenant"] = self._config.scope_tenants
        if self._config.scope_sites and "site" not in scoped:
            scoped["site"] = self._config.scope_sites
        return {k: v for k, v in scoped.items() if v is not None}

    # --- generic fetch primitives ----------------------------------------
    def _list(self, endpoint, filters: dict, *, include_config_context: bool) -> list[dict]:
        query = self._scoped(filters)
        if include_config_context:
            # NetBox renders config_context into list views only when asked.
            # TODO: verify the exact param against 3.6.9 vs 4.5.4 during testing.
            query["include"] = "config_context"
        records = endpoint.filter(**query) if query else endpoint.all()
        return [normalize_record(_convert(r), self.major) for r in records]

    def _get(self, endpoint, object_id: int) -> dict | None:
        record = endpoint.get(object_id)
        if record is None:
            return None
        # Detail view already includes config_context.
        return normalize_record(_convert(record), self.major)

    # --- CI-core objects (v1) --------------------------------------------
    def list_devices(self, *, include_config_context: bool, **filters) -> list[dict]:
        return self._list(self._api.dcim.devices, filters, include_config_context=include_config_context)

    def get_device(self, object_id: int) -> dict | None:
        return self._get(self._api.dcim.devices, object_id)

    def list_vms(self, *, include_config_context: bool, **filters) -> list[dict]:
        return self._list(
            self._api.virtualization.virtual_machines, filters,
            include_config_context=include_config_context,
        )

    def get_vm(self, object_id: int) -> dict | None:
        return self._get(self._api.virtualization.virtual_machines, object_id)

    def list_ip_addresses(self, **filters) -> list[dict]:
        return self._list(self._api.ipam.ip_addresses, filters, include_config_context=False)

    def list_prefixes(self, **filters) -> list[dict]:
        return self._list(self._api.ipam.prefixes, filters, include_config_context=False)

    def list_interfaces(self, **filters) -> list[dict]:
        # dcim interfaces only in v1; VM interfaces are a clean follow-up.
        return self._list(self._api.dcim.interfaces, filters, include_config_context=False)

    def list_sites(self, **filters) -> list[dict]:
        return self._list(self._api.dcim.sites, filters, include_config_context=False)

    def list_tenants(self, **filters) -> list[dict]:
        return self._list(self._api.tenancy.tenants, filters, include_config_context=False)

    # --- policy audit ------------------------------------------------------
    def audit_records(self, limit: int) -> tuple[list[dict], dict]:
        """Raw (unprojected) device/VM records for the redaction audit, plus a
        note of how many of each were sampled.

        Deliberately bypasses projection: the audit's whole job is to compare
        what NetBox holds against what the policy hides, so it needs the
        pre-redaction shape. Only KEY NAMES ever leave audit_config_context_keys
        -- never a value.
        """
        devices = self.list_devices(include_config_context=True)[:limit]
        vms = self.list_vms(include_config_context=True)[:limit]
        return devices + vms, {"devices": len(devices), "vms": len(vms)}

    def list_racks(self, **filters) -> list[dict]:
        return self._list(self._api.dcim.racks, filters, include_config_context=False)
