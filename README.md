# mcp-servers

A collection of [Model Context Protocol](https://modelcontextprotocol.io) servers.

Each server lives in its own subdirectory with its own `pyproject.toml`, is
managed with [uv](https://docs.astral.sh/uv/), and is registered with an MCP
client independently.

| Server | Purpose |
| --- | --- |
| [`netbox/`](./netbox) | Read-only, scoped access to NetBox Configuration Item (CI) data — devices, VMs, IPs, interfaces + org context — with a hard-gated `config_context` and secret redaction. |

See each server's own `README.md` for setup and registration.
