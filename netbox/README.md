# netbox-mcp

> **Status: pre-code draft.** This README describes the *intended* server so the
> design can be reviewed before implementation. The commands below are the
> planned interface, not yet runnable. See [`SPEC.md`](./SPEC.md) for the full
> design and rationale.

An MCP server that lets an LLM agent **read Configuration Item (CI) data from
NetBox** — devices, VMs, IP space, interfaces, and their org context — through a
**read-by-default, scoped, hard-bounded** interface.

The point isn't just "fetch a device." It's that the model **cannot** do
anything you didn't deliberately allow — enforced at the NetBox API and at this
server, not by asking the model nicely.

## What it exposes (v1 — CI core)

Read-only, scope-constrained, field-projected tools:

| Tool | NetBox object |
| --- | --- |
| `list_devices` / `get_device` | physical devices |
| `list_vms` / `get_vm` | virtual machines |
| `list_ip_addresses` | IP addresses |
| `list_prefixes` | prefixes / subnets |
| `list_interfaces` | device & VM interfaces |
| `list_sites` / `list_tenants` / `list_racks` | org & placement context |
| `netbox_status` | health + detected NetBox version |

**Custom fields and config context come through these tools** — not separate
endpoints. `custom_fields` is included by default (restrictable to named keys in
config). `config_context` is **OFF by default** — it commonly carries secrets
(provisioning data, credential hashes), so it is hard-gated: nothing returns it
until you set `[config_context] enabled = true`. Once enabled it is included on
`get_device`/`get_vm` and opt-in on `list_*` via `include_config_context = true`.
List filters: **name, tenant, site, status**.

**Secret redaction.** Every returned record is passed through a redaction layer
(`[redact]` in the toml): `keys` blanks matching key names anywhere (conservative
built-in defaults like `password`/`secret`/`token`), and `paths` blanks targeted
dotted, list-aware paths (e.g. `config_context.users.password`).
This covers `custom_fields` too, not just `config_context`.

DCIM detail (cables/power/console), **any write capability**, and remote/ChatGPT
support are deliberately **phase 2** — see [`SPEC.md`](./SPEC.md).

## Security model in one table

| Concern | Enforced where | Hard? |
| --- | --- | --- |
| Read vs write | NetBox token `write_enabled` flag (two tokens) | **Yes** — NetBox rejects writes |
| Tenant / site scope | NetBox **service-user** permission *constraints* | **Yes** — NetBox filters rows |
| Field whitelist | this server's projection layer | our code |
| Endpoint surface | explicit per-object tools, no passthrough | our code |

**RO token is required; the RW token is optional and absent by default** (v1
ships no write tools at all). A read-only NetBox token *physically cannot* mutate
data, so the safe path's guarantee comes from NetBox, not from our code.

---

## Setup

### 0. Generate API token(s) in NetBox

You need **a dedicated NetBox service user**, scoped with object permissions,
then a token for it. Two tokens recommended:

- **Read-only (required):** `write_enabled = false`.
- **Read-write (optional, phase 2):** keep separate; leave unconfigured for now.

> The fastest way to get the exact, least-privilege setup is the **wizard**
> below — it prints the precise permission constraint JSON and token steps for
> the tenant/site you choose. The manual walkthrough follows it.

### 1. Run the setup wizard (recommended)

```bash
cd mcp-servers/netbox
uv run netbox-mcp-setup
```

It interviews you — *which tenant(s)/site(s)? which objects? which fields?* — and
emits:

1. the **NetBox object-permission constraint JSON** to paste in,
2. the **field allow-set** config per object,
3. the **token-creation steps** (`write_enabled = false`, expiry),
4. a ready-to-paste **MCP client config block**.

The wizard never calls NetBox and never stores secrets — it only generates the
least-privilege instructions for you to apply.

### 2. Or do it manually in NetBox

1. **Create a service user** — *Admin → Users → Add* (e.g. `svc-claude-ro`).
2. **Add an object permission** — *Admin → Permissions → Add* — for each model
   you want to expose (Device, Virtual Machine, IP Address, Prefix, Interface,
   Site, Tenant, Rack):
   - **Actions:** tick **View** only.
   - **Constraints (JSON):** restrict the visible rows, e.g.
     ```json
     { "tenant__slug": "acme" }
     ```
     or a multi-site scope:
     ```json
     { "site__slug": ["lon1", "lon2"] }
     ```
   - Assign it to `svc-claude-ro`.
3. **Create the token** — *Admin → API Tokens → Add* — for `svc-claude-ro`, with
   **Write enabled = unchecked** and an expiry. Copy the token.

> Scope lives on the **user/permission**, not the token. The token only carries
> read/write + IP allow-list + expiry; it *inherits* the user's scoped view.

### 3. Install & configure

```bash
cd mcp-servers/netbox
uv sync          # creates .venv with deps; commits uv.lock for pinning
```

Environment:

```bash
export NETBOX_URL="https://netbox.example.com"
export NETBOX_TOKEN_RO="<read-only token>"
# export NETBOX_TOKEN_RW="<read-write token>"   # phase 2 — leave unset for now
```

If `NETBOX_TOKEN_RW` is unset, no write tools register — the server is a pure
reader. v3 and v4 are both supported automatically (version detected at startup).

**Secrets stay in env; everything else is `netbox-mcp.toml`.** Scope (tenant/
site), per-object field allow-sets, custom-field key restrictions, and default
filters live in a `netbox-mcp.toml` (the wizard writes it) — never secrets. That
file is reviewable and diffable; the tokens are not in it.

#### TLS / self-signed certificates

If your NetBox uses a self-signed or internal-CA certificate you'll otherwise
hit `CERTIFICATE_VERIFY_FAILED`. Point the server at the trust anchor using **any
one** of these. If more than one is set, they win in this order:

| Precedence | Option | Where | Notes |
| --- | --- | --- | --- |
| 1 | `NETBOX_CA_BUNDLE=/path/ca.pem` | env | Namespaced. Path to the CA/cert `.pem`. |
| 2 | `[tls]\nca_bundle = "/path/ca.pem"` | `netbox-mcp.toml` | Config-file route (env vars can't live in the toml). |
| 3 | `REQUESTS_CA_BUNDLE=/path/ca.pem` | env | Standard `requests` var — used only when 1 & 2 are unset and verify stays on. |

`.pem` must contain the **CA that signed the cert** (for a self-signed cert,
that's the cert itself). macOS's `/etc/ssl/cert.pem` is the *public*-CA bundle —
it works only if your cert chains to a public CA or you've appended the internal
cert to it; a truly self-signed cert won't be in there.

Last resort — **disable verification** (insecure; testing only, prints a warning
each start): `NETBOX_TLS_VERIFY=false` (env) or `[tls] verify = false` (toml).

### 4. Register with Claude Code

```bash
claude mcp add netbox -- \
  uv run --directory /absolute/path/to/mcp-servers/netbox netbox-mcp
```

Or add to `.mcp.json` / `~/.claude.json`:

```json
{
  "mcpServers": {
    "netbox": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/absolute/path/to/mcp-servers/netbox",
        "netbox-mcp"
      ],
      "env": {
        "NETBOX_URL": "https://netbox.example.com",
        "NETBOX_TOKEN_RO": "<read-only token>"
      }
    }
  }
}
```

For Claude Desktop, add the same block to `claude_desktop_config.json`.

---

## Other agents (ChatGPT, OpenAI Agents SDK)

MCP is an open, client-neutral protocol — **the tools are reused verbatim**;
only the transport differs.

| Client | Transport | Status |
| --- | --- | --- |
| Claude Code / Desktop | local stdio | v1 |
| OpenAI Agents SDK (your code) | stdio or HTTP | works in v1 |
| **ChatGPT (the app)** | **remote HTTP** + connector auth | phase 2 |

ChatGPT can't run a local stdio server — it needs a reachable HTTP endpoint with
its own auth. That's the same **remote transport** work tracked as phase 2 in
[`SPEC.md`](./SPEC.md); the tools themselves don't change.

## NetBox version support

One codebase covers **NetBox 3.x and 4.x** over the stable REST API (via
`pynetbox`), with a small compat shim for the few fields that differ. Tested
against **3.6.9** and **4.5.4**. Dropping v3 later is just deleting that shim —
it doesn't change anything else.

## Notes

- Read engine is **`pynetbox`** (NetBox Labs' official client), kept behind an
  internal `NetBoxClient` interface so it's swappable for raw `httpx` without
  touching the tools. `uv.lock` is **committed** for supply-chain pinning.
- No generic "query any endpoint" tool by design — each object is an explicit,
  individually-scoped tool.
