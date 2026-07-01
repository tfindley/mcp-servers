# netbox-mcp — Specification & Plan

Status: **draft / pre-code.** This document is the agreed design. No server code
exists yet; the README describes the *intended* install/use so we can argue
scope on paper first.

---

## 1. Goal

Let an LLM agent (Claude Code first, any MCP client second) **read Configuration
Item (CI) data out of NetBox** — devices, VMs, IP space, interfaces, and their
org context — through a **hard-bounded, scoped, read-by-default** interface.

The CMDB is authoritative infrastructure data. The defining requirement is not
"can the model fetch a device" — it's "the model **cannot** do anything we
didn't deliberately allow," enforced at a code/API boundary rather than by
prompt-level good behaviour.

Non-goals for v1: writing to NetBox, DCIM detail (cables/power/console), a
generic "query any endpoint" passthrough, remote/hosted deployment. All are
named below as deliberate phase-2 items so the v1 design doesn't preclude them.

---

## 2. Why an MCP server (not a skill)

A skill is prompt-level guidance — soft, and the model can ignore it. Everything
that makes this safe (read/write separation, write-elevation, scope enforcement,
field whitelisting) needs to be a **code boundary the model cannot cross**. That
is what an MCP server is. A thin skill *may* sit on top later to tell Claude
*when* to reach for these tools, but the guarantees live in the server.

---

## 3. Security model — the core of the spec

Four concerns, each pinned to **where** it is enforced. "Hard" = enforced by
NetBox itself or the transport, not by our Python. "Soft(our code)" = enforced
by this server and therefore only as good as our code.

| Concern | Enforced where | Hardness |
| --- | --- | --- |
| Read vs write | NetBox token `write_enabled` flag — **two separate tokens** | **Hard** (NetBox rejects writes server-side) |
| Tenant / site scope | NetBox **service-user** object-permission *constraints* | **Hard** (NetBox filters rows server-side) |
| Write elevation | MCP tool tagging + `confirm`/dry-run + action allowlist | Soft (our code) |
| Field whitelist | Server projection layer (trim columns before return) | Soft (our code) |
| Endpoint surface | Explicit per-object read tools, **no generic passthrough** | Soft (our code) |

### 3.1 Two tokens, RW optional and absent by default

NetBox tokens carry **only** `write_enabled` + optional IP allow-list + expiry.
A token with `write_enabled = false` **physically cannot mutate anything** — the
API refuses the write regardless of what the model or even this server attempts.
That is a hard guarantee we get for free, so we take it:

- **RO token — required.** `write_enabled = false`. The server will not start
  without it. This is the floor and the default path for every read tool.
- **RW token — optional, separate, absent by default.** If `NETBOX_TOKEN_RW`
  is unset, the write tools **do not register** and the server is a pure reader.
  v1 ships *no* write tools at all; the env var and the absent-by-default
  contract are reserved so phase-2 writes slot in without a redesign.

A single RW key "with enough safeguards" is strictly weaker: every safeguard
would then live in our code, so one bug or one clever prompt is all that stands
between the model and a write. Two keys means the safe path's guarantee is
enforced by NetBox, not by us. The second key costs ~nothing. Take the
guarantee.

### 3.2 Scope is a property of the NetBox *user*, not the token

Important and easy to get wrong: a NetBox **token does not carry "limit to
tenant X."** Scoping is done on the **user the token belongs to**, via NetBox's
object-permissions system. The setup is therefore:

1. Create a dedicated **service user**, e.g. `svc-claude-ro` (no UI login need).
2. Assign it an **object permission** per exposed model with:
   - actions limited to **`view`** only, and
   - a **constraint** (JSON) restricting visible rows, e.g.
     `{"tenant__slug": "acme"}` or `{"site__slug": ["lon1", "lon2"]}`.
3. Generate the token **for that user** with `write_enabled = false`.

The token then *inherits exactly* that scope. The README ships a click-by-click
walkthrough plus the setup-wizard (§6) that emits the exact constraint JSON.

### 3.3 Field whitelisting lives in this server

NetBox object permissions filter **which records** (rows), not **which fields**
(columns). There is no native "this token sees `name` and `status` but not
`custom_fields`." So field-level limiting is done **in this server's projection
layer**: fetch from NetBox, then project down to a configured allow-set before
returning to the model. This is also a token-efficiency win (smaller payloads).
Field config is therefore **server config**, conceptually separate from
key-generation — the README keeps the two sections apart.

**Defaults are sensible per-object allow-sets** (not deny-all) — each object
ships a curated default field set (see §8), overridable in config. Two
NetBox-specific field families must be first-class, not flattened away:

- **Custom fields (`custom_fields`).** Deployments add their own; the projection
  layer must pass through custom fields. Default: include the whole
  `custom_fields` map; allow config to restrict to named keys when a deployment
  wants only some exposed.
- **Config contexts (`config_context`).** Rendered config context is **critical
  data** for many deployments and must be retrievable — but it also commonly
  **carries secrets** (provisioning data, credential hashes). It is therefore a
  **hard gate, OFF by default** (`[config_context] enabled`, or
  `NETBOX_CONFIG_CONTEXT_ENABLED`): when off it is never requested from NetBox
  and always stripped in projection, so no tool can return it. When enabled, it
  is included on `get_*` and opt-in on `list_*` via `include_config_context`
  (to avoid bloating list payloads). See §8.

- **Secret redaction.** Independently of the gate, every returned record passes
  through a redaction layer (covers `config_context`, `custom_fields`, top
  level): `redact_keys` blanks matching key names anywhere (conservative
  built-in defaults); `redact_paths` blanks targeted dotted, list-aware paths.
  This is defense-in-depth, not the primary control — the gate is.

### 3.4 Endpoint surface

No generic "hit any NetBox endpoint" tool — that re-opens every door the scoping
just closed. Each exposed object is a deliberate, individually-described read
tool with scope + projection baked in.

---

## 4. NetBox version support: v3 **and** v4, one codebase

Single server, single tool set, **REST via `pynetbox`** (see §5). The REST
endpoints for CI-core objects are stable across 3.x and 4.x; the 3→4 breakage
was concentrated in **GraphQL** (Graphene → Strawberry in 4.0), which we
deliberately do **not** use.

**Tested version targets:** NetBox **3.6.9** (older line) and **4.5.4** (current
line). The compat shim is written and CI-checked against these two; other 3.6+ /
4.x minors are expected to work but these are the pinned references.

- Detect the NetBox version at startup (the API reports it).
- Route the handful of genuinely-different fields (e.g. `status` shape, minor
  renames) through a thin **compat shim**, isolated in one module.
- Everything else is shared by construction — this is what keeps the v3 and v4
  feature sets in lockstep: it's structural, not a discipline we have to uphold.

**Dropping v3 later** = delete the compat shim + the version-detect. Nothing
else changes, and it does **not** change the `pynetbox` choice (pynetbox is the
v4 client too). So v3 support is cheap to carry and cheap to drop — no regret
cost. Expected path: 3.x deployments today → both supported → pure v4 once all
target deployments have upgraded.

---

## 5. Read engine: `pynetbox`, behind an internal interface

- **`pynetbox`** is NetBox Labs' **official, first-party** client (same org that
  builds NetBox). It hands us pagination, auth, retries, and the version
  handshake — i.e. exactly the "engine not built by us" we want to offload.
- **Supply chain:** it is a dependency, mitigated the minimal-risk way — a
  first-party, widely-used package, **pinned in `uv.lock`** (the `pip freeze`
  instinct; uv does this for us). **NOTE:** unlike `doc-convert`, this project
  **commits `uv.lock`** (remove it from `.gitignore`) precisely for supply-chain
  reproducibility.
- **Swappability:** all NetBox access goes through a small internal interface
  (`NetBoxClient` with `get_devices()`, `get_vms()`, `get_ip_addresses()`, …).
  The MCP tool layer calls only that interface, never `pynetbox` directly. If
  pynetbox's lazy object model ever gets in the way of clean field projection,
  swapping to raw **`httpx`** REST is a one-file change that never touches the
  tools. httpx is the documented fallback, not the default.

---

## 6. Setup wizard

A CLI entrypoint (`netbox-mcp setup`) that interviews the operator and **emits
configuration + exact NetBox setup instructions** — it does not itself call
NetBox or store secrets. Output:

1. The **NetBox object-permission constraint JSON** for the chosen tenant/site
   scope, ready to paste into NetBox (or feed its REST API).
2. A **`netbox-mcp.toml`** with the per-object field allow-sets (starting from
   the sensible defaults), any custom-field key restrictions, and whether
   `config_context` is included on lists by default.
3. The **token-creation steps** (which user, `write_enabled = false`, expiry).
4. A ready-to-paste **MCP client config block** (stdio).

The wizard turns "what do you want to expose?" into the precise, least-privilege
NetBox setup — so scope decisions are made once, explicitly, and reproduced.

---

## 7. Transport: stdio first, remote designed-for, deferred

The tool logic is **transport-agnostic from day one** (FastMCP runs the same
tools over stdio or HTTP).

- **v1 — stdio / local**, like `doc-convert`. Reads tokens from env.
- **Phase 2 — remote HTTP.** Same tools verbatim. The genuinely-extra work,
  called out so v1 doesn't accidentally preclude it:
  - **secret handling** — not tokens-in-env on a shared box (vault / per-request),
  - **endpoint auth** — the remote URL is reachable by more than one person,
  - **multi-caller scoping** — scope may become per-caller, not per-server.

### 7.1 Agent-agnosticism / ChatGPT

MCP is an open, client-neutral protocol; **the tools are reused verbatim across
clients** — only the transport differs.

| Client | Transport it needs | Phase |
| --- | --- | --- |
| Claude Code / Claude Desktop | local stdio | **v1** |
| OpenAI Agents SDK (your own code) | stdio *or* HTTP | works in v1 |
| **ChatGPT (the app)** | **remote HTTP** + connector auth (OAuth/none) | **phase 2** |

So "support ChatGPT" ≈ "do the remote HTTP transport" — the same phase-2 lever,
not separate scope. This is the reason to keep the tool layer strictly
transport-agnostic now.

---

## 8. v1 scope — CI core only

Exposed read tools (all RO, scoped, projected):

| Tool | NetBox object | Purpose |
| --- | --- | --- |
| `list_devices` / `get_device` | dcim.devices | physical CIs |
| `list_vms` / `get_vm` | virtualization.virtual-machines | virtual CIs |
| `list_ip_addresses` | ipam.ip-addresses | addressing |
| `list_prefixes` | ipam.prefixes | subnets |
| `list_interfaces` | dcim/virtualization interfaces | connectivity |
| `list_sites` | dcim.sites | org/location context |
| `list_tenants` | tenancy.tenants | org context |
| `list_racks` | dcim.racks | placement context |
| `netbox_status` | / status + version | health + detected version |

Each list tool: scope-constrained by the service user, field-projected, paginated
through the internal interface, with common filters (**name, tenant, site,
status** — the confirmed v1 minimum).

**`custom_fields` and `config_context` are returned through these same tools**
(per §3.3), not as separate endpoints:
- `get_device` / `get_vm` include rendered `config_context` **by default** and
  the full `custom_fields` map.
- `list_*` tools include `custom_fields` by default but render
  `config_context` only when called with `include_config_context = true`
  (it can be large per object).

**Phase 2+ (named, not built):** DCIM detail (cables, power, console),
write/elevation tools, remote HTTP transport + ChatGPT connector.

---

## 9. Layout (mirrors `doc-convert`)

```
mcp-servers/netbox/
  pyproject.toml          # deps: mcp[cli], pynetbox; project.scripts entrypoints
  README.md               # install, token/permission walkthrough, wizard
  SPEC.md                 # this file
  uv.lock                 # COMMITTED (supply-chain pinning)
  .gitignore              # .venv, __pycache__  (NOT uv.lock)
  .python-version
  src/netbox_mcp/
    __init__.py
    server.py             # FastMCP app, tool registration, RO/RW gating
    client.py             # NetBoxClient internal interface (wraps pynetbox)
    compat.py             # v3/v4 field shim, isolated
    projection.py         # field allow-set trimming (defaults + custom_fields)
    config.py             # loads env (secrets/URL) + netbox-mcp.toml (scope/fields)
    setup.py              # setup-wizard entrypoint (writes netbox-mcp.toml)
```

**Config split:** secrets and connection (`NETBOX_URL`, `NETBOX_TOKEN_RO`,
`NETBOX_TOKEN_RW`) stay in **env vars** — never in a committed file. Everything
else (tenant/site scope, per-object field allow-sets, custom-field key
restrictions, default filters) lives in a **`netbox-mcp.toml`** the wizard
writes and `config.py` loads. TOML is human-diffable and reviewable; secrets are
deliberately kept out of it.

Entrypoints in `pyproject.toml`:
`netbox-mcp = "netbox_mcp.server:main"`,
`netbox-mcp-setup = "netbox_mcp.setup:main"`.

---

## 10. Resolved decisions

1. **Version targets** — test the compat shim against **3.6.9** and **4.5.4**
   (§4). Both are first-class until all target deployments reach v4.
2. **Field allow-sets** — **sensible per-object defaults**, not deny-all (§3.3,
   §8). **`custom_fields` must be supported** — passed through by default, with
   optional named-key restriction in `netbox-mcp.toml`.
3. **Config format** — **`netbox-mcp.toml`** for scope/field config (wizard
   writes it); secrets/connection stay in **env vars** (§9).
4. **Filter surface** — v1 list filters are **name, tenant, site, status**.
5. **`config_context` is critical but sensitive** — retrievable via the standard
   `get_*`/`list_*` tools, but **hard-gated OFF by default** because it can carry
   secrets; enable deliberately, then included on gets / opt-in on lists. A
   redaction layer (keys + dotted paths) additionally scrubs secrets from any
   returned record (§3.3, §8). *(Revised after a live test found credential
   hashes embedded in a VM's config_context.)*
