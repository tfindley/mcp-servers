# keycloak-mcp

An MCP server that lets an LLM agent **read Keycloak realm data** — groups (by
path, so child groups are first-class), users, and **the attributes on both** —
through a **read-only** interface with **key-based attribute redaction** for
confidential and GDPR-relevant data.

The point isn't just "fetch a group." It's that the model **cannot** write to
your IdP and **cannot** read the attributes you've decided it must not see —
enforced by the server having no write code path at all, and by a redaction
layer that every record passes through on the way out.

## What it exposes

| Tool | Reads |
| --- | --- |
| `get_group` | one group by **path** (`/Eng/Platform/Admins`) or id — attributes, roles, child count |
| `list_groups` | top-level / children of a path / realm-wide name search, as a flat list with `path` + `level` |
| `list_group_members` | direct members of a group, optionally with their attributes |
| `get_user` | one user by username, email or id — full record + attributes |
| `search_users` | user search by name/username/email |
| `get_user_groups` | a user's memberships **plus inherited ancestor groups**, with attributes |
| `get_effective_user_attributes` | user + group attributes merged, with per-value provenance |
| `keycloak_status` | connectivity, grant used, and the **active redaction policy** |

### Groups are addressed by path

`get_group(path="/Engineering/Platform/Admins")` resolves the whole hierarchy in
one call via Keycloak's `group-by-path` endpoint. Child groups don't need id
chaining. When a path misses, the error names the segment that broke and lists
what *was* available at that level.

Keycloak's own representation of subgroups changed at v23 (embedded `subGroups`
became `subGroupCount` + `GET /groups/{id}/children`). Both are handled, so this
works against old and current servers alike.

### Inherited attributes

In Keycloak, a member of `/team/admins` also inherits the attributes of every
ancestor group (`/team`) without being a direct member of it. `get_user_groups`
resolves those ancestors and flags them `inherited: true`;
`get_effective_user_attributes` merges everything and tells you which source
each value came from. That is normally the real question behind *"where is this
account getting this permission?"*

## Attribute redaction — the control that matters

Keycloak `attributes` are a free-form `{key: [values]}` bag on both groups and
users. In practice they hold a mix of things that are fine to read (entitlements,
cost centres, service tiers) and things that are not (personal data, and
occasionally outright secrets). Keycloak has no way to say *"return everything
except these keys"*, so the filtering happens here, on the way out.

Configured in `[redact]` in `keycloak-mcp.toml`:

| Setting | Effect |
| --- | --- |
| `keys` | whole-key names, case-insensitive, **never substring** (`secret` will not blank `secretary_name`) |
| `patterns` | fnmatch wildcards for deliberate matching — `"*secret*"`, `"urn:ietf:params:scim:*"` |
| `paths` | targeted dotted, list-aware paths — `"attributes.homeAddress"` |
| `mode` | `redact` (default) → value becomes `"[redacted]"`, key stays visible; `drop` → key removed entirely |

Redaction is applied **recursively to every record**, so adding `email` blanks
the top-level user email too, not just an attribute of that name. It runs inside
the client, not the tool layer, so no tool can return an unredacted record.

**Defaults:** a conservative credential set (`password`, `secret`, `token`,
`clientSecret`, …) is redacted out of the box. A **GDPR / personal-data starter
set** (`dateOfBirth`, `nationalInsuranceNumber`, `homeAddress`, `salary`,
special-category keys, …) ships **off** — which attribute keys hold personal data
is site-specific, and blanking them unasked would hide data you may legitimately
need. `keycloak-mcp-setup` offers to enable it, and
[`keycloak-mcp.toml.example`](./keycloak-mcp.toml.example) has it as a
copy-paste block.

In `redact` mode, `get_effective_user_attributes` reports the hidden keys under
`withheld_attributes`, so **a withheld attribute is never mistaken for an absent
one**. Run `keycloak_status` to see exactly what the running server is hiding.

For the strictest posture, `[attributes] group_keys` / `user_keys` flips to an
**allow-list**: only the keys you name survive at all.

## Security model in one table

| Concern | Enforced where | Hard? |
| --- | --- | --- |
| Read vs write | this server has **no non-GET code path** (bar the OIDC token POST) | **Yes** — no write code exists |
| Which users/groups are visible | Keycloak **service-account roles** (`view-users`, `query-groups`) | **Yes** — Keycloak enforces |
| Group subtree scope | `[scope] group_paths` in this server | our code |
| Attribute visibility | this server's redaction / allow-list layer | our code |
| Endpoint surface | eight explicit tools, no passthrough | our code |

Deliberately **not** a dependency on `python-keycloak`: its `KeycloakAdmin` is
write-capable, and the read-only guarantee here should come from the absence of
write code, not from a promise to avoid calling certain methods.

---

## Setup

### 1. Run the setup wizard (recommended)

```bash
cd mcp-servers/keycloak
uv run keycloak-mcp-setup
```

It interviews you — *which group subtrees? which attribute keys must never be
read? redact or drop?* — and emits the Keycloak service-account steps, a written
`keycloak-mcp.toml`, and a ready-to-paste MCP client config block. It never
contacts Keycloak and never stores secrets.

### 2. Or set the service account up manually

In the realm you want to read (**not** `master`):

1. **Clients → Create client**
   - Client ID: `svc-claude-ro` (any name)
   - **Client authentication: ON** (confidential client)
   - **Authorization: OFF**
   - Authentication flow: tick **only** *Service accounts roles* — untick
     Standard flow and Direct access grants; no human logs in as this client.
2. **Credentials** tab → copy the **Client secret**.
3. **Service accounts roles → Assign role → Filter by clients →
   `realm-management`**, and assign only:
   - `view-users` — reads users, groups and memberships
   - `query-groups` — lists groups

   Assign nothing else. Never `manage-users`, `manage-realm` or `realm-admin`:
   this server has no write code path and the account shouldn't have the right
   either. If a read still returns `403`, add `view-realm` and retry.

### 3. Install & configure

```bash
cd mcp-servers/keycloak
uv sync                                   # creates .venv; uv.lock is committed

cp keycloak-mcp.toml.example keycloak-mcp.toml   # then edit the [redact] block
```

Credentials come from the environment — **never** the toml. These are the same
four variables the sibling Keycloak tools use, so an existing read-only env
script works unchanged:

```bash
export KC_BASE_URL="https://sso.example.com"   # no trailing slash
export KC_REALM="your-realm"
export KC_CLIENT_ID="svc-claude-ro"
export KC_CLIENT_SECRET="<client secret>"
```

| Variable | Required | Purpose |
| --- | --- | --- |
| `KC_BASE_URL` | yes | Keycloak base URL, no trailing `/` |
| `KC_REALM` | yes | realm to read |
| `KC_CLIENT_ID` | yes | service-account client id (or admin username for the password grant) |
| `KC_CLIENT_SECRET` | yes | client secret (or admin password) |
| `KC_AUTH_MODE` | no | `auto` (default) \| `client-credentials` \| `password` |
| `KC_CA_BUNDLE` | no | path to an internal CA bundle |
| `KC_TLS_VERIFY` / `KC_NO_VERIFY` | no | TLS verification escape hatch (insecure) |
| `KC_TIMEOUT` | no | per-request seconds (default 30) |
| `KEYCLOAK_MCP_CONFIG` | no | path to `keycloak-mcp.toml` (default `./keycloak-mcp.toml`) |

`auto` tries the client-credentials grant against your realm, then falls back to
a `password` grant via `admin-cli` on `master` — matching the sibling toolkits.
A confidential client scoped to the realm is the better setup; pin it with
`KC_AUTH_MODE=client-credentials`.

#### TLS / internal CAs

Point `KC_CA_BUNDLE` (or `[tls] ca_bundle`) at your internal CA certificate —
that's the secure fix. `KC_TLS_VERIFY=false` disables verification entirely and
prints a warning to stderr; it exposes your bearer token to interception, so
it's for testing only.

### 4. Register with Claude Code

```bash
claude mcp add keycloak \
  -e KC_BASE_URL=https://sso.example.com \
  -e KC_REALM=your-realm \
  -e KC_CLIENT_ID=svc-claude-ro \
  -e KC_CLIENT_SECRET='<client secret>' \
  -e KEYCLOAK_MCP_CONFIG=/abs/path/to/keycloak-mcp.toml \
  -- uv run --directory /abs/path/to/mcp-servers/keycloak keycloak-mcp
```

Restart your MCP client, then verify with **"call keycloak_status"** — it echoes
the realm, the grant that authenticated, the configured scope, and the exact
list of attribute keys being redacted.

## Notes

- **Read-only by construction.** Every tool issues `GET`. The single `POST` in
  the codebase is the OIDC token request.
- **Direct members only.** Keycloak has no transitive-membership endpoint, so
  `list_group_members` returns direct members; walk children with `list_groups`
  to cover a subtree.
- **Bounds.** `[limits]` caps page size, members per group and recursion depth so
  a careless query can't pull a whole realm.
- `include_attributes` on `list_groups` costs one extra call per group — Keycloak
  omits attributes from list responses. Keep `limit` small, or use `get_group`.
- **Phase 2 candidates:** transitive group membership, role-mapping reads,
  client/realm role introspection, remote (HTTP) transport.
