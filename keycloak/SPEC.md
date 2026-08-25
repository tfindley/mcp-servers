# keycloak-mcp — Specification & Rationale

Sibling to [`netbox/`](../netbox); the layout, config split and security posture
deliberately mirror it. Where this server diverges from that pattern, the
divergence is called out and justified below.

## 1. Goal

Let an LLM agent answer questions about a Keycloak realm — *"what attributes does
this group carry?"*, *"which groups is this user in?"*, *"where is this account
getting this entitlement from?"* — without being able to change anything, and
without being able to read attribute values the operator has classified as
confidential or personal.

The audience is the same as the sibling CLI tools in `~/devel/python3`: Keycloak
administrators and stakeholders who need to understand inherited attributes,
because those attributes drive permissions in downstream systems.

## 2. Why an MCP server (not a skill)

The existing tooling is a set of CLIs that render for humans (Textual TUIs, CSV,
coloured terminal output). An agent needs the opposite: structured JSON, one
question per call, and hard limits it cannot argue its way past. A skill wrapping
those CLIs would inherit their human-facing formatting and, more importantly,
would put the credentials and the redaction decision in the model's context
rather than outside it.

## 3. Security model

### 3.1 Read-only by construction, not by policy

There is one request primitive, `KeycloakClient._get`, and it issues `GET`. The
only non-`GET` request anywhere in the server is the OIDC token `POST` in
`_post_token`. No write code path exists to be reached by a confused tool layer,
a prompt injection, or a future careless edit.

This is why `python-keycloak` is **not** a dependency despite being the obvious
"engine not built by us" choice (netbox-mcp uses `pynetbox` on exactly that
reasoning). `KeycloakAdmin` is a read/write client; depending on it would reduce
the guarantee to *"we promise not to call the write methods."* The admin REST
surface needed here is seven endpoints, so hand-rolling on `requests` is cheap
and buys a categorically stronger property. `requests` + `urllib3.Retry` is also
the stack the sibling Keycloak tools already use.

Every tool additionally advertises `readOnlyHint: true` / `destructiveHint:
false` in its MCP tool annotations, so a client sees the guarantee in the
protocol rather than in prose.

### 3.2 Scope: roles are the gate, paths are defense-in-depth

The authoritative constraint is the Keycloak **service account's role
assignments** — `view-users` and `query-groups` on `realm-management`, and
nothing else. Keycloak enforces those; this server cannot widen them.

On top, `[scope] group_paths` restricts reads to named subtrees. This is
client-side and therefore *our code*, not a hard gate — but it narrows and never
widens, it is enforced on both the path and the id lookup (no id bypass), and it
re-roots `list_groups` so a scoped server does not even enumerate the rest of the
realm.

### 3.3 Attribute redaction — the core of this server

Keycloak `attributes` are a free-form `{key: [values]}` bag on both groups and
users. Operators put entitlements in there; they also put personal data and
occasionally secrets in there. The admin API has **no** "return everything except
these keys" facility, so the filter has to be here.

Two controls, applied in order, in `redaction.py`:

1. **Projection** (allow-list, `[attributes] group_keys`/`user_keys`, off by
   default) — reduce `attributes` to named keys.
2. **Redaction** (deny-list, `[redact]`, on by default) — blank matching keys
   anywhere in the record.

Matcher design decisions:

- **Whole-key, never substring.** Substring matching would blank
  `secretary_name` for `secret`. Wildcards are available but must be asked for
  explicitly via `patterns`.
- **Case-insensitive by default**, so `clientSecret` and `clientsecret` are one
  entry. Underscore variants stay distinct, so both spellings ship where both are
  common in the wild.
- **Whole value replaced, not element-wise.** A redacted multi-valued attribute
  becomes `"[redacted]"`, not `["[redacted]", "[redacted]"]`, so cardinality does
  not leak.
- **Recursive over the entire record**, not just `attributes` — so redacting
  `email` also blanks the top-level `UserRepresentation.email`.
- **Applied in `client.py`, not in the tool layer.** This is a deliberate
  tightening of the netbox-mcp arrangement, where each tool calls `project()`
  itself. Here every representation leaves through `_shape_group`/`_shape_user`,
  so a tool cannot return a raw record by forgetting a call.

**Compound names, and why the audit tool exists.** Whole-key matching cannot
reach `storagepass` or `dbPassword`, and an indexed SCIM key
(`phoneNumbers.value[0]`) leaves `[1]` readable. Two responses, deliberately
separated:

- `patterns` ships with **anchored** defaults (`*secret`, `password*`), which
  cover compound names while preserving the never-substring property that keeps
  `secretary_name` readable. Anchoring is what makes a default pattern set safe
  enough to enable out of the box.
- `audit_attribute_keys` reports the realm's attribute **key names** (never
  values) and flags credential- or personal-shaped names the policy misses. The
  full uncovered list sits behind `include_all_keys`: it is the bulk of the
  payload and almost all routine, so the default answer is the actionable part
  plus a count.
  Discovery belongs in a report, not in sloppier matching: a blanket `*pass*`
  would catch `storagepass` and also blank `bypass`. The audit flags it and lets
  a human decide.

Validated against a live realm: the anchored defaults redacted nothing benign
across 59 distinct attribute keys, and the audit surfaced a visible postal
address that a hand-written grep had missed.

**Defaults.** The credential-ish set (`password`, `secret`, `token`,
`clientSecret`, …) is **on**: those are unambiguous, and failing safe on
credentials is right. The GDPR/personal-data set is **off**, shipped as a
starter list the wizard can enable. Rationale: which keys hold personal data is
site-specific, and silently hiding attributes an operator legitimately needs is
its own failure mode. The choice is surfaced, not made for them —
`keycloak_status` echoes the exact active policy.

**Withheld ≠ absent.** In `redact` mode the key stays visible with a
`"[redacted]"` value, and `get_effective_user_attributes` reports
`withheld_attributes` naming each hidden key and its source. A model must be able
to say *"this user has a `dateOfBirth` attribute I'm not permitted to read"*
rather than wrongly concluding it does not exist. `drop` mode is available when
the presence of the attribute is itself sensitive, and its cost — no
`withheld_attributes` reporting — is documented.

### 3.4 Endpoint surface

Eight explicit tools. No generic "call any admin endpoint" passthrough, which
would make every other control here decorative.

Groups are addressed by **path**, not id, because path is what a human asks about
and what makes child groups first-class. `group-by-path` resolves the whole
hierarchy server-side in one call. Ids remain accepted for round-tripping.

## 4. Keycloak version support

Keycloak changed its group representation at **v23**: before, a parent embedded
the entire subtree as `subGroups`; after, it reports `subGroupCount` and serves
children from `GET /groups/{id}/children`. Both are handled in
`KeycloakClient._children`, which also probes the children endpoint when the
server reports neither key rather than assuming a leaf, and treats a 404 from
`/children` as "pre-23 server" rather than an error.

The test suite runs the entire client twice, once against a mock presenting each
representation.

## 5. HTTP engine

`requests` with `urllib3.util.retry.Retry`: 5 attempts, exponential backoff,
retrying 429/502/503/504 and honouring `Retry-After`. Every request is
idempotent, so retrying all verbs is safe. Tokens refresh 30s before expiry so a
long paging run cannot trip over it. `auto` grant mode tries client-credentials
against the realm and falls back to a `password` grant via `admin-cli` on
`master`, matching the sibling toolkits' credential conventions.

## 6. Setup wizard

`keycloak-mcp-setup` interviews the operator and emits the service-account steps,
a written `keycloak-mcp.toml`, and an MCP client config block. It never contacts
Keycloak and never stores secrets. Its main job is making the redaction decision
an explicit, prompted one rather than something an operator discovers later.

## 7. Transport

stdio, which is what Claude Code / Desktop expect. The tool layer is otherwise
transport-agnostic, so a remote HTTP entrypoint can be added without touching the
tools.

## 8. v1 scope

**In:** redaction-policy auditing, groups (by path/id, children, members,
attributes), users (lookup,
search, attributes), group memberships including inherited ancestors, merged
effective attributes with provenance, status/policy introspection.

**Out (phase 2):** transitive group membership (Keycloak has no endpoint; it is
an N-call fan-out), role-mapping and client-role introspection, realm/client
configuration reads, sessions and events, any write capability, remote transport.

## 9. Layout

```
keycloak/
├── pyproject.toml
├── keycloak-mcp.toml.example     # scope + attribute policy (no secrets)
├── README.md
├── SPEC.md
└── src/keycloak_mcp/
    ├── config.py        # env + toml -> Config; redaction defaults
    ├── redaction.py     # RedactionPolicy + attribute projection
    ├── client.py        # the only Keycloak interface; GET-only; shapes+redacts
    ├── server.py        # eight MCP tools; error translation; read-only annotations
    └── setup.py         # keycloak-mcp-setup wizard
```

`uv.lock` is committed for supply-chain pinning, matching `netbox/`.

## 10. Resolved decisions

| Question | Decision | Why |
| --- | --- | --- |
| `python-keycloak`? | No — hand-rolled on `requests` | its admin client is write-capable; absence of write code is a stronger guarantee than avoiding methods |
| Redact where? | In `client.py`, not the tool layer | no tool can bypass it by omission |
| GDPR keys on by default? | No — shipped as a prompted starter set | which keys are personal is site-specific; silent hiding is its own failure |
| Credential keys on by default? | Yes | unambiguous, and failing safe on secrets is correct |
| Substring key matching? | No — whole-key, plus anchored default `patterns` | anchoring covers `clientSecret` while `secretary_name` stays readable |
| Catching what patterns miss? | `audit_attribute_keys`, not looser matching | a blanket `*pass*` would blank `bypass`; a report lets a human judge |
| Groups by id or path? | Path primary, id accepted | path is what humans ask about and makes child groups first-class |
| Nested or flat group listings? | Flat, with `path` + `level` per row | far cheaper in tokens; `path` already encodes hierarchy |
| MCP SDK version | Support 1.x and 2.x via a two-line import shim | 2.x renamed `FastMCP` to `MCPServer`; `netbox/` is locked at 1.28.1 |

## 11. Testing

No live Keycloak is required. The suite runs against a mock admin API that serves
both the pre-23 and 23+ group representations, and covers:

- redaction matching (exact/case/wildcard/path), `redact` vs `drop`, recursion
  into nested structures, non-mutation of inputs, cardinality non-leakage;
- config parsing, env precedence, scope normalisation and boundary cases
  (`/Engineering` must not match `/EngineeringOps`);
- every tool end-to-end, both KC representations, including inherited-ancestor
  resolution and attribute provenance;
- scope enforcement via path *and* id;
- **a read-only assertion over the recorded request log**: every request issued
  during the whole suite is a `GET`, except token `POST`s;
- the MCP protocol layer over real stdio, against SDK 1.x and 2.x, asserting tool
  registration, `readOnlyHint`, and that error text actually reaches the model.
