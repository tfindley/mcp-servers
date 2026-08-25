"""KeycloakClient — the single internal interface every tool calls.

The MCP tool layer (server.py) talks ONLY to this class. Three properties are
enforced here rather than trusted to the tools:

  READ-ONLY   There is exactly one request primitive, ``_get``, and it issues
              GET. The only non-GET request in the whole server is the OIDC
              token POST in ``_post_token``. No amount of tool-layer confusion
              can mutate the realm, because no code path exists to do it.

  SCOPED      Every group read passes ``_require_scope`` against the configured
              [scope].group_paths. Client-side defense-in-depth; the
              authoritative gate is the service account's realm roles.

  REDACTED    Every representation leaves through ``_shape_group`` /
              ``_shape_user``, which apply the attribute allow-list and then the
              redaction policy. A tool cannot return a raw record.

Keycloak version handling: KC < 23 embeds the whole subtree as ``subGroups`` in
the parent group representation; KC 23+ drops it in favour of ``subGroupCount``
plus GET /groups/{id}/children. Both are handled in ``_children``.
"""

from __future__ import annotations

import sys
import time
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import AUDIT_SUSPECT_FRAGMENTS, Config, normalize_path
from .redaction import RedactionPolicy, project_attributes

# Group fields worth returning. Keycloak pads representations with keys that are
# either transient or noise for a reader (``access``, the embedded subtree).
_GROUP_FIELDS = ("id", "name", "path", "parentId", "attributes",
                 "realmRoles", "clientRoles", "subGroupCount")
_USER_FIELDS = ("id", "username", "email", "firstName", "lastName", "enabled",
                "emailVerified", "createdTimestamp", "federationLink",
                "requiredActions", "attributes")


class KeycloakError(RuntimeError):
    """A Keycloak call failed, or a request fell outside configured scope."""


def make_session() -> requests.Session:
    """HTTP session with retry/backoff on transient failures — same policy as
    the sibling Keycloak tools. ``allowed_methods=None`` retries every verb,
    which is safe because every request this client makes is idempotent."""
    retry = Retry(
        total=5, connect=5, read=5, status=5,
        backoff_factor=1.0,                      # 0,1,2,4,8s between attempts
        status_forcelist=(429, 502, 503, 504),
        allowed_methods=None,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class KeycloakClient:
    def __init__(self, config: Config):
        self._config = config
        self._session = make_session()
        self._token: str | None = None
        self._expiry = 0.0
        self._grant: str | None = None
        self._admin_url = f"{config.base_url}/admin/realms/{config.realm}"
        self._policy = RedactionPolicy.build(
            keys=config.redact_keys,
            patterns=config.redact_patterns,
            paths=config.redact_paths,
            mode=config.redact_mode,
            case_sensitive=config.redact_case_sensitive,
        )
        if config.verify is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            print(
                "keycloak-mcp: WARNING — TLS certificate verification is DISABLED "
                "(KC_TLS_VERIFY=false / KC_NO_VERIFY=true). Bearer tokens and "
                "directory data are exposed to interception; point KC_CA_BUNDLE "
                "at your internal CA instead for anything but testing.",
                file=sys.stderr,
            )

    @property
    def policy(self) -> RedactionPolicy:
        return self._policy

    # --- auth -------------------------------------------------------------
    def _post_token(self, realm: str, data: dict) -> dict:
        """The ONLY non-GET request in this server."""
        resp = self._session.post(
            f"{self._config.base_url}/realms/{realm}/protocol/openid-connect/token",
            data=data, timeout=self._config.timeout, verify=self._config.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def _client_credentials(self) -> dict:
        return self._post_token(self._config.realm, {
            "grant_type": "client_credentials",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
        })

    def _password(self) -> dict:
        # The sibling toolkits also support an admin password grant via
        # admin-cli on master. Supported for credential-compatibility, but a
        # confidential client scoped to the realm is the better setup.
        return self._post_token("master", {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self._config.client_id,
            "password": self._config.client_secret,
        })

    def _fetch_token(self) -> dict:
        mode = self._config.auth_mode
        if mode == "client-credentials":
            self._grant = "client-credentials"
            return self._client_credentials()
        if mode == "password":
            self._grant = "password (admin-cli @ master)"
            return self._password()
        try:
            data = self._client_credentials()
            self._grant = "client-credentials"
            return data
        except requests.HTTPError as first:
            try:
                data = self._password()
                self._grant = "password (admin-cli @ master)"
                return data
            except requests.HTTPError as second:
                raise KeycloakError(
                    "Authentication failed with both grant types.\n"
                    f"  client_credentials : {first}\n"
                    f"  password           : {second}\n"
                    "Check KC_CLIENT_ID / KC_CLIENT_SECRET, or pin one with "
                    "KC_AUTH_MODE=client-credentials|password."
                ) from second

    @property
    def token(self) -> str:
        # Refresh 30s early so a long paging run never trips over an expiry.
        if time.time() > self._expiry - 30:
            data = self._fetch_token()
            self._token = data["access_token"]
            self._expiry = time.time() + data.get("expires_in", 300)
        return self._token

    @property
    def grant(self) -> str:
        return self._grant or self._config.auth_mode

    # --- request primitives -----------------------------------------------
    def _get(self, path: str, **params) -> Any:
        """GET /admin/realms/<realm><path>. Returns decoded JSON (or None)."""
        resp = self._session.get(
            f"{self._admin_url}{path}",
            headers={"Authorization": f"Bearer {self.token}"},
            params={k: v for k, v in params.items() if v is not None} or None,
            timeout=self._config.timeout,
            verify=self._config.verify,
        )
        if resp.status_code == 403:
            raise KeycloakError(
                f"Keycloak refused GET {path} (403). The service account is missing a "
                "role for this read — assign 'view-users' and 'query-groups' on the "
                "realm-management client (add 'view-realm' only if a read still 403s)."
            )
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def _get_paged(self, path: str, *, limit: int | None = None, **params) -> list:
        """GET every page of a first/max paginated collection endpoint, stopping
        at ``limit`` records so a large realm cannot be pulled by accident."""
        page_size = self._config.page_size
        out: list = []
        first = 0
        while True:
            want = page_size if limit is None else min(page_size, limit - len(out))
            if want <= 0:
                break
            page = self._get(path, first=first, max=want, **params) or []
            out.extend(page)
            if len(page) < want:
                break
            first += len(page)
        return out

    # --- scope ------------------------------------------------------------
    def _require_scope(self, path: str) -> None:
        if not self._config.in_scope(path):
            raise KeycloakError(
                f"Group {path!r} is outside the configured scope "
                f"({', '.join(self._config.scope_group_paths)}). This server is "
                "restricted to those subtrees."
            )

    # --- shaping (allow-list, then redaction) -----------------------------
    def _shape(self, raw: dict, fields: tuple[str, ...], kind: str,
               *, include_attributes: bool = True) -> dict:
        trimmed = {k: v for k, v in raw.items() if k in fields}
        if include_attributes:
            trimmed.setdefault("attributes", {})
            trimmed = project_attributes(trimmed, self._config.attribute_keys_for(kind))
        else:
            trimmed.pop("attributes", None)
        return self._policy.apply(trimmed)

    def _shape_group(self, raw: dict, *, include_attributes: bool = True) -> dict:
        return self._shape(raw, _GROUP_FIELDS, "group", include_attributes=include_attributes)

    def _shape_user(self, raw: dict, *, include_attributes: bool = True) -> dict:
        return self._shape(raw, _USER_FIELDS, "user", include_attributes=include_attributes)

    # --- groups: raw fetches ---------------------------------------------
    def _raw_group_by_path(self, path: str) -> dict:
        """Full GroupRepresentation for a group path, e.g. '/Team/Admins'.

        Uses Keycloak's group-by-path endpoint, which resolves the whole
        hierarchy in one call — that is what makes child groups first-class
        here. On a miss, walk the path to report exactly which segment broke and
        what was available there, which is far more actionable than '404'.
        """
        normalized = normalize_path(path)
        self._require_scope(normalized)
        safe = quote(normalized, safe="/")
        try:
            raw = self._get(f"/group-by-path{safe}")
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                raise KeycloakError(self._diagnose_path(normalized)) from exc
            raise
        if not raw:
            raise KeycloakError(self._diagnose_path(normalized))
        return raw

    def _raw_group_by_id(self, group_id: str) -> dict:
        try:
            raw = self._get(f"/groups/{quote(group_id, safe='')}")
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                raise KeycloakError(f"No group with id {group_id!r} in realm "
                                    f"{self._config.realm!r}.") from exc
            raise
        if not raw:
            raise KeycloakError(f"No group with id {group_id!r}.")
        self._require_scope(raw.get("path", ""))
        return raw

    def _resolve_raw(self, path: str | None, group_id: str | None) -> dict:
        if path:
            return self._raw_group_by_path(path)
        if group_id:
            return self._raw_group_by_id(group_id)
        raise KeycloakError("Provide either a group path (e.g. '/Team/Admins') or a group_id.")

    def _diagnose_path(self, path: str) -> str:
        """Walk a failed path segment by segment to say where it diverged.

        Best-effort: this runs to improve an error message, so any failure here
        (an out-of-scope ancestor, a permissions gap) degrades to the plain
        not-found text rather than masking the original problem.
        """
        try:
            return self._walk_diagnosis(path)
        except Exception:
            return f"Group path {path!r} not found in realm {self._config.realm!r}."

    def _walk_diagnosis(self, path: str) -> str:
        segments = [s for s in path.split("/") if s]
        tops = self._get_paged("/groups", search=segments[0], exact="true",
                               briefRepresentation="true", limit=self._config.page_size)
        current = next((g for g in tops if g.get("name") == segments[0]
                        and g.get("path", "").count("/") == 1), None)
        if current is None:
            return (f"Top-level group {segments[0]!r} not found in realm "
                    f"{self._config.realm!r} (from path {path!r}).")
        for segment in segments[1:]:
            children = self._children(self._raw_group_by_id(current["id"]), brief=True)
            match = next((c for c in children if c.get("name") == segment), None)
            if match is None:
                available = sorted(c.get("name", "") for c in children)
                return (f"Group path {path!r} not found: {segment!r} is not a child of "
                        f"{current.get('path')!r}. Available children: "
                        f"{available or ['(none)']}")
            current = match
        return f"Group path {path!r} not found in realm {self._config.realm!r}."

    def _children(self, group: dict, *, brief: bool = True) -> list[dict]:
        """Direct child groups of ``group``.

        KC < 23 embeds the subtree as ``subGroups``; KC 23+ reports
        ``subGroupCount`` and serves GET /groups/{id}/children. When the server
        reports neither key, probe the children endpoint rather than silently
        assuming the group is a leaf.
        """
        embedded = group.get("subGroups")
        if embedded:
            return embedded
        count = group.get("subGroupCount")
        if count or (embedded is None and count is None):
            try:
                return self._get_paged(
                    f"/groups/{quote(group['id'], safe='')}/children",
                    briefRepresentation="true" if brief else "false",
                )
            except requests.HTTPError as exc:
                # Pre-23 servers have no /children route.
                if exc.response is not None and exc.response.status_code == 404:
                    return []
                raise
        return []

    # --- groups: public API ----------------------------------------------
    def get_group(self, *, path: str | None = None, group_id: str | None = None,
                  include_children: bool = False,
                  include_member_count: bool = False) -> dict:
        raw = self._resolve_raw(path, group_id)
        out = self._shape_group(raw)
        out["subGroupCount"] = raw.get("subGroupCount", len(raw.get("subGroups") or []))
        if include_children:
            out["children"] = [
                {"id": c.get("id"), "name": c.get("name"),
                 "path": c.get("path"), "subGroupCount": c.get("subGroupCount")}
                for c in self._children(raw, brief=True)
            ]
        if include_member_count:
            out["memberCount"] = len(self._get_paged(
                f"/groups/{quote(raw['id'], safe='')}/members",
                briefRepresentation="true", limit=self._config.max_members,
            ))
        return out

    def list_groups(self, *, parent_path: str | None = None, search: str | None = None,
                    max_depth: int = 1, include_attributes: bool = False,
                    limit: int = 200) -> list[dict]:
        """Flat listing of groups with their paths and depth level.

        Returned flat rather than nested: it is far cheaper in tokens, and the
        `path` on every row already carries the hierarchy.
        """
        depth = max(1, min(max_depth, self._config.max_depth))
        rows: list[dict] = []

        if search:
            found = self._get_paged("/groups", search=search, exact="false",
                                    briefRepresentation="true", limit=limit)
            self._flatten_search(found, rows, limit)
        else:
            if parent_path:
                root = self._raw_group_by_path(parent_path)
                seeds = self._children(root, brief=True)
                base_level = normalize_path(root.get("path", parent_path)).count("/")
            elif self._config.scope_group_paths:
                # Scope is set: start from the configured roots rather than the
                # realm top level, so a scoped server lists only what it may read.
                seeds = [self._raw_group_by_path(p) for p in self._config.scope_group_paths]
                base_level = 0
            else:
                seeds = self._get_paged("/groups", briefRepresentation="true", limit=limit)
                base_level = 0
            self._walk(seeds, rows, level=1, depth=depth, base_level=base_level, limit=limit)

        if include_attributes:
            # One extra GET per row: brief/embedded representations omit
            # `attributes` entirely, so there is no way to get them in bulk.
            # Bounded by `limit`; keep that small when asking for attributes.
            for row in rows:
                row.update(self._shape_group(self._raw_group_by_id(row["id"])))
        return rows

    def _walk(self, groups: list[dict], rows: list[dict], *, level: int, depth: int,
              base_level: int, limit: int) -> None:
        for group in groups:
            if len(rows) >= limit:
                return
            path = group.get("path", "")
            if not self._config.in_scope(path):
                continue
            rows.append({
                "id": group.get("id"), "name": group.get("name"), "path": path,
                "level": max(0, normalize_path(path).count("/") - 1 - base_level),
                "subGroupCount": group.get("subGroupCount",
                                           len(group.get("subGroups") or [])),
            })
            if level < depth:
                self._walk(self._children(group, brief=True), rows,
                           level=level + 1, depth=depth, base_level=base_level, limit=limit)

    def _flatten_search(self, groups: list[dict], rows: list[dict], limit: int) -> None:
        """A group search returns matches nested under their ancestors on newer
        Keycloak. Flatten the whole returned tree and keep every node with a
        path, so the caller sees where each match actually lives."""
        for group in groups:
            if len(rows) >= limit:
                return
            path = group.get("path", "")
            if path and self._config.in_scope(path):
                rows.append({
                    "id": group.get("id"), "name": group.get("name"), "path": path,
                    "level": max(0, normalize_path(path).count("/") - 1),
                    "subGroupCount": group.get("subGroupCount",
                                               len(group.get("subGroups") or [])),
                })
            children = group.get("subGroups") or []
            if children:
                self._flatten_search(children, rows, limit)

    def list_group_members(self, *, path: str | None = None, group_id: str | None = None,
                           include_attributes: bool = False, limit: int = 200) -> list[dict]:
        """Direct members of a group. Keycloak has no transitive membership
        endpoint, so members of child groups are NOT included — list those
        groups' members separately."""
        raw = self._resolve_raw(path, group_id)
        capped = min(limit, self._config.max_members)
        members = self._get_paged(
            f"/groups/{quote(raw['id'], safe='')}/members",
            # brief=false is explicit: the brief form omits `attributes`, and the
            # default has varied between Keycloak releases.
            briefRepresentation="false" if include_attributes else "true",
            limit=capped,
        )
        return [self._shape_user(m, include_attributes=include_attributes) for m in members]

    # --- users ------------------------------------------------------------
    def _raw_user(self, *, username: str | None = None, email: str | None = None,
                  user_id: str | None = None) -> dict:
        if user_id:
            try:
                raw = self._get(f"/users/{quote(user_id, safe='')}")
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    raise KeycloakError(f"No user with id {user_id!r}.") from exc
                raise
            if not raw:
                raise KeycloakError(f"No user with id {user_id!r}.")
            return raw

        if username:
            params = {"username": username}
        elif email:
            params = {"email": email}
        else:
            raise KeycloakError("Provide one of: username, email, user_id.")

        results = self._get(
            "/users", exact="true", briefRepresentation="false", **params
        ) or []
        if not results:
            raise KeycloakError(
                f"No user matching {params} in realm {self._config.realm!r}."
            )
        if len(results) > 1:
            ids = ", ".join(u.get("id", "?") for u in results[:5])
            raise KeycloakError(
                f"{len(results)} users matched {params} — call again with user_id "
                f"for an exact lookup (first ids: {ids})."
            )
        return results[0]

    def get_user(self, *, username: str | None = None, email: str | None = None,
                 user_id: str | None = None) -> dict:
        return self._shape_user(self._raw_user(username=username, email=email, user_id=user_id))

    def search_users(self, *, search: str | None = None, username: str | None = None,
                     email: str | None = None, limit: int = 50,
                     include_attributes: bool = False) -> list[dict]:
        results = self._get_paged(
            "/users", search=search, username=username, email=email,
            briefRepresentation="false" if include_attributes else "true",
            limit=limit,
        )
        return [self._shape_user(u, include_attributes=include_attributes) for u in results]

    def _direct_group_paths(self, user_id: str) -> list[str]:
        groups = self._get_paged(f"/users/{quote(user_id, safe='')}/groups",
                                 briefRepresentation="true", limit=self._config.page_size * 5)
        return [g["path"] for g in groups if g.get("path")]

    def user_groups(self, *, username: str | None = None, email: str | None = None,
                    user_id: str | None = None, include_inherited: bool = True,
                    include_attributes: bool = True) -> dict:
        """Group memberships for a user.

        In Keycloak a member of `/team/admins` also inherits the attributes of
        every ancestor group (`/team`) without being a direct member of them.
        With include_inherited those ancestors are resolved and returned too,
        flagged `inherited: true` — that is usually the answer someone is
        actually after when they ask "where does this permission come from?".
        """
        raw_user = self._raw_user(username=username, email=email, user_id=user_id)
        direct = [p for p in self._direct_group_paths(raw_user["id"])
                  if self._config.in_scope(p)]

        ordered: list[tuple[str, bool]] = []
        seen: set[str] = set()
        for path in direct:
            if include_inherited:
                # Ancestors first so a parent's attributes read before the
                # child's, matching the order Keycloak resolves inheritance in.
                segments = [s for s in path.split("/") if s]
                for i in range(1, len(segments)):
                    ancestor = "/" + "/".join(segments[:i])
                    if ancestor not in seen and self._config.in_scope(ancestor):
                        seen.add(ancestor)
                        ordered.append((ancestor, True))
            if path not in seen:
                seen.add(path)
                ordered.append((path, False))

        groups: list[dict] = []
        unresolved: list[str] = []
        for path, inherited in ordered:
            entry: dict = {}
            if include_attributes:
                try:
                    raw_group = self._raw_group_by_path(path)
                    entry = dict(self._shape_group(raw_group))
                    hidden = self._policy.redacted_keys(raw_group)
                    if hidden:
                        entry["withheld_attribute_keys"] = hidden
                except (KeycloakError, requests.HTTPError):
                    # One unreadable ancestor must not sink the whole answer;
                    # report it instead of pretending it had no attributes.
                    unresolved.append(path)
                    entry = {"error": "could not be read (permissions or transient failure)"}
            # path/inherited are set last so they stay authoritative even if an
            # operator has redaction configured over a key named "path".
            entry["path"] = path
            entry["inherited"] = inherited
            groups.append(entry)

        return {
            "user": {"id": raw_user["id"], "username": raw_user.get("username"),
                     "email": raw_user.get("email")},
            "direct_count": len(direct),
            "inherited_count": sum(1 for _, i in ordered if i),
            "groups": groups,
            "unresolved_groups": unresolved,
        }

    def effective_user_attributes(self, *, username: str | None = None,
                                  email: str | None = None,
                                  user_id: str | None = None) -> dict:
        """Merge a user's own attributes with every group attribute they inherit,
        recording which source each value came from."""
        raw_user = self._raw_user(username=username, email=email, user_id=user_id)
        user = self._shape_user(raw_user)
        memberships = self.user_groups(user_id=raw_user["id"], include_inherited=True,
                                       include_attributes=True)

        merged: dict[str, dict] = {}
        # Which keys exist but were hidden — so the model can distinguish
        # "no such attribute" from "attribute withheld by policy".
        withheld: dict[str, list[str]] = {}
        for key in self._policy.redacted_keys(raw_user):
            withheld.setdefault(key, []).append("user")

        def absorb(attrs: dict, source: str) -> None:
            for key, value in (attrs or {}).items():
                values = value if isinstance(value, list) else [value]
                slot = merged.setdefault(key, {"values": [], "sources": []})
                for item in values:
                    if item not in slot["values"]:
                        slot["values"].append(item)
                if source not in slot["sources"]:
                    slot["sources"].append(source)

        # User's own attributes win first position; groups follow ancestors-first.
        absorb(user.get("attributes", {}), "user")
        for group in memberships["groups"]:
            label = f"{group['path']}{' (inherited)' if group['inherited'] else ''}"
            absorb(group.get("attributes", {}), label)
            for key in group.get("withheld_attribute_keys", ()):
                withheld.setdefault(key, []).append(label)

        return {
            "user": {"id": user["id"], "username": user.get("username"),
                     "email": user.get("email"), "enabled": user.get("enabled")},
            "attributes": merged,
            "sources": [{"path": g["path"], "inherited": g["inherited"]}
                        for g in memberships["groups"]],
            "direct_group_count": memberships["direct_count"],
            "inherited_group_count": memberships["inherited_count"],
            "withheld_attributes": {k: withheld[k] for k in sorted(withheld)},
            "unresolved_groups": memberships["unresolved_groups"],
        }

    # --- policy audit -----------------------------------------------------
    def audit_attribute_keys(self, *, sample_size: int = 200,
                             include_groups: bool = True,
                             include_users: bool = True) -> dict:
        """Report which attribute KEY NAMES exist in the realm and whether the
        active redaction policy covers them.

        Returns key names and occurrence counts only -- never a single attribute
        VALUE -- so running it cannot itself leak what it is auditing.

        The point is that whole-key matching silently misses compound names: a
        `keys` entry for `password` does not cover `storagepass`, and an indexed
        SCIM key like `phoneNumbers.value[0]` leaves `[1]` readable. This finds
        those gaps deliberately rather than leaving them to be discovered in a
        transcript.
        """
        counts: dict[str, int] = {}
        sampled = {"groups": 0, "users": 0}

        if include_users:
            users = self._get_paged("/users", briefRepresentation="false",
                                    limit=sample_size)
            sampled["users"] = len(users)
            for user in users:
                for key in (user.get("attributes") or {}):
                    counts[key] = counts.get(key, 0) + 1

        if include_groups:
            rows = self.list_groups(max_depth=self._config.max_depth,
                                    limit=sample_size)
            sampled["groups"] = len(rows)
            for row in rows:
                raw = self._raw_group_by_id(row["id"])
                for key in (raw.get("attributes") or {}):
                    counts[key] = counts.get(key, 0) + 1

        covered, uncovered, flagged = [], [], []
        for key, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            entry = {"key": key, "occurrences": n}
            if self._policy.matches(key):
                covered.append(entry)
                continue
            uncovered.append(entry)
            hits = [f for f in AUDIT_SUSPECT_FRAGMENTS if f in key.lower()]
            if hits:
                flagged.append({**entry, "matched_fragments": hits})

        return {
            "sampled": sampled,
            "distinct_attribute_keys": len(counts),
            "redacted_by_policy": covered,
            "not_redacted": uncovered,
            # The actionable list: credential- or personal-shaped names that the
            # policy does NOT currently hide.
            "flagged_not_redacted": flagged,
            "policy": self._config.policy_summary(),
            "note": ("Key names and counts only; no attribute values are read or "
                     "returned. 'flagged_not_redacted' is a heuristic prompt for "
                     "review, not a verdict -- some flagged keys are legitimately "
                     "public (e.g. an authorized-key list), and some sensitive "
                     "keys will not be flagged at all."),
        }

    # --- health -----------------------------------------------------------
    def status(self) -> dict:
        """Confirm connectivity + which grant worked, and echo the active policy
        so an operator can verify what is being hidden."""
        try:
            probe = self._get("/groups", first=0, max=1, briefRepresentation="true")
        except Exception as exc:
            raise KeycloakError(f"Keycloak connectivity check failed: {exc}") from exc
        return {
            "base_url": self._config.base_url,
            "realm": self._config.realm,
            "reachable": True,
            "grant": self.grant,
            "top_level_groups_visible": bool(probe),
            "server_version": self._server_version(),
            "write_tools": "none — this server has no write code path",
            "policy": self._config.policy_summary(),
        }

    def _server_version(self) -> str | None:
        """Best-effort. /admin/serverinfo is master-scoped and usually 403s for a
        realm service account, which is fine — report unknown rather than fail."""
        try:
            resp = self._session.get(
                f"{self._config.base_url}/admin/serverinfo",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=self._config.timeout, verify=self._config.verify,
            )
            if resp.ok:
                return (resp.json().get("systemInfo") or {}).get("version")
        except Exception:
            pass
        return None
