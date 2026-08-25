"""MCP server exposing read-only Keycloak tools.

Run with:  keycloak-mcp              (after `uv sync`/install)
       or:  uv run keycloak-mcp      (from the project directory)

Transport is stdio, which is what Claude Code / Desktop expect.

Every tool is read-only, scope-constrained and redaction-filtered. There is
deliberately NO generic "call any admin endpoint" tool: the surface is the eight
tools below and nothing else. Groups are addressed by PATH (`/Parent/Child`), so
child groups are first-class rather than something you reach by chaining id
lookups.
"""

from __future__ import annotations

import functools
from typing import Optional

import requests
from mcp.types import ToolAnnotations

from .client import KeycloakClient, KeycloakError
from .config import Config, load_config

try:  # mcp SDK >= 2.0 renamed FastMCP to MCPServer
    from mcp.server import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # mcp SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server
    from mcp.server.fastmcp.exceptions import ToolError

mcp = _Server("keycloak")

# Advertised on every tool, so a client can see the read-only guarantee in the
# protocol rather than having to take the docstrings' word for it. It is not
# merely a hint here: this server has no write code path to annotate otherwise.
# openWorldHint is true because the data lives in an external IdP.
# Built from the wire names: SDK 1.x declares these fields in camelCase, 2.x in
# snake_case with camelCase aliases, and model_validate accepts both.
_READ_ONLY = ToolAnnotations.model_validate({
    "readOnlyHint": True, "destructiveHint": False,
    "idempotentHint": True, "openWorldHint": True,
})


def _tool(fn):
    """Register a read-only tool, translating our errors into the SDK's ToolError.

    This matters: mcp SDK 2.x replaces the text of any exception that is NOT a
    ToolError with a generic "Error executing tool <name>" and keeps the detail
    server-side. Without this, the messages that make a failure recoverable --
    which path segment was wrong and what siblings exist, that a group is out of
    scope, that the service account is missing a role -- would never reach the
    model. functools.wraps keeps the signature and docstring the SDK reads to
    build the tool schema.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeycloakError as exc:
            raise ToolError(str(exc)) from exc
        except requests.RequestException as exc:
            raise ToolError(f"Keycloak request failed: {exc}") from exc

    return mcp.tool(annotations=_READ_ONLY)(wrapper)

# Lazily-built singletons so importing this module never requires live config.
_config: Config | None = None
_client: KeycloakClient | None = None


def _get() -> KeycloakClient:
    global _config, _client
    if _config is None:
        _config = load_config()
    if _client is None:
        _client = KeycloakClient(_config)
    return _client


# --- groups ---------------------------------------------------------------
@_tool
def get_group(
    path: Optional[str] = None,
    group_id: Optional[str] = None,
    include_children: bool = False,
    include_member_count: bool = False,
) -> dict:
    """Read one Keycloak group and its attributes.

    Address it by `path` — the full hierarchical path, e.g. '/Engineering' or
    '/Engineering/Platform/Admins' — which is how child groups are reached. A
    `group_id` (UUID) works too. Exactly one is required.

    Returns id, name, path, realmRoles, clientRoles, subGroupCount and the
    group's `attributes`. Attribute values whose key matches the server's
    redaction policy come back as "[redacted]" (or are absent, in drop mode).
    Set include_children for the direct child groups, include_member_count for
    the number of direct members.
    """
    return _get().get_group(
        path=path, group_id=group_id,
        include_children=include_children, include_member_count=include_member_count,
    )


@_tool
def list_groups(
    parent_path: Optional[str] = None,
    search: Optional[str] = None,
    max_depth: int = 1,
    include_attributes: bool = False,
    limit: int = 200,
) -> list[dict]:
    """List groups as a flat list of {id, name, path, level, subGroupCount}.

    - No arguments: the realm's top-level groups (or the configured scope roots).
    - `parent_path`: the children of that group, e.g. '/Engineering'.
    - `search`: name substring search across the realm; each match's full `path`
      shows where it actually sits in the hierarchy.

    `max_depth` recurses into child groups (1 = immediate level only). Every row
    carries its `path`, so the hierarchy is readable without nesting the output.

    `include_attributes` costs one extra call per group (Keycloak omits
    attributes from list responses) — keep `limit` small when using it. To read
    one group's attributes, prefer get_group.
    """
    return _get().list_groups(
        parent_path=parent_path, search=search, max_depth=max_depth,
        include_attributes=include_attributes, limit=limit,
    )


@_tool
def list_group_members(
    path: Optional[str] = None,
    group_id: Optional[str] = None,
    include_attributes: bool = False,
    limit: int = 200,
) -> list[dict]:
    """List the DIRECT members of a group, by path or group_id.

    Keycloak has no transitive-membership endpoint: members of child groups are
    not included here. To cover a subtree, call list_groups for the children and
    then this tool per child.

    `include_attributes` returns each member's attributes (redaction applies).
    """
    return _get().list_group_members(
        path=path, group_id=group_id,
        include_attributes=include_attributes, limit=limit,
    )


# --- users ----------------------------------------------------------------
@_tool
def get_user(
    username: Optional[str] = None,
    email: Optional[str] = None,
    user_id: Optional[str] = None,
) -> dict:
    """Read one user and their attributes. Provide exactly one of username,
    email (both matched exactly) or user_id (UUID).

    Returns id, username, email, first/last name, enabled, emailVerified,
    createdTimestamp, federationLink, requiredActions and `attributes`, with the
    redaction policy applied. Credentials are never exposed — Keycloak does not
    return them on read, and this server has no endpoint that would.
    """
    return _get().get_user(username=username, email=email, user_id=user_id)


@_tool
def search_users(
    search: Optional[str] = None,
    username: Optional[str] = None,
    email: Optional[str] = None,
    include_attributes: bool = False,
    limit: int = 50,
) -> list[dict]:
    """Search users. `search` matches against username, first/last name and
    email; `username`/`email` filter on those fields specifically.

    Returns a brief record per match. Use get_user for one user's full detail,
    or set include_attributes to pull attributes for every match at once.
    """
    return _get().search_users(
        search=search, username=username, email=email,
        include_attributes=include_attributes, limit=limit,
    )


@_tool
def get_user_groups(
    username: Optional[str] = None,
    email: Optional[str] = None,
    user_id: Optional[str] = None,
    include_inherited: bool = True,
    include_attributes: bool = True,
) -> dict:
    """List a user's group memberships, with each group's attributes.

    A member of '/team/admins' also inherits the attributes of every ancestor
    group ('/team') without being a direct member. With include_inherited those
    ancestors are resolved and returned too, marked `inherited: true`, ordered
    ancestors-first. Groups that could not be read are listed in
    `unresolved_groups` rather than silently dropped.
    """
    return _get().user_groups(
        username=username, email=email, user_id=user_id,
        include_inherited=include_inherited, include_attributes=include_attributes,
    )


@_tool
def get_effective_user_attributes(
    username: Optional[str] = None,
    email: Optional[str] = None,
    user_id: Optional[str] = None,
) -> dict:
    """Merge a user's own attributes with every attribute they inherit from
    their groups, recording where each value came from.

    This is the "why does this account have this permission?" tool. Returns
    `attributes` as {key: {values, sources}}, where a source is "user" or a
    group path (suffixed "(inherited)" for an ancestor the user is not a direct
    member of), plus `withheld_attributes` naming any keys that exist but were
    hidden by the redaction policy — so a withheld attribute is never mistaken
    for an absent one.
    """
    return _get().effective_user_attributes(
        username=username, email=email, user_id=user_id,
    )


# --- policy audit ---------------------------------------------------------
@_tool
def audit_attribute_keys(
    sample_size: int = 200,
    include_groups: bool = True,
    include_users: bool = True,
    include_all_keys: bool = False,
) -> dict:
    """Audit which attribute key names exist in the realm and whether the
    redaction policy actually covers them.

    Returns key NAMES and occurrence counts only — never an attribute value — so
    running the audit cannot leak what it is auditing.

    Use it to catch the gap whole-key matching leaves: a `keys` entry for
    `password` does not cover `storagepass`, and an indexed SCIM key like
    `phoneNumbers.value[0]` leaves `[1]` readable. `flagged_not_redacted` lists
    credential- and personal-shaped names the policy does NOT hide; treat it as
    a prompt for operator review, not a verdict — some flagged keys are
    legitimately public, and it will not catch a sensitive key with an
    innocuous name.

    The full list of unredacted keys is summarised to a count by default; set
    include_all_keys=True to get every one.
    """
    return _get().audit_attribute_keys(
        sample_size=sample_size,
        include_groups=include_groups, include_users=include_users,
        include_all_keys=include_all_keys,
    )


# --- health ---------------------------------------------------------------
@_tool
def keycloak_status() -> dict:
    """Confirm connectivity to Keycloak and report the active policy: base URL,
    realm, which OAuth grant authenticated, detected server version (when the
    account may read it), the configured group scope, and exactly which
    attribute keys/patterns are being redacted."""
    return _get().status()


def main() -> None:
    # Fail fast and loud if required config is missing, before serving.
    load_config()
    mcp.run()


if __name__ == "__main__":
    main()
