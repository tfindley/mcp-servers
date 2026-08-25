"""Configuration loading.

Split mirrors netbox-mcp:
  * Secrets + connection -> environment variables (never on disk here).
  * Scope / attribute policy -> keycloak-mcp.toml (diffable, no secrets).

The env var names are deliberately the ones already used by the sibling
Keycloak toolkits in ~/devel/python3 (KC_BASE_URL / KC_REALM / KC_CLIENT_ID /
KC_CLIENT_SECRET), so an existing credential-sourcing script works unchanged.

Env vars:
  KC_BASE_URL         (required)  e.g. https://sso.example.com  (no trailing /)
  KC_REALM            (required)  realm name
  KC_CLIENT_ID        (required)  service-account client id (or admin username
                                  when using the password grant)
  KC_CLIENT_SECRET    (required)  client secret (or admin password)
  KC_AUTH_MODE        (optional)  auto | client-credentials | password
  KC_TLS_VERIFY       (optional)  false disables TLS verification (insecure)
  KC_NO_VERIFY        (optional)  sibling-tool spelling of the same escape hatch
  KC_CA_BUNDLE        (optional)  path to an internal CA bundle (the secure fix)
  KC_TIMEOUT          (optional)  per-request timeout in seconds (default 30)
  KEYCLOAK_MCP_CONFIG (optional)  path to keycloak-mcp.toml (default: ./keycloak-mcp.toml)
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# --- Redaction defaults ----------------------------------------------------
# Keycloak `attributes` are free-form, so operators do stash secrets in them.
# These key names are blanked in EVERY returned record by default.
#
# Matching is whole-key and case-insensitive by default -- the lists below are
# written in the natural camelCase spelling and lowercased at policy-build time,
# so `clientSecret` and `clientsecret` are one entry. Matching is NEVER
# substring: that would silently blank `secretary_name` for `secret`. Underscore
# variants ARE distinct, so both spellings appear where both are common in the
# wild. For deliberate wildcard matching use [redact].patterns.
DEFAULT_REDACT_KEYS: list[str] = [
    "password", "passwd", "secret", "clientSecret", "client_secret",
    "token", "access_token", "refresh_token", "id_token",
    "private_key", "privateKey", "api_key", "apiKey",
    "credential", "credentials", "otp", "totp", "otpSecret",
    "recoveryCodes", "recovery_codes", "sessionKey",
]

# Compound key names that whole-key matching cannot reach: `storagepass`,
# `dbPassword`, `webhookSecret`. These wildcards are ANCHORED at one end on
# purpose -- "*secret" catches `clientSecret` and `appSecret` while leaving
# `secretary_name` alone, which a bare "*secret*" would blank. That keeps the
# never-substring invariant for `keys` intact while still covering compounds.
#
# Over-matching here is fail-safe (a redacted `passwordPolicy` boolean is a
# nuisance; a leaked password is not), and `audit_attribute_keys` shows exactly
# what the policy hides, so over-redaction is visible rather than silent.
# Setting [redact].patterns in the toml REPLACES this list.
DEFAULT_REDACT_PATTERNS: list[str] = [
    "*password", "password*", "*passwd", "passwd*",
    "*secret", "secret_*",
    "*token", "token_*",
    "*apikey", "*api_key", "*privatekey", "*private_key",
    "*credential", "*credentials",
]

# Key-name fragments that LOOK credential- or personal-shaped. Never used to
# redact anything -- `audit_attribute_keys` uses them to flag keys the active
# policy does NOT cover, so an operator finds the gap deliberately instead of
# discovering it in a transcript. Substring matching is fine here precisely
# because the output is a report, not a filter.
AUDIT_SUSPECT_FRAGMENTS: list[str] = [
    "pass", "secret", "token", "credential", "auth", "key", "hash", "salt",
    "otp", "mfa",  # no bare "pin": it matches "mapping" and is pure noise
    "phone", "mobile", "address", "postcode", "zip", "birth", "dob",
    "insurance", "national", "nino", "ssn", "taxid", "passport",
    "licence", "license", "bank", "iban", "sortcode", "account",
    "salary", "medical", "disab", "ethnic", "religion", "gender", "marital",
    "emergency", "nextofkin",
]

# A starter set of attribute keys that commonly hold personal data subject to
# GDPR. NOT enabled by default: which keys are personal is entirely
# site-specific, and blanking them unasked would hide data an operator may
# legitimately need. `keycloak-mcp-setup` offers to write these into your toml,
# and keycloak-mcp.toml.example ships them as a copy-paste block.
PERSONAL_DATA_KEYS: list[str] = [
    # identifiers
    "dateOfBirth", "date_of_birth", "dob", "birthDate",
    "nationalInsuranceNumber", "niNumber", "ni_number", "nino", "ssn",
    "socialSecurityNumber", "passportNumber", "drivingLicence",
    "drivingLicense", "taxId",
    # contact / location
    "homeAddress", "home_address", "postcode", "postalCode", "zipCode",
    "homePhone", "mobile", "mobilePhone", "personalEmail", "privateEmail",
    "emergencyContact", "nextOfKin",
    # financial
    "bankAccount", "accountNumber", "sortCode", "iban", "salary",
    # special-category data (GDPR Art. 9)
    "medicalNotes", "disability", "ethnicity", "religion", "gender",
    "maritalStatus",
]

REDACT_MODES = ("redact", "drop")


@dataclass(frozen=True)
class Config:
    base_url: str
    realm: str
    client_id: str
    client_secret: str = field(repr=False)   # keep out of tracebacks/logs
    auth_mode: str = "auto"

    # Client-side defense-in-depth on top of the Keycloak service account's
    # role assignments (which are the authoritative gate). When non-empty, only
    # groups at or below one of these paths may be read.
    scope_group_paths: list[str] = field(default_factory=list)

    # Attribute redaction -- the headline control. Applied to EVERY record the
    # client returns, recursively, before it can reach a tool.
    redact_mode: str = "redact"
    redact_keys: list[str] = field(default_factory=lambda: list(DEFAULT_REDACT_KEYS))
    redact_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_REDACT_PATTERNS))
    redact_paths: list[str] = field(default_factory=list)
    redact_case_sensitive: bool = False

    # Optional stricter mode: if set, `attributes` is reduced to these keys only
    # (an allow-list, applied before redaction). None = pass everything through.
    group_attribute_keys: list[str] | None = None
    user_attribute_keys: list[str] | None = None

    # Bounds -- keep a careless query from pulling a whole realm.
    page_size: int = 100          # Keycloak's own page ceiling on most endpoints
    max_members: int = 500
    max_depth: int = 10
    timeout: int = 30

    # TLS trust for the Keycloak endpoint (common case: internal IdP with an
    # internal CA). ca_bundle is the secure fix; verify=False is test-only.
    tls_verify: bool = True
    tls_ca_bundle: str | None = None

    @property
    def verify(self):
        """The value handed to requests as ``verify``: a CA-bundle path or bool."""
        return self.tls_ca_bundle if self.tls_ca_bundle else self.tls_verify

    def in_scope(self, path: str) -> bool:
        """True if a group path is readable under the configured scope.

        Empty scope means the whole realm (bounded by the service account's
        roles). Comparison is case-sensitive because Keycloak group names are.
        """
        if not self.scope_group_paths:
            return True
        candidate = normalize_path(path)
        return any(
            candidate == root or candidate.startswith(root.rstrip("/") + "/")
            for root in self.scope_group_paths
        )

    def attribute_keys_for(self, kind: str) -> list[str] | None:
        return self.group_attribute_keys if kind == "group" else self.user_attribute_keys

    def policy_summary(self) -> dict:
        """Human-readable view of the active policy, surfaced by keycloak_status
        so an operator can confirm what is actually being hidden."""
        return {
            "scope_group_paths": self.scope_group_paths or ["(whole realm)"],
            "redact_mode": self.redact_mode,
            "redact_keys": sorted(self.redact_keys),
            "redact_patterns": self.redact_patterns,
            "redact_paths": self.redact_paths,
            "redact_case_sensitive": self.redact_case_sensitive,
            "group_attribute_allow_list": self.group_attribute_keys or "(all keys)",
            "user_attribute_allow_list": self.user_attribute_keys or "(all keys)",
            "tls_verify": self.verify,
        }


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or malformed."""


def normalize_path(path: str) -> str:
    """'team/admins/' -> '/team/admins'. Keycloak group paths are absolute and
    have no trailing slash; accept the sloppy forms a model is likely to pass."""
    cleaned = "/".join(seg for seg in str(path).split("/") if seg)
    return "/" + cleaned


def _load_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _as_bool(value: str) -> bool:
    """Parse a truthy/falsey env string. Anything but an explicit false-ish
    value is True, so a typo fails safe (verification stays ON)."""
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


def _as_int(raw: str | None, default: int) -> int:
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return default


def load_config() -> Config:
    """Build Config from environment + keycloak-mcp.toml. Raises ConfigError on
    missing required values so the server fails fast and loud at startup."""
    base_url = os.environ.get("KC_BASE_URL", "").strip().rstrip("/")
    realm = os.environ.get("KC_REALM", "").strip()
    client_id = os.environ.get("KC_CLIENT_ID", "").strip()
    client_secret = os.environ.get("KC_CLIENT_SECRET", "").strip()

    missing = [
        name for name, val in (
            ("KC_BASE_URL", base_url), ("KC_REALM", realm),
            ("KC_CLIENT_ID", client_id), ("KC_CLIENT_SECRET", client_secret),
        ) if not val
    ]
    if missing:
        raise ConfigError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Source your read-only Keycloak credentials before starting the "
            "server (KC_BASE_URL, KC_REALM, KC_CLIENT_ID, KC_CLIENT_SECRET)."
        )

    auth_mode = (os.environ.get("KC_AUTH_MODE") or "auto").strip().lower()
    if auth_mode not in {"auto", "client-credentials", "password"}:
        raise ConfigError(
            f"KC_AUTH_MODE must be one of auto|client-credentials|password, got {auth_mode!r}."
        )

    cfg_path = Path(os.environ.get("KEYCLOAK_MCP_CONFIG", "keycloak-mcp.toml"))
    raw = _load_toml(cfg_path)

    scope = raw.get("scope", {})
    redact = raw.get("redact", {})
    attrs = raw.get("attributes", {})
    limits = raw.get("limits", {})
    tls = raw.get("tls", {})

    mode = str(redact.get("mode", "redact")).strip().lower()
    if mode not in REDACT_MODES:
        raise ConfigError(
            f"[redact].mode must be one of {'|'.join(REDACT_MODES)}, got {mode!r} in {cfg_path}."
        )

    # TLS: env overrides toml (env is the quick path for a self-signed test box).
    # KC_NO_VERIFY is the sibling tools' spelling and is inverted.
    ca_bundle = os.environ.get("KC_CA_BUNDLE", "").strip() or tls.get("ca_bundle")
    verify_env = os.environ.get("KC_TLS_VERIFY")
    no_verify_env = os.environ.get("KC_NO_VERIFY")
    if verify_env is not None:
        tls_verify = _as_bool(verify_env)
    elif no_verify_env is not None:
        tls_verify = not _as_bool(no_verify_env)
    else:
        tls_verify = bool(tls.get("verify", True))

    return Config(
        base_url=base_url,
        realm=realm,
        client_id=client_id,
        client_secret=client_secret,
        auth_mode=auth_mode,
        scope_group_paths=[normalize_path(p) for p in scope.get("group_paths", [])],
        redact_mode=mode,
        redact_keys=list(redact.get("keys", DEFAULT_REDACT_KEYS)),
        redact_patterns=list(redact.get("patterns", DEFAULT_REDACT_PATTERNS)),
        redact_paths=list(redact.get("paths", [])),
        redact_case_sensitive=bool(redact.get("case_sensitive", False)),
        group_attribute_keys=attrs.get("group_keys"),
        user_attribute_keys=attrs.get("user_keys"),
        page_size=_as_int(limits.get("page_size"), 100),
        max_members=_as_int(limits.get("max_members"), 500),
        max_depth=_as_int(limits.get("max_depth"), 10),
        timeout=_as_int(os.environ.get("KC_TIMEOUT", limits.get("timeout")), 30),
        tls_verify=tls_verify,
        tls_ca_bundle=ca_bundle or None,
    )
