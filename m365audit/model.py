"""Load and validate a Microsoft 365 / Entra ID configuration export (see docs/SCHEMA.md).

The auditor never talks to Microsoft Graph: it only reads a JSON file that an administrator
produced from THEIR OWN tenant with read-only cmdlets (docs/EXPORT.md). This module turns that
file into a validated `Tenant` object with a few helpers used by the checks.

The export must never contain secrets: keys such as `secretText` or `passwordCredentials`
are refused anywhere in the document, so a careless export fails loudly instead of being
processed (and copied into reports).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
MAX_FILE_BYTES = 50 * 1024 * 1024  # refuse absurdly large inputs instead of hanging
MAX_DEPTH = 20                      # the schema is shallow; deeper means a malformed file
FORBIDDEN_KEYS = {"secrettext", "clientsecret", "password", "passwordcredentials",
                  "keycredentials", "refreshtoken", "accesstoken", "certificate"}


class SchemaError(ValueError):
    """Raised when the export does not follow docs/SCHEMA.md."""


DATE = "date"
STR_LIST = "str_list"


def enum(*values):
    return ("enum", frozenset(values))


# Field specifications: name -> (type | DATE | STR_LIST | enum(...), required, default)
TENANT = {
    "id": (str, True, None),
    "defaultDomain": (str, True, None),
    "displayName": (str, False, ""),
    "licenses": (STR_LIST, False, []),
    "entraIdP1": (bool, False, False),
    "entraIdP2": (bool, False, False),
}
SECURITY_DEFAULTS = {"enabled": (bool, True, None)}
CA_POLICY = {
    "displayName": (str, True, None),
    "state": (enum("enabled", "disabled", "enabledForReportingButNotEnforced"), True, None),
    "includeUsers": (STR_LIST, False, []),
    "excludeUsers": (STR_LIST, False, []),
    "includeRoles": (STR_LIST, False, []),
    "includeApplications": (STR_LIST, False, []),
    "clientAppTypes": (STR_LIST, False, ["all"]),
    "grantControls": (STR_LIST, False, []),
    "signInRiskLevels": (STR_LIST, False, []),
    "userRiskLevels": (STR_LIST, False, []),
}
USER = {
    "userPrincipalName": (str, True, None),
    "displayName": (str, False, ""),
    "accountEnabled": (bool, True, None),
    "userType": (enum("Member", "Guest"), False, "Member"),
    "createdDateTime": (DATE, False, None),
    "lastSignInDateTime": (DATE, False, None),
    "onPremisesSyncEnabled": (bool, False, False),
    "assignedLicenses": (STR_LIST, False, []),
    "hasMailbox": (bool, False, False),
    "authMethods": (STR_LIST, False, []),
    "isBreakGlass": (bool, False, False),
}
ROLE_ASSIGNMENT = {
    "roleName": (str, True, None),
    "principal": (str, True, None),
    "principalType": (enum("user", "group", "servicePrincipal"), False, "user"),
    "assignmentType": (enum("active", "eligible"), False, "active"),
    "endDateTime": (DATE, False, None),
}
AUTHORIZATION = {
    "userConsent": (enum("allowAll", "allowVerifiedLowRisk", "none"), True, None),
    "guestUserAccess": (enum("sameAsMember", "limited", "restricted"), True, None),
    "allowInvitesFrom": (enum("everyone", "adminsGuestInvitersAndAllMembers",
                              "adminsAndGuestInviters", "none"), True, None),
    "usersCanRegisterApps": (bool, True, None),
}
PASSWORD_POLICY = {"expirationDays": (int, True, None)}
SSPR = {
    "enabled": (enum("none", "selected", "all"), True, None),
    "methodsRequired": (int, False, 1),
    "methods": (STR_LIST, False, []),
}
AUDIT = {
    "unifiedAuditLogEnabled": (bool, True, None),
    "mailboxAuditByDefault": (bool, True, None),
    "auditBypassMailboxes": (STR_LIST, False, []),
}
EXCHANGE = {
    "autoForwardingMode": (enum("Automatic", "On", "Off"), True, None),
    "remoteDomainAutoForward": (bool, False, False),
}
DOMAIN = {
    "name": (str, True, None),
    "isDefault": (bool, False, False),
    "dkimEnabled": (bool, False, False),
    "dmarcPolicy": (enum("none", "quarantine", "reject"), False, None),
    "spfRecord": (str, False, ""),
}
APPLICATION = {
    "displayName": (str, True, None),
    "appId": (str, True, None),
    "publisherVerified": (bool, False, False),
    "isMicrosoftFirstParty": (bool, False, False),
    "permissions": (list, False, []),
    "consentedBy": (str, False, ""),
    "createdDateTime": (DATE, False, None),
}
PERMISSION = {
    "name": (str, True, None),
    "type": (enum("Application", "Delegated"), True, None),
    "consentType": (enum("AllPrincipals", "Principal"), False, "AllPrincipals"),
}
TEAMS = {
    "externalAccess": (enum("allowAll", "allowList", "blocked"), True, None),
    "allowedDomains": (STR_LIST, False, []),
    "consumerAccess": (bool, True, None),
}
SHAREPOINT = {
    "sharingCapability": (enum("ExternalUserAndGuestSharing", "ExternalUserSharingOnly",
                               "ExistingExternalUserSharingOnly", "Disabled"), True, None),
    "anyoneLinkExpirationDays": (int, False, 0),
    "defaultSharingLinkType": (enum("AnonymousAccess", "Internal", "Direct"), False, "Internal"),
}
MONITORING = {"breakGlassSignInAlert": (bool, True, None)}

REQUIRED_SECTIONS = {
    "tenant": TENANT, "securityDefaults": SECURITY_DEFAULTS,
    "authorizationPolicy": AUTHORIZATION, "passwordPolicy": PASSWORD_POLICY, "sspr": SSPR,
    "audit": AUDIT, "exchange": EXCHANGE, "teams": TEAMS, "sharepoint": SHAREPOINT,
    "monitoring": MONITORING,
}

# Authentication methods that count as a second factor (docs/SCHEMA.md).
MFA_METHODS = {"microsoftAuthenticator", "fido2", "windowsHelloForBusiness", "softwareOath",
               "hardwareOath", "sms", "voice", "passkey"}


def parse_date(value, where: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SchemaError(f"{where}: date attendue (chaîne ISO-8601 ou null)")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaError(f"{where}: date invalide {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def check_fields(obj, spec: dict, where: str) -> dict:
    """Validate one JSON object against a field spec, return a normalised copy."""
    if not isinstance(obj, dict):
        raise SchemaError(f"{where}: objet JSON attendu, reçu {type(obj).__name__}")
    out = {}
    for name, (ftype, required, default) in spec.items():
        if name not in obj or (obj[name] is None and ftype is not DATE
                               and not isinstance(ftype, tuple)):
            if required:
                raise SchemaError(f"{where}: champ obligatoire manquant '{name}'")
            out[name] = list(default) if isinstance(default, list) else default
            continue
        value, loc = obj[name], f"{where}.{name}"
        if ftype is DATE:
            out[name] = parse_date(value, loc)
        elif ftype is STR_LIST:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise SchemaError(f"{loc}: liste de chaînes attendue")
            out[name] = list(value)
        elif isinstance(ftype, tuple):  # enum
            if value is None and not required:
                out[name] = None
            elif value not in ftype[1]:
                raise SchemaError(f"{loc}: valeur inconnue {value!r} "
                                  f"(attendu : {', '.join(sorted(ftype[1]))})")
            else:
                out[name] = value
        elif ftype is int:
            # bool is a subclass of int in Python: refuse it explicitly
            if isinstance(value, bool) or not isinstance(value, int):
                raise SchemaError(f"{loc}: entier attendu, reçu {value!r}")
            if value < 0:
                raise SchemaError(f"{loc}: valeur négative {value}")
            out[name] = value
        elif not isinstance(value, ftype):
            raise SchemaError(f"{loc}: type {ftype.__name__} attendu, reçu {type(value).__name__}")
        else:
            out[name] = value
    return out


def check_list(data: dict, key: str, spec: dict, unique_key: str | None) -> list[dict]:
    raw = data.get(key, [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise SchemaError(f"{key}: liste attendue")
    items, seen = [], set()
    for i, obj in enumerate(raw):
        item = check_fields(obj, spec, f"{key}[{i}]")
        if unique_key:
            k = item[unique_key].lower()
            if k in seen:
                raise SchemaError(f"{key}[{i}]: doublon '{item[unique_key]}'")
            seen.add(k)
        items.append(item)
    return items


def reject_secrets(node, where: str = "$", depth: int = 0) -> None:
    """Refuse any key that looks like a credential, at any depth (iterative-safe depth cap)."""
    if depth > MAX_DEPTH:
        raise SchemaError(f"{where}: imbrication trop profonde (> {MAX_DEPTH})")
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in FORBIDDEN_KEYS:
                raise SchemaError(f"{where}.{k}: l'export ne doit jamais contenir de secret "
                                  "(clé interdite, voir docs/EXPORT.md)")
            reject_secrets(v, f"{where}.{k}", depth + 1)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            reject_secrets(v, f"{where}[{i}]", depth + 1)


class Tenant:
    """Validated, read-only view of the export with helpers for the checks."""

    def __init__(self, data: dict):
        if not isinstance(data, dict):
            raise SchemaError("la racine du fichier doit être un objet JSON")
        reject_secrets(data)
        version = data.get("schemaVersion")
        if version not in SUPPORTED_SCHEMA_VERSIONS:
            raise SchemaError(f"schemaVersion non supportée: {version!r} (attendu: 1.0)")
        self.exported_at = parse_date(data.get("exportedAt"), "exportedAt")
        if self.exported_at is None:
            raise SchemaError("champ obligatoire manquant 'exportedAt'")
        for section, spec in REQUIRED_SECTIONS.items():
            if section not in data:
                raise SchemaError(f"section obligatoire manquante '{section}'")
            setattr(self, section, check_fields(data[section], spec, section))
        self.ca_policies = check_list(data, "conditionalAccessPolicies", CA_POLICY, "displayName")
        self.users = check_list(data, "users", USER, "userPrincipalName")
        self.role_assignments = check_list(data, "directoryRoleAssignments", ROLE_ASSIGNMENT, None)
        self.domains = check_list(data, "domains", DOMAIN, "name")
        self.applications = check_list(data, "applications", APPLICATION, "appId")
        for i, app in enumerate(self.applications):
            app["permissions"] = [check_fields(p, PERMISSION, f"applications[{i}].permissions[{j}]")
                                  for j, p in enumerate(app["permissions"])]
        self._users = {u["userPrincipalName"].lower(): u for u in self.users}

    # -- lookups ----------------------------------------------------------
    def user(self, upn: str) -> dict | None:
        return self._users.get(upn.lower())

    def age_days(self, dt: datetime | None) -> int | None:
        """Days between a timestamp and the export date (None if never set)."""
        if dt is None:
            return None
        return (self.exported_at - dt).days

    def enabled_ca(self) -> list[dict]:
        """CA policies that are actually enforced (report-only does not protect)."""
        return [p for p in self.ca_policies if p["state"] == "enabled"]

    def break_glass(self) -> list[dict]:
        return [u for u in self.users if u["isBreakGlass"]]

    def privileged_assignments(self, roles: list[str], include_eligible: bool = False):
        wanted = {r.lower() for r in roles}
        return [a for a in self.role_assignments if a["roleName"].lower() in wanted
                and (include_eligible or a["assignmentType"] == "active")]

    def privileged_users(self, roles: list[str], include_eligible: bool = False) -> dict[str, set[str]]:
        """{lower-case UPN: set(role names)} for assignments to enabled users.

        By default only ACTIVE assignments count. With include_eligible=True, PIM-eligible
        assignments count too: an eligible Global Administrator can become one in minutes.
        """
        out: dict[str, set[str]] = {}
        for a in self.privileged_assignments(roles, include_eligible):
            if a["principalType"] != "user":
                continue
            u = self.user(a["principal"])
            if u is not None and u["accountEnabled"]:
                out.setdefault(u["userPrincipalName"].lower(), set()).add(a["roleName"])
        return out


def load_export(path: str) -> Tenant:
    """Read a JSON export from disk and validate it. Raises SchemaError on any problem."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise SchemaError(f"fichier introuvable ou illisible: {path}") from exc
    if size > MAX_FILE_BYTES:
        raise SchemaError(f"fichier trop volumineux ({size} octets, max {MAX_FILE_BYTES})")
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:  # -sig: accept PowerShell BOM
            data = json.load(fh)
    except UnicodeDecodeError as exc:
        raise SchemaError("le fichier n'est pas encodé en UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise SchemaError(f"JSON invalide (ligne {exc.lineno}, colonne {exc.colno}): {exc.msg}") from exc
    except RecursionError as exc:
        raise SchemaError("JSON trop profondément imbriqué") from exc
    return Tenant(data)
