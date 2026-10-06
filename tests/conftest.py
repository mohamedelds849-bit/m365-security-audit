import copy
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from m365audit.config import load_config  # noqa: E402
from m365audit.engine import run_checks  # noqa: E402
from m365audit.model import Tenant, load_export  # noqa: E402

DATA = os.path.join(ROOT, "data")
LOGS = os.path.join(DATA, "logs")
VULN = os.path.join(DATA, "agrisouss_m365_vulnerable.json")
QUICK = os.path.join(DATA, "agrisouss_m365_quickwins.json")
HARD = os.path.join(DATA, "agrisouss_m365_hardened.json")

T = "test.onmicrosoft.com"
BG1, BG2, ADM, U1 = f"bg1@{T}", f"bg2@{T}", f"adm.a@{T}", "u.one@test.ma"


def _u(upn, **kw):
    u = {"userPrincipalName": upn, "accountEnabled": True, "userType": "Member",
         "createdDateTime": "2025-01-01T00:00:00Z", "lastSignInDateTime": "2026-09-28T08:00:00Z",
         "onPremisesSyncEnabled": False, "assignedLicenses": [], "hasMailbox": False,
         "authMethods": ["fido2"], "isBreakGlass": False}
    u.update(kw)
    return u


def _ca(name, **kw):
    p = {"displayName": name, "state": "enabled", "includeUsers": ["All"],
         "excludeUsers": [BG1, BG2], "includeApplications": ["All"], "clientAppTypes": ["all"],
         "grantControls": ["mfa"]}
    p.update(kw)
    return p


# A small, fully compliant export: no check fires on it.
MINIMAL = {
    "schemaVersion": "1.0",
    "exportedAt": "2026-09-30T08:00:00Z",
    "tenant": {"id": "t-1", "defaultDomain": T, "displayName": "Test SARL",
               "entraIdP1": True, "entraIdP2": True},
    "securityDefaults": {"enabled": False},
    "conditionalAccessPolicies": [
        _ca("CA01 admins", includeUsers=[], includeRoles=["Global Administrator"]),
        _ca("CA02 legacy", clientAppTypes=["exchangeActiveSync", "other"], grantControls=["block"]),
        _ca("CA03 mfa all"),
        _ca("CA04 sign-in risk", signInRiskLevels=["high"], grantControls=["block"]),
        _ca("CA05 user risk", userRiskLevels=["high"], grantControls=["mfa", "passwordChange"]),
    ],
    "users": [
        _u(BG1, isBreakGlass=True, lastSignInDateTime="2026-01-01T00:00:00Z"),
        _u(BG2, isBreakGlass=True, lastSignInDateTime=None),
        _u(ADM),
        _u(U1, hasMailbox=True, assignedLicenses=["O365_BUSINESS_PREMIUM"],
           onPremisesSyncEnabled=True, authMethods=["microsoftAuthenticator"]),
    ],
    "directoryRoleAssignments": [
        {"roleName": "Global Administrator", "principal": BG1},
        {"roleName": "Global Administrator", "principal": BG2},
        {"roleName": "Global Administrator", "principal": ADM, "assignmentType": "eligible"},
    ],
    "authorizationPolicy": {"userConsent": "none", "guestUserAccess": "limited",
                            "allowInvitesFrom": "adminsAndGuestInviters",
                            "usersCanRegisterApps": False},
    "passwordPolicy": {"expirationDays": 0},
    "sspr": {"enabled": "all", "methodsRequired": 2, "methods": ["microsoftAuthenticator", "sms"]},
    "audit": {"unifiedAuditLogEnabled": True, "mailboxAuditByDefault": True},
    "exchange": {"autoForwardingMode": "Off"},
    "domains": [
        {"name": T, "dkimEnabled": True},
        {"name": "test.ma", "isDefault": True, "dkimEnabled": True, "dmarcPolicy": "reject",
         "spfRecord": "v=spf1 include:spf.protection.outlook.com -all"},
    ],
    "applications": [],
    "teams": {"externalAccess": "allowList", "allowedDomains": ["partner.example"],
              "consumerAccess": False},
    "sharepoint": {"sharingCapability": "ExistingExternalUserSharingOnly"},
    "monitoring": {"breakGlassSignInAlert": True},
}


@pytest.fixture
def minimal():
    return copy.deepcopy(MINIMAL)


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def vuln():
    return load_export(VULN)


@pytest.fixture(scope="session")
def hard():
    return load_export(HARD)


def fired(data_or_tenant, cfg):
    t = data_or_tenant if isinstance(data_or_tenant, Tenant) else Tenant(data_or_tenant)
    return {f.id: f for f in run_checks(t, cfg)}


def write_json(tmp_path, data, name="export.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def write_jsonl(tmp_path, events, name):
    p = tmp_path / name
    p.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return str(p)
