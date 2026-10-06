"""Check plugins. Every module in this package is imported by engine.all_checks().

Reference conventions used in `references`:
- CIS = CIS Microsoft 365 Foundations Benchmark. Recommendations are cited by TITLE only:
  section numbers change between versions (v3 / v4 / v5...). Titles can be slightly reworded
  between versions too, so look them up by keyword.
- SCuBA = CISA Secure Cloud Business Applications M365 baselines (ScubaGear repository,
  `baselines/*.md`, main branch read on 2026-10-05). IDs like MS.AAD.1.1v1 include a version
  suffix that CISA bumps when a policy changes.
- MITRE ATT&CK IDs/names were checked on attack.mitre.org (v19.2) on 2026-10-05; they
  describe what the misconfiguration makes easier, not how to do it.
"""
from __future__ import annotations

CA_MFA_CONTROLS = {"mfa", "authenticationStrength"}


def upn(u) -> str:
    return u["userPrincipalName"]


def covers_all_users(p) -> bool:
    return "All" in p["includeUsers"]


def covers_all_apps(p) -> bool:
    return "All" in p["includeApplications"]


def requires_mfa(p) -> bool:
    return bool(CA_MFA_CONTROLS & set(p["grantControls"]))


def is_unconditional(p) -> bool:
    """A policy limited to risky sign-ins / users only applies when Identity Protection
    flags a risk: it is NOT a baseline MFA or blocking policy."""
    return not p["signInRiskLevels"] and not p["userRiskLevels"]


def is_mfa_all_users(p) -> bool:
    """Policy that requires MFA for all users, all cloud apps, every client type."""
    return (covers_all_users(p) and covers_all_apps(p) and requires_mfa(p)
            and "all" in p["clientAppTypes"] and is_unconditional(p))


def blocks_legacy(p) -> bool:
    """Policy that blocks the two legacy client types for all users and all apps."""
    return (covers_all_users(p) and covers_all_apps(p) and "block" in p["grantControls"]
            and {"exchangeActiveSync", "other"} <= set(p["clientAppTypes"])
            and is_unconditional(p))


def policy_targets_user(p, u, roles: set[str]) -> bool:
    """True if CA policy `p` applies to user `u` holding directory roles `roles`."""
    if upn(u).lower() in {x.lower() for x in p["excludeUsers"]}:
        return False
    if covers_all_users(p) or upn(u).lower() in {x.lower() for x in p["includeUsers"]}:
        return True
    return bool({r.lower() for r in roles} & {r.lower() for r in p["includeRoles"]})


def mfa_methods(u) -> set[str]:
    from ..model import MFA_METHODS
    return set(u["authMethods"]) & MFA_METHODS


def is_custom_domain(name: str) -> bool:
    return not name.lower().endswith(".onmicrosoft.com")
