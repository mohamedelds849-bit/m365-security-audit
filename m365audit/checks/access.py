"""Conditional Access, MFA and legacy authentication."""
from ..engine import Check, register
from . import (blocks_legacy, covers_all_apps, is_mfa_all_users, is_unconditional, mfa_methods,
               policy_targets_user, requires_mfa, upn)

VALID_ACCOUNTS = ("T1078.004", "Valid Accounts: Cloud Accounts")


@register
class NoBaselineProtection(Check):
    id = "M365-CA-001"
    title = "Aucune protection de base : security defaults désactivés et aucune stratégie d'accès conditionnel active"
    severity = "critical"
    category = "access"
    effort = "quick"
    why = ("Sans security defaults ni accès conditionnel, un simple mot de passe suffit pour "
           "ouvrir n'importe quel compte, administrateurs compris, depuis n'importe où. C'est "
           "la cause la plus fréquente des compromissions de messagerie dans les PME.")
    remediation = ("Activer immédiatement les security defaults (gratuit, toutes licences) OU, si "
                   "le tenant a Entra ID P1, créer des stratégies d'accès conditionnel (MFA pour "
                   "tous, blocage de l'authentification héritée) en mode rapport seul quelques "
                   "jours puis en mode activé. Les deux ne peuvent pas être actifs ensemble.")
    references = [
        "Microsoft Learn — Security defaults in Microsoft Entra ID",
        "Microsoft Learn — Plan a Conditional Access deployment",
        "SCuBA MS.AAD.3.2v2 — MFA SHALL be enforced for all users",
    ]
    license_note = "Security defaults : toutes licences. Accès conditionnel : Entra ID P1."
    mitre = [VALID_ACCOUNTS, ("T1110.003", "Brute Force: Password Spraying")]

    def evaluate(self, t, cfg):
        if t.securityDefaults["enabled"] or t.enabled_ca():
            return []
        ev = ["security defaults : désactivés ; stratégies d'accès conditionnel actives : 0"]
        for p in t.ca_policies:
            ev.append(f"stratégie '{p['displayName']}' en état '{p['state']}' (ne protège pas)")
        return ev


@register
class MfaNotForAllUsers(Check):
    id = "M365-CA-002"
    title = "MFA non imposée à tous les utilisateurs"
    severity = "high"
    category = "access"
    effort = "30d"
    why = ("Microsoft estime que la MFA bloque l'immense majorité des attaques automatisées sur "
           "les comptes. Sans MFA imposée à tous, un mot de passe hameçonné ou réutilisé ailleurs "
           "donne directement accès à la boîte mail et aux fichiers.")
    remediation = ("Créer une stratégie d'accès conditionnel 'Tous les utilisateurs / Toutes les "
                   "ressources / Exiger l'authentification multifacteur' en excluant uniquement "
                   "les comptes de secours (break-glass). Viser ensuite une MFA résistante à "
                   "l'hameçonnage (FIDO2, Windows Hello, passkeys).")
    references = [
        "CIS M365 Foundations — 'Ensure multifactor authentication is enabled for all users'",
        "SCuBA MS.AAD.3.2v2 — MFA SHALL be enforced for all users",
        "SCuBA MS.AAD.3.1v1 — Phishing-resistant MFA SHALL be enforced for all users",
    ]
    license_note = "Accès conditionnel : Entra ID P1 (sinon : security defaults)."
    mitre = [VALID_ACCOUNTS, ("T1110.003", "Brute Force: Password Spraying")]

    def evaluate(self, t, cfg):
        if t.securityDefaults["enabled"]:
            return []
        if any(is_mfa_all_users(p) for p in t.enabled_ca()):
            return []
        ev = ["aucune stratégie active 'Tous les utilisateurs + toutes les applications + MFA'"]
        partial = [p["displayName"] for p in t.enabled_ca() if requires_mfa(p) and is_unconditional(p)]
        if partial:
            ev.append("stratégies MFA partielles (périmètre réduit) : " + ", ".join(sorted(partial)))
        return ev


@register
class MfaNotForAdmins(Check):
    id = "M365-CA-003"
    title = "MFA non imposée (ou non enregistrée) pour des comptes à rôle privilégié"
    severity = "critical"
    category = "access"
    effort = "quick"
    why = ("Un administrateur sans MFA est la clé de tout le tenant : création de comptes, "
           "lecture de toutes les boîtes, désactivation des journaux. C'est la première "
           "cible des attaquants.")
    remediation = ("Imposer la MFA (idéalement résistante à l'hameçonnage) à tous les rôles "
                   "privilégiés par une stratégie d'accès conditionnel dédiée ; vérifier que chaque "
                   "administrateur a enregistré au moins une méthode forte.")
    references = [
        "CIS M365 Foundations — 'Ensure multifactor authentication is enabled for all users in administrative roles'",
        "SCuBA MS.AAD.3.6v1 — Phishing-resistant MFA SHALL be required for highly privileged roles",
        "Microsoft Learn — Require MFA for administrators (Conditional Access template)",
    ]
    license_note = "Accès conditionnel : Entra ID P1 (sinon : security defaults)."
    mitre = [VALID_ACCOUNTS]

    def evaluate(self, t, cfg):
        ev = []
        policies = [p for p in t.enabled_ca()
                    if requires_mfa(p) and covers_all_apps(p) and is_unconditional(p)]
        pmap = t.privileged_users(cfg["privileged_roles"], include_eligible=True)
        for name, roles in sorted(pmap.items()):
            u = t.user(name)
            if u["isBreakGlass"]:
                continue  # break-glass accounts are reviewed by M365-PRIV-004
            covered = t.securityDefaults["enabled"] or any(
                policy_targets_user(p, u, roles) for p in policies)
            if not covered:
                ev.append(f"{upn(u)} ({', '.join(sorted(roles))}) : aucune stratégie MFA ne s'applique")
            if not mfa_methods(u):
                ev.append(f"{upn(u)} : aucune méthode MFA enregistrée")
        return ev


@register
class LegacyAuthNotBlocked(Check):
    id = "M365-CA-004"
    title = "Authentification héritée (legacy) non bloquée"
    severity = "high"
    category = "access"
    effort = "quick"
    why = ("Les protocoles hérités (IMAP, POP3, SMTP AUTH, anciens clients Office) ne savent "
           "pas demander la MFA : un mot de passe seul suffit. Ils restent le canal préféré des "
           "attaques par pulvérisation de mots de passe, même quand la MFA est imposée ailleurs.")
    remediation = ("Créer une stratégie d'accès conditionnel 'Tous les utilisateurs / Toutes les "
                   "ressources / Applications clientes : Exchange ActiveSync + Autres clients / "
                   "Bloquer'. Avant : repérer les usages restants dans les journaux de connexion "
                   "(filtre 'Client app') et migrer les imprimantes / scanners vers une solution "
                   "moderne.")
    references = [
        "CIS M365 Foundations — 'Enable Conditional Access policies to block legacy authentication'",
        "SCuBA MS.AAD.1.1v1 — Legacy authentication SHALL be blocked",
        "Microsoft Learn — Block legacy authentication with Conditional Access",
    ]
    license_note = "Accès conditionnel : Entra ID P1 (security defaults bloquent aussi le legacy)."
    mitre = [VALID_ACCOUNTS, ("T1110.003", "Brute Force: Password Spraying")]

    def evaluate(self, t, cfg):
        if t.securityDefaults["enabled"]:
            return []
        if any(blocks_legacy(p) for p in t.enabled_ca()):
            return []
        ev = ["aucune stratégie active ne bloque les clients 'exchangeActiveSync' + 'other'"]
        ro = [p["displayName"] for p in t.ca_policies if blocks_legacy(p) and p["state"] != "enabled"]
        if ro:
            ev.append("stratégie de blocage présente mais non appliquée : " + ", ".join(sorted(ro)))
        return ev


@register
class RiskPoliciesMissing(Check):
    id = "M365-CA-005"
    title = "Pas de stratégie basée sur le risque (connexion / utilisateur) alors que la licence P2 est présente"
    severity = "medium"
    category = "access"
    effort = "30d"
    why = ("Entra ID Protection calcule un niveau de risque (identifiants divulgués, IP anonyme, "
           "voyage atypique...). Sans stratégie qui exige la MFA ou bloque quand le risque est "
           "élevé, ces signaux restent de simples lignes dans un rapport que personne ne lit.")
    remediation = ("Créer deux stratégies d'accès conditionnel : risque de connexion élevé -> "
                   "bloquer ou exiger la MFA ; risque utilisateur élevé -> bloquer ou exiger un "
                   "changement de mot de passe sécurisé. Tester d'abord en mode rapport seul.")
    references = [
        "SCuBA MS.AAD.2.3v1 — Sign-ins detected as high risk SHALL be blocked",
        "SCuBA MS.AAD.2.1v1 — Users detected as high risk SHALL be blocked",
        "CIS M365 Foundations — Identity Protection sign-in risk / user risk policy recommendations (titres variables selon la version)",
        "Microsoft Learn — Risk-based access policies (Microsoft Entra ID Protection)",
    ]
    license_note = ("Nécessite Entra ID P2 : contrôle évalué uniquement si tenant.entraIdP2 = true "
                    "(sinon ce n'est pas une mauvaise configuration mais une limite de licence).")
    mitre = [VALID_ACCOUNTS]

    def evaluate(self, t, cfg):
        if not t.tenant["entraIdP2"]:
            return []
        ev = []
        active = t.enabled_ca()
        if not any(p["signInRiskLevels"] for p in active):
            ev.append("aucune stratégie active sur le risque de connexion (signInRiskLevels)")
        if not any(p["userRiskLevels"] for p in active):
            ev.append("aucune stratégie active sur le risque utilisateur (userRiskLevels)")
        return ev


@register
class WeakenedCaPolicies(Check):
    id = "M365-CA-006"
    title = "Stratégies d'accès conditionnel affaiblies (exclusions larges, mode rapport seul)"
    severity = "medium"
    category = "access"
    effort = "30d"
    why = ("Une stratégie MFA qui exclut 'temporairement' des comptes, ou qui reste en mode "
           "rapport seul, donne une fausse impression de sécurité : les comptes exclus sont "
           "exactement ceux que l'attaquant visera.")
    remediation = ("Limiter les exclusions aux comptes de secours (break-glass) surveillés ; "
                   "remplacer les autres exclusions par un groupe revu chaque mois avec une date "
                   "de fin ; passer les stratégies validées du mode rapport seul au mode activé.")
    references = [
        "Microsoft Learn — Plan a Conditional Access deployment (exclusions, report-only mode)",
        "Microsoft Learn — Manage emergency access accounts in Microsoft Entra ID",
    ]
    license_note = "Accès conditionnel : Entra ID P1."
    # T1556.009 (an attacker MODIFYING CA policies) is a detection topic, not this weakness
    mitre = [VALID_ACCOUNTS]

    def evaluate(self, t, cfg):
        ev = []
        bg = {upn(u).lower() for u in t.break_glass()}
        mx = cfg["thresholds"]["max_ca_exclusions"]
        for p in sorted(t.ca_policies, key=lambda x: x["displayName"]):
            others = sorted(x for x in p["excludeUsers"] if x.lower() not in bg)
            if p["state"] == "enabled" and len(others) > mx:
                ev.append(f"'{p['displayName']}' exclut {len(others)} compte(s) hors break-glass "
                          f"(max {mx}) : " + ", ".join(others))
            if p["state"] == "enabledForReportingButNotEnforced" and (
                    requires_mfa(p) or "block" in p["grantControls"]):
                ev.append(f"'{p['displayName']}' est en mode rapport seul : elle n'applique rien")
        return ev
