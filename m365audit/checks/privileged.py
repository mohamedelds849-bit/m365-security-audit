"""Privileged directory roles, PIM and emergency access (break-glass) accounts."""
from ..engine import Check, register
from . import upn

GA = "Global Administrator"
ADD_ROLES = ("T1098.003", "Account Manipulation: Additional Cloud Roles")
VALID_ACCOUNTS = ("T1078.004", "Valid Accounts: Cloud Accounts")


@register
class GlobalAdminCount(Check):
    id = "M365-PRIV-001"
    title = "Nombre d'administrateurs généraux (Global Administrator) hors de la plage recommandée"
    severity = "high"
    category = "privileged"
    effort = "30d"
    why = ("Global Administrator peut tout faire dans le tenant. Trop de titulaires multiplie "
           "les comptes dont la compromission est fatale ; un seul titulaire crée un risque de "
           "blocage total s'il est perdu (départ, MFA perdue).")
    remediation = ("Garder 2 à 4 Global Administrators (dont les comptes de secours). Donner aux "
                   "autres des rôles plus fins : Exchange Administrator, User Administrator, "
                   "Helpdesk Administrator...")
    references = [
        "CIS M365 Foundations — 'Ensure that between two and four global admins are designated'",
        "SCuBA MS.AAD.7.1v1 — between two and eight Global Administrators (SCuBA est plus permissif que CIS)",
        "SCuBA MS.AAD.7.2v1 — finer-grained roles instead of Global Administrator",
    ]
    mitre = [VALID_ACCOUNTS, ADD_ROLES]

    def evaluate(self, t, cfg):
        th = cfg["thresholds"]
        gas = sorted(upn(t.user(n)) for n in t.privileged_users([GA], include_eligible=True))
        if th["min_global_admins"] <= len(gas) <= th["max_global_admins"]:
            return []
        return [f"{len(gas)} Global Administrator(s) actif(s) ou éligible(s) (attendu "
                f"{th['min_global_admins']}-{th['max_global_admins']}) : " + (", ".join(gas) or "aucun")]


@register
class PermanentPrivilegedAssignments(Check):
    id = "M365-PRIV-002"
    title = "Rôles privilégiés attribués de façon permanente (pas de PIM / juste-à-temps)"
    severity = "high"
    category = "privileged"
    effort = "90d"
    why = ("Une attribution 'active permanente' signifie que le compte est administrateur 24 h/24, "
           "même quand personne n'administre. Avec Privileged Identity Management (PIM), le rôle "
           "est 'éligible' et activé pour quelques heures, avec justification et MFA : la fenêtre "
           "d'exposition chute fortement.")
    remediation = ("Convertir les attributions actives permanentes en attributions éligibles PIM "
                   "(activation limitée dans le temps, MFA, approbation pour Global Administrator). "
                   "Seuls les comptes de secours restent actifs en permanence.")
    references = [
        "CIS M365 Foundations — 'Ensure Privileged Identity Management is used to manage roles'",
        "SCuBA MS.AAD.7.4v1 — Permanent active role assignments SHALL NOT be allowed for highly privileged roles",
        "SCuBA MS.AAD.7.6v1 — Activation of the Global Administrator role SHALL require approval",
    ]
    license_note = "PIM nécessite Entra ID P2 (ou Entra ID Governance)."
    mitre = [VALID_ACCOUNTS]

    def evaluate(self, t, cfg):
        ev = []
        for a in sorted(t.privileged_assignments(cfg["privileged_roles"]),
                        key=lambda x: (x["roleName"], x["principal"].lower())):
            if a["endDateTime"] is not None:
                continue
            u = t.user(a["principal"]) if a["principalType"] == "user" else None
            if u is not None and (u["isBreakGlass"] or not u["accountEnabled"]):
                continue
            ev.append(f"{a['principal']} : '{a['roleName']}' actif sans date de fin")
        if ev and not t.tenant["entraIdP2"]:
            ev.append("licence Entra ID P2 absente : PIM indisponible, réduire au minimum le "
                      "nombre d'attributions et les revoir chaque mois")
        return ev


@register
class AdminAccountsNotDedicated(Check):
    id = "M365-PRIV-003"
    title = "Comptes administrateurs non dédiés (boîte mail, licences, synchronisés depuis l'AD local)"
    severity = "medium"
    category = "privileged"
    effort = "30d"
    why = ("Un compte admin qui lit ses e-mails et navigue sur le web est exposé à l'hameçonnage. "
           "Un compte admin synchronisé depuis l'AD local permet à une compromission de l'AD de "
           "se propager au cloud.")
    remediation = ("Créer pour chaque administrateur un compte cloud-only séparé "
                   "(ex. adm.prenom@tenant.onmicrosoft.com), sans boîte mail ni licence "
                   "bureautique, utilisé uniquement pour l'administration.")
    references = [
        "CIS M365 Foundations — 'Ensure Administrative accounts are cloud-only'",
        "CIS M365 Foundations — 'Ensure administrative accounts use licenses with a reduced application footprint'",
        "SCuBA MS.AAD.7.3v1 — Privileged users SHALL be provisioned cloud-only accounts",
    ]
    mitre = [VALID_ACCOUNTS, ("T1566", "Phishing")]

    def evaluate(self, t, cfg):
        ev = []
        pmap = t.privileged_users(cfg["privileged_roles"], include_eligible=True)
        for name, roles in sorted(pmap.items()):
            u = t.user(name)
            if u["isBreakGlass"]:
                continue
            issues = []
            if u["hasMailbox"]:
                issues.append("boîte mail")
            if u["assignedLicenses"]:
                issues.append("licences " + ", ".join(sorted(u["assignedLicenses"])))
            if u["onPremisesSyncEnabled"]:
                issues.append("synchronisé depuis l'AD local")
            if issues:
                ev.append(f"{upn(u)} ({', '.join(sorted(roles))}) : " + " ; ".join(issues))
        return ev


@register
class BreakGlassAccounts(Check):
    id = "M365-PRIV-004"
    title = "Comptes d'accès d'urgence (break-glass) absents, incomplets ou non surveillés"
    severity = "high"
    category = "privileged"
    effort = "30d"
    why = ("Si la MFA tombe en panne ou si un administrateur se bloque avec une stratégie "
           "d'accès conditionnel, seuls des comptes de secours permettent de reprendre la main. "
           "Comme ils sont exclus de certaines protections, toute connexion avec eux doit "
           "déclencher une alerte.")
    remediation = ("Créer 2 comptes cloud-only (domaine .onmicrosoft.com) Global Administrator "
                   "permanents, avec une méthode résistante à l'hameçonnage (clé FIDO2) gardée au "
                   "coffre, exclus uniquement des stratégies qui pourraient bloquer l'accès, et une "
                   "alerte (Azure Monitor / Sentinel) sur chacune de leurs connexions.")
    references = [
        "Microsoft Learn — Manage emergency access accounts in Microsoft Entra ID",
        "CIS M365 Foundations — 'Ensure two emergency access accounts have been defined'",
    ]
    mitre = [VALID_ACCOUNTS]

    def evaluate(self, t, cfg):
        bg = [u for u in t.break_glass() if u["accountEnabled"]]
        ev = []
        if len(bg) < 2:
            ev.append(f"{len(bg)} compte(s) break-glass actif(s) déclaré(s) (attendu : 2)")
        gas = t.privileged_users([GA])
        for u in sorted(bg, key=upn):
            if upn(u).lower() not in gas:
                ev.append(f"{upn(u)} : n'est pas Global Administrator actif")
            if u["onPremisesSyncEnabled"]:
                ev.append(f"{upn(u)} : synchronisé depuis l'AD local (doit être cloud-only)")
        if bg and not t.monitoring["breakGlassSignInAlert"]:
            ev.append("aucune alerte configurée sur les connexions des comptes break-glass")
        return ev
