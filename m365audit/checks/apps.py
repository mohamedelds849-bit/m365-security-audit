"""OAuth applications: user consent, app registration, high-privilege permissions."""
from ..engine import Check, register

STEAL_TOKEN = ("T1528", "Steal Application Access Token")
APP_TOKEN = ("T1550.001", "Use Alternate Authentication Material: Application Access Token")


@register
class UserConsentAllowed(Check):
    id = "M365-APP-001"
    title = "Les utilisateurs peuvent consentir seuls à n'importe quelle application"
    severity = "high"
    category = "apps"
    effort = "quick"
    why = ("Le 'consent phishing' consiste à faire cliquer 'Accepter' sur une fausse application "
           "qui demande l'accès à la messagerie. Le jeton OAuth obtenu continue de fonctionner "
           "après un changement de mot de passe et contourne la MFA.")
    remediation = ("Mettre le consentement utilisateur sur 'Ne pas autoriser' ou 'éditeurs "
                   "vérifiés, permissions à faible risque', et activer le workflow de demande de "
                   "consentement administrateur (admin consent workflow).")
    references = [
        "CIS M365 Foundations — 'Ensure User consent for applications is set to Do not allow user consent'",
        "SCuBA MS.AAD.5.2v1 — User consent to applications SHALL be restricted",
        "SCuBA MS.AAD.5.3v1 — An admin consent workflow SHALL be configured",
        "Microsoft Learn — Configure how users consent to applications",
    ]
    mitre = [STEAL_TOKEN]

    def evaluate(self, t, cfg):
        if t.authorizationPolicy["userConsent"] == "allowAll":
            return ["consentement utilisateur autorisé pour toutes les applications (allowAll)"]
        return []


@register
class HighPrivilegeApps(Check):
    id = "M365-APP-002"
    title = "Applications tierces avec permissions à haut privilège non vérifiées ou consenties par un utilisateur"
    severity = "high"
    category = "apps"
    effort = "30d"
    why = ("Une application avec Mail.ReadWrite ou Directory.ReadWrite.All est un compte de "
           "service invisible : elle lit ou modifie les données sans connexion interactive, sans "
           "MFA, souvent sans que personne ne se souvienne de l'avoir autorisée.")
    remediation = ("Pour chaque application listée : identifier le propriétaire métier, vérifier "
                   "l'éditeur, retirer les permissions non nécessaires ou supprimer le "
                   "consentement (Entra > Applications d'entreprise > Autorisations). Préférer des "
                   "permissions limitées (ex. Mail.Read sur une boîte via RBAC for Applications).")
    references = [
        "Microsoft Learn — Investigate and remediate risky OAuth apps / Review permissions granted to enterprise applications",
        "Microsoft Learn — Detect and remediate illicit consent grants",
        "SCuBA MS.AAD.5.2v1 — User consent to applications SHALL be restricted",
    ]
    mitre = [STEAL_TOKEN, APP_TOKEN]

    def evaluate(self, t, cfg):
        high = {p.lower() for p in cfg["high_privilege_permissions"]}
        ev = []
        for app in sorted(t.applications, key=lambda a: a["displayName"].lower()):
            if app["isMicrosoftFirstParty"]:
                continue
            risky = sorted({p["name"] for p in app["permissions"] if p["name"].lower() in high})
            if not risky:
                continue
            user_consented = any(p["consentType"] == "Principal" for p in app["permissions"]
                                 if p["name"].lower() in high)
            if app["publisherVerified"] and not user_consented:
                continue  # verified publisher + admin consent = reviewed decision
            why = []
            if not app["publisherVerified"]:
                why.append("éditeur non vérifié")
            if user_consented:
                why.append(f"consenti par un utilisateur ({app['consentedBy'] or 'inconnu'})")
            ev.append(f"'{app['displayName']}' ({app['appId']}) : {', '.join(risky)} — "
                      + ", ".join(why))
        return ev


@register
class UsersCanRegisterApps(Check):
    id = "M365-APP-003"
    title = "Tous les utilisateurs peuvent enregistrer des applications"
    severity = "medium"
    category = "apps"
    effort = "quick"
    why = ("Un utilisateur (ou un attaquant qui a son mot de passe) peut créer une application "
           "dans le tenant, lui ajouter un secret et s'en servir comme porte dérobée persistante, "
           "qui apparaît comme une application 'interne' digne de confiance.")
    remediation = ("Désactiver 'Les utilisateurs peuvent inscrire des applications' et attribuer "
                   "le rôle Application Developer aux seules personnes qui en ont besoin.")
    references = [
        "CIS M365 Foundations — 'Ensure third party integrated applications are not allowed'",
        "SCuBA MS.AAD.5.1v1 — Only administrators SHALL be allowed to register applications",
    ]
    mitre = [("T1098.001", "Account Manipulation: Additional Cloud Credentials")]

    def evaluate(self, t, cfg):
        if t.authorizationPolicy["usersCanRegisterApps"]:
            return ["usersCanRegisterApps = true (paramètre par défaut d'un nouveau tenant)"]
        return []
