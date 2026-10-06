"""User accounts, guests, MFA registration, SSPR and password expiration."""
from ..engine import Check, register
from . import mfa_methods, upn

VALID_ACCOUNTS = ("T1078.004", "Valid Accounts: Cloud Accounts")


@register
class GuestAccessPermissive(Check):
    id = "M365-ACC-001"
    title = "Accès invités trop permissif (droits d'un membre, invitations par tous)"
    severity = "medium"
    category = "accounts"
    effort = "quick"
    why = ("Un invité avec les mêmes droits qu'un membre peut lister tout l'annuaire (noms, "
           "groupes, rôles) : une carte idéale pour préparer un hameçonnage ciblé. Si tout le "
           "monde peut inviter, des comptes externes non contrôlés s'accumulent.")
    remediation = ("Mettre l'accès invité sur 'accès limité' (défaut) ou 'restreint' et réserver "
                   "les invitations aux administrateurs et au rôle Guest Inviter ; revoir les "
                   "invités avec des Access Reviews si la licence le permet.")
    references = [
        "CIS M365 Foundations — 'Ensure that guest user access is restricted'",
        "CIS M365 Foundations — 'Ensure that guest user invitations are limited to the Guest Inviter role'",
        "SCuBA MS.AAD.8.1v1 / MS.AAD.8.2v1 — guest access limited, only Guest Inviter can invite",
    ]
    mitre = [("T1199", "Trusted Relationship"), ("T1087.004", "Account Discovery: Cloud Account")]

    def evaluate(self, t, cfg):
        a, ev = t.authorizationPolicy, []
        if a["guestUserAccess"] == "sameAsMember":
            ev.append("accès invités = mêmes droits que les membres (sameAsMember)")
        if a["allowInvitesFrom"] in ("everyone", "adminsGuestInvitersAndAllMembers"):
            ev.append(f"invitations autorisées pour : {a['allowInvitesFrom']}")
        return ev


@register
class StaleAccounts(Check):
    id = "M365-ACC-002"
    title = "Comptes actifs inutilisés (membres et invités)"
    severity = "medium"
    category = "accounts"
    effort = "quick"
    why = ("Un compte que personne n'utilise n'est surveillé par personne : son mot de passe "
           "peut fuiter ou être deviné sans que son titulaire ne remarque rien. Les anciens "
           "stagiaires et partenaires sont des cibles classiques.")
    remediation = ("Désactiver les comptes sans connexion depuis le seuil configuré (90 jours par "
                   "défaut), après validation du manager, puis les supprimer après 30 jours. "
                   "Mettre en place une revue d'accès trimestrielle des invités.")
    references = [
        "Microsoft Learn — How to manage inactive user accounts (signInActivity)",
        "CIS M365 Foundations — guest access review recommendations (titres variables selon la version)",
    ]
    mitre = [VALID_ACCOUNTS]

    def evaluate(self, t, cfg):
        th, ev = cfg["thresholds"], []
        for u in sorted(t.users, key=upn):
            if not u["accountEnabled"] or u["isBreakGlass"]:
                continue  # break-glass accounts are expected to be unused (M365-PRIV-004)
            limit = th["stale_guest_days"] if u["userType"] == "Guest" else th["stale_days"]
            last = t.age_days(u["lastSignInDateTime"])
            created = t.age_days(u["createdDateTime"])
            kind = "invité" if u["userType"] == "Guest" else "membre"
            if last is None:
                if created is not None and created > limit:
                    ev.append(f"{upn(u)} ({kind}) : jamais connecté, créé il y a {created} j")
            elif last > limit:
                ev.append(f"{upn(u)} ({kind}) : dernière connexion il y a {last} j (> {limit})")
        return ev


@register
class SsprWeak(Check):
    id = "M365-ACC-003"
    title = "Réinitialisation de mot de passe en libre-service (SSPR) avec une seule méthode ou des méthodes faibles"
    severity = "medium"
    category = "accounts"
    effort = "quick"
    why = ("Le SSPR est une porte d'entrée : si une seule méthode suffit (ou des questions "
           "secrètes), un attaquant qui contrôle l'e-mail personnel ou le numéro de téléphone "
           "(SIM swapping) peut réinitialiser le mot de passe sans connaître l'ancien.")
    remediation = ("Exiger 2 méthodes pour réinitialiser, retirer les questions de sécurité, et "
                   "utiliser l'inscription combinée MFA/SSPR pour que les méthodes enregistrées "
                   "soient protégées par la MFA.")
    references = [
        "CIS M365 Foundations — 'Ensure the number of methods required to reset is set to 2' (présent dans les versions antérieures)",
        "Microsoft Learn — Plan a Microsoft Entra self-service password reset deployment",
        "Microsoft Learn — Combined security information registration",
    ]
    mitre = [VALID_ACCOUNTS]

    def evaluate(self, t, cfg):
        s, ev = t.sspr, []
        if s["enabled"] == "none":
            return []
        mn = cfg["thresholds"]["min_sspr_methods"]
        if s["methodsRequired"] < mn:
            ev.append(f"{s['methodsRequired']} méthode(s) exigée(s) pour réinitialiser (attendu >= {mn})")
        if "securityQuestions" in s["methods"]:
            ev.append("questions de sécurité autorisées comme méthode SSPR")
        return ev


@register
class PasswordExpiration(Check):
    id = "M365-ACC-004"
    title = "Expiration périodique des mots de passe activée (contraire aux recommandations NIST / Microsoft actuelles)"
    severity = "low"
    category = "accounts"
    effort = "quick"
    why = ("NIST SP 800-63B et Microsoft déconseillent les changements forcés périodiques : les "
           "utilisateurs choisissent alors des variantes prévisibles (Agadir2026! -> Agadir2027!). "
           "Nuance : cela ne vaut QUE si la MFA est imposée, que les mots de passe interdits / "
           "divulgués sont filtrés, et qu'on force le changement en cas de suspicion de fuite. "
           "Une politique d'entreprise ou un audit de conformité peut encore exiger l'expiration.")
    remediation = ("Passer la stratégie d'expiration à 'jamais' APRÈS avoir imposé la MFA et "
                   "activé la protection par mot de passe Entra (liste globale + liste "
                   "personnalisée : AgriSouss, Agadir, Souss...). Documenter la décision si la "
                   "politique interne exige encore une expiration.")
    references = [
        "NIST SP 800-63B — Memorized secret verifiers (no periodic change without evidence of compromise)",
        "CIS M365 Foundations — 'Ensure the Password expiration policy is set to Set passwords to never expire (recommended)'",
        "SCuBA MS.AAD.6.1v1 — User passwords SHALL NOT expire",
        "Microsoft Learn — Password policy recommendations for Microsoft 365",
    ]
    mitre = [("T1110.001", "Brute Force: Password Guessing")]

    def evaluate(self, t, cfg):
        days = t.passwordPolicy["expirationDays"]
        if days <= cfg["thresholds"]["password_expiration_ok_days"]:
            return []
        return [f"les mots de passe expirent tous les {days} jours"]


@register
class UsersWithoutStrongMfa(Check):
    id = "M365-ACC-005"
    title = "Utilisateurs sans méthode MFA enregistrée ou uniquement SMS / appel vocal"
    severity = "medium"
    category = "accounts"
    effort = "30d"
    why = ("Une stratégie MFA ne sert à rien tant que l'utilisateur n'a rien enregistré : le "
           "premier qui saisit son mot de passe peut enregistrer SA méthode. Le SMS et l'appel "
           "sont mieux que rien mais vulnérables au SIM swapping et au relais d'hameçonnage.")
    remediation = ("Lancer une campagne d'enregistrement (registration campaign) vers Microsoft "
                   "Authenticator avec correspondance de nombre, puis vers des méthodes "
                   "résistantes à l'hameçonnage ; restreindre l'enregistrement aux emplacements "
                   "de confiance.")
    references = [
        "SCuBA MS.AAD.3.5v2 — SMS, Voice Call and Email OTP SHALL be disabled",
        "Microsoft Learn — Authentication methods activity / User registration details report",
        "Microsoft Learn — How to run a registration campaign to set up Microsoft Authenticator",
    ]
    mitre = [VALID_ACCOUNTS, ("T1621", "Multi-Factor Authentication Request Generation")]

    def evaluate(self, t, cfg):
        weak = set(cfg["weak_auth_methods"])
        ev = []
        for u in sorted(t.users, key=upn):
            if not u["accountEnabled"] or u["userType"] != "Member":
                continue
            methods = mfa_methods(u)
            if not methods:
                ev.append(f"{upn(u)} : aucune méthode MFA enregistrée")
            elif methods <= weak:
                ev.append(f"{upn(u)} : uniquement {', '.join(sorted(methods))}")
        return ev
