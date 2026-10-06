"""Exchange Online, e-mail authentication, Teams and SharePoint sharing."""
from ..engine import Check, register
from . import is_custom_domain


@register
class ExternalAutoForwarding(Check):
    id = "M365-COL-001"
    title = "Transfert automatique vers l'extérieur autorisé"
    severity = "high"
    category = "collab"
    effort = "quick"
    why = ("Après avoir pris une boîte, l'attaquant crée une règle qui transfère discrètement "
           "les factures et les échanges avec la banque vers une adresse externe (fraude au "
           "virement / BEC). Bloquer le transfert externe casse ce scénario.")
    remediation = ("Mettre la stratégie anti-spam sortante sur AutoForwardingMode = Off (ou "
                   "Automatic, qui vaut aujourd'hui Off) et autoriser uniquement les exceptions "
                   "documentées via une stratégie dédiée à quelques boîtes.")
    references = [
        "CIS M365 Foundations — 'Ensure all forms of mail forwarding are blocked and/or disabled'",
        "SCuBA MS.EXO.1.1v2 — Automatic forwarding to external domains SHALL be disabled",
        "Microsoft Learn — Control automatic external email forwarding in Microsoft 365",
    ]
    mitre = [("T1114.003", "Email Collection: Email Forwarding Rule")]

    def evaluate(self, t, cfg):
        ex = t.exchange
        if ex["autoForwardingMode"] != "On":
            return []
        ev = ["stratégie anti-spam sortante : AutoForwardingMode = On"]
        if ex["remoteDomainAutoForward"]:
            ev.append("domaine distant '*' : AutoForwardEnabled = True (aucun second verrou)")
        return ev


@register
class EmailAuthentication(Check):
    id = "M365-COL-002"
    title = "Domaine personnalisé sans DKIM, DMARC appliqué ou SPF strict"
    severity = "high"
    category = "collab"
    effort = "30d"
    why = ("Sans SPF, DKIM et DMARC en mode quarantine/reject, n'importe qui peut envoyer un "
           "e-mail qui semble venir de @agrisouss.ma : faux ordre de virement au comptable, "
           "fausse facture au client. DMARC 'p=none' observe mais ne protège pas.")
    remediation = ("Publier un SPF qui se termine par -all (ou ~all transitoire), activer la "
                   "signature DKIM dans Defender (2 CNAME selector1/selector2), publier DMARC "
                   "p=none avec rapports, analyser 2-4 semaines, puis passer en quarantine puis "
                   "reject.")
    references = [
        "CIS M365 Foundations — 'Ensure DKIM is enabled for all Exchange Online Domains'",
        "CIS M365 Foundations — 'Ensure DMARC Records for all Exchange Online domains are published'",
        "CIS M365 Foundations — 'Ensure SPF records are published for all Exchange Domains'",
        "SCuBA MS.EXO.2.2v3 (SPF), MS.EXO.3.1v1 (DKIM), MS.EXO.4.1v1 / MS.EXO.4.2v1 (DMARC p=reject)",
    ]
    # T1684.002 = ATT&CK v19 ID of the former T1672 "Email Spoofing" (checked 2026-10-06).
    # T1534 Internal Spearphishing is NOT used here: it needs a compromised internal mailbox,
    # which SPF/DKIM/DMARC do not prevent.
    mitre = [("T1566", "Phishing"), ("T1684.002", "Social Engineering: Email Spoofing")]

    def evaluate(self, t, cfg):
        ev = []
        for d in sorted(t.domains, key=lambda x: x["name"].lower()):
            if not is_custom_domain(d["name"]):
                continue
            name = d["name"]
            spf = d["spfRecord"].strip().lower()
            if not spf:
                ev.append(f"{name} : aucun enregistrement SPF")
            elif spf.endswith("+all") or spf.endswith("?all") or not spf.endswith("all"):
                ev.append(f"{name} : SPF non strict ({d['spfRecord']})")
            if not d["dkimEnabled"]:
                ev.append(f"{name} : signature DKIM désactivée")
            if d["dmarcPolicy"] is None:
                ev.append(f"{name} : aucun enregistrement DMARC")
            elif d["dmarcPolicy"] == "none":
                ev.append(f"{name} : DMARC p=none (surveillance seulement)")
        return ev


@register
class TeamsExternalAccessOpen(Check):
    id = "M365-COL-003"
    title = "Teams : accès externe ouvert à tous les domaines ou aux comptes Teams personnels"
    severity = "medium"
    category = "collab"
    effort = "quick"
    why = ("Des campagnes réelles ont utilisé des messages Teams depuis des tenants externes "
           "(faux 'support informatique') pour distribuer des liens malveillants ou obtenir un "
           "accès à distance. Ouvrir Teams à tous les domaines élargit cette surface.")
    remediation = ("Passer l'accès externe en liste d'autorisation (domaines des partenaires "
                   "réels), désactiver la communication avec les comptes Teams non gérés "
                   "(personnels), sensibiliser au 'faux support Teams'.")
    references = [
        "SCuBA MS.TEAMS.2.1v2 — External access SHALL only be enabled on a per-domain basis",
        "SCuBA MS.TEAMS.2.2v2 — Unmanaged users SHALL NOT be enabled to initiate contact",
        "CIS M365 Foundations — Teams external access / unmanaged users recommendations (titres variables selon la version)",
    ]
    mitre = [("T1566.003", "Phishing: Spearphishing via Service")]

    def evaluate(self, t, cfg):
        tm, ev = t.teams, []
        if tm["externalAccess"] == "allowAll":
            ev.append("accès externe : tous les domaines externes autorisés")
        if tm["consumerAccess"]:
            ev.append("communication avec les comptes Teams personnels (non gérés) autorisée")
        return ev


@register
class SharePointAnyoneLinks(Check):
    id = "M365-COL-004"
    title = "SharePoint / OneDrive : liens 'Tout le monde' (anonymes) sans limite suffisante"
    severity = "medium"
    category = "collab"
    effort = "quick"
    why = ("Un lien 'Tout le monde' donne accès au fichier à quiconque le possède, sans "
           "connexion ni trace d'identité. Transféré, indexé ou laissé dans un vieil e-mail, il "
           "expose les tarifs, contrats ou fichiers RH pour toujours s'il n'expire pas.")
    remediation = ("Limiter le partage externe à 'Invités existants' ou 'Nouveaux et existants "
                   "invités' ; si les liens anonymes restent nécessaires, imposer une expiration "
                   "<= 30 jours, des liens en lecture seule et un type de lien par défaut "
                   "'Personnes spécifiques'.")
    references = [
        "SCuBA MS.SHAREPOINT.1.1v1 — External sharing limited to Existing guests or Only people in your organization",
        "SCuBA MS.SHAREPOINT.2.1v1 — default sharing scope 'Specific people'",
        "SCuBA MS.SHAREPOINT.3.1v1 — Expiration days for Anyone links SHALL be 30 days or less",
        "CIS M365 Foundations — 'Ensure external content sharing is restricted' / 'Ensure link sharing is restricted in SharePoint and OneDrive'",
    ]
    mitre = [("T1530", "Data from Cloud Storage"), ("T1213.002", "Data from Information Repositories: Sharepoint")]

    def evaluate(self, t, cfg):
        sp = t.sharepoint
        if sp["sharingCapability"] != "ExternalUserAndGuestSharing":
            return []
        ev, mx = [], cfg["thresholds"]["anyone_link_max_days"]
        days = sp["anyoneLinkExpirationDays"]
        if days == 0:
            ev.append("liens 'Tout le monde' autorisés sans expiration")
        elif days > mx:
            ev.append(f"liens 'Tout le monde' : expiration {days} j (attendu <= {mx})")
        if sp["defaultSharingLinkType"] == "AnonymousAccess":
            ev.append("type de lien par défaut = 'Tout le monde' (AnonymousAccess)")
        return ev
