"""Audit logging: unified audit log and mailbox auditing."""
from ..engine import Check, register

CLOUD_LOG = ("T1685.002", "Disable or Modify Tools: Disable or Modify Cloud Log")
# Note: in ATT&CK v19 the former T1562.008 page redirects to T1685.002 (checked 2026-10-05).


@register
class UnifiedAuditLogDisabled(Check):
    id = "M365-LOG-001"
    title = "Journal d'audit unifié (Unified Audit Log) désactivé"
    severity = "high"
    category = "logging"
    effort = "quick"
    why = ("Sans journal d'audit unifié, impossible de savoir après un incident qui a créé une "
           "règle de transfert, qui a consenti à une application ou qui a téléchargé des "
           "fichiers. L'enquête et l'obligation de notification deviennent impossibles.")
    remediation = ("Activer la recherche dans le journal d'audit (portail Purview > Audit, ou "
                   "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true) et exporter "
                   "les journaux vers un SIEM si la rétention par défaut est trop courte.")
    references = [
        "CIS M365 Foundations — 'Ensure Microsoft 365 audit log search is Enabled'",
        "SCuBA MS.DEFENDER.6.1v1 — Unified Audit logging SHALL be enabled",
        "Microsoft Learn — Turn auditing on or off (Microsoft Purview)",
    ]
    mitre = [CLOUD_LOG]

    def evaluate(self, t, cfg):
        if not t.audit["unifiedAuditLogEnabled"]:
            return ["UnifiedAuditLogIngestionEnabled = false"]
        return []


@register
class MailboxAuditingOff(Check):
    id = "M365-LOG-002"
    title = "Audit des boîtes aux lettres désactivé ou contourné"
    severity = "medium"
    category = "logging"
    effort = "quick"
    why = ("L'audit des boîtes enregistre les accès (MailItemsAccessed, Send, règles...). C'est "
           "la seule façon de dire quels e-mails ont été lus lors d'une compromission (BEC). "
           "Il est activé par défaut depuis 2019 (« mailbox auditing on by default ») : "
           "AuditDisabled = True ou une boîte en 'AuditBypass' (invisible) est donc un choix "
           "délibéré, à justifier ou à annuler.")
    remediation = ("Remettre AuditDisabled = False au niveau de l'organisation "
                   "(Set-OrganizationConfig) et retirer le contournement "
                   "(Set-MailboxAuditBypassAssociation -AuditBypassEnabled $false) ; vérifier les "
                   "actions auditées par défaut.")
    references = [
        "CIS M365 Foundations — 'Ensure AuditDisabled organizationally is set to False'",
        "CIS M365 Foundations — 'Ensure AuditBypassEnabled is not enabled on mailboxes'",
        "SCuBA MS.EXO.13.1v1 — Mailbox auditing SHALL be enabled",
    ]
    mitre = [CLOUD_LOG]

    def evaluate(self, t, cfg):
        ev = []
        if not t.audit["mailboxAuditByDefault"]:
            ev.append("audit des boîtes désactivé au niveau de l'organisation (AuditDisabled = True)")
        for mbx in sorted(t.audit["auditBypassMailboxes"], key=str.lower):
            ev.append(f"{mbx} : AuditBypassEnabled = True")
        return ev
