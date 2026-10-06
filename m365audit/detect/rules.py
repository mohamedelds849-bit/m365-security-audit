"""Offline detections on Entra ID sign-in logs and Exchange / Entra ID audit events.

Each detection is a small class with metadata (ATT&CK mapping, link to its KQL equivalent in
docs/KQL.md, triage advice) and a `run()` method that returns `Alert`s. Thresholds come from
the `detections` section of config/default.yaml. These rules are teaching-grade heuristics on
synthetic data: docs/DETECTIONS.md lists their blind spots and false-positive sources.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import timedelta

from .model import RESULT_BAD_PASSWORD, RESULT_LOCKED, RESULT_MFA_FAILED, RESULT_SUCCESS

VALID_CLOUD = ("T1078.004", "Valid Accounts: Cloud Accounts")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FORWARD_PARAMS = ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress",
                  "ForwardingAddress")
HIDING_PARAMS = ("DeleteMessage", "MarkAsRead", "MoveToFolder", "StopProcessingRules")


@dataclass
class Alert:
    rule: str
    title: str
    severity: str
    time: str
    user: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    mitre: list[dict] = field(default_factory=list)
    kql: str = ""
    triage: str = ""

    def to_dict(self) -> dict:
        return {"rule": self.rule, "title": self.title, "severity": self.severity,
                "time": self.time, "user": self.user, "summary": self.summary,
                "evidence": self.evidence, "mitre": self.mitre, "kql": self.kql,
                "triage": self.triage}


def ts(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Detection:
    id = ""
    title = ""
    severity = "high"
    mitre: list[tuple[str, str]] = []
    kql = ""        # anchor in docs/KQL.md
    triage = ""     # first defensive response steps

    def alert(self, time, user, summary, evidence, severity=None) -> Alert:
        return Alert(self.id, self.title, severity or self.severity, ts(time), user, summary,
                     evidence, [{"id": i, "name": n} for i, n in self.mitre], self.kql, self.triage)

    def run(self, signins, audit, cfg) -> list[Alert]:  # pragma: no cover - interface
        raise NotImplementedError


def _group(events, key):
    out: dict[str, list] = {}
    for ev in events:
        out.setdefault(ev[key].lower(), []).append(ev)
    return out


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


# --------------------------------------------------------------------------- DET-001
class PasswordSpray(Detection):
    id = "DET-001"
    title = "Pulvérisation de mots de passe (password spray) depuis une seule IP"
    severity = "high"
    mitre = [("T1110.003", "Brute Force: Password Spraying"), VALID_CLOUD]
    kql = "det-001-password-spray"
    triage = ("Bloquer l'IP (emplacement nommé + accès conditionnel), vérifier si un des comptes "
              "visés a une connexion réussie depuis cette IP, réinitialiser ces mots de passe, "
              "confirmer que l'authentification héritée est bloquée.")

    def run(self, signins, audit, cfg):
        c = cfg["detections"]
        window = timedelta(minutes=c["spray_window_minutes"])
        alerts = []
        failures = [s for s in signins if s["resultType"] in (RESULT_BAD_PASSWORD, RESULT_LOCKED)]
        for ip, evs in sorted(_group(failures, "ipAddress").items()):
            start = 0
            for end in range(len(evs)):  # sliding window [start, end] of at most `window`
                while evs[end]["time"] - evs[start]["time"] > window:
                    start += 1
                users = {e["userPrincipalName"].lower() for e in evs[start:end + 1]}
                if len(users) >= c["spray_min_users"]:
                    # report the whole burst: every failure still inside the window
                    while end + 1 < len(evs) and evs[end + 1]["time"] - evs[start]["time"] <= window:
                        end += 1
                    users = {e["userPrincipalName"].lower() for e in evs[start:end + 1]}
                    first, last = evs[start]["time"], evs[end]["time"]
                    later = sorted({s["userPrincipalName"] for s in signins
                                    if s["ipAddress"].lower() == ip and s["resultType"] == RESULT_SUCCESS
                                    and s["time"] >= first})
                    ev = [f"IP {evs[start]['ipAddress']} ({evs[start]['country'] or '?'}) : "
                          f"{end - start + 1} échecs sur {len(users)} comptes distincts",
                          f"fenêtre {ts(first)} -> {ts(last)}",
                          "clients : " + ", ".join(sorted({e['clientAppUsed'] or '?' for e in evs[start:end + 1]}))]
                    if later:
                        ev.append("CONNEXION RÉUSSIE ensuite depuis la même IP : " + ", ".join(later))
                    alerts.append(self.alert(first, f"{len(users)} comptes",
                                             f"Spray depuis {evs[start]['ipAddress']}", ev))
                    break  # one alert per source IP
        return alerts


# --------------------------------------------------------------------------- DET-002
class MfaFatigue(Detection):
    id = "DET-002"
    title = "Fatigue MFA : rafale de refus MFA puis connexion réussie"
    severity = "high"
    mitre = [("T1621", "Multi-Factor Authentication Request Generation"), VALID_CLOUD]
    kql = "det-002-mfa-fatigue"
    triage = ("Appeler l'utilisateur par un canal connu : a-t-il approuvé une demande qu'il n'a pas "
              "initiée ? Si oui : révoquer les sessions (Revoke-MgUserSignInSession), "
              "réinitialiser le mot de passe, vérifier les méthodes MFA ajoutées et les règles de "
              "boîte. Activer la correspondance de nombre (number matching).")

    def run(self, signins, audit, cfg):
        c = cfg["detections"]
        window = timedelta(minutes=c["mfa_window_minutes"])
        after = timedelta(minutes=c["mfa_success_within_minutes"])
        alerts = []
        for user, evs in sorted(_group(signins, "userPrincipalName").items()):
            denials = [e for e in evs if e["resultType"] == RESULT_MFA_FAILED]
            start = 0
            for end in range(len(denials)):
                while denials[end]["time"] - denials[start]["time"] > window:
                    start += 1
                if end - start + 1 < c["mfa_min_denials"]:
                    continue
                # first window that reaches the threshold, extended to the whole burst
                while (end + 1 < len(denials)
                       and denials[end + 1]["time"] - denials[start]["time"] <= window):
                    end += 1
                burst = denials[start:end + 1]
                last = burst[-1]["time"]
                success = next((e for e in evs if e["resultType"] == RESULT_SUCCESS
                                and last < e["time"] <= last + after), None)
                ev = [f"{len(burst)} refus / expirations MFA (code {RESULT_MFA_FAILED}) entre "
                      f"{ts(burst[0]['time'])} et {ts(last)}",
                      "IP : " + ", ".join(sorted({b['ipAddress'] for b in burst}))]
                if success:
                    ev.append(f"connexion RÉUSSIE à {ts(success['time'])} depuis {success['ipAddress']} "
                              f"({success['country'] or '?'})")
                    alerts.append(self.alert(burst[0]["time"], burst[0]["userPrincipalName"],
                                             "Refus MFA répétés suivis d'une acceptation", ev))
                else:
                    ev.append("aucune connexion réussie ensuite : tentative (mot de passe connu de l'attaquant)")
                    alerts.append(self.alert(burst[0]["time"], burst[0]["userPrincipalName"],
                                             "Refus MFA répétés sans succès", ev, severity="medium"))
                break  # one alert per user
        return alerts


# --------------------------------------------------------------------------- DET-003
class LegacyAuthSuccess(Detection):
    id = "DET-003"
    title = "Connexion réussie avec un protocole d'authentification hérité"
    severity = "high"
    mitre = [VALID_CLOUD, ("T1110.003", "Brute Force: Password Spraying")]
    kql = "det-003-legacy-auth"
    triage = ("Une connexion héritée réussie = mot de passe valide utilisé SANS MFA. Vérifier "
              "l'IP et le client ; si inattendu : réinitialiser le mot de passe, révoquer les "
              "sessions, bloquer l'authentification héritée (M365-CA-004).")

    def run(self, signins, audit, cfg):
        legacy = {x.lower() for x in cfg["legacy_client_apps"]}
        seen: dict[tuple, list] = {}
        for s in signins:
            if s["resultType"] == RESULT_SUCCESS and s["clientAppUsed"].lower() in legacy:
                key = (s["userPrincipalName"].lower(), s["clientAppUsed"], s["ipAddress"])
                seen.setdefault(key, []).append(s)
        alerts = []
        for (user, app, ip), evs in sorted(seen.items()):
            ev = [f"{len(evs)} connexion(s) réussie(s) via '{app}' depuis {ip} "
                  f"({evs[0]['country'] or '?'}), première à {ts(evs[0]['time'])}"]
            alerts.append(self.alert(evs[0]["time"], evs[0]["userPrincipalName"],
                                     f"Authentification héritée réussie ({app})", ev))
        return alerts


# --------------------------------------------------------------------------- DET-004
class ImpossibleTravel(Detection):
    id = "DET-004"
    title = "Voyage impossible : deux connexions réussies trop éloignées pour le temps écoulé"
    severity = "medium"
    mitre = [VALID_CLOUD]
    kql = "det-004-impossible-travel"
    triage = ("Vérifier d'abord les explications bénignes : VPN d'entreprise, relais iCloud / "
              "proxy mobile, géolocalisation IP imprécise. Sinon : révoquer les sessions et "
              "réinitialiser le mot de passe.")

    def run(self, signins, audit, cfg):
        c = cfg["detections"]
        alerts = []
        ok = [s for s in signins if s["resultType"] == RESULT_SUCCESS and s["latitude"] is not None]
        for user, evs in sorted(_group(ok, "userPrincipalName").items()):
            for a, b in zip(evs, evs[1:]):
                km = haversine_km(a["latitude"], a["longitude"], b["latitude"], b["longitude"])
                if km < c["travel_min_km"]:
                    continue
                hours = (b["time"] - a["time"]).total_seconds() / 3600
                speed = math.inf if hours <= 0 else km / hours
                if speed <= c["travel_max_kmh"]:
                    continue
                speed_txt = "instantané" if math.isinf(speed) else f"{speed:.0f} km/h"
                ev = [f"{ts(a['time'])} {a['city'] or '?'} ({a['country'] or '?'}, {a['ipAddress']})",
                      f"{ts(b['time'])} {b['city'] or '?'} ({b['country'] or '?'}, {b['ipAddress']})",
                      f"{km:.0f} km en {hours * 60:.0f} min -> {speed_txt} "
                      f"(seuil {c['travel_max_kmh']} km/h)"]
                alerts.append(self.alert(b["time"], b["userPrincipalName"],
                                         f"{a['country'] or '?'} -> {b['country'] or '?'} en {hours * 60:.0f} min", ev))
                break  # one alert per user
        return alerts


# --------------------------------------------------------------------------- DET-005
def _addresses(value) -> list[str]:
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = value.replace(",", ";").split(";")
    else:
        return []
    out = []
    for x in items:
        if not isinstance(x, str):
            continue
        x = x.strip().removeprefix("smtp:").removeprefix("SMTP:")
        if "@" in x:
            out.append(x)
    return out


def external_forwards(event, internal_domains) -> list[str]:
    """External addresses an inbox rule / mailbox forwarding event sends mail to."""
    internal = {d.lower() for d in internal_domains}
    params = event["parameters"] or {}
    out = []
    for name in FORWARD_PARAMS:
        for addr in _addresses(params.get(name)):
            if addr.rsplit("@", 1)[1].lower() not in internal:
                out.append(addr)
    return sorted(set(out))


class BecForwardingAfterUnfamiliarSignin(Detection):
    id = "DET-005"
    title = "Compromission de messagerie (BEC) : connexion depuis un pays inhabituel puis règle de transfert externe"
    severity = "critical"
    mitre = [VALID_CLOUD, ("T1114.003", "Email Collection: Email Forwarding Rule"),
             ("T1564.008", "Hide Artifacts: Email Hiding Rules")]
    kql = "det-005-bec-forwarding"
    triage = ("Traiter comme un incident : désactiver la règle et le transfert, révoquer les "
              "sessions, réinitialiser le mot de passe, rechercher les e-mails envoyés / lus "
              "(MailItemsAccessed), prévenir la comptabilité et les clients d'un risque de "
              "fraude au virement (playbook BEC).")

    def run(self, signins, audit, cfg):
        c = cfg["detections"]
        usual = {x.upper() for x in c["usual_countries"]}
        window = timedelta(hours=c["bec_window_hours"])
        seen: dict[str, set[str]] = {}
        unfamiliar = []
        for s in signins:
            if s["resultType"] != RESULT_SUCCESS or not s["country"]:
                continue
            user, country = s["userPrincipalName"].lower(), s["country"].upper()
            known = seen.setdefault(user, set())
            if country not in usual and country not in known:
                unfamiliar.append(s)
            known.add(country)
        rules = [a for a in audit if a["workload"] == "Exchange"
                 and a["operation"] in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox",
                                        "UpdateInboxRules")]
        alerts, done = [], set()
        for s in unfamiliar:
            user = s["userPrincipalName"].lower()
            if user in done:
                continue
            for r in rules:
                if r["userId"].lower() != user or not (s["time"] <= r["time"] <= s["time"] + window):
                    continue
                ext = external_forwards(r, c["internal_domains"])
                if not ext:
                    continue
                params = r["parameters"] or {}
                hiding = [f"{k}={params[k]}" for k in HIDING_PARAMS if k in params]
                ev = [f"{ts(s['time'])} connexion réussie depuis {s['country']} "
                      f"({s['city'] or '?'}, {s['ipAddress']}) : pays jamais vu pour ce compte",
                      f"{ts(r['time'])} {r['operation']} '{params.get('Name', '')}' -> transfert vers "
                      + ", ".join(ext)]
                if hiding:
                    ev.append("dissimulation : " + ", ".join(hiding))
                alerts.append(self.alert(r["time"], s["userPrincipalName"],
                                         "Transfert externe créé après connexion inhabituelle", ev))
                done.add(user)
                break
        return alerts


# --------------------------------------------------------------------------- DET-006
class HighPrivilegeConsent(Detection):
    id = "DET-006"
    title = "Consentement à une application OAuth avec des permissions à haut privilège"
    severity = "high"
    mitre = [("T1528", "Steal Application Access Token"),
             ("T1550.001", "Use Alternate Authentication Material: Application Access Token")]
    kql = "det-006-oauth-consent"
    triage = ("Identifier l'application (éditeur, appId, URL de redirection). Si non légitime : "
              "supprimer le consentement et le principal de service, révoquer les sessions de "
              "l'utilisateur, rechercher l'activité de l'app dans les journaux, restreindre le "
              "consentement utilisateur (M365-APP-001).")

    def run(self, signins, audit, cfg):
        high = {p.lower() for p in cfg["high_privilege_permissions"]}
        alerts = []
        for a in audit:
            if a["workload"] != "AzureActiveDirectory" or not a["operation"].lower().startswith("consent to application"):
                continue
            p = a["parameters"] or {}
            perms = p.get("permissions") or []
            if isinstance(perms, str):
                perms = [x.strip() for x in perms.replace(",", " ").split()]
            risky = sorted({x for x in perms if isinstance(x, str) and x.lower() in high})
            if not risky:
                continue
            admin = bool(p.get("isAdminConsent"))
            ev = [f"application '{p.get('appDisplayName', '?')}' ({p.get('appId', '?')})",
                  "permissions à haut privilège : " + ", ".join(risky),
                  f"type de consentement : {p.get('consentType', '?')} "
                  f"({'administrateur' if admin else 'utilisateur'}), IP {a['clientIP'] or '?'}"]
            alerts.append(self.alert(a["time"], a["userId"], "Consentement OAuth à haut privilège", ev))
        return alerts


DETECTIONS = [PasswordSpray(), MfaFatigue(), LegacyAuthSuccess(), ImpossibleTravel(),
              BecForwardingAfterUnfamiliarSignin(), HighPrivilegeConsent()]


def run_detections(signins, audit, cfg, detections=None) -> list[Alert]:
    alerts = []
    for d in detections if detections is not None else DETECTIONS:
        alerts.extend(d.run(signins, audit, cfg))
    alerts.sort(key=lambda a: (a.time, SEV_ORDER[a.severity], a.rule, a.user))
    return alerts
