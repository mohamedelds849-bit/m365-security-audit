"""Deterministic SYNTHETIC sign-in and audit logs for the fictional tenant agrisouss.onmicrosoft.com.

Everything is invented. IP addresses come only from the documentation ranges of RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real host is ever named.

Two datasets are produced with a fixed seed:
- *_benign.jsonl : one week of normal activity PLUS deliberate near-misses (events that look a
  bit like an attack but must NOT raise an alert: 9-user failure burst, 4 MFA denials, short
  Agadir -> Casablanca trip, real business trip to Paris, internal forwarding rule...)
- *_attack.jsonl : the benign week + six attack scenarios, one per detection.

The scenarios describe what the defender SEES in logs; they contain no attack tooling.
"""
from __future__ import annotations

import json
import os
import random
from datetime import datetime, timedelta, timezone

from ..synthetic import ACCOUNTANT, DIRECTOR, base_tenant

SEED = 20261005
DAYS = [datetime(2026, 9, d, tzinfo=timezone.utc) for d in range(21, 28)]  # Mon 21 -> Sun 27

# (country, city, latitude, longitude)
AGADIR = ("MA", "Agadir", 30.4278, -9.5981)
TAROUDANT = ("MA", "Taroudant", 30.4703, -8.8770)
CASABLANCA = ("MA", "Casablanca", 33.5731, -7.5898)
PARIS = ("FR", "Paris", 48.8566, 2.3522)
AMSTERDAM = ("NL", "Amsterdam", 52.3676, 4.9041)
LONDON = ("GB", "London", 51.5072, -0.1276)
NEW_YORK = ("US", "New York", 40.7128, -74.0060)

OFFICE_IP = "198.51.100.10"      # Agadir head office NAT
TAROUDANT_IP = "198.51.100.20"   # Taroudant packing station NAT
HOTEL_IP = "192.0.2.50"          # director's hotel in Paris
SPRAY_IP = "203.0.113.45"
MFA_IP = "203.0.113.77"
TRAVEL_IP = "203.0.113.90"
BEC_IP = "203.0.113.120"
NOISE_IP = "203.0.113.200"

MODERN = ["Browser", "Mobile Apps and Desktop clients"]
APPS = ["Office 365 Exchange Online", "Microsoft Teams", "Office 365 SharePoint Online",
        "OfficeHome"]


def _members() -> list[str]:
    t = base_tenant()
    return sorted(u["userPrincipalName"] for u in t["users"]
                  if u["userType"] == "Member" and not u["isBreakGlass"]
                  and u["userPrincipalName"] not in ("scanner@agrisouss.ma", "i.naciri@agrisouss.ma",
                                                     "b.zahiri@agrisouss.ma"))


MEMBERS = _members()
_RANDOM_POOL = [u for u in MEMBERS if u not in (DIRECTOR, ACCOUNTANT)]
SPRAY_VICTIM = _RANDOM_POOL[3]        # one sprayed account whose password was guessed
MFA_VICTIM = _RANDOM_POOL[5]
TRAVEL_VICTIM = _RANDOM_POOL[7]
NEAR_MFA_USER = _RANDOM_POOL[9]       # 4 denials then success (below threshold)
NEAR_MFA_SPREAD = _RANDOM_POOL[11]    # 5 denials spread over 2 hours
NEAR_TRAVEL_USER = _RANDOM_POOL[13]   # Agadir -> Casablanca in 1 hour (< 500 km)
NEAR_LEGACY_USER = _RANDOM_POOL[15]   # one failed IMAP attempt
CONSENT_USER_BENIGN = _RANDOM_POOL[17]
SCRIPTED = {DIRECTOR, ACCOUNTANT, TRAVEL_VICTIM, NEAR_TRAVEL_USER}


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def signin(dt, user, ip, loc, result=0, client="Browser", app="Office 365 Exchange Online"):
    country, city, lat, lon = loc
    return {"time": _iso(dt), "userPrincipalName": user, "ipAddress": ip, "clientAppUsed": client,
            "resultType": result, "country": country, "city": city, "latitude": lat,
            "longitude": lon, "appDisplayName": app}


def audit(dt, workload, operation, user, ip, **params):
    return {"time": _iso(dt), "workload": workload, "operation": operation, "userId": user,
            "clientIP": ip, "parameters": params}


def _at(day_index, h, m=0):
    return DAYS[day_index] + timedelta(hours=h, minutes=m)


def benign() -> tuple[list[dict], list[dict]]:
    rnd = random.Random(SEED)
    s, a = [], []
    # --- normal working week: modern clients from the two sites, 08:00-17:59
    for user in MEMBERS:
        if user in SCRIPTED:
            continue
        site = (OFFICE_IP, AGADIR) if rnd.random() < 0.7 else (TAROUDANT_IP, TAROUDANT)
        for di in range(5):  # Monday -> Friday
            for _ in range(rnd.randint(1, 3)):
                dt = _at(di, rnd.randint(8, 17), rnd.randint(0, 59))
                s.append(signin(dt, user, site[0], site[1], client=rnd.choice(MODERN),
                                app=rnd.choice(APPS)))
    # --- scripted normal users
    for di in range(5):
        s.append(signin(_at(di, 8, 30), ACCOUNTANT, OFFICE_IP, AGADIR))
        s.append(signin(_at(di, 16, 45), ACCOUNTANT, OFFICE_IP, AGADIR, app="Microsoft Teams"))
        s.append(signin(_at(di, 9, 0), TRAVEL_VICTIM, OFFICE_IP, AGADIR))
    for di in range(4):
        s.append(signin(_at(di, 8, 15), DIRECTOR, OFFICE_IP, AGADIR, client="Mobile Apps and Desktop clients"))

    # --- near-miss 1: 9 users mistype their new password at the office (threshold is 10)
    for i, user in enumerate(_RANDOM_POOL[20:29]):
        dt = _at(0, 8, 0) + timedelta(minutes=5 * i)
        s.append(signin(dt, user, OFFICE_IP, AGADIR, result=50126))
        s.append(signin(dt + timedelta(minutes=1), user, OFFICE_IP, AGADIR))
    # --- near-miss 2: 12 users fail from Taroudant, but spread over 2h45 (max 5 per hour)
    # (12 distinct users: scripted users are skipped BEFORE slicing, otherwise only 9 remain and
    # the near-miss would be below the user threshold even with an unlimited window)
    for i, user in enumerate([u for u in MEMBERS if u not in SCRIPTED][:12]):
        dt = _at(2, 8, 0) + timedelta(minutes=15 * i)
        s.append(signin(dt, user, TAROUDANT_IP, TAROUDANT, result=50126))
    # --- near-miss 3: 4 MFA denials then success (threshold is 5)
    for i in range(4):
        s.append(signin(_at(3, 9, 2 * i), NEAR_MFA_USER, OFFICE_IP, AGADIR, result=500121))
    s.append(signin(_at(3, 9, 12), NEAR_MFA_USER, OFFICE_IP, AGADIR))
    # --- near-miss 4: 5 MFA denials over 2 hours (never 5 inside 30 minutes) then success
    for i in range(5):
        s.append(signin(_at(1, 10, 0) + timedelta(minutes=30 * i), NEAR_MFA_SPREAD, OFFICE_IP,
                        AGADIR, result=500121))
    s.append(signin(_at(1, 12, 5), NEAR_MFA_SPREAD, OFFICE_IP, AGADIR))
    # --- near-miss 5: one failed IMAP attempt (legacy, but not successful)
    s.append(signin(_at(2, 3, 10), NEAR_LEGACY_USER, NOISE_IP, AMSTERDAM, result=50126, client="IMAP4"))
    # --- near-miss 6: Agadir -> Casablanca by car / plane in 1 hour (~400 km, under 500 km)
    s.append(signin(_at(1, 9, 0), NEAR_TRAVEL_USER, OFFICE_IP, AGADIR))
    s.append(signin(_at(1, 10, 0), NEAR_TRAVEL_USER, "198.51.100.130", CASABLANCA,
                    client="Mobile Apps and Desktop clients"))
    # --- near-miss 7: real business trip of the director to Paris (5h30, ~2,300 km)
    s.append(signin(_at(4, 7, 0), DIRECTOR, OFFICE_IP, AGADIR))
    s.append(signin(_at(4, 12, 30), DIRECTOR, HOTEL_IP, PARIS))
    s.append(signin(_at(5, 9, 0), DIRECTOR, HOTEL_IP, PARIS))
    a.append(audit(_at(4, 13, 0), "Exchange", "New-InboxRule", DIRECTOR, HOTEL_IP,
                   Name="Newsletters", MoveToFolder="Newsletters", FromAddressContainsWords="newsletter"))
    a.append(audit(_at(5, 9, 10), "Exchange", "New-InboxRule", DIRECTOR, HOTEL_IP,
                   Name="Absence - vers assistante", ForwardTo="n.assistante@agrisouss.ma"))
    # --- near-miss 8: consent to a low-privilege app (sign-in with Microsoft)
    a.append(audit(_at(1, 14, 0), "AzureActiveDirectory", "Consent to application.",
                   CONSENT_USER_BENIGN, OFFICE_IP, appDisplayName="Planificateur Réunions",
                   appId="11111111-2222-4333-8444-555555555510",
                   permissions=["User.Read", "openid", "profile", "offline_access"],
                   consentType="Principal", isAdminConsent=False))
    # --- ordinary admin noise
    a.append(audit(_at(0, 11, 0), "Exchange", "Set-Mailbox", "y.benali@agrisouss.ma", OFFICE_IP,
                   Identity="scanner@agrisouss.ma", MaxSendSize="35MB"))
    a.append(audit(_at(2, 15, 0), "AzureActiveDirectory", "Add member to group.",
                   "y.benali@agrisouss.ma", OFFICE_IP, group="Equipe Export"))
    return s, a


def attacks() -> tuple[list[dict], list[dict]]:
    s, a = [], []
    # DET-001: password spray, 14 accounts from one IP in 30 minutes, one guessed (IMAP)
    targets = [u for u in _RANDOM_POOL[:16] if u != SPRAY_VICTIM][:13] + [SPRAY_VICTIM]
    for i, user in enumerate(targets):
        s.append(signin(_at(3, 2, 5) + timedelta(minutes=2 * i), user, SPRAY_IP, AMSTERDAM,
                        result=50126, client="Other clients"))
    # DET-003: the guessed account is used over IMAP (legacy authentication, no MFA)
    s.append(signin(_at(3, 2, 40), SPRAY_VICTIM, SPRAY_IP, AMSTERDAM, client="IMAP4"))
    # DET-002: MFA fatigue, 7 denials in 18 minutes late at night, then an approval
    for i in range(7):
        s.append(signin(_at(4, 23, 30) + timedelta(minutes=3 * i), MFA_VICTIM, MFA_IP, AMSTERDAM,
                        result=500121))
    s.append(signin(_at(4, 23, 52), MFA_VICTIM, MFA_IP, AMSTERDAM))
    # DET-004: impossible travel, Agadir 09:00 -> New York 10:30 the same day
    s.append(signin(_at(2, 10, 30), TRAVEL_VICTIM, TRAVEL_IP, NEW_YORK))
    # DET-005: BEC, accountant signs in from an unfamiliar country, forwarding rule 15 min later
    s.append(signin(_at(5, 6, 50), ACCOUNTANT, BEC_IP, LONDON))
    a.append(audit(_at(5, 7, 5), "Exchange", "New-InboxRule", ACCOUNTANT, BEC_IP,
                   Name=".", ForwardTo="f.bakkali.compta@mail-externe.example",
                   MarkAsRead="True", MoveToFolder="RSS Feeds", StopProcessingRules="True",
                   SubjectOrBodyContainsWords="facture;virement;RIB"))
    # DET-006: high-privilege consent (persistence through an OAuth app)
    a.append(audit(_at(5, 7, 20), "AzureActiveDirectory", "Consent to application.", ACCOUNTANT,
                   BEC_IP, appDisplayName="PDF Convert Express",
                   appId="11111111-2222-4333-8444-555555555501",
                   permissions=["Mail.ReadWrite", "Files.ReadWrite.All", "offline_access"],
                   consentType="Principal", isAdminConsent=False))
    return s, a


def _sorted(events):
    return sorted(events, key=lambda e: e["time"])  # stable: equal times keep build order


def build_all() -> dict[str, list[dict]]:
    bs, ba = benign()
    xs, xa = attacks()
    return {
        "signins_benign.jsonl": _sorted(bs), "audit_benign.jsonl": _sorted(ba),
        "signins_attack.jsonl": _sorted(bs + xs), "audit_attack.jsonl": _sorted(ba + xa),
    }


def write_all(folder: str) -> list[str]:
    os.makedirs(folder, exist_ok=True)
    paths = []
    for name, events in build_all().items():
        path = os.path.join(folder, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        paths.append(path)
    return paths
