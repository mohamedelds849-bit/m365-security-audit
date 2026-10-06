# Detections (part B): logic, thresholds, blind spots

Six teaching-grade rules in `m365audit/detect/rules.py`, run with
`python -m m365audit detect --signins S.jsonl --audit A.jsonl`. Thresholds come from the
`detections` section of `config/default.yaml`. The KQL equivalent of each rule is in
`docs/KQL.md`. ATT&CK IDs were checked on attack.mitre.org (v19.2) on 2026-10-05.

| ID | Severity | Logic (default thresholds) | Main false positives | Blind spots |
|---|---|---|---|---|
| DET-001 password spray | high | >= 10 distinct users with `50126` / `50053` from one IP in a sliding 60 min window; notes any later success from that IP | shared NAT after a forced password change, misconfigured service | slow spray (a few users per hour), attacker rotating IPs |
| DET-002 MFA fatigue | high (medium if no success) | >= 5 `500121` for one user within 30 min, success within 60 min after the last denial | user with a broken phone / app retrying | approvals spread over hours, fatigue on non-interactive flows |
| DET-003 legacy auth | high | any **successful** sign-in whose `clientAppUsed` is in `legacy_client_apps` | old multifunction printer / scanner using SMTP AUTH | legacy traffic that only appears in non-interactive logs |
| DET-004 impossible travel | medium | two successes > 500 km apart at > 900 km/h | corporate VPN, iCloud Private Relay, imprecise geo-IP | attacker using an IP in the user's own country |
| DET-005 BEC forwarding | critical | success from a country not in `usual_countries` **and** new for the user, then within 24 h an Exchange rule / mailbox change forwarding to a non-internal domain; hiding parameters (`MarkAsRead`, `MoveToFolder`...) reported | employee who travels and forwards to a personal address (itself a policy violation) | attacker from the same country, rule created days later, forwarding by transport rule |
| DET-006 OAuth consent | high | `Consent to application` with at least one permission in `high_privilege_permissions` | legitimate admin consent to a business app | consent to low scopes followed by an app update, application permissions granted by admin script |

## Results on the synthetic logs (2026-10-06)

| Dataset | Sign-ins | Audit events | Alerts |
|---|---|---|---|
| `data/logs/*_benign.jsonl` | 308 | 5 | **0** (includes 8 deliberate near-misses: 9-user burst, 12 users failing from one IP spread over 2h45, 4 MFA denials, 5 denials over 2 h, one failed IMAP, Agadir -> Casablanca in 1 h, real Paris trip, low-privilege consent) |
| `data/logs/*_attack.jsonl` | 333 | 7 | **6**: one per rule, 1 critical / 4 high / 1 medium |

Attack alerts: DET-001 14 accounts from `203.0.113.45` with a later success for one of them,
DET-003 that account over IMAP4, DET-002 7 denials in 18 min then approval, DET-004 Agadir ->
New York in 90 min (~3,871 km/h), DET-005 London sign-in then hidden forwarding rule 15 min
later, DET-006 user consent to an unverified "PDF Convert Express" with `Mail.ReadWrite` and
`Files.ReadWrite.All`.

These numbers show the rules behave as designed **on data written to test them**. They say
nothing about precision or recall on a real tenant.
