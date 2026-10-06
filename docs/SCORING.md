# Scoring method

**A risk score from 0 to 100 where LOWER IS BETTER**, the same formula as the sibling project
`ad-security-audit`, so both reports read the same way for an SME manager ("risk 80 -> 0").

## Formula (`m365audit/scoring.py`)

```
points(finding)  = 40 critical | 20 high | 10 medium | 5 low
category score   = min(100, sum of the points of the findings in that category)
global score     = round(0.5 * max(category scores) + 0.5 * mean(category scores))
level            = faible <= 20 < modéré <= 50 < élevé <= 75 < critique
```

Six categories (`m365audit/engine.py::CATEGORIES`): `access` (Conditional Access and MFA),
`privileged` (privileged roles), `accounts` (accounts, guests, passwords), `apps` (OAuth
applications and consent), `collab` (mail and collaboration), `logging` (audit logs).

The detections of part B (log analysis) are **not** scored: an alert is an event to triage,
not a configuration state.

## Design decisions (and their trade-offs)

| Decision | Why | Trade-off |
|---|---|---|
| Points do not depend on the number of affected objects | a 500-user tenant is not "riskier" than a 30-user one for the same misconfiguration | 1 stale guest and 50 stale guests score the same (the `affected` count is shown separately) |
| Category capped at 100 | a category is either "under control" or "saturated" | several categories can saturate on a neglected tenant |
| Global = half worst category + half mean | the max alone hides progress on the other categories; the mean alone would dilute one catastrophic category | not comparable with Microsoft Secure Score (different scale and meaning) |
| Severity set per check | simple, explainable, testable | context (e.g. a guest's real access) is in the evidence, not in the points |
| Licence-dependent checks | `M365-CA-005` (risk policies) is evaluated only when `tenant.entraIdP2 = true`: a missing P2 licence is a budget limit, not a misconfiguration | a P1-only tenant gets no penalty for missing risk-based protection |

## Results on the synthetic AgriSouss exports

Measured with `python -m m365audit audit data/agrisouss_m365_<x>.json` (2026-10-06) and
asserted by `tests/test_detections.py::test_agrisouss_scores`:

| Export | Global | access | privileged | accounts | apps | collab | logging | Findings (C/H/M/L) |
|---|---|---|---|---|---|---|---|---|
| vulnerable | **80 (critique)** | 100 | 70 | 45 | 50 | 60 | 30 | 24 (2/10/11/1) |
| quickwins | **48 (modéré)** | 40 | 70 | 10 | 20 | 20 | 0 | 10 (0/6/4/0) |
| hardened | **0 (faible)** | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Check of the formula on `vulnerable`: max = 100, mean = (100+70+45+50+60+30)/6 = 59.17,
global = round(50 + 29.58) = 80.

`quickwins` = the vulnerable tenant after applying only the actions tagged `quick` in the
plan; the 10 remaining findings are all `30d` / `90d` efforts (asserted by
`tests/test_checks.py::test_quickwins_keep_only_non_quick_findings`). The hardened export is
built to pass every check; a real tenant rarely reaches 0.
