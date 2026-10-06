# Security review: m365-security-audit

Reviewer role: senior Microsoft 365 / Entra ID security consultant and Python/KQL reviewer.
Date: 2026-10-06. Scope: the whole repository (24 checks, 6 detections, `docs/KQL.md`,
`tools/Export-M365Config.ps1`, docs, README, LEARN.md, tests) plus the guide chapter
`cyber-portfolio/guide/chapters/08-m365-security-audit.yaml`.

## Verdict

| Item | Result |
|---|---|
| Technical score | **8.5 / 10** |
| Educational score | **9 / 10** |
| Safety | **OK**: defensive only, offline, no network code, read-only export script, refuses secrets |
| Consistency | **OK after fixes**: 80 / 48 / 0, 6 alerts / 0 benign, 148 tests, same figures in README, LEARN, docs and guide |
| Final | **APPROVED** (with the fixes below applied) |

## What was verified, and how

- **Tests and CLI.** `python -m pytest`: 136 tests passed before the review, **148** after
  (12 added). Reproduced with the CLI: vulnerable **80/100** (24 findings: 2/10/11/1),
  quickwins **48/100** (10), hardened **0/100** (0); detections **6 alerts** on attack
  logs (1 critical, 4 high, 1 medium), **0** on benign logs; `--fail-on` exit codes 0/1/2.
- **Malformed input.** Invalid JSON, a root list, 5,000 nested levels, non-UTF-8 bytes, wrong
  types, `bool` given as an int in JSONL, and a `passwordCredentials` key: each one is
  refused with a clear message and exit code 2. No traceback.
- **HTML.** Every value from the export or logs goes through `html.escape`, and the page has
  a strict CSP (`default-src 'none'`). Checked by hand with `<script>` / `onerror` payloads,
  and now covered by tests.
- **No network.** No `socket`, `urllib`, `requests` or `subprocess` in `m365audit/`.
- **MITRE ATT&CK** (attack.mitre.org, v19, read on 2026-10-06). T1530 *Data from Cloud
  Storage*, T1534 *Internal Spearphishing*, T1199 *Trusted Relationship*, T1110.001 *Brute
  Force: Password Guessing* and T1566 *Phishing* exist and are not deprecated.
  **T1562.008 now redirects to T1685.002** *Disable or Modify Tools: Disable or Modify Cloud
  Log*, so the project's claim is correct. Also checked: T1078.004, T1110.003, T1621, T1528,
  T1550.001, T1098.001, T1098.003, T1087.004, T1114.003, T1564.008, T1566.003, T1213.002,
  T1556.009.
- **CISA SCuBA.** Each cited ID and version suffix was checked against the ScubaGear
  `baselines/*.md` files on `main`: MS.AAD.1.1v1, 2.1v1, 2.3v1, 3.1v1, 3.2v2, 3.5v2, 3.6v1,
  5.1-5.3v1, 6.1v1, 7.1-7.4v1, 7.6v1, 8.1-8.2v1; MS.EXO.1.1v2, 2.2v3, 3.1v1, 4.1-4.2v1,
  13.1v1; MS.DEFENDER.6.1v1; MS.TEAMS.2.1-2.2v2; MS.SHAREPOINT.1.1v1, 2.1v1, 3.1v1. All are
  correct, including the "2 to 8 Global Administrators" text of 7.1.
- **CIS titles.** These titles match CIS M365 Foundations v3/v4 wording: 2-4 global admins,
  block legacy auth, user consent "Do not allow", third-party integrated apps, guest access
  restricted, password never expire, audit log search, AuditDisabled, AuditBypassEnabled,
  mail forwarding, DKIM/DMARC/SPF, admin accounts cloud-only, reduced footprint licences,
  PIM, two emergency access accounts. The code says, correctly, that the SSPR "2 methods"
  recommendation only exists in older versions.
- **Microsoft semantics.** These are all correct:
  - Security defaults and Conditional Access cannot be used together.
  - Report-only policies and risk-conditioned policies do not count as baseline MFA.
  - The legacy block policy needs **both** `exchangeActiveSync` and `other`.
  - PIM-eligible holders count toward the Global Administrator total; only active
    assignments with no end date count as permanent.
  - Break-glass guidance: 2 cloud-only accounts, permanent GA, phishing-resistant method,
    alerting.
  - `AutoForwardingMode` Automatic now means Off. The remote-domain setting is only a second
    lock, and it does not stop SMTP forwarding, so flagging `On` regardless is right.
  - `SharingCapability = ExternalUserAndGuestSharing` means Anyone links.
  - Licence model: CA and sign-in activity need P1; PIM and risk policies need P2.
- **PowerShell.** Parsed with 0 errors on PowerShell 7 and 5.1. Every tenant cmdlet is
  `Get-*` or `Connect-*`; the only `Set-*` calls are the local `Set-StrictMode` and
  `Set-Content`, which writes the JSON file. Graph scopes are read-only, `Get-MgServicePrincipal`
  is limited to non-secret properties, and the authorization warning is present.
- **KQL** (checked against the SigninLogs / AuditLogs / OfficeActivity schemas). These are
  all correct:
  - `ResultType` is a string. `LocationDetails.countryOrRegion` and `.geoCoordinates` are
    the right fields.
  - `geo_distance_2points(lon, lat, lon, lat)` returns metres. `datetime_diff("second", a, b)`
    computes a - b. `prev()` works after `sort`.
  - In OfficeActivity, `Parameters` is a JSON string of `{Name, Value}` pairs.
  - In AuditLogs, `InitiatedBy.user.*` and the `ConsentAction.Permissions` /
    `ConsentContext.IsAdminConsent` modified properties are the right fields.

  No syntax error was found. The "not executed" disclaimer is kept.

## Problems found

| # | Severity | Problem | Status |
|---|---|---|---|
| 1 | **High (functional)** | `Export-M365Config.ps1`: the GUID for "guests have the same access as members" was wrong (`a0b1b346-...-753e3db50fdc`). Microsoft Learn gives `a0b1b346-4d3e-4e8b-98f8-753987be4970`. On a real tenant in the riskiest state, `guestUserAccess` came out null and the auditor refused the file. | **Fixed** + test |
| 2 | Medium (accuracy) | `M365-COL-002` (SPF/DKIM/DMARC) was mapped to **T1534 Internal Spearphishing**. That technique needs a *compromised internal account*, which email authentication does not prevent. v19 has the exact technique: **T1684.002 Social Engineering: Email Spoofing** (formerly T1672; its mitigation names SPF/DKIM/DMARC). | **Fixed** + test, README updated |
| 3 | Medium | User-consent mapping in the export script: any value other than legacy/low (for example `microsoft-user-default-recommended` or a custom policy) became `none`, the best possible state. It also looked at `ManagePermissionGrantsForOwnedResource.*` (group/team owner consent). | **Fixed**: only `ManagePermissionGrantsForSelf.*` is used; unknown values become `allowVerifiedLowRisk` with a warning |
| 4 | Low | The legacy client list (`config/default.yaml`, KQL DET-003) was missing several protocols that Microsoft Learn lists under "Other clients": Outlook Anywhere (RPC over HTTP), Exchange Online PowerShell, Reporting Web Services, Outlook Service. | **Fixed** in both places + tests |
| 5 | Low | NIST wording. NIST SP 800-63B rev. 4 (2025) says verifiers **SHALL NOT** require periodic changes, and the section is now called "password verifiers". The text said "déconseillent" and claimed NIST makes this conditional on MFA (that condition is Microsoft's framing, not NIST's). | **Fixed** in check `why`, its reference, and LEARN Q16 |
| 6 | Low | `M365-LOG-002` did not say that mailbox auditing has been **on by default** since 2019, which is the key interview point: a finding means someone made a deliberate change. | **Fixed** (`why`) |
| 7 | Low | The header comment said the script never calls `Set-` cmdlets, but it uses the local `Set-Content` / `Set-StrictMode`. | **Fixed** (comment clarified, and a static test whitelists only these two) |

## Fixes applied (commit on `main`, not pushed)

- `tools/Export-M365Config.ps1`: correct guest GUID; warning on an unknown GUID; consent
  mapping fixed; read-only statement made precise. Re-parsed with 0 errors on PS 7 and 5.1.
- `m365audit/checks/collab.py`: T1534 replaced by T1684.002, with a comment explaining why.
- `m365audit/checks/accounts.py`, `audit_logs.py`: NIST rev. 4 wording; mailbox auditing
  on by default.
- `config/default.yaml`, `docs/KQL.md`: complete legacy client list.
- `README.md`: ATT&CK renumbering note (T1562.008 -> T1685.002, T1672 -> T1684.002).
  `README.md`, `LEARN.md` and the guide chapter: test count changed to 148. LEARN Q16
  rewritten.
- `tests/test_review.py` (12 tests):
  - HTML escaping of the audit report and the detection report
  - every documented legacy client triggers DET-003; modern clients do not
  - COL-002 is mapped to T1684.002
  - the export script calls no tenant-modifying cmdlet and requests no secret
  - the guest GUIDs match Microsoft Learn
- `reports/*` regenerated. Scores unchanged: 80 / 48 / 0, 6 / 0 alerts.
- Guide PDF rebuilt (`guide/build_guide.py`, 8 chapters OK).

## Recommendations (not fixed: bigger, or need a real tenant)

1. **PIM export.** `Get-MgRoleManagementDirectoryRoleAssignmentSchedule` may not return
   every assignment. Compare it with `...RoleAssignmentScheduleInstance` (active instances,
   including direct assignments) on a test tenant, and record service principals as
   `servicePrincipal` instead of `group`.
2. **Conditional Access model.** `includeGroups`, `excludeGroups`, `excludeRoles` and
   `excludeApplications` are not modelled. Group-based exclusions are the most common real
   bypass, so this is the most valuable schema extension.
3. **Exchange.** Only the *Default* outbound spam policy is exported. Custom policies with
   `AutoForwardingMode On` that apply to some mailboxes would be missed.
4. **SPF.** A record that ends with `redirect=` is reported as "non strict". Resolve the
   redirect, or accept it with a note.
5. **Security defaults nuance (LEARN/guide).** For non-admin users, security defaults ask
   for MFA "when necessary", not at every sign-in. This is worth one sentence because
   interviewers ask about it.
6. **KQL.** Add `union AADNonInteractiveUserSignInLogs` to DET-001/003. Build the
   per-user country baseline for DET-005. Parse the scopes list for DET-006 instead of using
   `contains`. All three are already listed as limits in the doc.
7. **Formatting.** Two lines changed in README / LEARN are wider than the rest of the text.

## Honesty check (README / LEARN / CV line / guide)

- Every document says the data is synthetic and the tool was never run on a real tenant.
  The KQL and the PowerShell script are described as "reviewed / parser-checked, never
  executed", and AI assistance is disclosed.
- The CV line ("validé sur des données synthétiques (148 tests)") is accurate.
  `never_say` / « À ne jamais dire » covers the risky claims.
- **LEARN.md 18 answers.** All are correct. Q16 has been corrected (NIST nuance). Q1/Q7 are
  correct (CIS 2-4, SCuBA up to 8). Q9/Q10 use the right result codes: 50126, 50053 and
  500121.
- **Guide chapter.** No factual error found. Code anchors are still valid (the KQL excerpt
  at lines 29-47 did not move). Test counts are updated.
