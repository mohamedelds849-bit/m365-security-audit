# Export and log schema (version 1.0)

The auditor reads two kinds of input. Both are **simplified, flattened** formats designed for
this project: they are inspired by Microsoft Graph objects and Microsoft Sentinel tables but
are **not** raw Graph or Sentinel output. `docs/EXPORT.md` explains how each field could be
produced; `docs/KQL.md` maps log fields to the real table columns.

Validation lives in `m365audit/model.py` (configuration) and `m365audit/detect/model.py`
(logs). Any problem raises `SchemaError` and the CLI exits with code `2`.

## Part A - configuration export (`*.json`)

General rules (enforced by `Tenant.__init__`):

- root is a JSON object with `"schemaVersion": "1.0"` and an ISO-8601 `exportedAt`
  (all ages, e.g. "stale for 120 days", are computed relative to `exportedAt`, not "now");
- UTF-8, a PowerShell BOM is accepted; maximum 50 MB; nesting depth maximum 20;
- **secrets are refused anywhere**: a key named `secretText`, `clientSecret`, `password`,
  `passwordCredentials`, `keyCredentials`, `refreshToken`, `accessToken` or `certificate`
  (case-insensitive) makes the whole file invalid;
- dates are ISO-8601 strings or `null`; integers refuse booleans and negative values;
- list items are unique on their key (UPN, policy name, domain name, appId), case-insensitive.

### Required sections (objects)

| Section | Fields (required in **bold**) |
|---|---|
| `tenant` | **`id`**, **`defaultDomain`**, `displayName`, `licenses[]`, `entraIdP1` (bool), `entraIdP2` (bool) |
| `securityDefaults` | **`enabled`** (bool) |
| `authorizationPolicy` | **`userConsent`** (`allowAll` / `allowVerifiedLowRisk` / `none`), **`guestUserAccess`** (`sameAsMember` / `limited` / `restricted`), **`allowInvitesFrom`** (`everyone` / `adminsGuestInvitersAndAllMembers` / `adminsAndGuestInviters` / `none`), **`usersCanRegisterApps`** (bool) |
| `passwordPolicy` | **`expirationDays`** (int, `0` = never expire) |
| `sspr` | **`enabled`** (`none` / `selected` / `all`), `methodsRequired` (int, default 1), `methods[]` |
| `audit` | **`unifiedAuditLogEnabled`**, **`mailboxAuditByDefault`** (bool), `auditBypassMailboxes[]` |
| `exchange` | **`autoForwardingMode`** (`Automatic` / `On` / `Off`), `remoteDomainAutoForward` (bool) |
| `teams` | **`externalAccess`** (`allowAll` / `allowList` / `blocked`), `allowedDomains[]`, **`consumerAccess`** (bool) |
| `sharepoint` | **`sharingCapability`** (`ExternalUserAndGuestSharing` / `ExternalUserSharingOnly` / `ExistingExternalUserSharingOnly` / `Disabled`), `anyoneLinkExpirationDays` (int, `0` = no expiry), `defaultSharingLinkType` (`AnonymousAccess` / `Internal` / `Direct`) |
| `monitoring` | **`breakGlassSignInAlert`** (bool) - declared by the administrator, cannot be read from Graph |

### Lists (optional, default `[]`)

| List | Item fields |
|---|---|
| `conditionalAccessPolicies` | **`displayName`**, **`state`** (`enabled` / `disabled` / `enabledForReportingButNotEnforced`), `includeUsers[]` (`"All"` or UPNs), `excludeUsers[]`, `includeRoles[]` (role display names), `includeApplications[]` (`"All"` or app ids), `clientAppTypes[]` (default `["all"]`; `exchangeActiveSync`, `other` = legacy), `grantControls[]` (`mfa`, `authenticationStrength`, `block`, ...), `signInRiskLevels[]`, `userRiskLevels[]` |
| `users` | **`userPrincipalName`**, `displayName`, **`accountEnabled`**, `userType` (`Member` / `Guest`), `createdDateTime`, `lastSignInDateTime`, `onPremisesSyncEnabled`, `assignedLicenses[]`, `hasMailbox`, `authMethods[]`, `isBreakGlass` |
| `directoryRoleAssignments` | **`roleName`**, **`principal`** (UPN or name), `principalType` (`user` / `group` / `servicePrincipal`), `assignmentType` (`active` / `eligible`), `endDateTime` (`null` = permanent) |
| `domains` | **`name`**, `isDefault`, `dkimEnabled`, `dmarcPolicy` (`none` / `quarantine` / `reject` / `null` = no record), `spfRecord` (`""` = none) |
| `applications` | **`displayName`**, **`appId`**, `publisherVerified`, `isMicrosoftFirstParty`, `consentedBy`, `createdDateTime`, `permissions[]` = {**`name`**, **`type`** (`Application` / `Delegated`), `consentType` (`AllPrincipals` = admin, `Principal` = one user)} |

`authMethods` values counted as a second factor (`MFA_METHODS`): `microsoftAuthenticator`,
`fido2`, `windowsHelloForBusiness`, `softwareOath`, `hardwareOath`, `sms`, `voice`, `passkey`.
`password` and `email` are not MFA. `sms` / `voice` count as MFA but are flagged as weak by
`M365-ACC-005` (`weak_auth_methods` in `config/default.yaml`).

## Part B - logs (`*.jsonl`, one JSON object per line)

Events are sorted by `time` after loading (file order breaks ties), so a detection never
depends on how the file was ordered. Limits: 200 MB, 2,000,000 lines. Errors name the line
(`signins_attack.jsonl:42: ...`).

### Sign-ins (inspired by `SigninLogs`)

| Field | Type | Notes |
|---|---|---|
| **`time`** | ISO-8601 | `TimeGenerated` |
| **`userPrincipalName`** | str | |
| **`ipAddress`** | str | synthetic data uses only RFC 5737 documentation ranges |
| **`resultType`** | int | `0` success, `50126` bad password, `50053` locked, `500121` strong-auth failed |
| `clientAppUsed` | str | `Browser`, `Mobile Apps and Desktop clients`, or a legacy value (`IMAP4`, `POP3`, `Other clients`...) |
| `country`, `city` | str | `LocationDetails.countryOrRegion` / `.city` |
| `latitude`, `longitude` | float | both or none, range-checked |
| `appDisplayName` | str | |

### Audit events (inspired by `OfficeActivity` / `AuditLogs`)

| Field | Type | Notes |
|---|---|---|
| **`time`** | ISO-8601 | |
| **`workload`** | str | `Exchange`, `AzureActiveDirectory`, `SharePoint`, `MicrosoftTeams` |
| **`operation`** | str | e.g. `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `UpdateInboxRules`, `Consent to application.` |
| **`userId`** | str | actor UPN |
| `clientIP` | str | |
| `parameters` | object | flattened parameters: `Name`, `ForwardTo`, `RedirectTo`, `ForwardingSmtpAddress`, `MoveToFolder`, `MarkAsRead`... for Exchange; `appDisplayName`, `appId`, `permissions[]`, `consentType`, `isAdminConsent` for consent |
