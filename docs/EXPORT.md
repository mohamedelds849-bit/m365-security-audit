# Producing an export from your own tenant

> **Authorization.** Only run these commands on a Microsoft 365 tenant you administer, or
> with the written authorization of its owner (engagement letter naming the tenant, the
> period and the people involved). Even a read-only inventory reveals the structure of the
> organisation, its administrators and its weaknesses. The JSON file is **confidential**:
> keep it encrypted, transfer it only to the auditor, delete it when the audit is over.

> **Status: untested on a real tenant.** The project was built with synthetic data only.
> The cmdlet and property names below come from the Microsoft Graph PowerShell SDK and
> Exchange Online / Teams / SharePoint module documentation; `tools/Export-M365Config.ps1`
> was checked with the PowerShell parser only. Review both before use and expect to adjust
> property names (Graph objects evolve).

## Principles

- **Read-only.** Only `Get-*` cmdlets and read-only scopes. No policy, user or app is changed.
- **Never collect secrets.** No client secret, certificate, password, token or key is read.
  The auditor refuses any file containing keys such as `passwordCredentials`, `secretText`,
  `keyCredentials` or `accessToken` (`m365audit/model.py::FORBIDDEN_KEYS`).
- **Least privilege.** Use a named account with the **Global Reader** role (read-only
  across Entra ID and most workloads), with MFA, activated through PIM for the audit window
  if available. Do not use a Global Administrator for an inventory.
- Sign-in activity (`signInActivity`) and risk-based policies need **Entra ID P1 / P2**; on
  a tenant without them some fields stay empty and the related checks are less precise.

## 1. Connect (read-only scopes)

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser          # once
Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All","AuditLog.Read.All",
                        "RoleManagement.Read.Directory","Reports.Read.All"
# Optional workloads (read-only role: Global Reader / View-Only Organization Management)
Connect-ExchangeOnline -ShowBanner:$false                    # ExchangeOnlineManagement
Connect-MicrosoftTeams                                       # MicrosoftTeams
Connect-SPOService -Url https://<tenant>-admin.sharepoint.com # Microsoft.Online.SharePoint.PowerShell
```

## 2. One-shot script

```powershell
.\tools\Export-M365Config.ps1 -OutFile .\m365-export.json
python -m m365audit audit .\m365-export.json --html report.html
```

Sections whose module is not connected are written as `null`: the auditor then refuses the
file (missing required field) until you complete them by hand. This is deliberate: a guessed
"secure" value would hide a risk.

## 3. Where each section comes from

| Section / field | Read-only source | Notes |
|---|---|---|
| `tenant` | `Get-MgOrganization`, `Get-MgSubscribedSku` | P1 = service plan `AAD_PREMIUM`, P2 = `AAD_PREMIUM_P2` |
| `securityDefaults.enabled` | `Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy` | `IsEnabled` |
| `conditionalAccessPolicies` | `Get-MgIdentityConditionalAccessPolicy -All` | `Conditions.Users/Applications/ClientAppTypes/SignInRiskLevels/UserRiskLevels`, `GrantControls.BuiltInControls`; role ids resolved to names |
| `users` | `Get-MgUser -All -Property UserPrincipalName,DisplayName,AccountEnabled,UserType,CreatedDateTime,SignInActivity,OnPremisesSyncEnabled,AssignedLicenses` | `SignInActivity` needs `AuditLog.Read.All` + P1 |
| `users[].authMethods` | `Get-MgReportAuthenticationMethodUserRegistrationDetail -All` | `MethodsRegistered` mapped to the schema names (e.g. `microsoftAuthenticatorPush` -> `microsoftAuthenticator`, `mobilePhone` -> `sms`) |
| `users[].hasMailbox` | `Get-EXOMailbox -ResultSize Unlimited` | |
| `users[].isBreakGlass` | **by hand** | the administrator names the emergency accounts |
| `directoryRoleAssignments` | `Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All` (active) and `Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All` (eligible, PIM) | `ScheduleInfo.Expiration.EndDateTime` -> `endDateTime`; without P2 fall back to `Get-MgRoleManagementDirectoryRoleAssignment` |
| `authorizationPolicy` | `Get-MgPolicyAuthorizationPolicy` | `GuestUserRoleId`, `AllowInvitesFrom`, `DefaultUserRolePermissions.AllowedToCreateApps`, `...PermissionGrantPoliciesAssigned` (`microsoft-user-default-legacy` = allowAll, `microsoft-user-default-low` = verified low risk, empty = none) |
| `passwordPolicy.expirationDays` | `Get-MgDomain` -> `PasswordValidityPeriodInDays` | `2147483647` (never) -> `0` |
| `sspr` | **by hand** (Entra admin center > Password reset) | not fully exposed by Graph v1.0 |
| `audit` | `Get-AdminAuditLogConfig` (`UnifiedAuditLogIngestionEnabled`), `Get-OrganizationConfig` (`AuditDisabled`, inverted), `Get-MailboxAuditBypassAssociation` | Exchange Online module |
| `exchange` | `Get-HostedOutboundSpamFilterPolicy` (`AutoForwardingMode`), `Get-RemoteDomain Default` (`AutoForwardEnabled`) | |
| `domains` | `Get-MgDomain`, `Get-DkimSigningConfig`, `Resolve-DnsName -Type TXT <domain>` and `_dmarc.<domain>` | SPF / DMARC are public DNS records |
| `applications` | `Get-MgServicePrincipal -All`, `Get-MgOauth2PermissionGrant -All` (delegated, `ConsentType`), `Get-MgServicePrincipalAppRoleAssignment` (application permissions) | first-party = `AppOwnerOrganizationId` of Microsoft; `VerifiedPublisher`. **No** `PasswordCredentials` / `KeyCredentials` |
| `teams` | `Get-CsTenantFederationConfiguration` | `AllowFederatedUsers`, `AllowedDomains`, `AllowTeamsConsumer` |
| `sharepoint` | `Get-SPOTenant` | `SharingCapability`, `RequireAnonymousLinksExpireInDays`, `DefaultSharingLinkType` |
| `monitoring.breakGlassSignInAlert` | **by hand** | is there a Sentinel / Azure Monitor alert on break-glass sign-ins? |

## 4. Logs for part B (detections)

The detections run on JSON lines described in `docs/SCHEMA.md` part B. On a real tenant the
equivalent data is in Microsoft Sentinel / Defender (`SigninLogs`, `AuditLogs`,
`OfficeActivity`) or can be read with `Get-MgAuditLogSignIn` and `Search-UnifiedAuditLog`.
In practice the hunting queries of `docs/KQL.md` are the better route: the Python rules are
a teaching model of the same logic, not a replacement for a SIEM.

## 5. Handling the file

- Store it outside synced folders, encrypted (BitLocker / 7-Zip AES-256).
- Never commit it (`.gitignore` already excludes `m365-export*.json` and `*.local.json`).
- Never upload it to an online tool or an AI chat.
- Delete it, and the reports derived from it, at the end of the engagement.
- `Disconnect-MgGraph`, `Disconnect-ExchangeOnline` when done.
