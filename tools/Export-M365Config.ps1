<#
.SYNOPSIS
  READ-ONLY inventory of a Microsoft 365 / Entra ID tenant configuration for m365-security-audit.

.DESCRIPTION
  AUTHORIZATION WARNING
  Run this script ONLY on a tenant you administer or for which you hold WRITTEN authorization
  from the owner. Even read-only, this inventory is sensitive (administrators, weaknesses).
  The resulting JSON file is CONFIDENTIAL: store it encrypted, share it only with the
  auditor, delete it after the audit. Use a Global Reader account, not a Global Administrator.

  What it does: calls read-only Get-Mg* cmdlets of the Microsoft Graph PowerShell SDK and,
  if their modules are already connected, read-only Get-* cmdlets of Exchange Online,
  Microsoft Teams and SharePoint Online. It writes a JSON file that follows docs/SCHEMA.md.

  What it never does: modify anything, read client secrets, certificates, keys, tokens or
  passwords (PasswordCredentials / KeyCredentials are never requested), call any New-, Set-,
  Update- or Remove- cmdlet.

  Sections whose module is not connected (and 'sspr', not exposed by Graph v1.0) are written
  as null: the auditor refuses the file until they are completed by hand (docs/EXPORT.md).
  isBreakGlass comes from -BreakGlassUpn; monitoring.breakGlassSignInAlert must be set by hand.

  STATUS: syntax checked with the PowerShell parser only. NOT run against a real tenant by the
  author (synthetic data only). Property names follow the public documentation and may need
  adjustment. Group-based include/exclude in Conditional Access is NOT resolved (warning).

.EXAMPLE
  Connect-MgGraph -Scopes Policy.Read.All,Directory.Read.All,AuditLog.Read.All,RoleManagement.Read.Directory,Reports.Read.All
  .\Export-M365Config.ps1 -OutFile .\m365-export.json -BreakGlassUpn bg1@contoso.onmicrosoft.com,bg2@contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string[]]$BreakGlassUpn = @()
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue) -or -not (Get-MgContext)) {
    throw "Not connected: run Connect-MgGraph with the read-only scopes listed in docs/EXPORT.md"
}

function Iso($dt) {
    if ($null -eq $dt) { return $null }
    return ([datetime]$dt).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
function Has-Cmd($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }
function Arr($x) { if ($null -eq $x) { return @() } return @($x) }

$MsftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$MethodMap = @{
    'microsoftAuthenticatorPush' = 'microsoftAuthenticator'
    'microsoftAuthenticatorPasswordless' = 'microsoftAuthenticator'
    'softwareOneTimePasscode' = 'softwareOath'; 'hardwareOneTimePasscode' = 'hardwareOath'
    'fido2SecurityKey' = 'fido2'; 'passKeyDeviceBound' = 'passkey'
    'passKeyDeviceBoundAuthenticator' = 'passkey'; 'windowsHelloForBusiness' = 'windowsHelloForBusiness'
    'mobilePhone' = 'sms'; 'alternateMobilePhone' = 'sms'; 'officePhone' = 'voice'
    'email' = 'email'; 'securityQuestion' = 'securityQuestions'
}

# ---------------------------------------------------------------- tenant and licences
Write-Host "[1/7] tenant, licences, security defaults"
$org = Get-MgOrganization | Select-Object -First 1
$skus = Get-MgSubscribedSku -All
$plans = @($skus | ForEach-Object { $_.ServicePlans.ServicePlanName })
$tenant = [ordered]@{
    id = $org.Id
    defaultDomain = ($org.VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -First 1).Name
    displayName = $org.DisplayName
    licenses = @($skus.SkuPartNumber)
    entraIdP1 = ($plans -contains 'AAD_PREMIUM') -or ($plans -contains 'AAD_PREMIUM_P2')
    entraIdP2 = ($plans -contains 'AAD_PREMIUM_P2')
}
$secDefaults = [ordered]@{ enabled = [bool](Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy).IsEnabled }

# ---------------------------------------------------------------- users and MFA methods
Write-Host "[2/7] users and registered authentication methods"
$props = 'Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,CreatedDateTime,SignInActivity,OnPremisesSyncEnabled,AssignedLicenses'
$mgUsers = Get-MgUser -All -Property $props
$byId = @{}
foreach ($u in $mgUsers) { $byId[$u.Id] = $u.UserPrincipalName }
$methods = @{}
foreach ($r in Get-MgReportAuthenticationMethodUserRegistrationDetail -All) {
    $methods[$r.Id] = @(Arr $r.MethodsRegistered | ForEach-Object { $MethodMap[$_] } |
        Where-Object { $_ } | Sort-Object -Unique)
}
$skuName = @{}
foreach ($s in $skus) { $skuName[[string]$s.SkuId] = $s.SkuPartNumber }
$mailboxes = $null
if (Has-Cmd 'Get-EXOMailbox') {
    $mailboxes = @{}
    foreach ($m in Get-EXOMailbox -ResultSize Unlimited -Properties UserPrincipalName) {
        $mailboxes[$m.UserPrincipalName.ToLower()] = $true
    }
} else { Write-Warning "Exchange Online not connected: users[].hasMailbox set to false" }
$users = foreach ($u in $mgUsers) {
    [ordered]@{
        userPrincipalName = $u.UserPrincipalName
        displayName = $u.DisplayName
        accountEnabled = [bool]$u.AccountEnabled
        userType = $(if ($u.UserType -eq 'Guest') { 'Guest' } else { 'Member' })
        createdDateTime = Iso $u.CreatedDateTime
        lastSignInDateTime = Iso $u.SignInActivity.LastSignInDateTime
        onPremisesSyncEnabled = [bool]$u.OnPremisesSyncEnabled
        assignedLicenses = @(Arr $u.AssignedLicenses | ForEach-Object { $skuName[[string]$_.SkuId] } | Where-Object { $_ })
        hasMailbox = [bool]($mailboxes -and $mailboxes[$u.UserPrincipalName.ToLower()])
        authMethods = @(Arr $methods[$u.Id])
        isBreakGlass = [bool]($BreakGlassUpn -contains $u.UserPrincipalName)
    }
}

# ---------------------------------------------------------------- roles (active + PIM eligible)
Write-Host "[3/7] directory role assignments"
$roleName = @{}
foreach ($d in Get-MgRoleManagementDirectoryRoleDefinition -All) {
    $roleName[$d.Id] = $d.DisplayName
    if ($d.TemplateId) { $roleName[$d.TemplateId] = $d.DisplayName }
}
function Role-Item($a, $type) {
    $p = $byId[$a.PrincipalId]
    [ordered]@{
        roleName = $roleName[$a.RoleDefinitionId]
        principal = $(if ($p) { $p } else { $a.PrincipalId })
        principalType = $(if ($p) { 'user' } else { 'group' })   # non-user principals: review by hand
        assignmentType = $type
        endDateTime = Iso $a.ScheduleInfo.Expiration.EndDateTime
    }
}
$roles = @()
try {
    $roles += foreach ($a in Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All) { Role-Item $a 'active' }
    $roles += foreach ($a in Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All) { Role-Item $a 'eligible' }
} catch {
    Write-Warning "PIM schedules unavailable (no P2?): falling back to static role assignments"
    $roles = foreach ($a in Get-MgRoleManagementDirectoryRoleAssignment -All) {
        $p = $byId[$a.PrincipalId]
        [ordered]@{ roleName = $roleName[$a.RoleDefinitionId]
            principal = $(if ($p) { $p } else { $a.PrincipalId })
            principalType = $(if ($p) { 'user' } else { 'group' })
            assignmentType = 'active'; endDateTime = $null }
    }
}

# ---------------------------------------------------------------- Conditional Access
Write-Host "[4/7] Conditional Access policies"
function Upns($ids) { @(Arr $ids | ForEach-Object { if ($byId[$_]) { $byId[$_] } else { $_ } }) }
$ca = foreach ($p in Get-MgIdentityConditionalAccessPolicy -All) {
    $c = $p.Conditions
    if ((Arr $c.Users.IncludeGroups).Count -or (Arr $c.Users.ExcludeGroups).Count) {
        Write-Warning "CA '$($p.DisplayName)': group include/exclude not resolved, review by hand"
    }
    $grant = @(Arr $p.GrantControls.BuiltInControls)
    if ($p.GrantControls.AuthenticationStrength.Id) { $grant += 'authenticationStrength' }
    [ordered]@{
        displayName = $p.DisplayName
        state = [string]$p.State
        includeUsers = Upns $c.Users.IncludeUsers
        excludeUsers = Upns $c.Users.ExcludeUsers
        includeRoles = @(Arr $c.Users.IncludeRoles | ForEach-Object { $roleName[$_] } | Where-Object { $_ })
        includeApplications = @(Arr $c.Applications.IncludeApplications)
        clientAppTypes = @(Arr $c.ClientAppTypes | ForEach-Object { [string]$_ })
        grantControls = @($grant | ForEach-Object { [string]$_ })
        signInRiskLevels = @(Arr $c.SignInRiskLevels | ForEach-Object { [string]$_ })
        userRiskLevels = @(Arr $c.UserRiskLevels | ForEach-Object { [string]$_ })
    }
}

# ---------------------------------------------------------------- authorization, password, domains
Write-Host "[5/7] authorization policy, password expiration, domains"
$az = Get-MgPolicyAuthorizationPolicy
$grants = @(Arr $az.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
$consent = 'none'
if ($grants -match 'microsoft-user-default-legacy') { $consent = 'allowAll' }
elseif ($grants -match 'microsoft-user-default-low') { $consent = 'allowVerifiedLowRisk' }
$guestRole = @{ 'a0b1b346-4d3e-4e8b-98f8-753e3db50fdc' = 'sameAsMember'
                '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'limited'
                '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'restricted' }
$authz = [ordered]@{
    userConsent = $consent
    guestUserAccess = $guestRole[[string]$az.GuestUserRoleId]
    allowInvitesFrom = [string]$az.AllowInvitesFrom
    usersCanRegisterApps = [bool]$az.DefaultUserRolePermissions.AllowedToCreateApps
}
$mgDomains = @(Get-MgDomain -All | Where-Object { $_.IsVerified })
$validity = ($mgDomains | Where-Object { $_.IsDefault } | Select-Object -First 1).PasswordValidityPeriodInDays
$pwdPolicy = [ordered]@{ expirationDays = $(if ($null -eq $validity -or $validity -ge 2147483647) { 0 } else { [int]$validity }) }
function Txt($name) {
    if (-not (Has-Cmd 'Resolve-DnsName')) { return @() }
    try { @(Resolve-DnsName -Name $name -Type TXT -ErrorAction Stop | ForEach-Object { $_.Strings -join '' }) }
    catch { @() }
}
$domains = foreach ($d in $mgDomains) {
    $spf = (Txt $d.Id | Where-Object { $_ -like 'v=spf1*' } | Select-Object -First 1)
    $dmarc = (Txt "_dmarc.$($d.Id)" | Where-Object { $_ -like 'v=DMARC1*' } | Select-Object -First 1)
    $policy = $null
    if ($dmarc -match 'p=(none|quarantine|reject)') { $policy = $Matches[1] }
    $dkim = $false
    if (Has-Cmd 'Get-DkimSigningConfig') {
        try { $dkim = [bool](Get-DkimSigningConfig -Identity $d.Id -ErrorAction Stop).Enabled } catch { }
    }
    [ordered]@{ name = $d.Id; isDefault = [bool]$d.IsDefault; dkimEnabled = $dkim
                dmarcPolicy = $policy; spfRecord = $(if ($spf) { $spf } else { '' }) }
}

# ---------------------------------------------------------------- OAuth applications
Write-Host "[6/7] service principals and their permissions (no secrets requested)"
$sps = @{}
foreach ($s in Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,AppOwnerOrganizationId,VerifiedPublisher,AppRoles) {
    $sps[$s.Id] = $s
}
$perApp = @{}
function Add-Perm($spId, $name, $type, $consentType, $who) {
    if (-not $perApp.ContainsKey($spId)) { $perApp[$spId] = @{ perms = @(); by = '' } }
    $perApp[$spId].perms += [ordered]@{ name = $name; type = $type; consentType = $consentType }
    if ($who -and -not $perApp[$spId].by) { $perApp[$spId].by = $who }
}
foreach ($g in Get-MgOauth2PermissionGrant -All) {         # delegated permissions
    $who = $(if ($g.ConsentType -eq 'Principal') { $byId[$g.PrincipalId] } else { '' })
    foreach ($scope in ([string]$g.Scope).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
        Add-Perm $g.ClientId $scope 'Delegated' ([string]$g.ConsentType) $who
    }
}
foreach ($spId in @($sps.Keys)) {                           # application permissions
    foreach ($ra in Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -All) {
        $res = $sps[$ra.ResourceId]
        $role = $(if ($res) { $res.AppRoles | Where-Object { $_.Id -eq $ra.AppRoleId } | Select-Object -First 1 })
        $name = $(if ($role) { $role.Value } else { [string]$ra.AppRoleId })
        Add-Perm $spId $name 'Application' 'AllPrincipals' ''
    }
}
$apps = foreach ($spId in $perApp.Keys) {
    $s = $sps[$spId]
    if (-not $s) { continue }
    [ordered]@{
        displayName = $s.DisplayName; appId = $s.AppId
        publisherVerified = [bool]$s.VerifiedPublisher.VerifiedPublisherId
        isMicrosoftFirstParty = [bool]($MsftTenants -contains [string]$s.AppOwnerOrganizationId)
        consentedBy = $perApp[$spId].by
        permissions = @($perApp[$spId].perms)
    }
}

# ---------------------------------------------------------------- Exchange, Teams, SharePoint
Write-Host "[7/7] Exchange Online, Teams, SharePoint (only if connected)"
$audit = $null; $exchange = $null; $teams = $null; $sharepoint = $null
if (Has-Cmd 'Get-AdminAuditLogConfig') {
    $audit = [ordered]@{
        unifiedAuditLogEnabled = [bool](Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
        mailboxAuditByDefault = -not [bool](Get-OrganizationConfig).AuditDisabled
        auditBypassMailboxes = @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited |
            Where-Object { $_.AuditBypassEnabled } | ForEach-Object { [string]$_.Identity })
    }
    $exchange = [ordered]@{
        autoForwardingMode = [string](Get-HostedOutboundSpamFilterPolicy -Identity Default).AutoForwardingMode
        remoteDomainAutoForward = [bool](Get-RemoteDomain -Identity Default).AutoForwardEnabled
    }
} else { Write-Warning "Exchange Online not connected: 'audit' and 'exchange' left null" }
if (Has-Cmd 'Get-CsTenantFederationConfiguration') {
    $fed = Get-CsTenantFederationConfiguration
    $allowed = @(Arr $fed.AllowedDomains.AllowedDomain | ForEach-Object { [string]$_.Domain })
    $ext = 'blocked'
    if ($fed.AllowFederatedUsers) { $ext = $(if ($allowed.Count) { 'allowList' } else { 'allowAll' }) }
    $teams = [ordered]@{ externalAccess = $ext; allowedDomains = $allowed
                         consumerAccess = [bool]$fed.AllowTeamsConsumer }
} else { Write-Warning "Microsoft Teams not connected: 'teams' left null" }
if (Has-Cmd 'Get-SPOTenant') {
    $spo = Get-SPOTenant
    $link = [string]$spo.DefaultSharingLinkType
    $sharepoint = [ordered]@{
        sharingCapability = [string]$spo.SharingCapability
        anyoneLinkExpirationDays = [math]::Max(0, [int]$spo.RequireAnonymousLinksExpireInDays)
        defaultSharingLinkType = $(if ($link -in 'AnonymousAccess', 'Direct') { $link } else { 'Internal' })
    }
} else { Write-Warning "SharePoint Online not connected: 'sharepoint' left null" }

# ---------------------------------------------------------------- write
$export = [ordered]@{
    schemaVersion = '1.0'
    exportedAt = Iso (Get-Date)
    tenant = $tenant
    securityDefaults = $secDefaults
    conditionalAccessPolicies = @($ca)
    users = @($users)
    directoryRoleAssignments = @($roles)
    authorizationPolicy = $authz
    passwordPolicy = $pwdPolicy
    sspr = $null            # complete by hand: { enabled, methodsRequired, methods }
    audit = $audit
    exchange = $exchange
    domains = @($domains)
    applications = @($apps)
    teams = $teams
    sharepoint = $sharepoint
    monitoring = $null      # complete by hand: { breakGlassSignInAlert: true/false }
}
$export | ConvertTo-Json -Depth 8 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Written: $OutFile  (CONFIDENTIAL - complete the null sections, then run m365audit)"
