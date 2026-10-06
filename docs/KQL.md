# KQL hunting queries (Microsoft Sentinel / Defender)

> **Statut : syntaxe relue, non exécutée sur un vrai tenant.** These queries were written
> from the public schema of the `SigninLogs`, `AuditLogs` and `OfficeActivity` tables and
> reviewed by hand. They have **never been run** against a real workspace. Column names,
> `ResultType` values and `modifiedProperties` labels must be checked in your own workspace
> before you rely on them, and thresholds tuned to your normal activity.

One query per Python detection (`m365audit/detect/rules.py`). Thresholds mirror the
`detections` section of `config/default.yaml`.

Field mapping between the simplified JSONL logs (docs/SCHEMA.md part B) and the tables:

| JSONL field | `SigninLogs` column |
|---|---|
| `time` | `TimeGenerated` |
| `userPrincipalName` | `UserPrincipalName` |
| `ipAddress` | `IPAddress` |
| `resultType` (int) | `ResultType` (**string** in Sentinel: `"0"`, `"50126"`...) |
| `clientAppUsed` | `ClientAppUsed` |
| `country` / `city` | `LocationDetails.countryOrRegion` / `LocationDetails.city` |
| `latitude` / `longitude` | `LocationDetails.geoCoordinates.latitude` / `.longitude` |

Interactive sign-ins only: legacy protocols and some clients also appear in
`AADNonInteractiveUserSignInLogs`; a production rule should `union` both tables.

## det-001-password-spray

```kql
// DET-001 - many accounts failing from one IP in a short window
let lookback = 7d;
let window = 60m;
let minUsers = 10;
let failures = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType in ("50126", "50053")   // bad password, locked / blocked
    | summarize Users = dcount(UserPrincipalName), Failures = count(),
                Clients = make_set(ClientAppUsed), FirstSeen = min(TimeGenerated),
                LastSeen = max(TimeGenerated)
        by IPAddress, Bucket = bin(TimeGenerated, window)
    | where Users >= minUsers;
failures
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(lookback) and ResultType == "0"
    | summarize SuccessUsers = make_set(UserPrincipalName) by IPAddress
  ) on IPAddress
| project FirstSeen, LastSeen, IPAddress, Users, Failures, Clients, SuccessUsers
```

Difference with the Python rule: `bin()` uses fixed windows, the Python rule a sliding window
(a burst split across two bins can be missed here).

## det-002-mfa-fatigue

```kql
// DET-002 - burst of MFA denials followed by an approval
let lookback = 7d;
let window = 30m;
let minDenials = 5;
let successWithin = 60m;
SigninLogs
| where TimeGenerated > ago(lookback) and ResultType == "500121"
| summarize Denials = count(), FirstDenial = min(TimeGenerated),
            LastDenial = max(TimeGenerated), IPs = make_set(IPAddress)
    by UserPrincipalName, Bucket = bin(TimeGenerated, window)
| where Denials >= minDenials
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(lookback) and ResultType == "0"
    | project UserPrincipalName, SuccessTime = TimeGenerated, SuccessIP = IPAddress
  ) on UserPrincipalName
| extend Approved = SuccessTime > LastDenial and SuccessTime <= LastDenial + successWithin
| summarize Approved = max(toint(Approved)) by UserPrincipalName, FirstDenial, LastDenial,
            Denials, tostring(IPs)
| extend Severity = iff(Approved == 1, "High", "Medium")
```

## det-003-legacy-auth

```kql
// DET-003 - successful sign-in with a legacy (basic auth) client
let legacy = dynamic(["Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP",
    "Exchange Web Services", "MAPI Over HTTP", "Offline Address Book", "Autodiscover",
    "Other clients"]);
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0" and ClientAppUsed in (legacy)
| summarize Count = count(), First = min(TimeGenerated)
    by UserPrincipalName, ClientAppUsed, IPAddress,
       Country = tostring(LocationDetails.countryOrRegion)
```

## det-004-impossible-travel

```kql
// DET-004 - two successful sign-ins too far apart for the elapsed time
let minKm = 500.0;
let maxKmh = 900.0;
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == "0"
| extend Lat = toreal(LocationDetails.geoCoordinates.latitude),
         Lon = toreal(LocationDetails.geoCoordinates.longitude),
         Country = tostring(LocationDetails.countryOrRegion)
| where isnotnull(Lat) and isnotnull(Lon)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, Lat, Lon
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevUser = prev(UserPrincipalName), PrevTime = prev(TimeGenerated),
         PrevLat = prev(Lat), PrevLon = prev(Lon), PrevCountry = prev(Country)
| where UserPrincipalName == PrevUser
| extend Km = geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000.0,
         Hours = datetime_diff("second", TimeGenerated, PrevTime) / 3600.0
| where Km >= minKm
| extend Kmh = iff(Hours <= 0, real(+inf), Km / Hours)
| where Kmh > maxKmh
| project TimeGenerated, UserPrincipalName, PrevCountry, Country, IPAddress, Km, Hours, Kmh
```

Entra ID Protection already raises an "atypical travel" risk with P2; this query is the
transparent, tunable version (VPN egress and mobile proxies are the usual false positives).

## det-005-bec-forwarding

```kql
// DET-005 - sign-in from an unusual country, then an external forwarding rule within 24h
let usualCountries = dynamic(["MA"]);
let internalDomains = dynamic(["agrisouss.ma", "agrisouss.onmicrosoft.com"]);
let unfamiliar = SigninLogs
    | where TimeGenerated > ago(14d) and ResultType == "0"
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | where isnotempty(Country) and Country !in (usualCountries)
    | project SigninTime = TimeGenerated, UPN = tolower(UserPrincipalName), Country,
              SigninIP = IPAddress;
OfficeActivity
| where TimeGenerated > ago(14d)
| where OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")
| mv-expand Param = todynamic(Parameters)
| where tostring(Param.Name) in ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo",
                                 "ForwardingSmtpAddress", "ForwardingAddress")
| extend Target = tolower(tostring(Param.Value)), UPN = tolower(UserId)
| where Target contains "@"
| extend TargetDomain = tostring(split(Target, "@")[-1])
| where TargetDomain !in (internalDomains)
| join kind=inner unfamiliar on UPN
| where TimeGenerated between (SigninTime .. (SigninTime + 24h))
| project SigninTime, Country, SigninIP, RuleTime = TimeGenerated, UPN, Operation, Target
```

Limits: the Python rule also requires the country to be **new for this user** (needs a
baseline, e.g. a 30-day `make_set` of countries per user); `UpdateInboxRules` from Outlook
clients stores rule details in a different shape; a target list such as
`"a@x.com;b@y.com"` should be split before the domain test.

## det-006-oauth-consent

```kql
// DET-006 - consent to an application with high-privilege permissions
let high = dynamic(["Mail.ReadWrite", "Mail.Read", "Mail.Send", "MailboxSettings.ReadWrite",
    "Files.ReadWrite.All", "Files.Read.All", "Sites.FullControl.All", "Sites.ReadWrite.All",
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All", "User.ReadWrite.All",
    "full_access_as_app", "EWS.AccessAsUser.All"]);
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName == "Consent to application"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         ActorIP = tostring(InitiatedBy.user.ipAddress),
         AppName = tostring(TargetResources[0].displayName),
         AppObjectId = tostring(TargetResources[0].id)
| mv-expand Prop = TargetResources[0].modifiedProperties
| extend PropName = tostring(Prop.displayName), PropValue = tostring(Prop.newValue)
| summarize Permissions = make_set_if(PropValue, PropName == "ConsentAction.Permissions"),
            AdminConsent = make_set_if(PropValue, PropName == "ConsentContext.IsAdminConsent")
    by TimeGenerated, Actor, ActorIP, AppName, AppObjectId
| extend PermText = tostring(Permissions)
| mv-expand Perm = high to typeof(string)
| where PermText contains Perm
| summarize RiskyPermissions = make_set(Perm)
    by TimeGenerated, Actor, ActorIP, AppName, AppObjectId, tostring(AdminConsent)
```

`contains` is a substring test: `Mail.Read` also matches inside `Mail.ReadWrite` (harmless
here, both are risky) but would match `Mail.ReadBasic` too; parse the scope list for a
production rule. The Unified Audit Log records the same event in `OfficeActivity` as
`Operation == "Consent to application."` (with a trailing dot).
