<#
.SYNOPSIS
    Audits Microsoft Entra MFA readiness for the retirement of Microsoft-provided
    SMS and voice authentication.

.DESCRIPTION
    Get-EntraMfaReadinessAudit.ps1 is a read-only Microsoft Entra audit intended
    for administrators preparing for the retirement of Microsoft-provided SMS
    and voice authentication.

    The script intentionally uses Microsoft Graph REST requests through
    Invoke-MgGraphRequest for policy/report data instead of depending on generated
    Microsoft.Graph.Identity.SignIns policy cmdlets.

    The audit can:
      - Read SMS and Voice Authentication Methods policy configuration.
      - Expand included/excluded groups transitively to calculate effective user scope.
      - Read the Authentication Methods user registration report.
      - Correlate registered methods, MFA capability, passwordless capability, and
        system/user preferred methods to effective policy scope.
      - Read user sign-in activity to distinguish active, inactive, and accounts
        with no retained successful sign-in timestamp.
      - Classify users by authentication origin (internal/external) independently
        from UserType, including Internal Guest, External Guest, Internal Member,
        and External Member classifications for retirement planning.
      - Read Security Defaults and Conditional Access policies that require MFA or
        an MFA-satisfying authentication strength.
      - Evaluate user/group scope of those Conditional Access policies.
      - Optionally inspect recent sign-in authentication details and actual telephony
        usage, including Graph labels such as "Text message" and
        "Phone call approval (Authentication phone)".
      - Build migration waves that separate recent telephony users, likely telephony-
        dependent users, Authenticator-ready users, phishing-resistant users, and
        unregistered accounts with no retained successful sign-in.
      - Optionally pseudonymize exported identities while retaining cross-file and,
        with a supplied key, cross-run correlation.

    This tool does not change tenant configuration.

.PARAMETER TenantId
    Optional tenant ID or verified domain passed to Connect-MgGraph when a new
    Graph connection is required.

.PARAMETER OutputDirectory
    Output directory. If omitted, a timestamped folder is created under the
    current directory.

.PARAMETER IncludeRecentUsage
    Inspect recent sign-in logs for authentication methods, SMS/voice use, MFA
    requirements, and applicable Conditional Access MFA policies.

    Recent authentication detail analysis uses Microsoft Graph beta sign-in
    properties. Core policy, registration, Conditional Access, Security Defaults,
    and signInActivity analysis uses Microsoft Graph v1.0.

.PARAMETER UsageDays
    Number of days of recent sign-ins to inspect. Default 30. Maximum 30.

.PARAMETER Anonymize
    Pseudonymize identifying values in exported files and identifying console output.

.PARAMETER AnonymizationKey
    Optional private string used to produce stable pseudonyms across runs.
    If omitted, a random in-memory key is generated and pseudonyms are stable only
    within the current run. The key is never written to audit output.

.EXAMPLE
    .\Scripts\Get-EntraMfaReadinessAudit.ps1

.EXAMPLE
    .\Scripts\Get-EntraMfaReadinessAudit.ps1 -IncludeRecentUsage -UsageDays 30

.EXAMPLE
    $key = Read-Host 'Private anonymization key'
    .\Scripts\Get-EntraMfaReadinessAudit.ps1 -Anonymize -AnonymizationKey $key -IncludeRecentUsage

.NOTES
    Version: 1.5.0
    License: GPL-3.0-only
    Copyright (C) 2026 Dan Michel

    Requested delegated Graph scopes:
      Policy.Read.All
      AuditLog.Read.All
      User.Read.All
      User.Read
      Group.Read.All

    Microsoft Entra directory roles can also affect access to reports and policy data.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$OutputDirectory,

    [Parameter()]
    [switch]$IncludeRecentUsage,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$UsageDays = 30,

    [Parameter()]
    [switch]$Anonymize,

    [Parameter()]
    [string]$AnonymizationKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.5.0'
$GraphV1       = 'https://graph.microsoft.com/v1.0'
$GraphBeta     = 'https://graph.microsoft.com/beta'
$script:CurrentAuditStage = 'Startup'
$script:GroupNameCache = @{}
$script:GroupMemberCache = @{}
$script:AnonymizationKeyBytes = $null

function Set-AuditStage {
    param([Parameter(Mandatory)][string]$Name)
    $script:CurrentAuditStage = $Name
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkGray
}

function Write-AuditFailureContext {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    Write-Host ''
    Write-Host 'MFA Audit diagnostic context' -ForegroundColor Red
    Write-Host "Stage: $script:CurrentAuditStage" -ForegroundColor Red

    if ($ErrorRecord.InvocationInfo) {
        Write-Host ("Script line: {0}" -f $ErrorRecord.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
        if ($ErrorRecord.InvocationInfo.Line) {
            Write-Host ("Code: {0}" -f $ErrorRecord.InvocationInfo.Line.Trim()) -ForegroundColor Red
        }
    }

    if ($ErrorRecord.ScriptStackTrace) {
        Write-Host 'Stack:' -ForegroundColor Red
        Write-Host $ErrorRecord.ScriptStackTrace -ForegroundColor Red
    }
}

function Get-Prop {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Default = $null
    )

    if ($null -eq $Object) { return $Default }

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }

    return $Default
}

function Get-UserIdentityOriginInfo {
    param(
        [Parameter(Mandatory)][object]$User,
        [string[]]$HostDomains = @()
    )

    $userType = [string](Get-Prop -Object $User -Name 'userType' -Default '')
    $upn = [string](Get-Prop -Object $User -Name 'userPrincipalName' -Default '')
    $externalUserState = [string](Get-Prop -Object $User -Name 'externalUserState' -Default '')
    $identities = @(Get-Prop -Object $User -Name 'identities' -Default @())

    $normalizedHostDomains = @(
        $HostDomains |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
            Select-Object -Unique
    )

    $externalIssuerDetected = $false
    $hostIssuerDetected = $false

    foreach ($identity in $identities) {
        $issuer = [string](Get-Prop -Object $identity -Name 'issuer' -Default '')
        if ([string]::IsNullOrWhiteSpace($issuer)) { continue }

        # Issuer comparison is only authoritative when the tenant's verified
        # domains were successfully retrieved. If not, fall back to invitation
        # state and B2B UPN indicators rather than treating every issuer as external.
        if (@($normalizedHostDomains).Count -gt 0) {
            $normalizedIssuer = $issuer.Trim().ToLowerInvariant()
            if ($normalizedIssuer -in $normalizedHostDomains) {
                $hostIssuerDetected = $true
            }
            else {
                # For workforce tenants, an identity issuer outside the tenant's
                # verified domains indicates authentication is homed elsewhere.
                $externalIssuerDetected = $true
            }
        }
    }

    $isExternal = $false
    $confidence = 'Inferred'
    $basis = 'No explicit external identity indicator was found.'

    if ($externalUserState -in @('Accepted', 'PendingAcceptance')) {
        $isExternal = $true
        $confidence = 'High'
        $basis = 'B2B invitation state indicates an external identity.'
    }
    elseif ($externalIssuerDetected) {
        $isExternal = $true
        $confidence = 'High'
        $basis = 'At least one sign-in identity issuer is outside the tenant verified domains.'
    }
    elseif ($upn -match '#EXT#@') {
        $isExternal = $true
        $confidence = 'High'
        $basis = 'B2B-style #EXT# user principal name detected.'
    }
    elseif ($hostIssuerDetected) {
        $isExternal = $false
        $confidence = 'High'
        $basis = 'Sign-in identity issuer is a verified domain of this tenant.'
    }
    else {
        $isExternal = $false
        $confidence = 'Inferred'
        $basis = 'No external identity indicator was found; treated as internally authenticated.'
    }

    $origin = if ($isExternal) { 'External' } else { 'Internal' }
    $relationship = if ($userType -eq 'Guest') { 'Guest' } elseif ($userType -eq 'Member') { 'Member' } else { 'Unknown' }
    $classification = "$origin $relationship"

    $retirementMilestone = if ($isExternal) {
        'July 1, 2027 - external user'
    }
    elseif ($userType -eq 'Guest') {
        'February 1, 2027 - internal guest'
    }
    else {
        'February 1, 2027 - internal user (Global Administrators are July 1, 2027)'
    }

    [PSCustomObject]@{
        IdentityOrigin              = $origin
        UserClassification          = $classification
        IsExternalUser              = $isExternal
        IdentityOriginConfidence    = $confidence
        IdentityClassificationBasis = $basis
        ExternalUserState           = $externalUserState
        TelephonyRetirementMilestone = $retirementMilestone
    }
}

function ConvertTo-UtcText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    try {
        return ([datetimeoffset]$Value).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ssZ')
    }
    catch {
        return [string]$Value
    }
}

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)

    Invoke-MgGraphRequest `
        -Method GET `
        -Uri $Uri `
        -OutputType PSObject `
        -ErrorAction Stop
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $response = Invoke-GraphGet -Uri $nextUri
        foreach ($item in @(Get-Prop -Object $response -Name 'value' -Default @())) {
            if ($null -ne $item) { $items.Add($item) }
        }
        $nextUri = [string](Get-Prop -Object $response -Name '@odata.nextLink' -Default '')
    }

    return $items.ToArray()
}

function Ensure-GraphConnection {
    $requiredScopes = @(
        'Policy.Read.All',
        'AuditLog.Read.All',
        'User.Read.All',
        'User.Read',
        'Group.Read.All'
    )

    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) -or
        -not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw @'
Microsoft.Graph.Authentication is required.

Install it with:
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
'@
    }

    $context = Get-MgContext -ErrorAction SilentlyContinue
    $missingScopes = @()
    $tenantMismatch = $false

    if ($null -ne $context) {
        $currentScopes = @($context.Scopes)
        foreach ($scope in $requiredScopes) {
            if ($scope -notin $currentScopes) { $missingScopes += $scope }
        }

        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $tenantMismatch = ([string]$context.TenantId -ne $TenantId -and [string]$context.TenantId -notlike $TenantId)
        }
    }
    else {
        $missingScopes = $requiredScopes
    }

    if (($null -eq $context) -or @($missingScopes).Count -gt 0 -or $tenantMismatch) {
        if ($null -ne $context) {
            if (@($missingScopes).Count -gt 0) {
                Write-Host "Current Graph session is missing: $($missingScopes -join ', ')" -ForegroundColor Yellow
            }
            if ($tenantMismatch) {
                Write-Host 'Current Graph session does not match the requested tenant.' -ForegroundColor Yellow
            }
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }

        $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $connectParams['TenantId'] = $TenantId
        }

        Connect-MgGraph @connectParams
        $context = Get-MgContext
    }

    return $context
}

function Initialize-Anonymization {
    if (-not $Anonymize) { return }

    if (-not [string]::IsNullOrWhiteSpace($AnonymizationKey)) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $script:AnonymizationKeyBytes = $sha.ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($AnonymizationKey)
            )
        }
        finally {
            $sha.Dispose()
        }
    }
    else {
        $script:AnonymizationKeyBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($script:AnonymizationKeyBytes) }
        finally { $rng.Dispose() }
    }
}

function Get-AnonymizedToken {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [AllowNull()][string]$Value,
        [ValidateRange(6, 32)][int]$Length = 10
    )

    if (-not $Anonymize) { return $Value }
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    if ($null -eq $script:AnonymizationKeyBytes) { throw 'Anonymization has not been initialized.' }

    $normalized = '{0}|{1}' -f $Kind.ToUpperInvariant(), $Value.Trim().ToLowerInvariant()
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($script:AnonymizationKeyBytes)
    try {
        $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalized))
    }
    finally {
        $hmac.Dispose()
    }

    $hex = ([System.BitConverter]::ToString($hash)).Replace('-', '')
    return $hex.Substring(0, $Length)
}

function Get-AnonymizedUserValues {
    param([string]$ObjectId, [string]$UserPrincipalName)

    $seed = if ($ObjectId) { $ObjectId } else { $UserPrincipalName }
    $token = Get-AnonymizedToken -Kind 'User' -Value $seed

    [PSCustomObject]@{
        DisplayName       = if ($token) { "User-$token" } else { '' }
        UserPrincipalName = if ($token) { "user-$($token.ToLowerInvariant())@example.invalid" } else { '' }
        ObjectId          = if ($token) { "USR-$token" } else { '' }
    }
}

function Get-AnonymizedGroupId {
    param([string]$GroupId)
    if (-not $Anonymize -or $GroupId -eq 'all_users') { return $GroupId }
    $token = Get-AnonymizedToken -Kind 'Group' -Value $GroupId
    if ($token) { return "GRP-$token" }
    return ''
}

function Get-AnonymizedGroupName {
    param([string]$GroupId, [string]$GroupName)
    if (-not $Anonymize) { return $GroupName }
    if ($GroupId -eq 'all_users') { return 'All users' }
    $token = Get-AnonymizedToken -Kind 'Group' -Value $GroupId
    if ($token) { return "Group-$token" }
    return ''
}

function Get-AnonymizedApplicationName {
    param([string]$ApplicationName)
    if (-not $Anonymize -or [string]::IsNullOrWhiteSpace($ApplicationName)) { return $ApplicationName }
    $token = Get-AnonymizedToken -Kind 'Application' -Value $ApplicationName
    if ($token) { return "App-$token" }
    return ''
}

function Get-AnonymizedPolicyName {
    param([string]$PolicyId, [string]$PolicyName)
    if (-not $Anonymize) { return $PolicyName }
    $seed = if ($PolicyId) { $PolicyId } else { $PolicyName }
    $token = Get-AnonymizedToken -Kind 'ConditionalAccessPolicy' -Value $seed
    if ($token) { return "CA-Policy-$token" }
    return ''
}

function Get-AnonymizedPolicyId {
    param([string]$PolicyId)
    if (-not $Anonymize) { return $PolicyId }
    $token = Get-AnonymizedToken -Kind 'ConditionalAccessPolicy' -Value $PolicyId
    if ($token) { return "CAP-$token" }
    return ''
}

function Get-AnonymizedTenantId {
    param([string]$Value)
    if (-not $Anonymize) { return $Value }
    $token = Get-AnonymizedToken -Kind 'Tenant' -Value $Value
    if ($token) { return "TEN-$token" }
    return ''
}

function Get-AnonymizedAccount {
    param([string]$Value)
    if (-not $Anonymize) { return $Value }
    $token = Get-AnonymizedToken -Kind 'AdminAccount' -Value $Value
    if ($token) { return "Admin-$token" }
    return ''
}

function Get-GroupName {
    param([Parameter(Mandatory)][string]$GroupId)

    if ($script:GroupNameCache.ContainsKey($GroupId)) { return [string]$script:GroupNameCache[$GroupId] }

    try {
        $group = Invoke-GraphGet -Uri "$GraphV1/groups/${GroupId}?`$select=id,displayName"
        $name = [string](Get-Prop -Object $group -Name 'displayName' -Default $GroupId)
    }
    catch {
        $name = $GroupId
        $warningGroup = if ($Anonymize) { Get-AnonymizedGroupId -GroupId $GroupId } else { $GroupId }
        Write-Warning "Could not resolve group $warningGroup. $($_.Exception.Message)"
    }

    $script:GroupNameCache[$GroupId] = $name
    return $name
}

function Get-GroupUserSet {
    param([Parameter(Mandatory)][string]$GroupId)

    if ($script:GroupMemberCache.ContainsKey($GroupId)) { return $script:GroupMemberCache[$GroupId] }

    $set = @{}
    $uri = "$GraphV1/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
    foreach ($member in @(Get-GraphCollection -Uri $uri)) {
        $id = [string](Get-Prop -Object $member -Name 'id' -Default '')
        if ($id) { $set[$id] = $true }
    }

    $script:GroupMemberCache[$GroupId] = $set
    return $set
}

function Add-AuthenticationMethodTargetToSet {
    param(
        [Parameter(Mandatory)][hashtable]$Set,
        [Parameter(Mandatory)][object]$Target,
        [Parameter(Mandatory)][object[]]$AllUsers
    )

    $targetId = [string](Get-Prop -Object $Target -Name 'id' -Default '')
    $targetType = [string](Get-Prop -Object $Target -Name 'targetType' -Default 'group')
    if (-not $targetId) { return }

    if ($targetId -eq 'all_users') {
        foreach ($user in @($AllUsers)) {
            $id = [string](Get-Prop -Object $user -Name 'id' -Default '')
            if ($id) { $Set[$id] = $true }
        }
        return
    }

    if ($targetType -eq 'user') {
        $Set[$targetId] = $true
        return
    }

    foreach ($id in (Get-GroupUserSet -GroupId $targetId).Keys) {
        $Set[$id] = $true
    }
}

function Remove-AuthenticationMethodTargetFromSet {
    param(
        [Parameter(Mandatory)][hashtable]$Set,
        [Parameter(Mandatory)][object]$Target
    )

    $targetId = [string](Get-Prop -Object $Target -Name 'id' -Default '')
    $targetType = [string](Get-Prop -Object $Target -Name 'targetType' -Default 'group')
    if (-not $targetId) { return }

    if ($targetId -eq 'all_users') {
        $Set.Clear()
        return
    }

    if ($targetType -eq 'user') {
        if ($Set.ContainsKey($targetId)) { $Set.Remove($targetId) }
        return
    }

    foreach ($id in (Get-GroupUserSet -GroupId $targetId).Keys) {
        if ($Set.ContainsKey($id)) { $Set.Remove($id) }
    }
}

function Get-AuthenticationMethodPolicyScope {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][object[]]$AllUsers
    )

    $state = [string](Get-Prop -Object $Configuration -Name 'state' -Default 'unknown')
    $includes = @(Get-Prop -Object $Configuration -Name 'includeTargets' -Default @())
    $excludes = @(Get-Prop -Object $Configuration -Name 'excludeTargets' -Default @())

    $effective = @{}
    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($target in $includes) {
        $targetId = [string](Get-Prop -Object $target -Name 'id' -Default '')
        $targetType = [string](Get-Prop -Object $target -Name 'targetType' -Default 'group')

        if ($targetId -eq 'all_users') {
            $name = 'All users'
            $count = @($AllUsers).Count
        }
        elseif ($targetType -eq 'user') {
            $name = $targetId
            $count = 1
        }
        else {
            $name = Get-GroupName -GroupId $targetId
            $count = (Get-GroupUserSet -GroupId $targetId).Count
        }

        $rows.Add([PSCustomObject]@{
            Method      = $Method
            PolicyState = $state
            Action      = 'Include'
            TargetType  = $targetType
            TargetId    = $targetId
            TargetName  = $name
            MemberCount = $count
        })

        if ($state -eq 'enabled') {
            Add-AuthenticationMethodTargetToSet -Set $effective -Target $target -AllUsers $AllUsers
        }
    }

    foreach ($target in $excludes) {
        $targetId = [string](Get-Prop -Object $target -Name 'id' -Default '')
        $targetType = [string](Get-Prop -Object $target -Name 'targetType' -Default 'group')

        if ($targetId -eq 'all_users') {
            $name = 'All users'
            $count = @($AllUsers).Count
        }
        elseif ($targetType -eq 'user') {
            $name = $targetId
            $count = 1
        }
        else {
            $name = Get-GroupName -GroupId $targetId
            $count = (Get-GroupUserSet -GroupId $targetId).Count
        }

        $rows.Add([PSCustomObject]@{
            Method      = $Method
            PolicyState = $state
            Action      = 'Exclude'
            TargetType  = $targetType
            TargetId    = $targetId
            TargetName  = $name
            MemberCount = $count
        })

        if ($state -eq 'enabled') {
            Remove-AuthenticationMethodTargetFromSet -Set $effective -Target $target
        }
    }

    [PSCustomObject]@{
        Method         = $Method
        State          = $state
        EffectiveUsers = $effective
        TargetRows     = $rows.ToArray()
    }
}

function Convert-PolicyConfigurationForExport {
    param([Parameter(Mandatory)][object]$Policy, [Parameter(Mandatory)][string]$Method)

    if (-not $Anonymize) { return $Policy }

    $convertTargets = {
        param([object[]]$Targets)
        foreach ($target in @($Targets)) {
            $targetId = [string](Get-Prop -Object $target -Name 'id' -Default '')
            $targetType = [string](Get-Prop -Object $target -Name 'targetType' -Default '')
            $exportId = if ($targetType -eq 'user') {
                $token = Get-AnonymizedToken -Kind 'User' -Value $targetId
                if ($token) { "USR-$token" } else { '' }
            }
            else {
                Get-AnonymizedGroupId -GroupId $targetId
            }

            [PSCustomObject]@{ targetType = $targetType; id = $exportId }
        }
    }

    [PSCustomObject]@{
        anonymized     = $true
        method         = $Method
        state          = [string](Get-Prop -Object $Policy -Name 'state' -Default '')
        includeTargets = @(& $convertTargets @(Get-Prop -Object $Policy -Name 'includeTargets' -Default @()))
        excludeTargets = @(& $convertTargets @(Get-Prop -Object $Policy -Name 'excludeTargets' -Default @()))
    }
}

function Test-PhoneRegistered {
    param([object[]]$Methods)
    $phoneMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
    foreach ($method in @($Methods)) {
        if ([string]$method -in $phoneMethods) { return $true }
    }
    return $false
}

function Test-NonTelephonyMfa {
    param([object[]]$Methods)

    $notAlternative = @(
        'mobilePhone',
        'alternateMobilePhone',
        'officePhone',
        'email',
        'securityQuestions',
        'password',
        'temporaryAccessPass'
    )

    foreach ($method in @($Methods)) {
        $value = [string]$method
        if ($value -and $value -notin $notAlternative) { return $true }
    }
    return $false
}

function Test-PasskeyOrFido {
    param([object[]]$Methods)
    foreach ($method in @($Methods)) {
        if ([string]$method -match '(?i)passkey|fido') { return $true }
    }
    return $false
}

function Test-AuthenticatorRegistered {
    param([object[]]$Methods)

    foreach ($method in @($Methods)) {
        if ([string]$method -in @('microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless')) {
            return $true
        }
    }
    return $false
}

function Test-WindowsHelloForBusinessRegistered {
    param([object[]]$Methods)

    foreach ($method in @($Methods)) {
        if ([string]$method -eq 'windowsHelloForBusiness') { return $true }
    }
    return $false
}

function Test-PhishingResistantRegistered {
    param([object[]]$Methods)

    foreach ($method in @($Methods)) {
        $value = [string]$method
        if ($value -match '(?i)^passKey' -or
            $value -match '(?i)fido' -or
            $value -eq 'windowsHelloForBusiness') {
            return $true
        }
    }
    return $false
}

function Test-TelephonyPreferred {
    param([string]$Preferred, [object[]]$SystemPreferred)

    $telephony = @('sms', 'voiceMobile', 'voiceAlternateMobile', 'voiceOffice')
    if ($Preferred -and $Preferred -in $telephony) { return $true }
    foreach ($method in @($SystemPreferred)) {
        if ([string]$method -in $telephony) { return $true }
    }
    return $false
}

function Get-SignInHistoryInfo {
    param([Parameter(Mandatory)][object]$User)

    $activity = Get-Prop -Object $User -Name 'signInActivity' -Default $null
    $lastInteractive = Get-Prop -Object $activity -Name 'lastSignInDateTime' -Default $null
    $lastNonInteractive = Get-Prop -Object $activity -Name 'lastNonInteractiveSignInDateTime' -Default $null
    $lastSuccessful = Get-Prop -Object $activity -Name 'lastSuccessfulSignInDateTime' -Default $null

    $hasAny = ($null -ne $lastInteractive) -or ($null -ne $lastNonInteractive) -or ($null -ne $lastSuccessful)
    $hasSuccessful = ($null -ne $lastSuccessful)

    $classification = if ($hasSuccessful) {
        'Successful sign-in recorded'
    }
    elseif ($hasAny) {
        'Sign-in activity recorded; no successful timestamp'
    }
    else {
        'No retained sign-in activity'
    }

    [PSCustomObject]@{
        HasAnySignInActivity            = $hasAny
        HasSuccessfulSignInRecorded     = $hasSuccessful
        LastInteractiveSignInAttemptUtc = (ConvertTo-UtcText $lastInteractive)
        LastNonInteractiveAttemptUtc    = (ConvertTo-UtcText $lastNonInteractive)
        LastSuccessfulSignInUtc         = (ConvertTo-UtcText $lastSuccessful)
        Classification                  = $classification
    }
}

function Get-CaMfaPolicyInfo {
    $strengthById = @{}

    try {
        foreach ($strength in @(Get-GraphCollection -Uri "$GraphV1/policies/authenticationStrengthPolicies")) {
            $strengthId = [string](Get-Prop -Object $strength -Name 'id' -Default '')
            if ($strengthId) { $strengthById[$strengthId] = $strength }
        }
    }
    catch {
        Write-Warning "Could not enumerate authentication strength policies. MFA grant-control policies will still be detected. $($_.Exception.Message)"
    }

    $allPolicies = @(Get-GraphCollection -Uri "$GraphV1/identity/conditionalAccess/policies")
    $mfaPolicies = [System.Collections.Generic.List[object]]::new()
    $exportRows = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $allPolicies) {
        $grant = Get-Prop -Object $policy -Name 'grantControls' -Default $null
        if ($null -eq $grant) { continue }

        $builtIn = @((Get-Prop -Object $grant -Name 'builtInControls' -Default @()) | ForEach-Object { [string]$_ })
        $authStrength = Get-Prop -Object $grant -Name 'authenticationStrength' -Default $null
        $requiresMfa = ($builtIn -contains 'mfa')
        $requirementType = if ($requiresMfa) { 'MFA grant control' } else { '' }

        if (-not $requiresMfa -and $null -ne $authStrength) {
            $requirementsSatisfied = [string](Get-Prop -Object $authStrength -Name 'requirementsSatisfied' -Default '')
            $strengthId = [string](Get-Prop -Object $authStrength -Name 'id' -Default '')

            if (-not $requirementsSatisfied -and $strengthId -and $strengthById.ContainsKey($strengthId)) {
                $requirementsSatisfied = [string](Get-Prop -Object $strengthById[$strengthId] -Name 'requirementsSatisfied' -Default '')
            }

            if ($requirementsSatisfied -eq 'mfa') {
                $requiresMfa = $true
                $strengthName = [string](Get-Prop -Object $authStrength -Name 'displayName' -Default '')
                if (-not $strengthName -and $strengthId -and $strengthById.ContainsKey($strengthId)) {
                    $strengthName = [string](Get-Prop -Object $strengthById[$strengthId] -Name 'displayName' -Default '')
                }
                $requirementType = if ($strengthName) { "Authentication strength: $strengthName" } else { 'MFA-satisfying authentication strength' }
            }
        }

        if (-not $requiresMfa) { continue }

        $policyId = [string](Get-Prop -Object $policy -Name 'id' -Default '')
        $policyName = [string](Get-Prop -Object $policy -Name 'displayName' -Default '')
        $state = [string](Get-Prop -Object $policy -Name 'state' -Default '')
        $conditions = Get-Prop -Object $policy -Name 'conditions' -Default $null
        $usersCondition = Get-Prop -Object $conditions -Name 'users' -Default $null
        $apps = Get-Prop -Object $conditions -Name 'applications' -Default $null
        $locations = Get-Prop -Object $conditions -Name 'locations' -Default $null
        $platforms = Get-Prop -Object $conditions -Name 'platforms' -Default $null
        $devices = Get-Prop -Object $conditions -Name 'devices' -Default $null

        $includeUsers = @(Get-Prop -Object $usersCondition -Name 'includeUsers' -Default @())
        $excludeUsers = @(Get-Prop -Object $usersCondition -Name 'excludeUsers' -Default @())
        $includeGroups = @(Get-Prop -Object $usersCondition -Name 'includeGroups' -Default @())
        $excludeGroups = @(Get-Prop -Object $usersCondition -Name 'excludeGroups' -Default @())
        $includeRoles = @(Get-Prop -Object $usersCondition -Name 'includeRoles' -Default @())
        $excludeRoles = @(Get-Prop -Object $usersCondition -Name 'excludeRoles' -Default @())

        $hasOtherConditions =
            (@(Get-Prop -Object $apps -Name 'includeApplications' -Default @()).Count -gt 0) -or
            (@(Get-Prop -Object $apps -Name 'includeUserActions' -Default @()).Count -gt 0) -or
            (@(Get-Prop -Object $locations -Name 'includeLocations' -Default @()).Count -gt 0) -or
            (@(Get-Prop -Object $platforms -Name 'includePlatforms' -Default @()).Count -gt 0) -or
            ($null -ne (Get-Prop -Object $devices -Name 'deviceFilter' -Default $null)) -or
            (@(Get-Prop -Object $conditions -Name 'clientAppTypes' -Default @()).Count -gt 0) -or
            (@(Get-Prop -Object $conditions -Name 'userRiskLevels' -Default @()).Count -gt 0) -or
            (@(Get-Prop -Object $conditions -Name 'signInRiskLevels' -Default @()).Count -gt 0)

        $mfaPolicies.Add($policy)
        $exportRows.Add([PSCustomObject]@{
            PolicyId                    = (Get-AnonymizedPolicyId -PolicyId $policyId)
            PolicyName                  = (Get-AnonymizedPolicyName -PolicyId $policyId -PolicyName $policyName)
            State                       = $state
            Requirement                 = $requirementType
            IncludeAllUsers             = ($includeUsers -contains 'All')
            IncludeUserCount            = @($includeUsers | Where-Object { $_ -notin @('All', 'GuestsOrExternalUsers') }).Count
            IncludeGroupCount           = @($includeGroups).Count
            IncludeRoleCount            = @($includeRoles).Count
            ExcludeUserCount            = @($excludeUsers).Count
            ExcludeGroupCount           = @($excludeGroups).Count
            ExcludeRoleCount            = @($excludeRoles).Count
            GuestOrExternalScopePresent = (($includeUsers -contains 'GuestsOrExternalUsers') -or ($null -ne (Get-Prop -Object $usersCondition -Name 'includeGuestsOrExternalUsers' -Default $null)))
            HasOtherSignInConditions    = $hasOtherConditions
        })
    }

    [PSCustomObject]@{ Policies = $mfaPolicies.ToArray(); ExportRows = $exportRows.ToArray() }
}

function Test-UserInCaPolicyUserScope {
    param([Parameter(Mandatory)][object]$User, [Parameter(Mandatory)][object]$Policy)

    $userId = [string](Get-Prop -Object $User -Name 'id' -Default '')
    $userType = [string](Get-Prop -Object $User -Name 'userType' -Default '')
    $conditions = Get-Prop -Object $Policy -Name 'conditions' -Default $null
    $usersCondition = Get-Prop -Object $conditions -Name 'users' -Default $null

    if ($null -eq $usersCondition) {
        return [PSCustomObject]@{ Included = $false; Excluded = $false; Indeterminate = $true; Reason = 'No user condition returned' }
    }

    $includeUsers = @((Get-Prop -Object $usersCondition -Name 'includeUsers' -Default @()) | ForEach-Object { [string]$_ })
    $excludeUsers = @((Get-Prop -Object $usersCondition -Name 'excludeUsers' -Default @()) | ForEach-Object { [string]$_ })
    $includeGroups = @((Get-Prop -Object $usersCondition -Name 'includeGroups' -Default @()) | ForEach-Object { [string]$_ })
    $excludeGroups = @((Get-Prop -Object $usersCondition -Name 'excludeGroups' -Default @()) | ForEach-Object { [string]$_ })
    $includeRoles = @((Get-Prop -Object $usersCondition -Name 'includeRoles' -Default @()) | ForEach-Object { [string]$_ })
    $excludeRoles = @((Get-Prop -Object $usersCondition -Name 'excludeRoles' -Default @()) | ForEach-Object { [string]$_ })
    $includeGuestConfig = Get-Prop -Object $usersCondition -Name 'includeGuestsOrExternalUsers' -Default $null
    $excludeGuestConfig = Get-Prop -Object $usersCondition -Name 'excludeGuestsOrExternalUsers' -Default $null

    $included = $false
    $excluded = $false
    $indeterminate = $false
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($includeUsers -contains 'All') { $included = $true; $reasons.Add('All users') }
    if ($includeUsers -contains $userId) { $included = $true; $reasons.Add('Direct user include') }

    if ($userType -eq 'Guest' -and (($includeUsers -contains 'GuestsOrExternalUsers') -or ($null -ne $includeGuestConfig))) {
        $included = $true
        $reasons.Add('Guest/external include')
    }

    foreach ($groupId in $includeGroups) {
        try {
            if ((Get-GroupUserSet -GroupId $groupId).ContainsKey($userId)) {
                $included = $true
                $reasons.Add('Included group')
                break
            }
        }
        catch { $indeterminate = $true }
    }

    if (@($includeRoles).Count -gt 0 -and -not $included) {
        # Role membership is not expanded by this audit. Role targeting is only
        # unresolved when no direct/all/group/guest include has already established
        # that this user is in the policy's include scope.
        $indeterminate = $true
        $reasons.Add('Role-targeted include not evaluated')
    }

    if ($excludeUsers -contains $userId) { $excluded = $true; $reasons.Add('Direct user exclusion') }
    if ($userType -eq 'Guest' -and (($excludeUsers -contains 'GuestsOrExternalUsers') -or ($null -ne $excludeGuestConfig))) {
        $excluded = $true
        $reasons.Add('Guest/external exclusion')
    }

    foreach ($groupId in $excludeGroups) {
        try {
            if ((Get-GroupUserSet -GroupId $groupId).ContainsKey($userId)) {
                $excluded = $true
                $reasons.Add('Excluded group')
                break
            }
        }
        catch { $indeterminate = $true }
    }

    if (@($excludeRoles).Count -gt 0 -and $included -and -not $excluded) {
        # An unevaluated role exclusion can affect a user who otherwise appears
        # included, so keep this policy indeterminate until role membership is known.
        $indeterminate = $true
        $reasons.Add('Role-targeted exclusion not evaluated')
    }

    [PSCustomObject]@{
        Included      = ($included -and -not $excluded)
        Excluded      = $excluded
        Indeterminate = $indeterminate
        Reason        = ($reasons -join '; ')
    }
}

function Get-UserCaMfaCoverage {
    param([Parameter(Mandatory)][object]$User, [Parameter(Mandatory)][object[]]$MfaPolicies)

    $enabledNames = [System.Collections.Generic.List[string]]::new()
    $enabledIds = [System.Collections.Generic.List[string]]::new()
    $reportOnlyNames = [System.Collections.Generic.List[string]]::new()
    $indeterminate = $false
    $confirmedEnabledCoverage = $false

    foreach ($policy in @($MfaPolicies)) {
        $scope = Test-UserInCaPolicyUserScope -User $User -Policy $policy
        if ($scope.Indeterminate) { $indeterminate = $true }
        if (-not $scope.Included) { continue }

        $caPolicyId = [string](Get-Prop -Object $policy -Name 'id' -Default '')
        $policyName = [string](Get-Prop -Object $policy -Name 'displayName' -Default '')
        $state = [string](Get-Prop -Object $policy -Name 'state' -Default '')
        $exportName = Get-AnonymizedPolicyName -PolicyId $caPolicyId -PolicyName $policyName

        if ($state -eq 'enabled') {
            $enabledNames.Add($exportName)
            $enabledIds.Add($caPolicyId)
            if (-not $scope.Indeterminate) {
                $confirmedEnabledCoverage = $true
            }
        }
        elseif ($state -eq 'enabledForReportingButNotEnforced') {
            $reportOnlyNames.Add($exportName)
        }
    }

    [PSCustomObject]@{
        EnabledPolicyCount      = $enabledNames.Count
        EnabledPolicyNames      = ($enabledNames -join '; ')
        EnabledPolicyIds        = $enabledIds.ToArray()
        ReportOnlyPolicyCount   = $reportOnlyNames.Count
        ReportOnlyPolicyNames   = ($reportOnlyNames -join '; ')
        # Do not send every user to enforcement review merely because some
        # separate MFA policy uses directory-role targeting. If at least one enabled
        # MFA policy definitively covers the user, unresolved additional policy scope
        # does not make the user's overall MFA coverage indeterminate.
        ScopeIndeterminate      = ($indeterminate -and -not $confirmedEnabledCoverage)
        InEnabledMfaPolicyScope = ($enabledNames.Count -gt 0)
    }
}

function Get-LegacyPerUserMfaStates {
    param([Parameter(Mandatory)][object[]]$UsersToCheck)

    $states = @{}
    if (@($UsersToCheck).Count -eq 0) {
        return [PSCustomObject]@{ States = $states; Status = 'Not needed' }
    }

    $firstFailure = $null
    foreach ($user in @($UsersToCheck)) {
        $id = [string](Get-Prop -Object $user -Name 'id' -Default '')
        if (-not $id) { continue }

        try {
            $requirements = Invoke-GraphGet -Uri "$GraphBeta/users/$id/authentication/requirements"
            $states[$id] = [string](Get-Prop -Object $requirements -Name 'perUserMfaState' -Default 'unknown')
        }
        catch {
            $states[$id] = 'unavailable'
            if ($null -eq $firstFailure) { $firstFailure = $_.Exception.Message }
        }
    }

    $status = if ($null -eq $firstFailure) { 'Completed' } else { "Partial/unavailable: $firstFailure" }
    if ($null -ne $firstFailure) {
        Write-Warning 'Legacy per-user MFA state could not be read for one or more unregistered users. Core audit continues.'
    }

    [PSCustomObject]@{ States = $states; Status = $status }
}

function Get-TelephonyMethodKind {
    param([AllowNull()][string]$AuthenticationMethod)

    if ([string]::IsNullOrWhiteSpace($AuthenticationMethod)) { return $null }
    $method = $AuthenticationMethod.Trim()

    # Graph sign-in authenticationDetails uses human-readable labels that can
    # differ from registration-report method names. Keep this list deliberately
    # narrow to avoid classifying unrelated phone-based methods as telephony MFA.
    if ($method -match '^(?i:SMS|Text message(?: .*)?|SMS one-time passcode)$') {
        return 'SMS'
    }

    if ($method -match '^(?i:Voice|Voice call|Phone call(?: approval| verification)?(?: \(.*\))?)$') {
        return 'Voice'
    }

    return $null
}

function Get-RecentSignInAnalysis {
    param(
        [Parameter(Mandatory)][int]$Days,
        [Parameter()][string[]]$EnabledMfaCaPolicyIds = @()
    )

    $startUtc = (Get-Date).ToUniversalTime().AddDays(-$Days)
    $filter = [uri]::EscapeDataString("createdDateTime ge $($startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))")
    $nextUri = "$GraphBeta/auditLogs/signIns?`$filter=$filter&`$top=1000"

    $usageById = @{}
    $methodSummary = @{}
    $totalSignIns = 0
    $enabledPolicySet = @{}

    foreach ($policyId in @($EnabledMfaCaPolicyIds)) {
        if ($policyId) { $enabledPolicySet[$policyId] = $true }
    }

    while ($nextUri) {
        $response = Invoke-GraphGet -Uri $nextUri

        foreach ($signIn in @(Get-Prop -Object $response -Name 'value' -Default @())) {
            $totalSignIns++
            $userId = [string](Get-Prop -Object $signIn -Name 'userId' -Default '')
            if (-not $userId) { continue }

            if (-not $usageById.ContainsKey($userId)) {
                $usageById[$userId] = [ordered]@{
                    SmsCount                = 0
                    VoiceCount              = 0
                    LastTelephonyUseUtc     = $null
                    LastTelephonyMethod     = ''
                    LastTelephonyApp        = ''
                    RecentSignInCount       = 0
                    RecentSuccessfulCount   = 0
                    RecentInteractiveCount  = 0
                    RecentMfaRequiredCount  = 0
                    RecentCaMfaAppliedCount = 0
                }
            }

            $record = $usageById[$userId]
            $record.RecentSignInCount++

            $status = Get-Prop -Object $signIn -Name 'status' -Default $null
            $errorCode = Get-Prop -Object $status -Name 'errorCode' -Default $null
            if ([string]$errorCode -eq '0') { $record.RecentSuccessfulCount++ }

            $interactive = Get-Prop -Object $signIn -Name 'isInteractive' -Default $false
            if (($interactive -eq $true) -or ([string]$interactive -eq 'true')) { $record.RecentInteractiveCount++ }

            if ([string](Get-Prop -Object $signIn -Name 'authenticationRequirement' -Default '') -eq 'multiFactorAuthentication') {
                $record.RecentMfaRequiredCount++
            }

            $caApplied = $false
            foreach ($appliedPolicy in @(Get-Prop -Object $signIn -Name 'appliedConditionalAccessPolicies' -Default @())) {
                $appliedPolicyId = [string](Get-Prop -Object $appliedPolicy -Name 'id' -Default '')
                $result = [string](Get-Prop -Object $appliedPolicy -Name 'result' -Default '')
                if ($appliedPolicyId -and $enabledPolicySet.ContainsKey($appliedPolicyId) -and $result -in @('success', 'failure')) {
                    $caApplied = $true
                    break
                }
            }
            if ($caApplied) { $record.RecentCaMfaAppliedCount++ }

            foreach ($step in @(Get-Prop -Object $signIn -Name 'authenticationDetails' -Default @())) {
                $method = [string](Get-Prop -Object $step -Name 'authenticationMethod' -Default '')
                if (-not $method) { continue }

                if (-not $methodSummary.ContainsKey($method)) {
                    $methodSummary[$method] = [ordered]@{ Method = $method; TotalSteps = 0; SuccessfulSteps = 0; TelephonyKind = '' }
                }

                $methodSummary[$method].TotalSteps++
                $success = Get-Prop -Object $step -Name 'succeeded' -Default $false
                $isSuccess = ($success -eq $true) -or ([string]$success -eq 'true')
                if ($isSuccess) { $methodSummary[$method].SuccessfulSteps++ }

                $telephonyKind = Get-TelephonyMethodKind -AuthenticationMethod $method
                if ($telephonyKind) { $methodSummary[$method].TelephonyKind = $telephonyKind }
                if (-not $isSuccess -or -not $telephonyKind) { continue }

                if ($telephonyKind -eq 'SMS') { $record.SmsCount++ }
                elseif ($telephonyKind -eq 'Voice') { $record.VoiceCount++ }

                $when = Get-Prop -Object $step -Name 'authenticationStepDateTime' -Default $null
                if ($null -eq $when) { $when = Get-Prop -Object $signIn -Name 'createdDateTime' -Default $null }

                if ($null -ne $when) {
                    try { $dt = ([datetimeoffset]$when).UtcDateTime } catch { $dt = $null }
                    if ($null -ne $dt -and (($null -eq $record.LastTelephonyUseUtc) -or ($dt -gt $record.LastTelephonyUseUtc))) {
                        $record.LastTelephonyUseUtc = $dt
                        $record.LastTelephonyMethod = $method
                        $record.LastTelephonyApp = [string](Get-Prop -Object $signIn -Name 'appDisplayName' -Default '')
                    }
                }
            }
        }

        $nextUri = [string](Get-Prop -Object $response -Name '@odata.nextLink' -Default '')
        Write-Host ("  Processed {0:N0} sign-ins..." -f $totalSignIns)
    }

    $methodRows = @(
        foreach ($key in ($methodSummary.Keys | Sort-Object)) {
            [PSCustomObject]$methodSummary[$key]
        }
    )

    [PSCustomObject]@{
        StartUtc          = $startUtc
        SignInCount       = $totalSignIns
        UsageById         = $usageById
        MethodSummaryRows = $methodRows
    }
}

try {
    Set-AuditStage 'Initialization'
    Write-Section "Microsoft Entra MFA Readiness Audit v$ScriptVersion"

    if (-not [string]::IsNullOrWhiteSpace($AnonymizationKey) -and -not $Anonymize) {
        Write-Warning '-AnonymizationKey was supplied without -Anonymize and will not be used.'
    }

    Initialize-Anonymization
    $context = Ensure-GraphConnection

    $consoleTenant = Get-AnonymizedTenantId -Value ([string]$context.TenantId)
    $consoleAccount = Get-AnonymizedAccount -Value ([string]$context.Account)
    Write-Host "Tenant:  $consoleTenant"
    Write-Host "Account: $consoleAccount"

    if (-not $OutputDirectory) {
        $prefix = if ($Anonymize) { 'MFA-Audit-Anonymized' } else { 'MFA-Audit' }
        $OutputDirectory = Join-Path (Get-Location) ("{0}-{1}" -f $prefix, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }

    $OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Write-Host "Output:  $OutputDirectory"

    Set-AuditStage 'Reading Authentication Methods policies'
    Write-Section 'Reading Authentication Methods policies'

    $authMethodsPolicy = Invoke-GraphGet -Uri "$GraphV1/policies/authenticationMethodsPolicy"
    $smsPolicy = Invoke-GraphGet -Uri "$GraphV1/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms"
    $voicePolicy = Invoke-GraphGet -Uri "$GraphV1/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/voice"

    $migrationState = [string](Get-Prop -Object $authMethodsPolicy -Name 'policyMigrationState' -Default 'unknown')
    $registrationEnforcement = Get-Prop -Object $authMethodsPolicy -Name 'registrationEnforcement' -Default $null
    $registrationCampaign = Get-Prop -Object $registrationEnforcement -Name 'authenticationMethodsRegistrationCampaign' -Default $null
    $registrationCampaignState = [string](Get-Prop -Object $registrationCampaign -Name 'state' -Default 'unknown')

    Write-Host "Authentication Methods migration state: $migrationState"
    Write-Host "Registration campaign state:          $registrationCampaignState"
    Write-Host "SMS policy state:                      $([string](Get-Prop -Object $smsPolicy -Name 'state' -Default 'unknown'))"
    Write-Host "Voice policy state:                    $([string](Get-Prop -Object $voicePolicy -Name 'state' -Default 'unknown'))"

    if ($Anonymize) {
        [PSCustomObject]@{
            anonymized = $true
            policyMigrationState = $migrationState
            registrationCampaignState = $registrationCampaignState
        } | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $OutputDirectory 'MFA-AuthenticationMethodsPolicy.json') -Encoding UTF8
    }
    else {
        $authMethodsPolicy | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $OutputDirectory 'MFA-AuthenticationMethodsPolicy.json') -Encoding UTF8
    }

    Convert-PolicyConfigurationForExport -Policy $smsPolicy -Method 'SMS' |
        ConvertTo-Json -Depth 20 | Set-Content (Join-Path $OutputDirectory 'MFA-SMS-Policy.json') -Encoding UTF8
    Convert-PolicyConfigurationForExport -Policy $voicePolicy -Method 'Voice' |
        ConvertTo-Json -Depth 20 | Set-Content (Join-Path $OutputDirectory 'MFA-Voice-Policy.json') -Encoding UTF8

    Set-AuditStage 'Reading Entra users and sign-in activity'
    Write-Section 'Reading Entra users and sign-in activity'

    $users = @(Get-GraphCollection -Uri "$GraphV1/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,externalUserState,identities,signInActivity&`$top=500")
    if (@($users).Count -eq 0) { throw 'Graph returned zero Entra users.' }
    Write-Host ("Users returned: {0:N0}" -f @($users).Count)

    $hostDomains = @()
    try {
        $organizationResponse = Invoke-GraphGet -Uri "$GraphV1/organization?`$select=verifiedDomains"
        $organization = @(Get-Prop -Object $organizationResponse -Name 'value' -Default @()) | Select-Object -First 1
        $hostDomains = @(
            @(Get-Prop -Object $organization -Name 'verifiedDomains' -Default @()) |
                ForEach-Object { [string](Get-Prop -Object $_ -Name 'name' -Default '') } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        Write-Host ("Tenant verified domains available for identity-origin classification: {0:N0}" -f @($hostDomains).Count)
    }
    catch {
        Write-Warning 'Could not read tenant verified domains. External/internal classification will fall back to invitation state and B2B UPN indicators where possible.'
        Write-Warning (Get-GraphErrorSummary -ErrorRecord $_)
    }

    Set-AuditStage 'Expanding effective SMS/Voice policy scope' 
    Write-Section 'Expanding effective SMS/Voice policy scope'

    $smsScope = Get-AuthenticationMethodPolicyScope -Method 'SMS' -Configuration $smsPolicy -AllUsers $users
    $voiceScope = Get-AuthenticationMethodPolicyScope -Method 'Voice' -Configuration $voicePolicy -AllUsers $users

    $policyTargetRows = @($smsScope.TargetRows) + @($voiceScope.TargetRows)
    if ($Anonymize) {
        $policyTargetRows = @(
            foreach ($row in $policyTargetRows) {
                $targetId = [string]$row.TargetId
                $targetType = [string]$row.TargetType
                $exportId = if ($targetType -eq 'user') {
                    $token = Get-AnonymizedToken -Kind 'User' -Value $targetId
                    if ($token) { "USR-$token" } else { '' }
                }
                else { Get-AnonymizedGroupId -GroupId $targetId }

                $exportName = if ($targetType -eq 'user') { $exportId } else { Get-AnonymizedGroupName -GroupId $targetId -GroupName ([string]$row.TargetName) }

                [PSCustomObject]@{
                    Method      = $row.Method
                    PolicyState = $row.PolicyState
                    Action      = $row.Action
                    TargetType  = $targetType
                    TargetId    = $exportId
                    TargetName  = $exportName
                    MemberCount = $row.MemberCount
                }
            }
        )
    }

    $policyTargetRows | Sort-Object Method, Action, TargetName |
        Export-Csv (Join-Path $OutputDirectory 'MFA-PolicyTargets.csv') -NoTypeInformation -Encoding UTF8

    Write-Host ("Effective SMS users:   {0:N0}" -f $smsScope.EffectiveUsers.Count)
    Write-Host ("Effective Voice users: {0:N0}" -f $voiceScope.EffectiveUsers.Count)

    Set-AuditStage 'Reading MFA enforcement policies'
    Write-Section 'Reading MFA enforcement policies'

    $securityDefaultsEnabled = $false
    try {
        $securityDefaults = Invoke-GraphGet -Uri "$GraphV1/policies/identitySecurityDefaultsEnforcementPolicy"
        $securityDefaultsEnabled = [bool](Get-Prop -Object $securityDefaults -Name 'isEnabled' -Default $false)
        Write-Host "Security Defaults enabled: $securityDefaultsEnabled"
    }
    catch {
        Write-Warning "Could not read Security Defaults. $($_.Exception.Message)"
    }

    try {
        $caMfaInfo = Get-CaMfaPolicyInfo
        $caMfaPolicies = @($caMfaInfo.Policies)
        Write-Host ("Conditional Access MFA/authentication-strength policies found: {0:N0}" -f @($caMfaPolicies).Count)
        $caMfaInfo.ExportRows | Sort-Object State, PolicyName |
            Export-Csv (Join-Path $OutputDirectory 'MFA-ConditionalAccessMfaPolicies.csv') -NoTypeInformation -Encoding UTF8
    }
    catch {
        $caMfaPolicies = @()
        Write-Warning "Conditional Access MFA policy analysis failed. $($_.Exception.Message)"
    }

    $enabledCaMfaPolicyIds = @(
        foreach ($policy in $caMfaPolicies) {
            if ([string](Get-Prop -Object $policy -Name 'state' -Default '') -eq 'enabled') {
                [string](Get-Prop -Object $policy -Name 'id' -Default '')
            }
        }
    )

    Set-AuditStage 'Reading Authentication Methods registration report'
    Write-Section 'Reading Authentication Methods registration report'

    $registrations = @(Get-GraphCollection -Uri "$GraphV1/reports/authenticationMethods/userRegistrationDetails")
    if (@($registrations).Count -eq 0) {
        throw 'userRegistrationDetails returned zero records. Check AuditLog.Read.All, licensing, and directory role.'
    }
    Write-Host ("Registration records: {0:N0}" -f @($registrations).Count)

    $regById = @{}
    $regByUpn = @{}
    foreach ($registration in $registrations) {
        $id = [string](Get-Prop -Object $registration -Name 'id' -Default '')
        $upn = [string](Get-Prop -Object $registration -Name 'userPrincipalName' -Default '')
        if ($id) { $regById[$id] = $registration }
        if ($upn) { $regByUpn[$upn.ToLowerInvariant()] = $registration }
    }

    $unregisteredUsersToCheck = @(
        foreach ($user in $users) {
            $id = [string](Get-Prop -Object $user -Name 'id' -Default '')
            if (-not [bool](Get-Prop -Object $user -Name 'accountEnabled' -Default $false)) { continue }
            if (-not ($smsScope.EffectiveUsers.ContainsKey($id) -or $voiceScope.EffectiveUsers.ContainsKey($id))) { continue }

            $upn = [string](Get-Prop -Object $user -Name 'userPrincipalName' -Default '')
            $registration = $null
            if ($id -and $regById.ContainsKey($id)) { $registration = $regById[$id] }
            elseif ($upn -and $regByUpn.ContainsKey($upn.ToLowerInvariant())) { $registration = $regByUpn[$upn.ToLowerInvariant()] }

            $methods = if ($null -ne $registration) { @(Get-Prop -Object $registration -Name 'methodsRegistered' -Default @()) } else { @() }
            if (@($methods).Count -eq 0) { $user }
        }
    )

    $legacyMfaResult = Get-LegacyPerUserMfaStates -UsersToCheck $unregisteredUsersToCheck
    $legacyMfaStates = $legacyMfaResult.States
    Write-Host ("Unregistered enabled users in SMS/Voice scope checked for legacy per-user MFA: {0:N0}" -f @($unregisteredUsersToCheck).Count)

    $usageById = @{}
    $recentMethodRows = @()
    $usageStatus = 'Not requested'

    if ($IncludeRecentUsage) {
        Set-AuditStage 'Checking recent sign-in MFA usage/enforcement'
        Write-Section "Checking recent sign-in MFA usage/enforcement ($UsageDays days)"
        Write-Warning 'Recent sign-in analysis uses Microsoft Graph beta authenticationDetails/authenticationRequirement properties; core sign-in history and policy analysis remain v1.0.'

        try {
            $usageResult = Get-RecentSignInAnalysis -Days $UsageDays -EnabledMfaCaPolicyIds $enabledCaMfaPolicyIds
            $usageById = $usageResult.UsageById
            $recentMethodRows = @($usageResult.MethodSummaryRows)
            $usageStatus = "Completed: $($usageResult.SignInCount) sign-ins examined since $($usageResult.StartUtc.ToString('u'))"
            $recentMethodRows | Export-Csv (Join-Path $OutputDirectory 'MFA-RecentAuthMethodSummary.csv') -NoTypeInformation -Encoding UTF8
        }
        catch {
            $usageStatus = "Failed: $($_.Exception.Message)"
            Write-Warning 'Recent usage check failed; continuing with core audit.'
            Write-Warning ("Graph error: {0}" -f $_.Exception.Message)
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { Write-Warning ("Graph details: {0}" -f $_.ErrorDetails.Message) }
            if ($_.Exception.InnerException) { Write-Warning ("Inner error: {0}" -f $_.Exception.InnerException.Message) }
        }
    }

    Set-AuditStage 'Building per-user audit'
    Write-Section 'Building per-user audit'

    $rows = [System.Collections.Generic.List[object]]::new()
    $registrationMatchCount = 0

    foreach ($user in $users) {
        $id = [string](Get-Prop -Object $user -Name 'id' -Default '')
        $upn = [string](Get-Prop -Object $user -Name 'userPrincipalName' -Default '')

        $registration = $null
        if ($id -and $regById.ContainsKey($id)) { $registration = $regById[$id] }
        elseif ($upn -and $regByUpn.ContainsKey($upn.ToLowerInvariant())) { $registration = $regByUpn[$upn.ToLowerInvariant()] }

        $registrationMatched = ($null -ne $registration)
        if ($registrationMatched) { $registrationMatchCount++ }

        $methods = @()
        $systemPreferred = @()
        $preferred = ''
        $mfaRegistered = $null
        $mfaCapable = $null
        $passwordless = $null
        $systemPreferredEnabled = $null
        $lastUpdated = $null
        $isAdmin = $null

        if ($registrationMatched) {
            $methods = @(Get-Prop -Object $registration -Name 'methodsRegistered' -Default @())
            $systemPreferred = @(Get-Prop -Object $registration -Name 'systemPreferredAuthenticationMethods' -Default @())
            $preferred = [string](Get-Prop -Object $registration -Name 'userPreferredMethodForSecondaryAuthentication' -Default '')
            $mfaRegistered = Get-Prop -Object $registration -Name 'isMfaRegistered' -Default $null
            $mfaCapable = Get-Prop -Object $registration -Name 'isMfaCapable' -Default $null
            $passwordless = Get-Prop -Object $registration -Name 'isPasswordlessCapable' -Default $null
            $systemPreferredEnabled = Get-Prop -Object $registration -Name 'isSystemPreferredAuthenticationMethodEnabled' -Default $null
            $lastUpdated = Get-Prop -Object $registration -Name 'lastUpdatedDateTime' -Default $null
            $isAdmin = Get-Prop -Object $registration -Name 'isAdmin' -Default $null
        }

        $smsInScope = $smsScope.EffectiveUsers.ContainsKey($id)
        $voiceInScope = $voiceScope.EffectiveUsers.ContainsKey($id)
        $telephonyScope = $smsInScope -or $voiceInScope
        $phoneRegistered = Test-PhoneRegistered -Methods $methods
        $nonTelephonyMfa = Test-NonTelephonyMfa -Methods $methods
        $passkeyOrFido = Test-PasskeyOrFido -Methods $methods
        $authenticatorRegistered = Test-AuthenticatorRegistered -Methods $methods
        $windowsHelloRegistered = Test-WindowsHelloForBusinessRegistered -Methods $methods
        $phishingResistantRegistered = Test-PhishingResistantRegistered -Methods $methods
        $telephonyPreferred = Test-TelephonyPreferred -Preferred $preferred -SystemPreferred $systemPreferred
        $likelyDependent = $telephonyScope -and $phoneRegistered -and (-not $nonTelephonyMfa)
        $noRegisteredMethods = (@($methods).Count -eq 0)
        $identityOrigin = Get-UserIdentityOriginInfo -User $user -HostDomains $hostDomains

        $signInHistory = Get-SignInHistoryInfo -User $user
        $caCoverage = Get-UserCaMfaCoverage -User $user -MfaPolicies $caMfaPolicies

        $legacyPerUserMfaState = 'notQueried'
        if ($legacyMfaStates.ContainsKey($id)) { $legacyPerUserMfaState = [string]$legacyMfaStates[$id] }

        $smsCount = 0
        $voiceCount = 0
        $lastUse = $null
        $lastMethod = ''
        $lastApp = ''
        $recentSignInCount = 0
        $recentSuccessfulCount = 0
        $recentInteractiveCount = 0
        $recentMfaRequiredCount = 0
        $recentCaMfaAppliedCount = 0

        if ($usageById.ContainsKey($id)) {
            $usage = $usageById[$id]
            $smsCount = [int]$usage.SmsCount
            $voiceCount = [int]$usage.VoiceCount
            $lastUse = $usage.LastTelephonyUseUtc
            $lastMethod = [string]$usage.LastTelephonyMethod
            $lastApp = [string]$usage.LastTelephonyApp
            $recentSignInCount = [int]$usage.RecentSignInCount
            $recentSuccessfulCount = [int]$usage.RecentSuccessfulCount
            $recentInteractiveCount = [int]$usage.RecentInteractiveCount
            $recentMfaRequiredCount = [int]$usage.RecentMfaRequiredCount
            $recentCaMfaAppliedCount = [int]$usage.RecentCaMfaAppliedCount
        }

        $recentTelephonyUse = (($smsCount + $voiceCount) -gt 0)

        if (-not $telephonyScope) {
            $priority = 'Not in SMS/Voice policy scope'
            $action = 'No SMS/Voice policy migration action identified by this audit.'
        }
        elseif ($noRegisteredMethods -and -not $signInHistory.HasSuccessfulSignInRecorded) {
            $priority = '0A - Unregistered / no successful sign-in recorded'
            $action = 'Verify account purpose and MFA enforcement before communications; no successful sign-in timestamp is retained.'
        }
        elseif ($noRegisteredMethods -and $signInHistory.HasSuccessfulSignInRecorded) {
            $priority = '0B - Unregistered / successful sign-in recorded'
            $action = 'Investigate: successful sign-in history exists but no registered authentication method is reported.'
        }
        elseif ($recentTelephonyUse) {
            $priority = '1 - Recent SMS/Voice use'
            $action = 'Contact first; successful recent telephony authentication was observed.'
        }
        elseif ($likelyDependent) {
            $priority = '2 - Likely telephony dependent'
            $action = 'Register a non-telephony MFA/passkey method before retirement.'
        }
        elseif ($telephonyPreferred) {
            $priority = '3 - SMS/Voice preferred'
            $action = 'Move preferred authentication away from SMS/Voice and verify a replacement method.'
        }
        elseif ($phoneRegistered) {
            $priority = '4 - Phone registered'
            $action = 'Verify a non-telephony method works and remove telephony dependency where appropriate.'
        }
        else {
            $priority = '5 - Policy scope only'
            $action = 'In SMS/Voice policy scope; no registered phone method was reported.'
        }

        # Migration waves are deliberately mutually exclusive. They are intended
        # for operational outreach sequencing, not as Microsoft-defined risk tiers.
        $migrationWaveOrder = 99
        $migrationWave = 'Not applicable'
        $migrationWaveReason = 'User is not an enabled account in effective SMS/voice scope.'

        if ((Get-Prop -Object $user -Name 'accountEnabled' -Default $false) -and $telephonyScope) {
            if ($noRegisteredMethods -and -not $signInHistory.HasSuccessfulSignInRecorded) {
                $migrationWaveOrder = 90
                $migrationWave = 'Separate - Unregistered / no successful sign-in recorded'
                $migrationWaveReason = 'No registered authentication methods and no retained successful sign-in timestamp. Verify account purpose before user outreach.'
            }
            elseif ($noRegisteredMethods -and $signInHistory.HasSuccessfulSignInRecorded) {
                $migrationWaveOrder = 0
                $migrationWave = 'Review - Unregistered / successful sign-in recorded'
                $migrationWaveReason = 'Successful sign-in history exists but no registered authentication method is reported. Investigate enforcement before migration outreach.'
            }
            elseif ($recentTelephonyUse) {
                $migrationWaveOrder = 10
                $migrationWave = 'Tier 1 - Recent SMS/voice use'
                $migrationWaveReason = 'At least one successful telephony authentication step was observed during the recent sign-in window.'
            }
            elseif ($likelyDependent) {
                $migrationWaveOrder = 20
                $migrationWave = 'Tier 2 - Telephony dependent / no recent use'
                $migrationWaveReason = 'Phone authentication is registered and no durable non-telephony MFA alternative was detected, but no recent successful telephony step was observed.'
            }
            elseif ($phishingResistantRegistered) {
                $migrationWaveOrder = 40
                $migrationWave = 'Tier 4 - Passkey/FIDO2/WHfB ready'
                $migrationWaveReason = 'A passkey, FIDO-family method, or Windows Hello for Business registration is present.'
            }
            elseif ($authenticatorRegistered -and $telephonyPreferred) {
                $migrationWaveOrder = 30
                $migrationWave = 'Tier 3A - Authenticator available / telephony preferred'
                $migrationWaveReason = 'Microsoft Authenticator is registered, but the user/system preference still indicates SMS or voice.'
            }
            elseif ($authenticatorRegistered) {
                $migrationWaveOrder = 31
                $migrationWave = 'Tier 3B - Authenticator available / telephony not preferred'
                $migrationWaveReason = 'Microsoft Authenticator is registered and telephony is not currently identified as the preferred method.'
            }
            else {
                $migrationWaveOrder = 50
                $migrationWave = 'Review - Other in-scope state'
                $migrationWaveReason = 'The account is in SMS/voice scope but does not match the defined migration-wave patterns.'
            }
        }

        $enforcementSignals = [System.Collections.Generic.List[string]]::new()
        if ($securityDefaultsEnabled) { $enforcementSignals.Add('Security Defaults enabled') }
        if ($legacyPerUserMfaState -in @('enabled', 'enforced')) { $enforcementSignals.Add("Legacy per-user MFA: $legacyPerUserMfaState") }
        if ($caCoverage.InEnabledMfaPolicyScope) { $enforcementSignals.Add('In user/group scope of enabled CA MFA policy') }
        if ($recentMfaRequiredCount -gt 0) { $enforcementSignals.Add('Recent sign-in explicitly required MFA') }
        if ($recentCaMfaAppliedCount -gt 0) { $enforcementSignals.Add('Enabled CA MFA policy observed applying recently') }

        if ($enforcementSignals.Count -gt 0) {
            $enforcementAssessment = ($enforcementSignals -join '; ')
        }
        elseif ($noRegisteredMethods -and $signInHistory.HasSuccessfulSignInRecorded) {
            $enforcementAssessment = if ($caCoverage.ScopeIndeterminate) {
                'Needs review: successful sign-in recorded, no MFA method, CA role/guest scope partly indeterminate'
            }
            else {
                'Potential enforcement gap: successful sign-in recorded, no MFA method, no enforcement signal identified'
            }
        }
        elseif ($noRegisteredMethods -and -not $signInHistory.HasSuccessfulSignInRecorded) {
            $enforcementAssessment = 'Not yet observed: no registered MFA method and no successful sign-in timestamp'
        }
        else {
            $enforcementAssessment = 'No explicit enforcement signal identified by this audit'
        }

        $realDisplayName = [string](Get-Prop -Object $user -Name 'displayName' -Default '')
        $exportDisplayName = $realDisplayName
        $exportUpn = $upn
        $exportObjectId = $id
        $exportLastApp = $lastApp

        if ($Anonymize) {
            $anonymousUser = Get-AnonymizedUserValues -ObjectId $id -UserPrincipalName $upn
            $exportDisplayName = $anonymousUser.DisplayName
            $exportUpn = $anonymousUser.UserPrincipalName
            $exportObjectId = $anonymousUser.ObjectId
            $exportLastApp = Get-AnonymizedApplicationName -ApplicationName $lastApp
        }

        $rows.Add([PSCustomObject]@{
            DisplayName                       = $exportDisplayName
            UserPrincipalName                 = $exportUpn
            ObjectId                          = $exportObjectId
            AccountEnabled                    = (Get-Prop -Object $user -Name 'accountEnabled' -Default $null)
            UserType                          = [string](Get-Prop -Object $user -Name 'userType' -Default '')
            IdentityOrigin                    = $identityOrigin.IdentityOrigin
            UserClassification                = $identityOrigin.UserClassification
            IsExternalUser                    = $identityOrigin.IsExternalUser
            IdentityOriginConfidence          = $identityOrigin.IdentityOriginConfidence
            IdentityClassificationBasis       = $identityOrigin.IdentityClassificationBasis
            ExternalUserState                 = $identityOrigin.ExternalUserState
            TelephonyRetirementMilestone      = $identityOrigin.TelephonyRetirementMilestone
            IsAdmin                           = $isAdmin

            HasAnySignInActivity              = $signInHistory.HasAnySignInActivity
            HasSuccessfulSignInRecorded       = $signInHistory.HasSuccessfulSignInRecorded
            LastInteractiveSignInAttemptUtc   = $signInHistory.LastInteractiveSignInAttemptUtc
            LastNonInteractiveAttemptUtc      = $signInHistory.LastNonInteractiveAttemptUtc
            LastSuccessfulSignInUtc           = $signInHistory.LastSuccessfulSignInUtc
            SignInHistoryClassification       = $signInHistory.Classification

            RegistrationReportMatch           = $registrationMatched
            SmsPolicyInScope                  = $smsInScope
            VoicePolicyInScope                = $voiceInScope
            SmsOrVoicePolicyInScope           = $telephonyScope

            MethodsRegistered                 = ($methods -join '; ')
            PhoneRegistered                   = $phoneRegistered
            NonTelephonyMfaRegistered         = $nonTelephonyMfa
            AuthenticatorRegistered           = $authenticatorRegistered
            PasskeyOrFidoRegistered           = $passkeyOrFido
            WindowsHelloForBusinessRegistered = $windowsHelloRegistered
            PhishingResistantRegistered       = $phishingResistantRegistered
            IsMfaRegistered                   = $mfaRegistered
            IsMfaCapable                      = $mfaCapable
            IsPasswordlessCapable             = $passwordless
            IsSystemPreferredEnabled          = $systemPreferredEnabled
            SystemPreferredMethods            = ($systemPreferred -join '; ')
            UserPreferredMfaMethod             = $preferred
            SmsOrVoicePreferred               = $telephonyPreferred
            RegistrationReportLastUpdatedUtc  = $lastUpdated
            LikelyTelephonyDependent          = $likelyDependent
            NoRegisteredAuthenticationMethods = $noRegisteredMethods

            SecurityDefaultsEnabled           = $securityDefaultsEnabled
            LegacyPerUserMfaState             = $legacyPerUserMfaState
            CaMfaEnabledPolicyUserScope       = $caCoverage.InEnabledMfaPolicyScope
            CaMfaEnabledPolicyCount           = $caCoverage.EnabledPolicyCount
            CaMfaEnabledPolicyNames           = $caCoverage.EnabledPolicyNames
            CaMfaReportOnlyPolicyCount        = $caCoverage.ReportOnlyPolicyCount
            CaMfaReportOnlyPolicyNames        = $caCoverage.ReportOnlyPolicyNames
            CaMfaScopeIndeterminate           = $caCoverage.ScopeIndeterminate

            RecentSmsUseCount                 = $smsCount
            RecentVoiceUseCount               = $voiceCount
            RecentTelephonyAuthCount           = ($smsCount + $voiceCount)
            RecentSmsOrVoiceUse               = $recentTelephonyUse
            LastSmsOrVoiceUseUtc              = (ConvertTo-UtcText $lastUse)
            LastSmsOrVoiceMethod              = $lastMethod
            LastSmsOrVoiceApp                 = $exportLastApp
            RecentSignInCount                 = $recentSignInCount
            RecentSuccessfulSignInCount       = $recentSuccessfulCount
            RecentInteractiveSignInCount      = $recentInteractiveCount
            RecentMfaRequiredSignInCount      = $recentMfaRequiredCount
            RecentCaMfaAppliedSignInCount     = $recentCaMfaAppliedCount

            MfaEnforcementAssessment          = $enforcementAssessment
            MigrationWaveOrder                = $migrationWaveOrder
            MigrationWave                     = $migrationWave
            MigrationWaveReason               = $migrationWaveReason
            MigrationPriority                 = $priority
            RecommendedAction                 = $action
        })
    }

    $audit = @($rows.ToArray() | Sort-Object MigrationPriority, DisplayName)

    if ($registrationMatchCount -eq 0) {
        Write-Warning 'ZERO users matched the Authentication Methods registration report. Do not trust per-user registration classifications until resolved.'
    }
    elseif ($registrationMatchCount -lt [math]::Floor(@($users).Count * 0.80)) {
        Write-Warning ("Only {0:N0} of {1:N0} users matched the Authentication Methods registration report." -f $registrationMatchCount, @($users).Count)
    }

    $auditPath = Join-Path $OutputDirectory 'MFA-UserAudit.csv'
    $candidatePath = Join-Path $OutputDirectory 'MFA-MigrationCandidates.csv'
    $migrationWavesPath = Join-Path $OutputDirectory 'MFA-MigrationWaves.csv'
    $enforcementReviewPath = Join-Path $OutputDirectory 'MFA-EnforcementReview.csv'
    $guestExternalPath = Join-Path $OutputDirectory 'MFA-GuestAndExternalUsers.csv'
    $summaryPath = Join-Path $OutputDirectory 'MFA-Summary.csv'

    $audit | Export-Csv $auditPath -NoTypeInformation -Encoding UTF8

    $audit | Where-Object { $_.AccountEnabled -eq $true -and $_.SmsOrVoicePolicyInScope -eq $true } |
        Export-Csv $candidatePath -NoTypeInformation -Encoding UTF8

    $audit | Where-Object { $_.AccountEnabled -eq $true -and $_.SmsOrVoicePolicyInScope -eq $true } |
        Sort-Object MigrationWaveOrder, DisplayName |
        Export-Csv $migrationWavesPath -NoTypeInformation -Encoding UTF8

    $audit | Where-Object {
        $_.AccountEnabled -eq $true -and $_.SmsOrVoicePolicyInScope -eq $true -and
        ($_.NoRegisteredAuthenticationMethods -eq $true -or
         $_.MfaEnforcementAssessment -like 'Potential enforcement gap*' -or
         $_.CaMfaScopeIndeterminate -eq $true)
    } | Export-Csv $enforcementReviewPath -NoTypeInformation -Encoding UTF8

    $audit | Where-Object { $_.AccountEnabled -eq $true -and ($_.UserType -eq 'Guest' -or $_.IsExternalUser -eq $true) } |
        Sort-Object UserClassification, DisplayName |
        Export-Csv $guestExternalPath -NoTypeInformation -Encoding UTF8

    $enabled = @($audit | Where-Object AccountEnabled -eq $true)
    $enabledInScope = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.SmsOrVoicePolicyInScope -eq $true })
    $telephonyDependent = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.LikelyTelephonyDependent -eq $true })
    $telephonyPreferred = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.SmsOrVoicePreferred -eq $true })
    $passwordlessUsers = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.IsPasswordlessCapable -eq $true })
    $unregisteredInScope = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.SmsOrVoicePolicyInScope -eq $true -and $_.NoRegisteredAuthenticationMethods -eq $true })
    $unregisteredNoSuccessful = @($unregisteredInScope | Where-Object { $_.HasSuccessfulSignInRecorded -ne $true })
    $unregisteredWithSuccessful = @($unregisteredInScope | Where-Object { $_.HasSuccessfulSignInRecorded -eq $true })
    $caMfaScoped = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.CaMfaEnabledPolicyUserScope -eq $true })
    $potentialGaps = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.MfaEnforcementAssessment -like 'Potential enforcement gap*' })
    $recentTelephonyUsers = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.RecentSmsOrVoiceUse -eq $true })
    $recentSmsUsers = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.RecentSmsUseCount -gt 0 })
    $recentVoiceUsers = @($audit | Where-Object { $_.AccountEnabled -eq $true -and $_.RecentVoiceUseCount -gt 0 })
    $waveTier1 = @($audit | Where-Object { $_.MigrationWaveOrder -eq 10 })
    $waveTier2 = @($audit | Where-Object { $_.MigrationWaveOrder -eq 20 })
    $waveTier3A = @($audit | Where-Object { $_.MigrationWaveOrder -eq 30 })
    $waveTier3B = @($audit | Where-Object { $_.MigrationWaveOrder -eq 31 })
    $waveTier4 = @($audit | Where-Object { $_.MigrationWaveOrder -eq 40 })
    $waveNeverUsed = @($audit | Where-Object { $_.MigrationWaveOrder -eq 90 })
    $waveUnregisteredActive = @($audit | Where-Object { $_.MigrationWaveOrder -eq 0 })
    $waveOtherReview = @($audit | Where-Object { $_.MigrationWaveOrder -eq 50 })
    $enabledInternalMembers = @($enabled | Where-Object { $_.UserClassification -eq 'Internal Member' })
    $enabledInternalGuests = @($enabled | Where-Object { $_.UserClassification -eq 'Internal Guest' })
    $enabledExternalGuests = @($enabled | Where-Object { $_.UserClassification -eq 'External Guest' })
    $enabledExternalMembers = @($enabled | Where-Object { $_.UserClassification -eq 'External Member' })
    $enabledExternalUsers = @($enabled | Where-Object { $_.IsExternalUser -eq $true })
    $enabledInternalGuestsInScope = @($enabledInScope | Where-Object { $_.UserClassification -eq 'Internal Guest' })
    $enabledExternalUsersInScope = @($enabledInScope | Where-Object { $_.IsExternalUser -eq $true })

    $summary = @(
        [PSCustomObject]@{ Metric = 'Script version'; Value = $ScriptVersion }
        [PSCustomObject]@{ Metric = 'Generated UTC'; Value = (Get-Date).ToUniversalTime().ToString('u') }
        [PSCustomObject]@{ Metric = 'Anonymized output'; Value = [bool]$Anonymize }
        [PSCustomObject]@{ Metric = 'Stable anonymization key supplied'; Value = [bool](-not [string]::IsNullOrWhiteSpace($AnonymizationKey) -and $Anonymize) }
        [PSCustomObject]@{ Metric = 'Tenant ID'; Value = (Get-AnonymizedTenantId -Value ([string]$context.TenantId)) }
        [PSCustomObject]@{ Metric = 'Authentication Methods migration state'; Value = $migrationState }
        [PSCustomObject]@{ Metric = 'Registration campaign state'; Value = $registrationCampaignState }
        [PSCustomObject]@{ Metric = 'SMS policy state'; Value = $smsScope.State }
        [PSCustomObject]@{ Metric = 'Voice policy state'; Value = $voiceScope.State }
        [PSCustomObject]@{ Metric = 'Total Entra users'; Value = @($users).Count }
        [PSCustomObject]@{ Metric = 'Enabled Entra users'; Value = @($enabled).Count }
        [PSCustomObject]@{ Metric = 'Enabled internal members'; Value = @($enabledInternalMembers).Count }
        [PSCustomObject]@{ Metric = 'Enabled internal guests'; Value = @($enabledInternalGuests).Count }
        [PSCustomObject]@{ Metric = 'Enabled external guests'; Value = @($enabledExternalGuests).Count }
        [PSCustomObject]@{ Metric = 'Enabled external members'; Value = @($enabledExternalMembers).Count }
        [PSCustomObject]@{ Metric = 'Enabled external users (all UserType values)'; Value = @($enabledExternalUsers).Count }
        [PSCustomObject]@{ Metric = 'Enabled internal guests in SMS/Voice scope (Feb 1, 2027)'; Value = @($enabledInternalGuestsInScope).Count }
        [PSCustomObject]@{ Metric = 'Enabled external users in SMS/Voice scope (Jul 1, 2027)'; Value = @($enabledExternalUsersInScope).Count }
        [PSCustomObject]@{ Metric = 'Registration report records'; Value = @($registrations).Count }
        [PSCustomObject]@{ Metric = 'Users matched to registration report'; Value = $registrationMatchCount }
        [PSCustomObject]@{ Metric = 'Effective SMS policy users'; Value = $smsScope.EffectiveUsers.Count }
        [PSCustomObject]@{ Metric = 'Effective Voice policy users'; Value = $voiceScope.EffectiveUsers.Count }
        [PSCustomObject]@{ Metric = 'Enabled users in SMS/Voice scope'; Value = @($enabledInScope).Count }
        [PSCustomObject]@{ Metric = 'Enabled users likely telephony dependent'; Value = @($telephonyDependent).Count }
        [PSCustomObject]@{ Metric = 'Enabled users with SMS/Voice preferred'; Value = @($telephonyPreferred).Count }
        [PSCustomObject]@{ Metric = 'Enabled users passwordless capable'; Value = @($passwordlessUsers).Count }
        [PSCustomObject]@{ Metric = 'Enabled in-scope users with no registered auth methods'; Value = @($unregisteredInScope).Count }
        [PSCustomObject]@{ Metric = 'Unregistered in-scope users with no successful sign-in recorded'; Value = @($unregisteredNoSuccessful).Count }
        [PSCustomObject]@{ Metric = 'Unregistered in-scope users with successful sign-in recorded'; Value = @($unregisteredWithSuccessful).Count }
        [PSCustomObject]@{ Metric = 'Security Defaults enabled'; Value = $securityDefaultsEnabled }
        [PSCustomObject]@{ Metric = 'MFA Conditional Access policies found'; Value = @($caMfaPolicies).Count }
        [PSCustomObject]@{ Metric = 'Enabled users in scope of an enabled CA MFA policy'; Value = @($caMfaScoped).Count }
        [PSCustomObject]@{ Metric = 'Potential MFA enforcement gaps identified'; Value = @($potentialGaps).Count }
        [PSCustomObject]@{ Metric = 'Legacy per-user MFA audit'; Value = $legacyMfaResult.Status }
        [PSCustomObject]@{ Metric = 'Enabled users with recent SMS/Voice use'; Value = @($recentTelephonyUsers).Count }
        [PSCustomObject]@{ Metric = 'Enabled users with recent SMS use'; Value = @($recentSmsUsers).Count }
        [PSCustomObject]@{ Metric = 'Enabled users with recent Voice use'; Value = @($recentVoiceUsers).Count }
        [PSCustomObject]@{ Metric = 'Migration Wave 1 - Recent SMS/Voice use'; Value = @($waveTier1).Count }
        [PSCustomObject]@{ Metric = 'Migration Wave 2 - Telephony dependent / no recent use'; Value = @($waveTier2).Count }
        [PSCustomObject]@{ Metric = 'Migration Wave 3A - Authenticator available / telephony preferred'; Value = @($waveTier3A).Count }
        [PSCustomObject]@{ Metric = 'Migration Wave 3B - Authenticator available / telephony not preferred'; Value = @($waveTier3B).Count }
        [PSCustomObject]@{ Metric = 'Migration Wave 4 - Passkey/FIDO2/WHfB ready'; Value = @($waveTier4).Count }
        [PSCustomObject]@{ Metric = 'Migration Separate - Unregistered / no successful sign-in recorded'; Value = @($waveNeverUsed).Count }
        [PSCustomObject]@{ Metric = 'Migration Review - Unregistered / successful sign-in recorded'; Value = @($waveUnregisteredActive).Count }
        [PSCustomObject]@{ Metric = 'Migration Review - Other in-scope state'; Value = @($waveOtherReview).Count }
        [PSCustomObject]@{ Metric = 'Recent usage/enforcement audit'; Value = $usageStatus }
    )

    $summary | Export-Csv $summaryPath -NoTypeInformation -Encoding UTF8

    Set-AuditStage 'Writing summary and output files'
    Write-Section 'Audit complete'
    $summary | Format-Table -AutoSize

    Write-Host ''
    Write-Host 'Files created:' -ForegroundColor Green
    foreach ($path in @(
        $summaryPath,
        $auditPath,
        $candidatePath,
        $migrationWavesPath,
        $enforcementReviewPath,
        $guestExternalPath,
        (Join-Path $OutputDirectory 'MFA-PolicyTargets.csv'),
        (Join-Path $OutputDirectory 'MFA-ConditionalAccessMfaPolicies.csv'),
        (Join-Path $OutputDirectory 'MFA-AuthenticationMethodsPolicy.json'),
        (Join-Path $OutputDirectory 'MFA-SMS-Policy.json'),
        (Join-Path $OutputDirectory 'MFA-Voice-Policy.json')
    )) { Write-Host "  $path" }

    if ($IncludeRecentUsage) {
        Write-Host "  $(Join-Path $OutputDirectory 'MFA-RecentAuthMethodSummary.csv')"
    }

    Write-Host ''
    if ($Anonymize) {
        Write-Host 'Anonymization: ENABLED. No identity mapping or anonymization key was written to disk.' -ForegroundColor Green
        if ([string]::IsNullOrWhiteSpace($AnonymizationKey)) {
            Write-Host 'Anonymous IDs are stable only within this run. Supply -AnonymizationKey to correlate later runs.' -ForegroundColor Yellow
        }
        else {
            Write-Host 'The supplied anonymization key makes anonymous IDs stable across runs using the same key.' -ForegroundColor Green
        }
    }

    Write-Host 'MFA-MigrationWaves.csv is the recommended outreach-sequencing list.' -ForegroundColor Cyan
    Write-Host 'MFA-MigrationCandidates.csv remains the full enabled in-scope population.' -ForegroundColor Cyan
    Write-Host 'MFA-EnforcementReview.csv isolates unregistered users and other accounts requiring enforcement review.' -ForegroundColor Cyan
    Write-Host 'MFA-GuestAndExternalUsers.csv separates internal guests from external users for retirement planning.' -ForegroundColor Cyan
}
catch {
    Write-AuditFailureContext -ErrorRecord $_
    throw
}
