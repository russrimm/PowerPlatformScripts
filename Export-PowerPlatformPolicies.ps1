<#
.SYNOPSIS
    Exports Power Platform data loss prevention (DLP) policies and advanced connector
    policies (ACP) for every environment in the tenant.

.DESCRIPTION
    Produces a per-environment snapshot of the connector governance that applies to it:

      * DLP (classic data policies) via the Microsoft.PowerApps.Administration.PowerShell
        module. DLP policies are tenant objects scoped to environments, so the script
        reads every policy once and then resolves which environments each policy covers
        (AllEnvironments / OnlyEnvironments / ExceptEnvironments). For each policy it also
        pulls the connector configurations (endpoint filtering and connector action rules)
        and the exempt resources list.

      * ACP (advanced connector policies) via the Power Platform API. ACP has no
        PowerShell cmdlets. The policies are exposed as governance/ruleBasedPolicies, and
        the ConnectorManagement rule set holds the connector allowlist. The script reads
        the assignment for each environment and then the full policy document.

    Output layout under -OutputPath:

        _tenant\
            environments.json           All environments with metadata
            dlp-policies.json           Every DLP policy, with connector configurations
            dlp-error-settings.json     Tenant DLP error/blocked-message settings
            acp-policies.json           Every distinct ACP policy encountered
            summary.csv                 One row per environment/policy pairing
            export-manifest.json        Run metadata and per-source errors
        <environment display name>__<environment id>\
            environment.json
            dlp-policies.json
            acp-policies.json

.PARAMETER OutputPath
    Root folder for the export. Defaults to .\power-platform-policy-export\<timestamp>.

.PARAMETER EnvironmentName
    Optional environment IDs (GUIDs) to limit the export to. Defaults to all environments.

.PARAMETER TenantId
    Tenant GUID. Required by the DLP connector-configuration cmdlets. Resolved
    automatically from the first environment when omitted.

.PARAMETER SkipAcp
    Skip the advanced connector policy export and only produce the DLP snapshot.

.PARAMETER AcpClientId
    Application (client) ID of an app registration with Power Platform API permissions.
    Only used when the MSAL.PS fallback is needed to obtain the ACP token. If omitted the
    script uses Az.Accounts or the Azure CLI, in that order.

.PARAMETER AcpApiVersion
    Power Platform API version for the governance endpoints. Defaults to 2024-10-01.

.EXAMPLE
    ./Export-PowerPlatformPolicies.ps1

    Exports DLP and ACP for every environment to a timestamped folder.

.EXAMPLE
    ./Export-PowerPlatformPolicies.ps1 -OutputPath C:\audit\ppolicies -SkipAcp

    Exports only DLP policies to a fixed folder.

.EXAMPLE
    ./Export-PowerPlatformPolicies.ps1 -EnvironmentName 3b1c...,7f92... -AcpClientId 00001111-aaaa-2222-bbbb-3333cccc4444

    Exports two environments and uses MSAL.PS with the given app registration for ACP.

.NOTES
    Required roles: Power Platform Administrator, Dynamics 365 Administrator, or Global
    Administrator. The script is read-only.

    DLP cmdlets:  https://learn.microsoft.com/powershell/module/microsoft.powerapps.administration.powershell/
    ACP REST API: https://learn.microsoft.com/rest/api/power-platform/governance/rule-based-policies
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string[]]$EnvironmentName,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAcp,

    [Parameter(Mandatory = $false)]
    [string]$AcpClientId,

    [Parameter(Mandatory = $false)]
    [string]$AcpApiVersion = '2024-10-01'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:AcpApiBaseUrl = 'https://api.powerplatform.com'
$script:Errors = [System.Collections.Generic.List[object]]::new()

#region Helpers

function Add-ExportError {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][string]$Target
    )

    $script:Errors.Add([pscustomobject]@{
            source  = $Source
            target  = $Target
            message = $Message
            time    = (Get-Date).ToUniversalTime().ToString('o')
        })
    Write-Warning "$Source$(if ($Target) { " [$Target]" }): $Message"
}

function ConvertTo-SafeFolderName {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return 'unnamed' }

    $invalid = [System.IO.Path]::GetInvalidFileNameChars() + @('.', ' ')
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $Name.ToCharArray()) {
        [void]$sb.Append($(if ($invalid -contains $ch) { '-' } else { $ch }))
    }

    $clean = $sb.ToString().Trim('-')
    if ($clean.Length -gt 80) { $clean = $clean.Substring(0, 80).TrimEnd('-') }
    if ([string]::IsNullOrWhiteSpace($clean)) { return 'unnamed' }
    return $clean
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowNull()]$InputObject
    )

    if ($null -eq $InputObject) {
        $json = '[]'
    }
    elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        # ConvertTo-Json unwraps single-element collections into a bare object on PS 5.1,
        # which breaks downstream consumers that expect a JSON array.
        $items = @($InputObject)
        $json = if ($items.Count -eq 0) {
            '[]'
        }
        elseif ($items.Count -eq 1) {
            "[$($items[0] | ConvertTo-Json -Depth 30)]"
        }
        else {
            $items | ConvertTo-Json -Depth 30
        }
    }
    else {
        $json = $InputObject | ConvertTo-Json -Depth 30
    }

    # -Encoding utf8 emits a BOM on Windows PowerShell 5.1; write bytes directly instead.
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function Get-PropertyOrDefault {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function Get-FirstPropertyValue {
    <#
        Returns the first non-null value among several candidate property names.
        The BAP governance APIs are inconsistent about casing between routes, so
        binding to a single spelling breaks on some tenants.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $false)]$Default = $null
    )

    foreach ($name in $Names) {
        $value = Get-PropertyOrDefault -InputObject $InputObject -Name $name
        if ($null -ne $value) { return $value }
    }
    return $Default
}

function Expand-ApiCollection {
    <#
        InvokeApi in Microsoft.PowerApps.Administration.PowerShell returns the raw
        service payload, so list cmdlets such as Get-DlpPolicy hand back an object
        shaped { value = [...] } rather than the items themselves.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()]$Response)

    if ($null -eq $Response) { return @() }

    $value = Get-PropertyOrDefault -InputObject $Response -Name 'value'
    if ($null -ne $value) { return @($value) }

    return @($Response)
}

#endregion

#region DLP

function Initialize-PowerAppsSession {
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell)) {
        throw "Microsoft.PowerApps.Administration.PowerShell is not installed. Run: Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser"
    }

    Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop

    # Add-PowerAppsAccount is a no-op when a cached token is still valid.
    Write-Host 'Signing in to the Power Platform admin APIs...' -ForegroundColor Cyan
    if ($TenantId) {
        Add-PowerAppsAccount -TenantID $TenantId | Out-Null
    }
    else {
        Add-PowerAppsAccount | Out-Null
    }
}

function Get-EnvironmentInventory {
    Write-Host 'Reading environments...' -ForegroundColor Cyan
    $environments = @(Get-AdminPowerAppEnvironment)

    if ($EnvironmentName) {
        $wanted = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$EnvironmentName, [System.StringComparer]::OrdinalIgnoreCase)
        $environments = @($environments | Where-Object { $wanted.Contains($_.EnvironmentName) })

        $found = @($environments | ForEach-Object { $_.EnvironmentName })
        foreach ($id in $EnvironmentName) {
            if ($found -notcontains $id) {
                Add-ExportError -Source 'Environments' -Target $id -Message 'Environment not found or not visible to this admin.'
            }
        }
    }

    Write-Host "  $($environments.Count) environment(s) in scope." -ForegroundColor Green
    return $environments
}

function Get-DlpPolicySnapshot {
    param([Parameter(Mandatory = $true)][string]$ResolvedTenantId)

    Write-Host 'Reading DLP policies...' -ForegroundColor Cyan

    $policies = @()
    try {
        $policies = @(Get-DlpPolicy)
    }
    catch {
        Add-ExportError -Source 'DLP' -Message "Failed to list DLP policies: $($_.Exception.Message)"
        return @()
    }

    $snapshot = foreach ($policy in $policies) {
        $policyId = Get-PropertyOrDefault -InputObject $policy -Name 'name'
        $displayName = Get-PropertyOrDefault -InputObject $policy -Name 'displayName' -Default $policyId

        Write-Host "  $displayName" -ForegroundColor DarkGray

        # Endpoint filtering and connector action rules live outside the policy document.
        $connectorConfigurations = $null
        try {
            $connectorConfigurations = Get-PowerAppDlpPolicyConnectorConfigurations `
                -TenantId $ResolvedTenantId -PolicyName $policyId
        }
        catch {
            # A policy with no endpoint/action rules returns 404 rather than an empty body.
            if ($_.Exception.Message -notmatch '404|NotFound') {
                Add-ExportError -Source 'DLP.ConnectorConfigurations' -Target $displayName -Message $_.Exception.Message
            }
        }

        $exemptResources = $null
        try {
            $exemptResources = Get-PowerAppDlpPolicyExemptResources `
                -TenantId $ResolvedTenantId -PolicyName $policyId
        }
        catch {
            if ($_.Exception.Message -notmatch '404|NotFound') {
                Add-ExportError -Source 'DLP.ExemptResources' -Target $displayName -Message $_.Exception.Message
            }
        }

        [pscustomobject]@{
            policyId                = $policyId
            displayName             = $displayName
            environmentType         = Get-PropertyOrDefault -InputObject $policy -Name 'environmentType' -Default 'Unknown'
            scopedEnvironments      = @(Get-PropertyOrDefault -InputObject $policy -Name 'environments' -Default @())
            createdBy               = Get-PropertyOrDefault -InputObject $policy -Name 'createdBy'
            createdTime             = Get-PropertyOrDefault -InputObject $policy -Name 'createdTime'
            lastModifiedBy          = Get-PropertyOrDefault -InputObject $policy -Name 'lastModifiedBy'
            lastModifiedTime        = Get-PropertyOrDefault -InputObject $policy -Name 'lastModifiedTime'
            connectorGroups         = @(Get-PropertyOrDefault -InputObject $policy -Name 'connectorGroups' -Default @())
            customConnectorPatterns = Get-PropertyOrDefault -InputObject $policy -Name 'customConnectorUrlPatternsDefinition'
            connectorConfigurations = $connectorConfigurations
            exemptResources         = $exemptResources
            raw                     = $policy
        }
    }

    return @($snapshot)
}

function Test-DlpPolicyAppliesToEnvironment {
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [Parameter(Mandatory = $true)][string]$EnvironmentId
    )

    $scopedIds = @($Policy.scopedEnvironments | ForEach-Object {
            Get-PropertyOrDefault -InputObject $_ -Name 'name'
        } | Where-Object { $_ })

    switch ($Policy.environmentType) {
        'AllEnvironments' { return $true }
        'OnlyEnvironments' { return $scopedIds -contains $EnvironmentId }
        'ExceptEnvironments' { return $scopedIds -notcontains $EnvironmentId }
        default {
            # Unknown scoping model: report the pairing rather than silently dropping it.
            return $scopedIds -contains $EnvironmentId
        }
    }
}

#endregion

#region ACP

function Get-PowerPlatformApiToken {
    <#
        Returns a bearer token for https://api.powerplatform.com.
        Preference order: Az.Accounts -> Azure CLI -> MSAL.PS with -AcpClientId.
    #>

    if (Get-Module -ListAvailable -Name Az.Accounts) {
        try {
            Import-Module Az.Accounts -ErrorAction Stop
            if (Get-AzContext -ErrorAction SilentlyContinue) {
                $token = Get-AzAccessToken -ResourceUrl $script:AcpApiBaseUrl -ErrorAction Stop
                # Az.Accounts 5.x returns a SecureString by default.
                if ($token.Token -is [System.Security.SecureString]) {
                    $plain = [System.Net.NetworkCredential]::new('', $token.Token).Password
                }
                else {
                    $plain = [string]$token.Token
                }
                if ($plain) {
                    Write-Host '  ACP token acquired via Az.Accounts.' -ForegroundColor DarkGray
                    return $plain
                }
            }
        }
        catch {
            Write-Verbose "Az.Accounts token acquisition failed: $($_.Exception.Message)"
        }
    }

    if (Get-Command az -ErrorAction SilentlyContinue) {
        try {
            $raw = az account get-access-token --resource $script:AcpApiBaseUrl --output json 2>$null
            if ($LASTEXITCODE -eq 0 -and $raw) {
                $parsed = $raw | ConvertFrom-Json
                if ($parsed.accessToken) {
                    Write-Host '  ACP token acquired via Azure CLI.' -ForegroundColor DarkGray
                    return $parsed.accessToken
                }
            }
        }
        catch {
            Write-Verbose "Azure CLI token acquisition failed: $($_.Exception.Message)"
        }
    }

    if ($AcpClientId) {
        if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
            throw 'MSAL.PS is not installed. Run: Install-Module MSAL.PS -Scope CurrentUser'
        }
        Import-Module MSAL.PS -ErrorAction Stop
        $msalParams = @{
            ClientId    = $AcpClientId
            Scopes      = "$script:AcpApiBaseUrl/.default"
            Interactive = $true
        }
        if ($TenantId) { $msalParams['TenantId'] = $TenantId }
        $result = Get-MsalToken @msalParams
        Write-Host '  ACP token acquired via MSAL.PS.' -ForegroundColor DarkGray
        return $result.AccessToken
    }

    throw 'Could not acquire a Power Platform API token. Run Connect-AzAccount, or az login, or pass -AcpClientId to use MSAL.PS.'
}

function Invoke-PowerPlatformApi {
    param(
        [Parameter(Mandatory = $true)][string]$RelativeUri,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )

    $separator = if ($RelativeUri.Contains('?')) { '&' } else { '?' }
    $uri = "$script:AcpApiBaseUrl/$($RelativeUri.TrimStart('/'))${separator}api-version=$AcpApiVersion"

    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -ErrorAction Stop
        }
        catch {
            $status = $null
            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
                $status = [int]$_.Exception.Response.StatusCode
            }

            if ($status -eq 404) { return $null }
            if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 4) {
                $delay = [Math]::Pow(2, $attempt)
                Write-Verbose "HTTP $status from $uri; retrying in $delay second(s)."
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

function Get-AcpSnapshot {
    param(
        [Parameter(Mandatory = $true)][array]$Environments,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )

    $policyCache = @{}
    $byEnvironment = @{}

    foreach ($environment in $Environments) {
        $environmentId = $environment.EnvironmentName
        $displayName = Get-PropertyOrDefault -InputObject $environment -Name 'DisplayName' -Default $environmentId

        $assigned = @()
        try {
            $assignments = Invoke-PowerPlatformApi `
                -RelativeUri "governance/ruleBasedPolicies/environments/$environmentId/assignments" `
                -Headers $Headers

            $assignmentValues = @(Get-PropertyOrDefault -InputObject $assignments -Name 'value' -Default @())

            foreach ($assignment in $assignmentValues) {
                $policyId = Get-PropertyOrDefault -InputObject $assignment -Name 'policyId'
                if (-not $policyId) { continue }

                if (-not $policyCache.ContainsKey($policyId)) {
                    $policyCache[$policyId] = Invoke-PowerPlatformApi `
                        -RelativeUri "governance/ruleBasedPolicies/$policyId" -Headers $Headers
                }

                $policy = $policyCache[$policyId]
                $ruleSets = @(Get-PropertyOrDefault -InputObject $policy -Name 'ruleSets' -Default @())
                $connectorManagement = $ruleSets | Where-Object { $_.id -eq 'ConnectorManagement' }

                $assigned += [pscustomobject]@{
                    policyId                = $policyId
                    policyName              = Get-PropertyOrDefault -InputObject $policy -Name 'name'
                    assignmentScope         = Get-PropertyOrDefault -InputObject $assignment -Name 'scope' -Default 'environment'
                    assignment              = $assignment
                    connectorManagementRule = $connectorManagement
                    policy                  = $policy
                }
            }
        }
        catch {
            Add-ExportError -Source 'ACP' -Target $displayName -Message $_.Exception.Message
        }

        $byEnvironment[$environmentId] = @($assigned)
    }

    return [pscustomobject]@{
        ByEnvironment = $byEnvironment
        Policies      = @($policyCache.Values)
    }
}

#endregion

#region Main

if (-not $OutputPath) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $OutputPath = Join-Path (Get-Location) "power-platform-policy-export\$stamp"
}

$null = New-Item -ItemType Directory -Path $OutputPath -Force
$tenantFolder = Join-Path $OutputPath '_tenant'
$null = New-Item -ItemType Directory -Path $tenantFolder -Force

Write-Host "Export folder: $OutputPath" -ForegroundColor Cyan

Initialize-PowerAppsSession
$environments = Get-EnvironmentInventory

if (-not $environments -or $environments.Count -eq 0) {
    Write-Warning 'No environments in scope. Nothing to export.'
    return
}

if (-not $TenantId) {
    $internal = Get-PropertyOrDefault -InputObject $environments[0] -Name 'Internal'
    $properties = Get-PropertyOrDefault -InputObject $internal -Name 'properties'
    $TenantId = Get-PropertyOrDefault -InputObject $properties -Name 'tenantId'
    if (-not $TenantId) {
        throw 'Unable to resolve the tenant ID from the environment list. Pass -TenantId explicitly.'
    }
    Write-Host "Resolved tenant: $TenantId" -ForegroundColor DarkGray
}

$dlpPolicies = Get-DlpPolicySnapshot -ResolvedTenantId $TenantId

$dlpErrorSettings = $null
try {
    $dlpErrorSettings = Get-PowerAppDlpErrorSettings -TenantId $TenantId
}
catch {
    if ($_.Exception.Message -notmatch '404|NotFound') {
        Add-ExportError -Source 'DLP.ErrorSettings' -Message $_.Exception.Message
    }
}

$acp = $null
if (-not $SkipAcp) {
    Write-Host 'Reading advanced connector policies...' -ForegroundColor Cyan
    try {
        $acpToken = Get-PowerPlatformApiToken
        $acpHeaders = @{ Authorization = "Bearer $acpToken" }
        $acp = Get-AcpSnapshot -Environments $environments -Headers $acpHeaders
    }
    catch {
        Add-ExportError -Source 'ACP' -Message "Advanced connector policy export skipped: $($_.Exception.Message)"
    }
    finally {
        # Do not leave the bearer token in the session scope.
        Remove-Variable -Name acpToken, acpHeaders -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host 'Skipping advanced connector policies (-SkipAcp).' -ForegroundColor DarkGray
}

# Per-environment output
$summary = [System.Collections.Generic.List[object]]::new()

foreach ($environment in $environments) {
    $environmentId = $environment.EnvironmentName
    $displayName = Get-PropertyOrDefault -InputObject $environment -Name 'DisplayName' -Default $environmentId
    $folder = Join-Path $OutputPath ("{0}__{1}" -f (ConvertTo-SafeFolderName -Name $displayName), $environmentId)
    $null = New-Item -ItemType Directory -Path $folder -Force

    Write-JsonFile -Path (Join-Path $folder 'environment.json') -InputObject $environment

    $environmentDlp = @($dlpPolicies | Where-Object {
            Test-DlpPolicyAppliesToEnvironment -Policy $_ -EnvironmentId $environmentId
        })
    Write-JsonFile -Path (Join-Path $folder 'dlp-policies.json') -InputObject $environmentDlp

    $environmentAcp = @()
    if ($acp -and $acp.ByEnvironment.ContainsKey($environmentId)) {
        $environmentAcp = @($acp.ByEnvironment[$environmentId])
    }
    Write-JsonFile -Path (Join-Path $folder 'acp-policies.json') -InputObject $environmentAcp

    foreach ($policy in $environmentDlp) {
        $summary.Add([pscustomobject]@{
                EnvironmentName        = $displayName
                EnvironmentId          = $environmentId
                EnvironmentType        = Get-PropertyOrDefault -InputObject $environment -Name 'EnvironmentType'
                PolicyKind             = 'DLP'
                PolicyName             = $policy.displayName
                PolicyId               = $policy.policyId
                Scope                  = $policy.environmentType
                ConnectorGroupCount    = @($policy.connectorGroups).Count
                HasConnectorConfigs    = [bool]$policy.connectorConfigurations
                HasExemptResources     = [bool]$policy.exemptResources
                AcpAllowedConnectorCnt = $null
            })
    }

    foreach ($policy in $environmentAcp) {
        $allowedConnectors = @()
        if ($policy.connectorManagementRule) {
            $allowedConnectors = @(Get-PropertyOrDefault `
                    -InputObject $policy.connectorManagementRule -Name 'allowedConnectors' -Default @())
        }

        $summary.Add([pscustomobject]@{
                EnvironmentName        = $displayName
                EnvironmentId          = $environmentId
                EnvironmentType        = Get-PropertyOrDefault -InputObject $environment -Name 'EnvironmentType'
                PolicyKind             = 'ACP'
                PolicyName             = $policy.policyName
                PolicyId               = $policy.policyId
                Scope                  = $policy.assignmentScope
                ConnectorGroupCount    = $null
                HasConnectorConfigs    = $null
                HasExemptResources     = $null
                AcpAllowedConnectorCnt = $allowedConnectors.Count
            })
    }

    if ($environmentDlp.Count -eq 0 -and $environmentAcp.Count -eq 0) {
        $summary.Add([pscustomobject]@{
                EnvironmentName        = $displayName
                EnvironmentId          = $environmentId
                EnvironmentType        = Get-PropertyOrDefault -InputObject $environment -Name 'EnvironmentType'
                PolicyKind             = 'None'
                PolicyName             = $null
                PolicyId               = $null
                Scope                  = $null
                ConnectorGroupCount    = $null
                HasConnectorConfigs    = $null
                HasExemptResources     = $null
                AcpAllowedConnectorCnt = $null
            })
    }
}

# Tenant-level output
Write-JsonFile -Path (Join-Path $tenantFolder 'environments.json') -InputObject $environments
Write-JsonFile -Path (Join-Path $tenantFolder 'dlp-policies.json') -InputObject $dlpPolicies
Write-JsonFile -Path (Join-Path $tenantFolder 'dlp-error-settings.json') -InputObject $dlpErrorSettings
Write-JsonFile -Path (Join-Path $tenantFolder 'acp-policies.json') -InputObject $(if ($acp) { $acp.Policies } else { @() })

$summary | Sort-Object EnvironmentName, PolicyKind, PolicyName |
    Export-Csv -Path (Join-Path $tenantFolder 'summary.csv') -NoTypeInformation -Encoding UTF8

$manifest = [pscustomobject]@{
    exportedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
    exportedBy       = "$env:USERNAME@$env:USERDNSDOMAIN"
    tenantId         = $TenantId
    environmentCount = $environments.Count
    dlpPolicyCount   = @($dlpPolicies).Count
    acpPolicyCount   = $(if ($acp) { @($acp.Policies).Count } else { 0 })
    acpSkipped       = [bool]$SkipAcp
    acpApiVersion    = $AcpApiVersion
    errors           = @($script:Errors)
}
Write-JsonFile -Path (Join-Path $tenantFolder 'export-manifest.json') -InputObject $manifest

Write-Host ''
Write-Host 'Export complete.' -ForegroundColor Green
Write-Host "  Environments : $($environments.Count)"
Write-Host "  DLP policies : $(@($dlpPolicies).Count)"
Write-Host "  ACP policies : $(if ($acp) { @($acp.Policies).Count } else { 'skipped' })"
Write-Host "  Output       : $OutputPath"
if ($script:Errors.Count -gt 0) {
    Write-Host "  Errors       : $($script:Errors.Count) (see _tenant\export-manifest.json)" -ForegroundColor Yellow
}

#endregion
