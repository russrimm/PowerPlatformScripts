<#
.SYNOPSIS
    Creates a new environment group and copies the source group's rule-based policy (including connector actions) to it.
.PARAMETER TenantId
    Optional. Defaults to the tenant of the current Az session (Get-AzContext). If there is no session, you are prompted to sign in.
.EXAMPLE
    .\Copy-PolicyToNewEnvironmentGroup.ps1 -SourceGroupId <source-group-guid> -TargetGroupName "Contoso - Copy"
.EXAMPLE
    .\Copy-PolicyToNewEnvironmentGroup.ps1 -TenantId <tenant-guid> -SourceGroupId <source-group-guid> -TargetGroupName "Contoso - Copy"
#>
param(
    [string]$TenantId,
    [string]$SourceGroupId,
    [string]$TargetGroupName,
    [string]$TargetGroupDescription
)

$apiBaseUrl   = "https://api.powerplatform.com"
$apiVersion   = "2024-10-01"
$CopyAllRules = $true   # $false = copy only the ConnectorManagement rule set

# ---------- Helpers ----------
function Get-Prop($obj, $name) {
    if ($null -ne $obj -and $obj.PSObject.Properties.Name -contains $name) { return $obj.$name }
    return $null
}

function Get-ConnectorKey($entry) { (([string]$entry.AllowedConnector) -split "/")[-1].ToLowerInvariant() }

function Get-ConnectorManagement($policy) {
    $policy.ruleSets | Where-Object { $_.id -eq "ConnectorManagement" } | Select-Object -First 1
}

function Get-ActionSignature($entry) {
    $mode = Get-Prop $entry "AllowedActionsMode"
    if (-not $mode) { $mode = "AllAllowed" }
    if ($mode -ne "SomeAllowed") { return $mode }
    $actions = (@(Get-Prop $entry "AllowedActions") | Where-Object { $_ } | Sort-Object) -join "|"
    return "$mode::$actions"
}

# Copies AllowedActionsMode/AllowedActions from each source connector to the matching target connector.
# Returns the number of connectors that were changed.
function Sync-ConnectorActions($sourceCm, $targetCm) {
    $changed = 0
    foreach ($src in @($sourceCm.inputs.AllowedConnectorList)) {
        $key = Get-ConnectorKey $src
        $tgt = @($targetCm.inputs.AllowedConnectorList) | Where-Object { (Get-ConnectorKey $_) -eq $key } | Select-Object -First 1
        if (-not $tgt) { Write-Warning "  $key is in the source but not in the target rule - skipped"; continue }
        if ((Get-ActionSignature $src) -eq (Get-ActionSignature $tgt)) { continue }

        $mode = Get-Prop $src "AllowedActionsMode"
        if (-not $mode) { $mode = "AllAllowed" }
        $tgt | Add-Member -NotePropertyName AllowedActionsMode -NotePropertyValue $mode -Force
        if ($mode -eq "SomeAllowed") {
            $actions = [object[]]@(Get-Prop $src "AllowedActions")
            $tgt | Add-Member -NotePropertyName AllowedActions -NotePropertyValue $actions -Force
            Write-Host "  $key -> SomeAllowed ($($actions.Count) allowed): $($actions -join ', ')"
        }
        else {
            $tgt.PSObject.Properties.Remove("AllowedActions")
            Write-Host "  $key -> $mode"
        }
        $changed++
    }
    return $changed
}

if ($MyInvocation.InvocationName -eq ".") { return }  # dot-sourced: load helpers only

# Validated here rather than with [Parameter(Mandatory)] so dot-sourcing for the helpers doesn't prompt
$missing = @("SourceGroupId", "TargetGroupName") | Where-Object { [string]::IsNullOrWhiteSpace((Get-Variable $_ -ValueOnly)) }
if ($missing) { throw "Missing required parameter(s): $(($missing | ForEach-Object { "-$_" }) -join ', ')" }
if (-not $TargetGroupDescription) { $TargetGroupDescription = "Created by script - rules copied from group $SourceGroupId" }

# ---------- Authenticate (requires the Az.Accounts module: Install-Module Az.Accounts -Scope CurrentUser) ----------
$context = Get-AzContext
if ($TenantId) {
    if (-not $context -or $context.Tenant.Id -ne $TenantId) { Connect-AzAccount -Tenant $TenantId | Out-Null }
}
else {
    if (-not $context) { Connect-AzAccount | Out-Null }
    $TenantId = (Get-AzContext).Tenant.Id
    if (-not $TenantId) { throw "Could not determine the current tenant. Pass -TenantId explicitly." }
}
Write-Host "Using tenant $TenantId"
$token = (Get-AzAccessToken -ResourceUrl $apiBaseUrl -TenantId $TenantId -AsSecureString).Token | ConvertFrom-SecureString -AsPlainText
$headers = @{ Authorization = "Bearer $token" }

function Invoke-PpApi($method, $path, $body) {
    $params = @{ Method = $method; Uri = "$apiBaseUrl/$path`?api-version=$apiVersion"; Headers = $headers }
    if ($body) { $params.ContentType = "application/json"; $params.Body = $body }
    Invoke-RestMethod @params
}

# ---------- 1. Read the source group's policy ----------
$sourceAssignments = Invoke-PpApi Get "governance/ruleBasedPolicies/environmentGroups/$SourceGroupId/assignments"
if (-not $sourceAssignments.value) { throw "No policy is assigned to source group $SourceGroupId" }
$sourcePolicyId = $sourceAssignments.value[0].policyId
$source   = Invoke-PpApi Get "governance/ruleBasedPolicies/$sourcePolicyId"
$sourceCm = Get-ConnectorManagement $source

$ruleSetsToCopy = if ($CopyAllRules) { @($source.ruleSets) } else { @($sourceCm) }
if (-not $ruleSetsToCopy -or -not $ruleSetsToCopy[0]) { throw "Source policy $sourcePolicyId has no rule sets to copy." }

# ---------- 2. Create the target environment group ----------
$groupBody = @{ displayName = $TargetGroupName; description = $TargetGroupDescription } | ConvertTo-Json
$newGroup  = Invoke-PpApi Post "environmentmanagement/environmentGroups" $groupBody
$targetGroupId = Get-Prop $newGroup "id"

if (-not $targetGroupId) {
    # The service can answer 204 No Content - look the new group up by name instead
    $allGroups = Invoke-PpApi Get "environmentmanagement/environmentGroups"
    $match = @($allGroups.value | Where-Object { $_.displayName -eq $TargetGroupName } |
        Sort-Object { [datetime](Get-Prop $_ "createdTime") } -Descending)
    if (-not $match) { throw "Environment group '$TargetGroupName' was created but its ID could not be found." }
    $targetGroupId = $match[0].id
}
Write-Host "Created environment group '$TargetGroupName' ($targetGroupId)"

# ---------- 3. Copy the rules into a new policy and assign it to the new group ----------
try {
    $copyBody = @{ name = "$($source.name) (copy)"; ruleSets = $ruleSetsToCopy } | ConvertTo-Json -Depth 20
    $copy = Invoke-PpApi Post "governance/ruleBasedPolicies" $copyBody
    $targetPolicyId = $copy.id
    Invoke-PpApi Post "governance/ruleBasedPolicies/$targetPolicyId/environmentGroups/$targetGroupId/assignments" "{}" | Out-Null
}
catch {
    Write-Warning "Policy copy/assignment failed. The new environment group $targetGroupId still exists - delete it or assign a policy manually."
    throw
}
Write-Host "Copied $($ruleSetsToCopy.Count) rule set(s) ($(($ruleSetsToCopy.id) -join ', ')) to new policy $targetPolicyId and assigned it to group $targetGroupId"

# ---------- 4. Copy connector actions for each copied connector rule ----------
if (-not $sourceCm) { Write-Host "Source policy has no ConnectorManagement rule set - no connector actions to copy."; return }

$restricted = @($sourceCm.inputs.AllowedConnectorList | Where-Object { (Get-Prop $_ "AllowedActionsMode") -eq "SomeAllowed" })
Write-Host "Source has $($restricted.Count) connector(s) with restricted (partly disabled) actions."

# Re-read what the service actually stored for the target
$target   = Invoke-PpApi Get "governance/ruleBasedPolicies/$targetPolicyId"
$targetCm = Get-ConnectorManagement $target
if (-not $targetCm) { throw "Target policy $targetPolicyId has no ConnectorManagement rule set after the copy." }

Write-Host "Syncing connector actions into policy $targetPolicyId :"
$changed = Sync-ConnectorActions $sourceCm $targetCm
if ($changed -gt 0) {
    $patchBody = @{ name = $target.name; ruleSets = @($targetCm) } | ConvertTo-Json -Depth 20
    Invoke-PpApi Patch "governance/ruleBasedPolicies/$targetPolicyId" $patchBody | Out-Null
    Write-Host "Updated actions on $changed connector(s)."
}
else {
    Write-Host "Connector actions already match the source - nothing to update."
}

# ---------- 5. Verify ----------
$verifyCm = Get-ConnectorManagement (Invoke-PpApi Get "governance/ruleBasedPolicies/$targetPolicyId")
$mismatches = 0
foreach ($src in @($sourceCm.inputs.AllowedConnectorList)) {
    $key = Get-ConnectorKey $src
    $tgt = @($verifyCm.inputs.AllowedConnectorList) | Where-Object { (Get-ConnectorKey $_) -eq $key } | Select-Object -First 1
    if (-not $tgt -or (Get-ActionSignature $src) -ne (Get-ActionSignature $tgt)) {
        Write-Warning "Mismatch for $key - source: $(Get-ActionSignature $src) | target: $(Get-ActionSignature $tgt)"
        $mismatches++
    }
}
if ($mismatches -eq 0) { Write-Host "Verified: connector actions in $targetPolicyId match the source." }
Write-Host "Done. New environment group ID: $targetGroupId"
