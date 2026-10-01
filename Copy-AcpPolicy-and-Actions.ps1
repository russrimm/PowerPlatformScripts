$tenantId   = "<tenant-id>"
$apiBaseUrl = "https://api.powerplatform.com"
$apiVersion = "2024-10-01"

$sourceGroupId = "<source environment group ID>"
$targetGroupId = "<target environment group ID>"
$CopyAllRules  = $true

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

# ---------- Authenticate (requires the Az.Accounts module: Install-Module Az.Accounts -Scope CurrentUser) ----------
Connect-AzAccount -Tenant $tenantId | Out-Null
$token = (Get-AzAccessToken -ResourceUrl $apiBaseUrl -AsSecureString).Token | ConvertFrom-SecureString -AsPlainText
$headers = @{ Authorization = "Bearer $token" }

function Invoke-PpApi($method, $path, $body) {
    $params = @{ Method = $method; Uri = "$apiBaseUrl/$path`?api-version=$apiVersion"; Headers = $headers }
    if ($body) { $params.ContentType = "application/json"; $params.Body = $body }
    Invoke-RestMethod @params
}

# ---------- 1. Read the source group's policy ----------
$sourceAssignments = Invoke-PpApi Get "governance/ruleBasedPolicies/environmentGroups/$sourceGroupId/assignments"
if (-not $sourceAssignments.value) { throw "No policy is assigned to source group $sourceGroupId" }
$sourcePolicyId = $sourceAssignments.value[0].policyId
$source   = Invoke-PpApi Get "governance/ruleBasedPolicies/$sourcePolicyId"
$sourceCm = Get-ConnectorManagement $source

# ---------- 2. Copy the rules (unchanged logic) ----------
# A group can have only one assigned policy, so check the target first
$targetAssignments = Invoke-PpApi Get "governance/ruleBasedPolicies/environmentGroups/$targetGroupId/assignments"
$targetPolicyId = if ($targetAssignments.value) { $targetAssignments.value[0].policyId } else { $null }

if ($targetPolicyId) {
    # Target already has a policy: patch the source rule sets into it (patch adds/updates rule sets by ID)
    $targetPolicy = Invoke-PpApi Get "governance/ruleBasedPolicies/$targetPolicyId"
    $ruleSetsToCopy = if ($CopyAllRules) { @($source.ruleSets) } else { @($sourceCm) }
    if (-not $ruleSetsToCopy -or -not $ruleSetsToCopy[0]) { throw "Source policy $sourcePolicyId has no rule sets to copy." }

    $patchBody = @{ name = $targetPolicy.name; ruleSets = $ruleSetsToCopy } | ConvertTo-Json -Depth 20
    Invoke-PpApi Patch "governance/ruleBasedPolicies/$targetPolicyId" $patchBody | Out-Null
    Write-Host "Target group already uses policy $targetPolicyId - updated it with $($ruleSetsToCopy.Count) rule set(s): $(($ruleSetsToCopy.id) -join ', ')"
}
elseif ($CopyAllRules) {
    # No policy on the target: copy ALL rule sets into a new policy and assign it
    $copyBody = @{ name = "$($source.name) (copy)"; ruleSets = $source.ruleSets } | ConvertTo-Json -Depth 20
    $copy = Invoke-PpApi Post "governance/ruleBasedPolicies" $copyBody
    Invoke-PpApi Post "governance/ruleBasedPolicies/$($copy.id)/environmentGroups/$targetGroupId/assignments" "{}" | Out-Null
    $targetPolicyId = $copy.id
    Write-Host "Copied all rules to new policy $targetPolicyId and assigned it to group $targetGroupId"
}
else {
    throw "No policy is assigned to target group $targetGroupId. Set `$CopyAllRules = `$true to create one."
}

# ---------- 3. Copy connector actions for each copied connector rule ----------
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

# ---------- 4. Verify ----------
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
