<#
.SYNOPSIS
  Assigns the built-in "Power Platform reader" role to a user or group at the
  tenant scope using the Power Platform RBAC API (preview). Supports signing
  in with a different account / tenant on each run.

.PARAMETER TenantId
  Target Microsoft Entra tenant GUID (the tenant where the role is assigned).

.PARAMETER UserPrincipalName
  UPN of the user to grant Reader.

.PARAMETER GroupId
  Object ID of an Entra security group to grant Reader.

.PARAMETER GroupDisplayName
  Display name of an Entra security group (resolved via Graph).

.PARAMETER Credential
  Optional PSCredential for non-interactive user sign-in (no MFA accounts only).

.PARAMETER ServicePrincipal
  Switch. Use with -Credential where UserName = AppId and Password = client secret.

.EXAMPLE
  # Interactive — prompts for account, lets you pick a different tenant/user
  .\Grant-PPReader.ps1 -TenantId <tenant-guid> -UserPrincipalName jane.doe@contoso.com

.EXAMPLE
  # Service principal in another tenant
  $cred = Get-Credential   # username = <appId>, password = <client secret>
  .\Grant-PPReader.ps1 -TenantId <tenant-guid> -GroupDisplayName "PPAC Readers" `
                       -Credential $cred -ServicePrincipal
#>

[CmdletBinding(DefaultParameterSetName = 'User')]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true, ParameterSetName = 'User')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true, ParameterSetName = 'GroupById')]
    [string]$GroupId,

    [Parameter(Mandatory = $true, ParameterSetName = 'GroupByName')]
    [string]$GroupDisplayName,

    [Parameter()]
    [pscredential]$Credential,

    [Parameter()]
    [switch]$ServicePrincipal
)

$ErrorActionPreference = 'Stop'

# Built-in role: Power Platform reader (read-only at tenant scope)
$PowerPlatformReaderRoleId = 'c886ad2e-27f7-4874-8381-5849b8d8a090'
$ApiVersion = '2024-10-01'
$PPResource = 'https://api.powerplatform.com/'
$Scope      = "/tenants/$TenantId"

# --- 1. Ensure required modules (and keep Az.Accounts current) ---
$MinAzAccountsVersion = [version]'2.19.0'   # needs -AuthScope / -ContextScope

# Make sure NuGet provider + PSGallery trust are in place for unattended installs
if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
}
if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

# Az.Accounts: install or update to at least $MinAzAccountsVersion
$installedAz = Get-Module -ListAvailable -Name Az.Accounts |
               Sort-Object Version -Descending | Select-Object -First 1
if (-not $installedAz) {
    Write-Host "Installing Az.Accounts..."
    Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber
} elseif ($installedAz.Version -lt $MinAzAccountsVersion) {
    Write-Host "Updating Az.Accounts ($($installedAz.Version) -> latest)..."
    # Remove any loaded copy first so Update-Module can replace it cleanly
    Get-Module Az.Accounts | Remove-Module -Force -ErrorAction SilentlyContinue
    try {
        Update-Module Az.Accounts -Force -ErrorAction Stop
    } catch {
        Write-Warning "Update-Module failed ($($_.Exception.Message)); falling back to Install-Module."
        Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber
    }
}

# Other required modules (install if missing; don't force-update)
foreach ($m in 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Groups') {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing module $m..."
        Install-Module $m -Scope CurrentUser -Force -AllowClobber
    }
}

# Import the newest Az.Accounts explicitly, then the rest
Import-Module Az.Accounts -MinimumVersion $MinAzAccountsVersion -ErrorAction Stop
foreach ($m in 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Groups') {
    Import-Module $m -ErrorAction Stop
}

Write-Host "Az.Accounts version in use: $((Get-Module Az.Accounts).Version)"

# --- 2. Clear any cached sessions so a different identity / tenant can be used ---
Write-Host "Clearing any existing Az / Graph sessions..."
try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
try { Disconnect-MgGraph    -ErrorAction SilentlyContinue | Out-Null } catch {}

# --- 3. Sign in to Azure for the Power Platform API ---
$connectCmd = Get-Command Connect-AzAccount
$supported  = $connectCmd.Parameters.Keys

$azConnect = @{
    TenantId = $TenantId
    Force    = $true
}
if ($supported -contains 'AuthScope')    { $azConnect.AuthScope    = $PPResource }
if ($supported -contains 'ContextScope') { $azConnect.ContextScope = 'Process' }

if ($Credential) {
    $azConnect.Credential = $Credential
    if ($ServicePrincipal) { $azConnect.ServicePrincipal = $true }
    Write-Host "Connecting to Az with supplied credentials..."
} else {
    Write-Host "Launching interactive sign-in (pick the account for tenant $TenantId)..."
}

Connect-AzAccount @azConnect | Out-Null

$ctx = Get-AzContext
Write-Host "Signed in as: $($ctx.Account.Id)  Tenant: $($ctx.Tenant.Id)"
if ($ctx.Tenant.Id -ne $TenantId) {
    throw "Signed-in tenant ($($ctx.Tenant.Id)) does not match -TenantId ($TenantId)."
}

# Get the Power Platform API token. Handle both string (old Az) and SecureString (new Az).
$tokenObj = Get-AzAccessToken -TenantId $TenantId -ResourceUrl $PPResource

if ($tokenObj.Token -is [System.Security.SecureString]) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenObj.Token)
    try {
        $tokenString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
} else {
    $tokenString = [string]$tokenObj.Token
}

if ([string]::IsNullOrWhiteSpace($tokenString) -or ($tokenString.Split('.').Count -ne 3)) {
    throw "Did not get a valid JWT from Get-AzAccessToken. Length=$($tokenString.Length)"
}

$headers = @{
    'Authorization' = "Bearer $tokenString"
    'Content-Type'  = 'application/json'
}

Write-Host "Acquired Power Platform API token (length=$($tokenString.Length))."

# --- 4. Resolve principal via Microsoft Graph (same tenant, same identity) ---
if ($Credential -and $ServicePrincipal) {
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential -NoWelcome | Out-Null
} else {
    Connect-MgGraph -TenantId $TenantId -Scopes 'User.Read.All','Group.Read.All' -NoWelcome | Out-Null
}

switch ($PSCmdlet.ParameterSetName) {
    'User' {
        $principal = Get-MgUser -UserId $UserPrincipalName
        $principalObjectId = $principal.Id
        $principalType     = 'User'
        Write-Host "Resolved user '$UserPrincipalName' -> $principalObjectId"
    }
    'GroupById' {
        $principal = Get-MgGroup -GroupId $GroupId
        $principalObjectId = $principal.Id
        $principalType     = 'Group'
        Write-Host "Using group '$($principal.DisplayName)' -> $principalObjectId"
    }
    'GroupByName' {
        $groups = Get-MgGroup -Filter "displayName eq '$GroupDisplayName'"
        if (-not $groups)        { throw "No group found with displayName '$GroupDisplayName'." }
        if ($groups.Count -gt 1) { throw "Multiple groups match '$GroupDisplayName'; use -GroupId instead." }
        $principalObjectId = $groups.Id
        $principalType     = 'Group'
        Write-Host "Resolved group '$GroupDisplayName' -> $principalObjectId"
    }
}

# --- 5. Create the role assignment ---
$body = @{
    roleDefinitionId  = $PowerPlatformReaderRoleId
    principalObjectId = $principalObjectId
    principalType     = $principalType
    scope             = $Scope
} | ConvertTo-Json

$uri = "https://api.powerplatform.com/authorization/roleAssignments?api-version=$ApiVersion"

Write-Host "POST $uri"
Write-Host $body
$result = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
$result | Format-List

# --- 6. Verify ---
$all = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$all.value |
    Where-Object { $_.principalObjectId -eq $principalObjectId } |
    Format-Table roleAssignmentId, roleDefinitionId, scope, principalType

# --- 7. Optional cleanup — uncomment to fully sign out when done ---
# Disconnect-AzAccount | Out-Null
# Disconnect-MgGraph   | Out-Null
