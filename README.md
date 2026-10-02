# Power Platform Scripts

This is where I keep my Power Platform related scripts. Expect a growing
collection of PowerShell and other utilities for administering, governing, and
automating Microsoft Power Platform tenants and environments.

## Scripts

| Script | Description |
| ------ | ----------- |
| [`Copy-PolicyToNewEnvironmentGroup.ps1`](Copy-PolicyToNewEnvironmentGroup.ps1) | Creates a new environment group and copies the source group's rule-based policy to it, including per-connector action settings, then verifies the result. |
| [`Export-PowerPlatformPolicies.ps1`](Export-PowerPlatformPolicies.ps1) | Exports DLP and ACP policies for every environment in the tenant into a per-environment snapshot. |
| [`Grant-PPReader.ps1`](Grant-PPReader.ps1) | Assigns the built-in "Power Platform reader" role at tenant scope to a user or Entra group. |

## Usage

Each script is self-contained and includes comment-based help. Review it
before running a script:

```powershell
Get-Help .\<script>.ps1 -Full
```

Most scripts authenticate with the `Az.Accounts` module:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
```

Check each script's help for any additional modules or permissions it requires.

Some scripts use preview Power Platform APIs, so their behavior may change over
time.

## Disclaimer

These scripts are provided as-is, without warranty. Test them in a non-production
environment before running them against production tenants.
