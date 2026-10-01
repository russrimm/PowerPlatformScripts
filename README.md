# Power Platform Scripts

This is where I keep my Power Platform related scripts. Expect a growing collection of
PowerShell and other utilities for administering, governing, and automating Microsoft
Power Platform tenants and environments.

## Scripts

| Script | Description |
| ------ | ----------- |
| [`Copy-AcpPolicy-and-Actions.ps1`](Copy-AcpPolicy-and-Actions.ps1) | Copies advanced connector policy (ACP) connector action settings from one environment group to another using the Power Platform API. |
| [`Export-PowerPlatformPolicies.ps1`](Export-PowerPlatformPolicies.ps1) | Exports DLP and ACP policies for every environment in the tenant into a per-environment snapshot. |
| [`Grant-PPReader.ps1`](Grant-PPReader.ps1) | Assigns the built-in "Power Platform reader" role at tenant scope to a user or Entra group. |

## Usage

Each script is self-contained. Review the top of a script before running it: most include
comment-based help (run `Get-Help .\<script>.ps1 -Full`), while others use configuration
variables (such as tenant and group IDs) that you fill in first.

Some scripts use preview Power Platform APIs, so their behavior may change over time.

## Disclaimer

These scripts are provided as-is, without warranty. Test them in a non-production
environment before running them against production tenants.
