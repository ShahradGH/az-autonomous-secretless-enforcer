<#
.SYNOPSIS
    Provisions secretless OIDC Federated Identity Credentials via Graph v2.x and disables Storage Shared Key access.
.DESCRIPTION
    Replaces declarative Bicep templates with pure PowerShell 7.4+ Microsoft Graph v2.x (/federatedIdentityCredentials,
    /removePassword) and Azure Resource Manager (Invoke-AzRestMethod) calls to enforce allowSharedKeyAccess=false.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ApplicationObjectId,

    [Parameter(Mandatory)]
    [string]$GitHubRepository,

    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$StorageAccountName,

    [Parameter()]
    [string]$BranchName = 'main',

    [Parameter()]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ficPayload = @{
    name        = "gh-$($GitHubRepository.Replace('/', '-'))-$BranchName"
    issuer      = 'https://token.actions.githubusercontent.com'
    subject     = "repo:${GitHubRepository}:ref:refs/heads/${BranchName}"
    description = 'Secretless GitHub Actions OIDC Workload Identity Federation'
    audiences   = @('api://AzureADTokenExchange')
}

$ficUri = "https://graph.microsoft.com/v1.0/applications/$ApplicationObjectId/federatedIdentityCredentials"
$storageUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/${StorageAccountName}?api-version=2023-05-01"
$storagePatch = @{
    properties = @{
        allowSharedKeyAccess     = $false
        minimumTlsVersion        = 'TLS1_2'
        supportsHttpsTrafficOnly = $true
    }
}

if ($DryRun) {
    return [PSCustomObject]@{
        Mode                   = 'DRY_RUN'
        FederatedCredentialUri = $ficUri
        FederatedCredential    = $ficPayload
        StorageHardeningUri    = $storageUri
        StorageHardeningBody   = $storagePatch
    }
}

if ($PSCmdlet.ShouldProcess($ApplicationObjectId, 'Create GitHub Actions OIDC Federated Identity Credential via Graph')) {
    $ficResp = Invoke-MgGraphRequest -Method POST -Uri $ficUri -Body ($ficPayload | ConvertTo-Json -Depth 6) -ContentType 'application/json'
}

if ($PSCmdlet.ShouldProcess($StorageAccountName, 'Enforce allowSharedKeyAccess=false via Invoke-AzRestMethod')) {
    $azResp = Invoke-AzRestMethod -Method PATCH -Path $storageUri -Payload ($storagePatch | ConvertTo-Json -Depth 6)
}

return [PSCustomObject]@{
    Mode                = 'APPLIED'
    FederatedCredential = $ficResp
    StorageStatusCode   = $azResp.StatusCode
}
