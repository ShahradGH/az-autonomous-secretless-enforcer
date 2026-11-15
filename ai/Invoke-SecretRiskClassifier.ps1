<#
.SYNOPSIS
    Classifies leaked or newly added Entra SPN credentials by Graph scope & Azure RBAC blast radius and generates OIDC PR diffs.
.DESCRIPTION
    Evaluates an Entra Application / Service Principal inventory record against ai/secret-risk-rubric.json
    (or an Azure AI Foundry endpoint when configured), computes a deterministic blast-radius score,
    and outputs a scoped GitHub Actions + PowerShell Workload Identity OIDC migration diff.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCustomObject]$ServicePrincipalContext,

    [Parameter()]
    [string]$RubricPath = (Join-Path $PSScriptRoot 'secret-risk-rubric.json'),

    [Parameter()]
    [string]$GitHubOrgRepo = 'contoso-platform/workload-ci'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rubric = Get-Content -Path $RubricPath -Raw | ConvertFrom-Json
$score = 0
$findings = [System.Collections.Generic.List[string]]::new()

foreach ($perm in @($ServicePrincipalContext.GraphPermissions)) {
    $prop = $rubric.scoringWeights.graphPermissions.PSObject.Properties[$perm]
    if ($null -ne $prop) {
        $score += [int]$prop.Value
        $findings.Add("Graph:$perm (+$($prop.Value))")
    } else {
        $score += 10
        $findings.Add("Graph:$perm (+10)")
    }
}

foreach ($role in @($ServicePrincipalContext.AzureRbacRoles)) {
    $prop = $rubric.scoringWeights.azureRbacRoles.PSObject.Properties[$role]
    if ($null -ne $prop) {
        $score += [int]$prop.Value
        $findings.Add("RBAC:$role (+$($prop.Value))")
    }
}

if ([int]$ServicePrincipalContext.SecretAgeDays -gt 90) {
    $score += [int]$rubric.scoringWeights.credentialPosture.secretAgeOver90Days
    $findings.Add("SecretAgeDays=$($ServicePrincipalContext.SecretAgeDays) (+15)")
}

if (-not [bool]$ServicePrincipalContext.HasFederatedOidc) {
    $score += [int]$rubric.scoringWeights.credentialPosture.missingFederatedOidc
    $findings.Add('MissingFederatedOidc (+10)')
}

$selectedBand = $rubric.severityBands |
    Where-Object { $score -ge $_.minScore } |
    Sort-Object -Property minScore -Descending |
    Select-Object -First 1

$appId = $ServicePrincipalContext.AppId
$oidcDiff = @"
--- a/.github/workflows/deploy.yml
+++ b/.github/workflows/deploy.yml
@@ -8,9 +8,11 @@
+permissions:
+  id-token: write
+  contents: read
 steps:
   - uses: azure/login@v2
     with:
-      creds: `${{ secrets.AZURE_SPN_CREDENTIALS }}
+      client-id: $appId
+      tenant-id: `${{ vars.AZURE_TENANT_ID }}
+      subscription-id: `${{ vars.AZURE_SUBSCRIPTION_ID }}
"@

return [PSCustomObject]@{
    AppId              = $appId
    DisplayName        = $ServicePrincipalContext.DisplayName
    BlastRadiusScore   = $score
    SeverityTier       = $selectedBand.tier
    RecommendedAction  = $selectedBand.action
    RiskFactors        = $findings.ToArray()
    TargetRepository   = $GitHubOrgRepo
    OidcMigrationDiff  = $oidcDiff
}
