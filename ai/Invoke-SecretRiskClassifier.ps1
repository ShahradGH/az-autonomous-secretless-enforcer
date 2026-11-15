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
    [string]$GitHubOrgRepo = 'contoso-platform/workload-ci',

    [Parameter()]
    [string]$FoundryEndpoint = '',

    [Parameter()]
    [string]$FoundryApiKey = '',

    [Parameter()]
    [string]$FoundryDeployment = 'gpt-4o',

    [Parameter()]
    [string]$FoundryApiVersion = '2024-10-21',

    [Parameter()]
    [switch]$UseLiveFoundry
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($UseLiveFoundry) {
    if ([string]::IsNullOrWhiteSpace($FoundryEndpoint)) {
        throw [System.ArgumentException]::new('Fail-closed: -FoundryEndpoint is required when -UseLiveFoundry is specified.')
    }
    if ($FoundryEndpoint -notmatch '^https://') {
        throw [System.ArgumentException]::new('Fail-closed: -FoundryEndpoint must use https://.')
    }
}

function Get-FoundryAuthHeader {
    param([string]$ApiKey)
    if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
        return @{
            'api-key'      = $ApiKey
            'Content-Type' = 'application/json'
        }
    }
    if (Get-Command -Name 'Get-AzAccessToken' -ErrorAction SilentlyContinue) {
        $tok = Get-AzAccessToken -ResourceUrl 'https://cognitiveservices.azure.com' -ErrorAction Stop
        $rawToken = if ($tok.Token -is [System.Security.SecureString]) {
            [System.Net.NetworkCredential]::new('', $tok.Token).Password
        } else {
            [string]$tok.Token
        }
        return @{
            'Authorization' = "Bearer $rawToken"
            'Content-Type'  = 'application/json'
        }
    }
    $imdsUri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://cognitiveservices.azure.com'
    $imdsResp = Invoke-RestMethod -Method Get -Uri $imdsUri -Headers @{ Metadata = 'true' } -TimeoutSec 5 -ErrorAction Stop
    return @{
        'Authorization' = "Bearer $($imdsResp.access_token)"
        'Content-Type'  = 'application/json'
    }
}

function Invoke-FoundryJsonInference {
    param(
        [string]$Endpoint,
        [string]$ApiKey,
        [string]$Deployment,
        [string]$ApiVersion,
        [string]$SystemPrompt,
        [hashtable]$Payload
    )
    $uri = if ($Endpoint -match '/chat/completions') {
        $Endpoint
    } else {
        "$($Endpoint.TrimEnd('/'))/openai/deployments/$Deployment/chat/completions?api-version=$ApiVersion"
    }
    $headers = Get-FoundryAuthHeader -ApiKey $ApiKey
    $body = @{
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
        messages        = @(
            @{ role = 'system'; content = $SystemPrompt },
            @{ role = 'user'; content = ($Payload | ConvertTo-Json -Depth 6 -Compress) }
        )
    } | ConvertTo-Json -Depth 8 -Compress

    $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -TimeoutSec 30 -ErrorAction Stop
    $content = $resp.choices[0].message.content
    return ($content | ConvertFrom-Json -ErrorAction Stop)
}

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

$severityTier = $selectedBand.tier
$recommendedAction = $selectedBand.action
$inferenceMode = 'DETERMINISTIC_LOCAL'
$foundryRationale = $null

if ($UseLiveFoundry) {
    $allowedTiers = @($rubric.severityBands | ForEach-Object { $_.tier })
    $allowedActions = @($rubric.severityBands | ForEach-Object { $_.action })
    try {
        $foundryResult = Invoke-FoundryJsonInference `
            -Endpoint $FoundryEndpoint `
            -ApiKey $FoundryApiKey `
            -Deployment $FoundryDeployment `
            -ApiVersion $FoundryApiVersion `
            -SystemPrompt 'You are an Entra ID Workload Identity security classifier. Return JSON with keys: severityTier, recommendedAction, rationale.' `
            -Payload @{
                appId            = $appId
                displayName      = $ServicePrincipalContext.DisplayName
                graphPermissions = @($ServicePrincipalContext.GraphPermissions)
                azureRbacRoles   = @($ServicePrincipalContext.AzureRbacRoles)
                secretAgeDays    = [int]$ServicePrincipalContext.SecretAgeDays
                hasFederatedOidc = [bool]$ServicePrincipalContext.HasFederatedOidc
                deterministicScore = $score
                deterministicTier  = $severityTier
            }

        $llmTier = if ($null -ne $foundryResult.PSObject.Properties['severityTier']) { [string]$foundryResult.severityTier } else { '' }
        $llmAction = if ($null -ne $foundryResult.PSObject.Properties['recommendedAction']) { [string]$foundryResult.recommendedAction } else { '' }
        if ($llmTier -in $allowedTiers -and $llmAction -in $allowedActions) {
            # Never downgrade a CRITICAL_PRIVILEGED_SPN deterministic classification
            if ($severityTier -ne 'CRITICAL_PRIVILEGED_SPN') {
                $severityTier = $llmTier
                $recommendedAction = $llmAction
            }
            $inferenceMode = 'LIVE_FOUNDRY'
            if ($null -ne $foundryResult.PSObject.Properties['rationale']) {
                $foundryRationale = [string]$foundryResult.rationale
            }
        } else {
            Write-Warning "Foundry returned invalid tier/action ('$llmTier'/'$llmAction'); falling back to deterministic rubric."
            $inferenceMode = 'DETERMINISTIC_FALLBACK'
        }
    } catch {
        Write-Warning "Live Foundry inference failed ($($_.Exception.Message)); falling back to deterministic rubric."
        $inferenceMode = 'DETERMINISTIC_FALLBACK'
    }
}

return [PSCustomObject]@{
    AppId              = $appId
    DisplayName        = $ServicePrincipalContext.DisplayName
    BlastRadiusScore   = $score
    SeverityTier       = $severityTier
    RecommendedAction  = $recommendedAction
    RiskFactors        = $findings.ToArray()
    TargetRepository   = $GitHubOrgRepo
    OidcMigrationDiff  = $oidcDiff
    InferenceMode      = $inferenceMode
    FoundryRationale   = $foundryRationale
}
