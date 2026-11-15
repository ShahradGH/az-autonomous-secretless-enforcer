# Invoke-EntraSecretlessEnforcement.ps1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [PSCustomObject]$ApplicationObject,

    [Parameter()]
    [string[]]$BreakGlassExemptAppIds = @(),

    [Parameter()]
    [switch]$ExecuteGraphRevocation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($BreakGlassExemptAppIds -contains $ApplicationObject.AppId) {
    return [PSCustomObject]@{
        AppId         = $ApplicationObject.AppId
        DisplayName   = $ApplicationObject.DisplayName
        Action        = 'EXEMPT_BREAK_GLASS_AUDITED'
        RevokedCount  = 0
        RevokedKeyIds = @()
    }
}

$activeSecrets = @($ApplicationObject.PasswordCredentials)
$federatedCreds = @($ApplicationObject.FederatedIdentityCredentials)

if ($activeSecrets.Count -gt 0) {
    $revokedKeys = [System.Collections.Generic.List[string]]::new()

    if ($ExecuteGraphRevocation) {
        $objId = $ApplicationObject.ObjectId
        foreach ($secret in $activeSecrets) {
            if ($PSCmdlet.ShouldProcess($ApplicationObject.DisplayName, "Remove passwordCredential $($secret.keyId) via Graph v2.x")) {
                $body = @{ keyId = $secret.keyId } | ConvertTo-Json
                $null = Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/applications/$objId/removePassword" `
                    -Body $body `
                    -ContentType 'application/json'
                $revokedKeys.Add($secret.keyId)
            }
        }
    } else {
        foreach ($secret in $activeSecrets) {
            if ($null -ne $secret.PSObject.Properties['keyId']) {
                $revokedKeys.Add($secret.keyId)
            }
        }
    }

    return [PSCustomObject]@{
        AppId               = $ApplicationObject.AppId
        DisplayName         = $ApplicationObject.DisplayName
        Action              = 'REVOKE_STATIC_SECRET_ENFORCE_OIDC'
        RevokedCount        = $activeSecrets.Count
        RevokedKeyIds       = $revokedKeys.ToArray()
        HasFederatedOidc    = ($federatedCreds.Count -gt 0)
        RemediationRequired = ($federatedCreds.Count -eq 0)
    }
}

return [PSCustomObject]@{
    AppId         = $ApplicationObject.AppId
    DisplayName   = $ApplicationObject.DisplayName
    Action        = 'COMPLIANT_SECRETLESS_WORKLOAD'
    RevokedCount  = 0
    RevokedKeyIds = @()
}
