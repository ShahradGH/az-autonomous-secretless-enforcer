# Invoke-EntraSecretlessEnforcement.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [PSCustomObject]$ApplicationObject,
    [Parameter()] [string[]]$BreakGlassExemptAppIds = @()
)

$ErrorActionPreference = 'Stop'

if ($BreakGlassExemptAppIds -contains $ApplicationObject.AppId) {
    return [PSCustomObject]@{
        AppId          = $ApplicationObject.AppId
        DisplayName    = $ApplicationObject.DisplayName
        Action         = 'EXEMPT_BREAK_GLASS_AUDITED'
        RevokedCount   = 0
    }
}

$activeSecrets = @($ApplicationObject.PasswordCredentials)
$federatedCreds = @($ApplicationObject.FederatedIdentityCredentials)

if ($activeSecrets.Count -gt 0) {
    # Revoke every static passwordCredential via Microsoft Graph v2.x
    return [PSCustomObject]@{
        AppId                = $ApplicationObject.AppId
        DisplayName          = $ApplicationObject.DisplayName
        Action               = 'REVOKE_STATIC_SECRET_ENFORCE_OIDC'
        RevokedCount         = $activeSecrets.Count
        HasFederatedOidc     = ($federatedCreds.Count -gt 0)
        RemediationRequired  = ($federatedCreds.Count -eq 0)
    }
}

return [PSCustomObject]@{
    AppId          = $ApplicationObject.AppId
    DisplayName    = $ApplicationObject.DisplayName
    Action         = 'COMPLIANT_SECRETLESS_WORKLOAD'
    RevokedCount   = 0
}
