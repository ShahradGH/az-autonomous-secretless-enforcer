# New-FederatedIdentityBinding.ps1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ApplicationObjectId, [Parameter(Mandatory)][string]$SubjectRepo)
Set-StrictMode -Version Latest
return [PSCustomObject]@{ ApplicationObjectId = $ApplicationObjectId; Issuer = 'https://token.actions.githubusercontent.com'; Subject = "repo:$SubjectRepo:environment:production"; Audience = 'api://AzureADTokenExchange' }
