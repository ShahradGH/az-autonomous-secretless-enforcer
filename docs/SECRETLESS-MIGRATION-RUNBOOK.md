# Secretless Workload Identity Migration & L2/L3 Enforcement Runbook

## 1. Operational Scope

This runbook governs automated detection, blast-radius scoring, OIDC migration PR generation, and deterministic revocation of static Entra ID client secrets (`passwordCredentials`) and Azure Storage Shared Keys (`allowSharedKeyAccess`).

All control-plane actions execute in **PowerShell 7.4+** using **Microsoft Graph v2.x** (`Invoke-MgGraphRequest`) and **Azure Resource Manager REST** (`Invoke-AzRestMethod`). No declarative Bicep or Terraform templates are permitted in this estate.

## 2. Automated Enforcement Workflow

1. **Entra Audit Log Hunt (`queries/Entra-SecretAddition-Hunt.kql`)**:
   - Continuously monitors `AuditLogs` for `Add service principal credentials` and `Update application – Certificates and secrets management` where `ModifiedProps has "PasswordCredential"`.
2. **AI Blast-Radius Classifier (`ai/Invoke-SecretRiskClassifier.ps1`)**:
   - Scores the offending Service Principal against `ai/secret-risk-rubric.json` using its Graph API permissions (`Directory.ReadWrite.All`, `Application.ReadWrite.All`, etc.), Azure RBAC roles (`Owner`, `Contributor`), and credential age.
   - Outputs a deterministic severity tier (`CRITICAL_PRIVILEGED_SPN`, `HIGH_DATA_PLANE_SPN`, `MODERATE_APP_SPN`) and generates a scoped GitHub Actions OIDC migration diff (`azure/login@v2` with `id-token: write`, replacing `secrets.AZURE_SPN_CREDENTIALS`).
3. **OIDC Binding & Storage Hardening (`graph/Deploy-EntraSecretlessWatchdog.ps1`)**:
   - Registers a Federated Identity Credential (`https://token.actions.githubusercontent.com`) via `POST /applications/{id}/federatedIdentityCredentials`.
   - Enforces `allowSharedKeyAccess = $false`, `minimumTlsVersion = 'TLS1_2'`, and `supportsHttpsTrafficOnly = $true` on target Storage Accounts via `Invoke-AzRestMethod`.
4. **Deterministic Secret Revocation (`src/Invoke-EntraSecretlessEnforcement.ps1`)**:
   - Verifies whether the `AppId` is in `$BreakGlassExemptAppIds`. If exempt, logs `EXEMPT_BREAK_GLASS_AUDITED`.
   - Otherwise, revokes all `passwordCredentials` via `POST /applications/{id}/removePassword`.

## 3. L2/L3 Incident Escalation Procedures

### 3.1 `CRITICAL_PRIVILEGED_SPN` Secret Added Outside Change Control
- **Trigger**: Blast-radius score `>= 75` (for example, `Directory.ReadWrite.All` + `Owner`).
- **Action**:
  1. Execute `src/Invoke-EntraSecretlessEnforcement.ps1 -ExecuteGraphRevocation` immediately.
  2. Open the generated OIDC migration PR in the owning repository and notify the Cloud Security Duty Officer.
  3. Audit all sign-in logs for the `AppId` over the preceding 24 hours in `AADServicePrincipalSignInLogs`.

### 3.2 Break-Glass Legacy Workload Exemption
- **Trigger**: A legacy appliance cannot support OIDC or Managed Identity.
- **Action**:
  1. Require written CISO approval with a 30-day expiry date.
  2. Add the `AppId` to `$BreakGlassExemptAppIds` and restrict Conditional Access for Workload Identities to the synthetic egress range (`198.51.100.0/24`).
