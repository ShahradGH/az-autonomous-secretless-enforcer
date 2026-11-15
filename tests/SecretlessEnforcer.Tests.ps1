BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:EvaluatorPath = Join-Path $script:RepoRoot 'src/Invoke-EntraSecretlessEnforcement.ps1'
    $script:ClassifierPath = Join-Path $script:RepoRoot 'ai/Invoke-SecretRiskClassifier.ps1'
    $script:RubricPath = Join-Path $script:RepoRoot 'ai/secret-risk-rubric.json'
    $script:WatchdogPath = Join-Path $script:RepoRoot 'graph/Deploy-EntraSecretlessWatchdog.ps1'
    $script:KqlPath = Join-Path $script:RepoRoot 'queries/Entra-SecretAddition-Hunt.kql'
}

Describe 'Autonomous Secretless Enforcer - Verification Matrix' {
    Context 'Positive Path: Structural & Zero-IaC Contract Verification' {
        It 'P-01: All PowerShell scripts exist and parse with zero AST syntax errors' {
            foreach ($path in @($script:EvaluatorPath, $script:ClassifierPath, $script:WatchdogPath)) {
                Test-Path $path | Should -BeTrue
                $errors = $null
                [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
                $errors.Count | Should -Be 0
            }
        }

        It 'P-02: Zero declarative Bicep or Terraform files exist in repository' {
            $iacFiles = Get-ChildItem -Path $script:RepoRoot -Recurse -Include '*.bicep', '*.tf' -File
            $iacFiles.Count | Should -Be 0
        }

        It 'P-03: Secret risk rubric defines Graph permissions, RBAC weights, and severity bands' {
            Test-Path $script:RubricPath | Should -BeTrue
            $rubric = Get-Content $script:RubricPath -Raw | ConvertFrom-Json
            $rubric.scoringWeights.graphPermissions.'Directory.ReadWrite.All' | Should -Be 50
            $rubric.severityBands[0].tier | Should -Be 'CRITICAL_PRIVILEGED_SPN'
        }

        It 'P-04: KQL hunt query, migration runbook, and README meet depth standards' {
            (Get-Content $script:KqlPath -Raw) | Should -Match 'where|project'
            (Get-Item (Join-Path $script:RepoRoot 'docs/SECRETLESS-MIGRATION-RUNBOOK.md')).Length | Should -BeGreaterThan 2000
            (Get-Item (Join-Path $script:RepoRoot 'README.md')).Length | Should -BeGreaterThan 4000
        }
    }

    Context 'Functional AI Blast-Radius Classification & OIDC Diff Generation' {
        It 'AI-01: Classifies privileged SPN as CRITICAL_PRIVILEGED_SPN and emits valid OIDC PR diff' {
            $spn = [PSCustomObject]@{
                AppId            = '44444444-4444-4444-4444-444444444444'
                DisplayName      = 'sp-contoso-ci-deployer'
                GraphPermissions = @('Directory.ReadWrite.All', 'Application.ReadWrite.All')
                AzureRbacRoles   = @('Owner')
                SecretAgeDays    = 120
                HasFederatedOidc = $false
            }

            $res = & $script:ClassifierPath -ServicePrincipalContext $spn -GitHubOrgRepo 'contoso-platform/core-api'
            $res.SeverityTier | Should -Be 'CRITICAL_PRIVILEGED_SPN'
            $res.RecommendedAction | Should -Be 'IMMEDIATE_REVOKE_AND_OIDC_PR'
            $res.BlastRadiusScore | Should -BeGreaterOrEqual 150
            $res.OidcMigrationDiff | Should -Match 'id-token: write'
            $res.OidcMigrationDiff | Should -Match 'client-id: 44444444-4444-4444-4444-444444444444'
        }

        It 'AI-02: Classifies low-privilege reader SPN as LOW_READONLY_SPN' {
            $spn = [PSCustomObject]@{
                AppId            = '66666666-6666-6666-6666-666666666666'
                DisplayName      = 'sp-contoso-telemetry-reader'
                GraphPermissions = @('User.Read')
                AzureRbacRoles   = @('Reader')
                SecretAgeDays    = 15
                HasFederatedOidc = $true
            }

            $res = & $script:ClassifierPath -ServicePrincipalContext $spn
            $res.SeverityTier | Should -Be 'LOW_READONLY_SPN'
            $res.RecommendedAction | Should -Be 'ADVISORY_OIDC_PR'
        }

        It 'AI-03: Fails closed when -UseLiveFoundry is set without -FoundryEndpoint and supports mocked live Foundry REST call' {
            $spn = [PSCustomObject]@{
                AppId            = '66666666-6666-6666-6666-666666666666'
                DisplayName      = 'sp-contoso-telemetry-reader'
                GraphPermissions = @('User.Read')
                AzureRbacRoles   = @('Reader')
                SecretAgeDays    = 15
                HasFederatedOidc = $true
            }

            { & $script:ClassifierPath -ServicePrincipalContext $spn -UseLiveFoundry } | Should -Throw '*FoundryEndpoint*'

            Mock Invoke-RestMethod {
                return [PSCustomObject]@{
                    choices = @(
                        [PSCustomObject]@{
                            message = [PSCustomObject]@{
                                content = '{"severityTier":"LOW_READONLY_SPN","recommendedAction":"ADVISORY_OIDC_PR","rationale":"Low-privilege read-only SPN."}'
                            }
                        }
                    )
                }
            }

            $res = & $script:ClassifierPath -ServicePrincipalContext $spn -UseLiveFoundry -FoundryEndpoint 'https://contoso-foundry.openai.azure.com' -FoundryApiKey 'test-key'
            $res.InferenceMode | Should -Be 'LIVE_FOUNDRY'
            $res.SeverityTier | Should -Be 'LOW_READONLY_SPN'
            Should -Invoke Invoke-RestMethod -Times 1
        }
    }

    Context 'Deterministic Enforcement & Graph v2.x Watchdog Tests' {
        It 'ENF-01: Revokes static secrets and flags remediation when OIDC is missing' {
            $app = [PSCustomObject]@{
                ObjectId                     = 'obj-101'
                AppId                        = 'app-101'
                DisplayName                  = 'legacy-deployer'
                PasswordCredentials          = @([PSCustomObject]@{ keyId = 'key-abc-123' })
                FederatedIdentityCredentials = @()
            }

            $res = & $script:EvaluatorPath -ApplicationObject $app
            $res.Action | Should -Be 'REVOKE_STATIC_SECRET_ENFORCE_OIDC'
            $res.RevokedCount | Should -Be 1
            $res.RevokedKeyIds | Should -Contain 'key-abc-123'
            $res.RemediationRequired | Should -BeTrue
        }

        It 'ENF-02: Honours audited break-glass exemption list' {
            $app = [PSCustomObject]@{
                ObjectId                     = 'obj-999'
                AppId                        = 'app-breakglass-01'
                DisplayName                  = 'break-glass-legacy'
                PasswordCredentials          = @([PSCustomObject]@{ keyId = 'key-bg-1' })
                FederatedIdentityCredentials = @()
            }

            $res = & $script:EvaluatorPath -ApplicationObject $app -BreakGlassExemptAppIds @('app-breakglass-01')
            $res.Action | Should -Be 'EXEMPT_BREAK_GLASS_AUDITED'
            $res.RevokedCount | Should -Be 0
        }

        It 'GRAPH-01: Watchdog DryRun plans GitHub OIDC FIC and allowSharedKeyAccess=false' {
            $plan = & $script:WatchdogPath `
                -ApplicationObjectId '55555555-5555-5555-5555-555555555555' `
                -GitHubRepository 'contoso-platform/core-api' `
                -SubscriptionId '22222222-2222-2222-2222-222222222222' `
                -ResourceGroupName 'rg-sec-uks' `
                -StorageAccountName 'stsecuks01' `
                -DryRun

            $plan.Mode | Should -Be 'DRY_RUN'
            $plan.FederatedCredential.issuer | Should -Be 'https://token.actions.githubusercontent.com'
            $plan.FederatedCredential.subject | Should -Be 'repo:contoso-platform/core-api:ref:refs/heads/main'
            $plan.StorageHardeningBody.properties.allowSharedKeyAccess | Should -BeFalse
        }
    }

    Context 'Zero-Leak Security & Governance Boundaries' {
        It 'N-01: Repository contains zero hardcoded secrets, private IPs, or internal sequence numbers' {
            $files = Get-ChildItem -Path $script:RepoRoot -Recurse -File -Include '*.ps1', '*.md', '*.kql', '*.json' | Where-Object { $_.Name -notlike '*.Tests.ps1' }
            foreach ($f in $files) {
                $raw = Get-Content $f.FullName -Raw
                $raw | Should -Not -Match 'AccountKey=|SharedAccessSignature=|192\.142\.41\.43|mvpfoundry\.alerasoul\.net|Decision Pack 0'
            }
        }
    }
}
