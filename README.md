# Autonomous Zero-Trust Secretless Enforcer: Eradicating Static Keys via Workload Identity

[![Pester Verification](https://img.shields.io/badge/pester-16%2F16%20passing-brightgreen)](tests/SecretlessEnforcer.Tests.ps1)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture Deep-Dive](https://img.shields.io/badge/blog-alerasoul.net-0a1128)](https://alerasoul.net/autonomous-zero-trust-secretless-enforcer/)

> **Primary Governance Artefact:** 100% Secretless Workload Identity Migration Matrix  
> **Accountable Service Owner:** Principal Cloud Security Architect & CISO Technical Lead  
> **Full Architectural Deep-Dive:** [https://alerasoul.net/autonomous-zero-trust-secretless-enforcer/](https://alerasoul.net/autonomous-zero-trust-secretless-enforcer/)

---

## Repository Layout (12 Files)

```text
├── .github/workflows/security-gate.yml
├── LICENSE
├── README.md
├── SECURITY.md
├── docs/SECRETLESS-MIGRATION-RUNBOOK.md
├── fixtures/spn-credential-inventory.json
├── infra/workload-federation.bicep
├── policies/deny-application-password-addition.json
├── queries/Entra-SecretAddition-Hunt.kql
├── src/Invoke-EntraSecretlessEnforcement.ps1
├── src/New-FederatedIdentityBinding.ps1
└── tests/SecretlessEnforcer.Tests.ps1
```

## Quickstart & Offline Verification

```powershell
# 1. Execute the primary PowerShell 7 evaluator
pwsh -NoProfile -File ./src/Invoke-EntraSecretlessEnforcement.ps1

# 2. Run the 16-test Pester verification contract
Invoke-Pester -Path ./tests/SecretlessEnforcer.Tests.ps1 -Output Detailed
```

## License

Released under the [MIT License](LICENSE). Authored by **Shahrad Alerasoul** ([alerasoul.net](https://alerasoul.net)).
