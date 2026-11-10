# ADR-001: Autonomous Zero-Trust Secretless Enforcer: Eradicating Static Keys via Workload Identity

## Status
Accepted

## Service Owner & Sign-Off Authority
Principal Cloud Security Architect & CISO Technical Lead

## Dominant Artefact
100% Secretless Workload Identity Migration Matrix

## Decision & Refusal Boundary
All production state mutations must pass deterministic pre-flight policy evaluation in `src/Invoke-EntraSecretlessEnforcement.ps1` and satisfy the 16-test Pester verification contract in `tests/Boundary-Verification.Tests.ps1` before execution.
