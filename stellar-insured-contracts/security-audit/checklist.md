# Security Audit Checklist

Last updated: 2026-03-25

## Status Legend

- `Mitigated`: issue addressed in code and covered by regression tests.
- `Monitoring`: controls exist and are tested, but the area still needs ongoing audit review.
- `In Review`: area has known security-sensitive behavior and needs deeper manual review.
- `Open`: finding is not fully remediated yet and should block sign-off until resolved.

## Required Security Test Matrix

| Control area | Coverage | Evidence |
| --- | --- | --- |
| Re-entrancy | Escrow payout flow prevents double execution after release and zeroes escrowed balance before transfer. | `contracts/escrow/src/tests.rs` security re-entrancy regression |
| Integer overflows | Escrow deposit path rejects overflow; insurance premium calculation is exercised with maximum-value coverage inputs. | `contracts/escrow/src/tests.rs`, `contracts/insurance/src/lib.rs` security arithmetic regressions |
| Access control | Admin-only emergency override and claim cooldown configuration are explicitly tested for unauthorized callers. | `contracts/escrow/src/tests.rs`, `contracts/insurance/src/lib.rs` security access-control regressions |
| Time manipulation | Escrow timelock boundary and insurance claim cooldown boundary are explicitly tested. | `contracts/escrow/src/tests.rs`, `contracts/insurance/src/lib.rs` security time-boundary regressions |
| Upgrade/admin controls | Proxy admin handoff and renounce flows must be two-step and timelocked, with explicit regression tests for early acceptance and unauthorized callers. | `contracts/proxy/src/lib.rs` admin transition tests |

## Contract Area Tracker

| Contract area | Primary findings / checklist items | Status | Risk level | Remediation owner |
| --- | --- | --- | --- | --- |
| `contracts/escrow` | Payout sequencing previously relied on external transfer before terminal state update; deposit path used unchecked addition in a security-sensitive balance path. Re-entrancy-style double execution, overflow rejection, admin gating, and timelock boundaries are now explicitly covered. | Mitigated | High | Escrow contract maintainer |
| `contracts/insurance` | Claim cooldown and policy timing remain a manipulation surface and must stay boundary-tested. Large-value premium math is now explicitly exercised. Admin-only operational controls should remain part of every release checklist. | Monitoring | High | Insurance contract maintainer |
| `contracts/property-token` | Secondary-market and dividend flows perform value movement and state mutation in the same paths. Needs a dedicated follow-up review for transfer-failure atomicity, share-sale arithmetic boundaries, and any re-entrancy assumptions around external value transfer. | Open | High | Tokenization maintainer |
| `contracts/lib` | Property registry ownership changes and escrow integration paths should be reviewed for authorization guarantees, stale-state assumptions, and double-execution resistance in end-to-end flows. Existing e2e coverage helps, but audit sign-off still needs a manual pass. | In Review | Medium | Core contracts maintainer |
| `contracts/fractional` | Fraction issuance, redemption, dividend, and governance math are financially sensitive and should be reviewed for rounding drift, dilution edge cases, and quorum manipulation. | In Review | High | Fractionalization maintainer |
| `contracts/ipfs-metadata` | Access grants, malicious-file reporting, and document verification are privilege-sensitive. Checklist items: unauthorized access attempts, CID validation, and audit-log integrity. | In Review | Medium | Metadata/storage maintainer |
| `contracts/oracle` | Oracle authorization, freshness guarantees, and stale-data handling should be reviewed. Checklist items: signer allowlist changes, timestamp validity, and fallback behavior on missing oracle input. | In Review | High | Oracle integration maintainer |
| `contracts/bridge` | Cross-chain bridge logic is inherently high risk. Checklist items: signature thresholds, replay protection, timeout handling, duplicate request detection, and emergency pause effectiveness. | In Review | High | Bridge maintainer |
| `contracts/proxy` | Upgrade and admin paths should be audited for implementation hijack, initializer misuse, and rollback safety. | In Review | High | Upgradeability maintainer |
| `contracts/fees` | Fee configuration and arithmetic should be reviewed for unauthorized mutation, overflow/rounding behavior, and zero-fee edge cases. | In Review | Medium | Treasury/fees maintainer |
| `contracts/compliance_registry` | Registry mutability, verifier authorization, and compliance-expiry handling should be reviewed for privilege escalation and stale-state abuse. | In Review | Medium | Compliance maintainer |
| `contracts/analytics` | Mostly lower-risk reporting logic, but admin-only mutation and any ledger-time assumptions should still be validated. | Monitoring | Low | Analytics maintainer |
| `contracts/traits` | Interfaces should stay stable and aligned with access-control expectations so downstream contracts do not make unsafe assumptions about counterpart behavior. | Monitoring | Low | Platform interface maintainer |
| `security-audit` | Current audit tooling reports static-analysis metrics, but checklist governance and contract-specific security regressions must remain part of the release gate, not just JSON report generation. | Monitoring | Medium | Security engineering |

## Release Sign-off Checklist

- [x] Security checklist exists in-repo and is versioned with code changes.
- [x] Re-entrancy regression coverage exists for a payout path.
- [x] Integer-overflow regression coverage exists for security-sensitive arithmetic.
- [x] Access-control regression coverage exists for privileged functions.
- [x] Time-boundary regression coverage exists for timelocks and cooldowns.
- [ ] Proxy and ownership control changes enforce a minimum on-chain delay of `n` days before finalization.
- [ ] Production value for `n` is documented, governance-approved, and set to at least `7 days`.
- [ ] Admin transfer uses `set_admin(new_admin)` then `accept_admin()`; no immediate single-call ownership takeover exists in production paths.
- [ ] Admin renounce uses a schedule-then-execute flow and is tested for early execution rejection.
- [ ] Property-token value-transfer paths have dedicated transfer-failure and re-entrancy review coverage.
- [ ] Bridge/proxy upgrade paths have dedicated audit sign-off before production deployment.
