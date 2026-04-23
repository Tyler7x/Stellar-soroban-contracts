

(Stellar Soroban Contracts – Insurance Logic)

Stellar Insured 🧠 — Soroban Smart Contracts

This repository contains the core insurance smart contracts for Stellar Insured, written using Stellar Soroban. These contracts power policy issuance, claims processing, settlements, risk pools, and DAO governance in a fully decentralized and trustless manner.

They are intended for policyholders, DAO members, auditors, and developers who require transparent, immutable, and verifiable insurance logic deployed on the Stellar blockchain.

Architecture
1. Policy Contract
Manages insurance policy issuance, renewal, and lifecycle.

Issue Policy: Create new insurance policies with coverage amounts and premiums
Renew Policy: Extend policy duration before expiry
Cancel Policy: Policyholder can cancel active policies
Expire Policy: Mark policies as expired
Key Functions:

initialize(admin, risk_pool) - Initialize contract
issue_policy(holder, coverage_amount, premium_amount, duration_days, policy_type) - Issue new policy
get_policy(policy_id) - Retrieve policy details
renew_policy(policy_id, duration_days) - Renew existing policy
cancel_policy(policy_id) - Cancel policy
expire_policy(policy_id) - Mark as expired
get_stats() - Get contract statistics
2. Claims Contract
Processes insurance claims with deterministic multi-stage approval workflow.

Submit Claim: Policyholders submit claims with evidence (Submitted status)
Start Review: Admin moves claim to review stage (UnderReview status)
Approve/Reject Claim: Admin approves valid claims or rejects invalid ones (Approved/Rejected status)
Settle Claim: Release funds to claimant for approved claims only (Settled status)
Multi-Stage Workflow:

Submitted → UnderReview → Approved/Rejected → Settled (Approved only)
State Transition Rules:

Only admin can transition claims between states
Claims can only be settled if approved (prevents premature settlement)
Full state validation prevents invalid transitions
Key Functions:

initialize(admin, policy_contract, risk_pool) - Initialize contract
submit_claim(policy_id, amount) - Submit new claim (sets status to Submitted)
start_review(claim_id) - Admin moves claim to UnderReview status
get_claim(claim_id) - Retrieve claim details with status
approve_claim(claim_id) - Admin approves UnderReview claims (sets to Approved)
reject_claim(claim_id) - Admin rejects UnderReview claims (sets to Rejected)
settle_claim(claim_id) - Settle approved claims only, integrates with risk pool
get_stats() - Get claims statistics
3. Risk Pool Contract
Manages liquidity pool for claims settlement.

Deposit Liquidity: Providers deposit XLM to earn rewards
Withdraw Liquidity: Withdraw staked amounts
Reserve Liquidity: Lock funds for pending claims
Release Liquidity: Return reserved funds after settlement
Key Functions:

initialize(admin, xlm_token, min_provider_stake) - Initialize pool
deposit_liquidity(provider, amount) - Deposit into pool
withdraw_liquidity(provider, amount) - Withdraw from pool
payout_claim(recipient, amount) - Pay out approved claims (admin only)
get_pool_stats() - Pool statistics
get_provider_info(provider) - Provider stake info
5. Slashing Contract
Professional on-chain slashing mechanism to penalize malicious or negligent actors.

Slashable Roles: Oracle providers, claim submitters, governance participants, risk pool providers
Configurable Penalties: DAO-controlled penalty percentages and multipliers
Fund Redirection: Slashed funds redirected to risk pool, treasury, or compensation fund
Repeat Offender System: Progressive penalties for multiple violations
Cooldown Periods: Time-based protection against excessive slashing
Key Functions:

initialize(admin, governance_contract, risk_pool_contract) - Initialize with governance integration
configure_penalty_parameters(role, reason, percentage, destination, multiplier, cooldown) - Set penalty rules
slash_funds(target, role, reason, amount) - Execute slashing with validation
add_slashable_role(role) / remove_slashable_role(role) - Manage slashable roles
get_slashing_history(target, role) - View violation history
get_violation_count(target, role) - Check repeat offenses
can_be_slashed(target, role) - Verify slashing eligibility
pause() / unpause() - Emergency controls
4. Governance Contract
Professional DAO proposal system enabling decentralized protocol decisions.

Proposal Creation: Create detailed proposals with title, description, and execution data
Voting Period Enforcement: Strict time-based voting with configurable periods
Proposal Storage Schema: Efficient storage using Soroban-compatible data structures
Read-only Queries: Comprehensive query functions for proposal data and statistics
Key Functions:

initialize(admin, token_contract, voting_period_days, min_voting_percentage, min_quorum_percentage, slashing_contract) - Initialize with quorum requirements
create_proposal(title, description, execution_data, threshold_percentage) - Create detailed proposal
get_proposal(proposal_id) - Retrieve full proposal details
vote(proposal_id, vote_weight, is_yes) - Cast vote with duplicate prevention
finalize_proposal(proposal_id) - Finalize after voting period with quorum/threshold checks
execute_proposal(proposal_id) - Execute passed proposals
create_slashing_proposal(target, role, reason, amount, evidence, threshold) - Create slashing proposals
execute_slashing_proposal(proposal_id) - Execute approved slashing actions
get_active_proposals() - Query all active proposals
get_proposal_stats(proposal_id) - Get voting statistics
get_all_proposals() - List all proposals
get_vote_record(proposal_id, voter) - Check individual voting records
✨ Contract Features

- Insurance policy creation and lifecycle management
- Automated claim validation and settlement
- Decentralized risk pool accounting
- Professional DAO governance with quorum and threshold requirements
- On-chain slashing mechanism with configurable penalties
- Secure and deterministic execution via Soroban PRNG
- Capped bridge history to prevent storage explosion
- Emergency pause mechanism in escrow and bridge contracts

🧑‍💻 Tech Stack

- Blockchain: Stellar
- Smart Contracts: Soroban
- Language: Rust
- SDK: soroban-sdk (v20.0.0)

📁 Project Structure
contracts/
├── bridge/ - Cross-chain property bridge (Soroban)
├── escrow/ - Advanced escrow system (Soroban)
├── lib/ - Shared utilities (Randomness, etc.)
└── ... (Other contracts being migrated)

📦 Setup & Development Prerequisites

Rust (latest stable)

Stellar CLI

Soroban SDK

Build Contracts cargo build --target wasm32-unknown-unknown --release

Run Tests cargo test

🌐 Network Configuration

Network: Stellar Testnet

Execution: Soroban VM

Wallets: Non-custodial Stellar wallets

🔐 Security Considerations

Deterministic execution

Multi-stage state transition validation preventing invalid claim flows

Admin-only authorization for all sensitive claim operations

Settlement prevention for non-approved claims

Explicit authorization checks

Auditable contract logic

Minimal trusted off-chain assumptions

📚 Resources

Soroban Docs: https://soroban.stellar.org/docs

Stellar Developers: https://developers.stellar.org

Rust Docs: https://doc.rust-lang.org

Deployment
Build all contracts:
cd contracts/policy && cargo build --release
cd contracts/claims && cargo build --release
cd contracts/risk_pool && cargo build --release
cd contracts/governance && cargo build --release
Deploy to Stellar network using Soroban CLI

Initialize each contract with proper parameters

Local sandbox orchestration:

`stellar-insured-contracts/scripts/orchestrate-soroban.sh` deploys the Soroban stack in dependency order, initializes governance defaults, and primes the pool for local integration runs. See `stellar-insured-contracts/docs/soroban-orchestrator.md` for usage and override examples.

Security Considerations
Authorization: All sensitive operations require authentication
State Validation: Comprehensive checks on contract state transitions
Error Handling: Descriptive error codes for debugging
Event Logging: All important actions emit events
Rate Limiting: Consider implementing rate limits for production
🤝 Contributing

Fork the repository

Create a contract-specific branch

Add tests for all logic changes

Submit a Pull Request
