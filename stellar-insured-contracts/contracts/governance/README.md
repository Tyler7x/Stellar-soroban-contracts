# Governance Contract with Spam Protection

A robust DAO governance contract for Stellar/Soroban that implements comprehensive spam protection and anti-front-running mechanisms.

## Features

### 🛡️ Spam Protection
- **Minimum Deposit Requirement**: Proposals must meet a minimum deposit threshold to prevent spam
- **Proposal Cooldown**: Time-based cooldown between proposals from the same proposer
- **Maximum Active Proposals**: Limit on concurrent active proposals per proposer
- **Proposal Uniqueness**: Hash-based deduplication prevents duplicate proposals

### 🔒 Anti-Front-Running
- **Commit-Reveal Mechanism**: Optional two-step proposal submission to prevent front-running
- **Time-Lock Protection**: Configurable delay before proposal execution
- **Timestamp-Based Ordering**: Fair proposal ordering based on creation time

### 📊 Governance Features
- **Voting System**: Weighted voting with configurable thresholds
- **Quorum Requirements**: Minimum participation requirements for proposal validity
- **Proposal Lifecycle**: Complete proposal state management (Active → Passed/Rejected → Executed)
- **Deposit Management**: Security deposits returned upon successful execution

### 🧹 Maintenance
- **Automatic Cleanup**: Admin function to clean up expired proposals
- **Statistics Tracking**: Per-proposer statistics for active and total proposals
- **Query Functions**: Rich set of query functions for governance data

## Contract Structure

### Core Components

#### `GovernanceData`
Configuration parameters for the governance system:
- Admin address
- Token contract reference
- Voting periods and thresholds
- Spam protection settings
- Feature toggles (commit-reveal, time-lock)

#### `Proposal`
Complete proposal information:
- Metadata (title, description, proposer)
- Execution data and voting parameters
- Timestamps and deadlines
- Status tracking and vote counts

#### `ProposerStats`
Per-proposer statistics:
- Active proposal count
- Total proposal count
- Last proposal timestamp

#### `Vote`
Individual vote records:
- Voter address and weight
- Vote direction (yes/no)
- Timestamp

### Error Types

- `InsufficientDeposit`: Proposal deposit below minimum
- `ProposalTooFrequent`: Cooldown period not met or max proposals exceeded
- `ProposalDuplicate`: Duplicate proposal detected
- `ProposalNotFound`: Proposal ID invalid
- `NotAuthorized`: Unauthorized action attempted
- `VotingPeriodNotEnded`: Voting still active
- `VotingPeriodEnded`: Voting period expired
- `AlreadyVoted`: Duplicate vote attempt
- `QuorumNotMet`: Minimum participation not reached
- `ThresholdNotMet`: Approval threshold not met
- `InvalidCommitReveal`: Commit-reveal validation failed
- `RevealPeriodNotEnded`: Reveal period still active
- `TimeLockNotExpired`: Time-lock period not expired

## Usage

### Initialization

```rust
GovernanceContract::initialize(
    &env,
    admin_address,
    token_contract_address,
    voting_period_days,           // 7
    min_voting_percentage,       // 51
    min_quorum_percentage,       // 10
    min_proposal_deposit,        // 100 tokens
    max_proposals_per_proposer,  // 5
    proposal_cooldown_seconds,   // 86400 (1 day)
    commit_reveal_enabled,       // true
    commit_period_days,          // 1
    reveal_period_days,          // 1
    time_lock_enabled,           // true
    time_lock_seconds,           // 3600 (1 hour)
);
```

### Creating Proposals

#### Standard Proposal
```rust
let proposal_id = GovernanceContract::create_proposal(
    &env,
    proposer_address,
    "Proposal Title".to_string(),
    "Proposal Description".to_string(),
    execution_data,
    threshold_percentage,  // 51
    deposit_amount,       // >= min_proposal_deposit
    None,                // No commitment
)?;
```

#### Commit-Reveal Proposal
```rust
// Step 1: Commit
let commitment = hash_proposal_data(&title, &execution_data);
let proposal_id = GovernanceContract::create_proposal(
    &env,
    proposer_address,
    title,
    description,
    execution_data,
    threshold_percentage,
    deposit_amount,
    Some(commitment),  // Commitment hash
)?;

// Step 2: Reveal (after voting period ends)
GovernanceContract::reveal_proposal(
    &env,
    proposal_id,
    actual_execution_data,
)?;
```

### Voting

```rust
GovernanceContract::vote(
    &env,
    voter_address,
    proposal_id,
    vote_weight,  // Based on token holdings
    is_yes,       // true for yes, false for no
)?;
```

### Finalization and Execution

```rust
// Finalize after voting period
GovernanceContract::finalize_proposal(&env, proposal_id)?;

// Execute after time-lock (if enabled)
GovernanceContract::execute_proposal(&env, proposal_id)?;
```

### Query Functions

```rust
// Get proposal details
let proposal = GovernanceContract::get_proposal(&env, proposal_id)?;

// Get proposer statistics
let stats = GovernanceContract::get_proposer_stats(&env, proposer_address);

// Get all active proposals
let active_proposals = GovernanceContract::get_active_proposals(&env);

// Check for duplicate proposals
let existing_id = GovernanceContract::get_proposal_by_hash(
    &env,
    title.to_string(),
    execution_data,
);
```

### Maintenance

```rust
// Clean up expired proposals (admin only)
let cleaned_count = GovernanceContract::cleanup_expired_proposals(
    &env,
    admin_address,
)?;
```

## Security Considerations

### Spam Protection
1. **Deposit Requirements**: Minimum deposits prevent spam but should be balanced to avoid excluding legitimate proposers
2. **Cooldown Periods**: Time-based limits prevent rapid-fire proposals
3. **Proposal Limits**: Per-proposer limits ensure fair participation
4. **Hash Deduplication**: Prevents identical proposals from multiple proposers

### Front-Running Protection
1. **Commit-Reveal**: Two-step process hides proposal details until reveal
2. **Time-Locks**: Delays execution to allow community review
3. **Timestamp Ordering**: Fair ordering based on submission time

### Economic Security
1. **Deposit Slashing**: Consider implementing deposit slashing for malicious proposals
2. **Quorum Requirements**: Ensures sufficient participation
3. **Threshold Validation**: Prevents low-quality proposals from passing

## Configuration Recommendations

### Conservative Settings
- `min_proposal_deposit`: 1% of total supply
- `max_proposals_per_proposer`: 3
- `proposal_cooldown_seconds`: 7 days
- `voting_period_days`: 7 days
- `min_quorum_percentage`: 20%
- `min_voting_percentage`: 51%

### Progressive Settings
- Start with higher deposits and limits
- Gradually reduce as governance matures
- Monitor proposal quality and participation
- Adjust based on community feedback

## Testing

The contract includes comprehensive tests covering:
- Spam protection mechanisms
- Commit-reveal functionality
- Time-lock behavior
- Edge cases and error conditions
- Statistics tracking
- Cleanup operations

Run tests with:
```bash
cargo test -p propchain-governance
```

## Integration Notes

### Token Requirements
- Contract needs access to token contract for deposit handling
- Voting weight should be based on token holdings
- Consider implementing token locking during voting

### Frontend Integration
- Display proposal status and deadlines clearly
- Show proposer statistics
- Implement commit-reveal UI if enabled
- Provide cleanup interface for admins

### Upgrade Path
- Store configuration in upgradeable storage
- Implement versioning for proposal structures
- Consider migration strategies for existing proposals

## License

MIT License - see LICENSE file for details.
