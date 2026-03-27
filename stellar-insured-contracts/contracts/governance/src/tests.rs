use soroban_sdk::{Address, BytesN, Env, Symbol};
use crate::{
    GovernanceContract, GovernanceError, ProposalStatus, GovernanceData, ProposerStats,
    DATA_KEY, PROPOSAL_KEY, PROPOSER_STATS_KEY
};

#[test]
fn test_initialize() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);

    GovernanceContract::initialize(
        &env,
        admin.clone(),
        token_contract,
        7, // voting_period_days
        51, // min_voting_percentage
        10, // min_quorum_percentage
        100, // min_proposal_deposit
        5, // max_proposals_per_proposer
        86400, // proposal_cooldown_seconds
        true, // commit_reveal_enabled
        1, // commit_period_days
        1, // reveal_period_days
        true, // time_lock_enabled
        3600, // time_lock_seconds
    );

    let data: GovernanceData = env.storage().instance().get(&DATA_KEY).unwrap();
    assert_eq!(data.admin, admin);
    assert_eq!(data.min_proposal_deposit, 100);
    assert_eq!(data.max_proposals_per_proposer, 5);
}

#[test]
fn test_create_proposal_minimum_deposit() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 86400, false, 1, 1, false, 3600,
    );

    // Try to create proposal with insufficient deposit
    let result = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[0u8; 32]),
        51, // threshold_percentage
        50, // deposit_amount (insufficient)
        None, // commitment
    );

    assert_eq!(result, Err(GovernanceError::InsufficientDeposit));
}

#[test]
fn test_create_proposal_cooldown() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize with short cooldown for testing
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 10, false, 1, 1, false, 3600,
    );

    // Create first proposal
    let result1 = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal 1".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result1.is_ok());

    // Try to create second proposal immediately (should fail due to cooldown)
    let result2 = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal 2".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[2u8; 32]),
        51, 100, None,
    );
    assert_eq!(result2, Err(GovernanceError::ProposalTooFrequent));
}

#[test]
fn test_create_proposal_uniqueness() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer1 = Address::generate(&env);
    let proposer2 = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Create first proposal
    let result1 = GovernanceContract::create_proposal(
        &env,
        proposer1,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result1.is_ok());

    // Try to create duplicate proposal with different proposer
    let result2 = GovernanceContract::create_proposal(
        &env,
        proposer2,
        "Test Proposal".to_string(), // Same title
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]), // Same execution data
        51, 100, None,
    );
    assert_eq!(result2, Err(GovernanceError::ProposalDuplicate));
}

#[test]
fn test_create_proposal_max_per_proposer() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize with max 2 proposals per proposer
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 2, 0, false, 1, 1, false, 3600,
    );

    // Create first proposal
    let result1 = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal 1".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result1.is_ok());

    // Create second proposal
    let result2 = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal 2".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[2u8; 32]),
        51, 100, None,
    );
    assert!(result2.is_ok());

    // Try to create third proposal (should fail)
    let result3 = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal 3".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[3u8; 32]),
        51, 100, None,
    );
    assert_eq!(result3, Err(GovernanceError::ProposalTooFrequent));
}

#[test]
fn test_commit_reveal_mechanism() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize with commit-reveal enabled
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, true, 1, 1, false, 3600,
    );

    // Create proposal with commitment
    let commitment = BytesN::from_array(&[42u8; 32]);
    let result = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, Some(commitment),
    );
    assert!(result.is_ok());
    let proposal_id = result.unwrap();

    // Check proposal is in committed status
    let proposal = GovernanceContract::get_proposal(&env, proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Committed);

    // Try to reveal with wrong data (should fail)
    let wrong_reveal = BytesN::from_array(&[99u8; 32]);
    let reveal_result = GovernanceContract::reveal_proposal(&env, proposal_id, wrong_reveal);
    assert_eq!(reveal_result, Err(GovernanceError::InvalidCommitReveal));

    // Reveal with correct data
    let correct_reveal = BytesN::from_array(&[1u8; 32]);
    let reveal_result = GovernanceContract::reveal_proposal(&env, proposal_id, correct_reveal);
    assert!(reveal_result.is_ok());

    // Check proposal is now active
    let proposal = GovernanceContract::get_proposal(&env, proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Active);
}

#[test]
fn test_time_lock_mechanism() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter = Address::generate(&env);

    // Initialize with time-lock enabled
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, true, 3600, // 1 hour time-lock
    );

    // Create and pass a proposal
    let result = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result.is_ok());
    let proposal_id = result.unwrap();

    // Vote and finalize
    let vote_result = GovernanceContract::vote(&env, voter, proposal_id, 1000, true);
    assert!(vote_result.is_ok());

    // Simulate time passing
    env.ledger().set_timestamp(env.ledger().timestamp() + 8 * 86400);

    let finalize_result = GovernanceContract::finalize_proposal(&env, proposal_id);
    assert!(finalize_result.is_ok());

    // Try to execute immediately (should fail due to time-lock)
    let execute_result = GovernanceContract::execute_proposal(&env, proposal_id);
    assert_eq!(execute_result, Err(GovernanceError::TimeLockNotExpired));

    // Simulate time-lock passing
    env.ledger().set_timestamp(env.ledger().timestamp() + 3600);

    // Now execution should work
    let execute_result = GovernanceContract::execute_proposal(&env, proposal_id);
    assert!(execute_result.is_ok());
}

#[test]
fn test_voting_and_finalization() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Create proposal
    let result = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result.is_ok());
    let proposal_id = result.unwrap();

    // Vote
    let vote_result1 = GovernanceContract::vote(&env, voter1.clone(), proposal_id, 600, true);
    assert!(vote_result1.is_ok());

    let vote_result2 = GovernanceContract::vote(&env, voter2, proposal_id, 400, false);
    assert!(vote_result2.is_ok());

    // Try to vote again (should fail)
    let duplicate_vote = GovernanceContract::vote(&env, voter1, proposal_id, 100, true);
    assert_eq!(duplicate_vote, Err(GovernanceError::AlreadyVoted));

    // Simulate voting period ending
    env.ledger().set_timestamp(env.ledger().timestamp() + 8 * 86400);

    // Finalize
    let finalize_result = GovernanceContract::finalize_proposal(&env, proposal_id);
    assert!(finalize_result.is_ok());

    // Check proposal status
    let proposal = GovernanceContract::get_proposal(&env, proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Passed);
    assert_eq!(proposal.yes_votes, 600);
    assert_eq!(proposal.no_votes, 400);
}

#[test]
fn test_quorum_not_met() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter = Address::generate(&env);

    // Initialize with high quorum requirement
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 50, 100, 5, 0, false, 1, 1, false, 3600, // 50% quorum
    );

    // Create proposal
    let result = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result.is_ok());
    let proposal_id = result.unwrap();

    // Vote with insufficient participation
    let vote_result = GovernanceContract::vote(&env, voter, proposal_id, 100, true);
    assert!(vote_result.is_ok());

    // Simulate voting period ending
    env.ledger().set_timestamp(env.ledger().timestamp() + 8 * 86400);

    // Try to finalize (should fail due to quorum not met)
    let finalize_result = GovernanceContract::finalize_proposal(&env, proposal_id);
    assert_eq!(finalize_result, Err(GovernanceError::QuorumNotMet));
}

#[test]
fn test_proposer_stats() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Check initial stats
    let stats = GovernanceContract::get_proposer_stats(&env, proposer.clone());
    assert_eq!(stats.active_proposal_count, 0);
    assert_eq!(stats.total_proposal_count, 0);
    assert_eq!(stats.last_proposal_at, 0);

    // Create proposal
    let result = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result.is_ok());

    // Check updated stats
    let stats = GovernanceContract::get_proposer_stats(&env, proposer);
    assert_eq!(stats.active_proposal_count, 1);
    assert_eq!(stats.total_proposal_count, 1);
    assert!(stats.last_proposal_at > 0);
}

#[test]
fn test_get_active_proposals() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Create multiple proposals
    let result1 = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal 1".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result1.is_ok());

    let result2 = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal 2".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[2u8; 32]),
        51, 100, None,
    );
    assert!(result2.is_ok());

    // Get active proposals
    let active_proposals = GovernanceContract::get_active_proposals(&env);
    assert_eq!(active_proposals.len(), 2);
}

#[test]
fn test_proposal_cleanup() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin.clone(),
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Create proposal
    let result = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result.is_ok());

    // Simulate long time passing (more than cleanup threshold)
    env.ledger().set_timestamp(env.ledger().timestamp() + 120 * 86400); // 120 days

    // Clean up expired proposals
    let cleanup_result = GovernanceContract::cleanup_expired_proposals(&env, admin);
    assert!(cleanup_result.is_ok());
    assert_eq!(cleanup_result.unwrap(), 1); // Should clean up 1 proposal
}

#[test]
fn test_cleanup_unauthorized() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Try to clean up with unauthorized address
    let cleanup_result = GovernanceContract::cleanup_expired_proposals(&env, unauthorized);
    assert_eq!(cleanup_result, Err(GovernanceError::NotAuthorized));
}

#[test]
fn test_proposal_hash_lookup() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Create proposal
    let result = GovernanceContract::create_proposal(
        &env,
        proposer,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result.is_ok());
    let proposal_id = result.unwrap();

    // Look up proposal by hash
    let found_id = GovernanceContract::get_proposal_by_hash(
        &env,
        "Test Proposal".to_string(),
        BytesN::from_array(&[1u8; 32]),
    );
    assert_eq!(found_id, Some(proposal_id));

    // Try non-existent proposal
    let not_found = GovernanceContract::get_proposal_by_hash(
        &env,
        "Non-existent".to_string(),
        BytesN::from_array(&[2u8; 32]),
    );
    assert_eq!(not_found, None);
}

#[test]
fn test_active_proposal_count_decrement() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let token_contract = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter = Address::generate(&env);

    // Initialize
    GovernanceContract::initialize(
        &env,
        admin,
        token_contract,
        7, 51, 10, 100, 5, 0, false, 1, 1, false, 3600,
    );

    // Create proposal
    let result = GovernanceContract::create_proposal(
        &env,
        proposer.clone(),
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        BytesN::from_array(&[1u8; 32]),
        51, 100, None,
    );
    assert!(result.is_ok());
    let proposal_id = result.unwrap();

    // Check active count is 1
    let stats = GovernanceContract::get_proposer_stats(&env, proposer.clone());
    assert_eq!(stats.active_proposal_count, 1);

    // Vote and finalize
    let vote_result = GovernanceContract::vote(&env, voter, proposal_id, 1000, true);
    assert!(vote_result.is_ok());

    // Simulate voting period ending
    env.ledger().set_timestamp(env.ledger().timestamp() + 8 * 86400);

    // Finalize (should decrement active count)
    let finalize_result = GovernanceContract::finalize_proposal(&env, proposal_id);
    assert!(finalize_result.is_ok());

    // Check active count is back to 0
    let stats = GovernanceContract::get_proposer_stats(&env, proposer);
    assert_eq!(stats.active_proposal_count, 0);
    assert_eq!(stats.total_proposal_count, 1); // Total should remain
}
