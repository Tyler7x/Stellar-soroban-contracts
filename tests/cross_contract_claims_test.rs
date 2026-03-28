use soroban_sdk::{testutils::Address as _, Address, Env};

mod policy { include!("../contracts/policy/src/lib.rs"); }
mod claims { include!("../contracts/claims/src/lib.rs"); }
mod risk_pool { include!("../contracts/risk_pool/src/lib.rs"); }

use policy::{PolicyContract, PolicyContractClient};
use claims::{ClaimsContract, ClaimsContractClient, ClaimError};
use risk_pool::{RiskPoolContract, RiskPoolContractClient};

fn setup(env: &Env) -> (Address, Address, Address, PolicyContractClient, ClaimsContractClient, RiskPoolContractClient) {
    let admin = Address::generate(env);
    let guardian = Address::generate(env);
    let manager = Address::generate(env);

    let pol_addr = env.register_contract(None, PolicyContract);
    let pol = PolicyContractClient::new(env, &pol_addr);
    pol.initialize(&admin, &guardian);

    let clm_addr = env.register_contract(None, ClaimsContract);
    let clm = ClaimsContractClient::new(env, &clm_addr);
    clm.initialize(&admin, &guardian);

    let pool_addr = env.register_contract(None, RiskPoolContract);
    let pool = RiskPoolContractClient::new(env, &pool_addr);
    pool.initialize(&admin, &guardian);

    (pol_addr, admin, guardian, pol, clm, pool)
}

#[test]
fn test_claim_lifecycle_e2e() {
    let env = Env::default();
    env.mock_all_auths();
    let (pol_addr, admin, _guardian, pol, clm, pool) = setup(&env);
    let holder = Address::generate(&env);

    // 1. Issue Policy
    pol.issue_policy(&holder, &1u64, &10_000_000i128, &100_000i128).unwrap();
    assert!(pol.is_policy_active(&1u64));

    // 2. Submit Claim
    clm.submit_claim(&pol_addr, &1u64, &1u64, &5_000_000i128).unwrap();

    // 3. Approve Claim
    clm.approve_claim(&1u64).unwrap();

    // 4. Settle Claim
    clm.settle_claim(&1u64).unwrap();

    // 5. Verify Risk Pool Withdrawal (Simple check if pool logic is there)
    pool.deposit(&holder, &10_000_000i128).unwrap();
    assert_eq!(pool.get_balance(), 10_000_000i128);
    pool.withdraw(&holder, &5_000_000i128).unwrap();
    assert_eq!(pool.get_balance(), 5_000_000i128);
}

#[test]
fn test_emergency_pause_prevents_claims() {
    let env = Env::default();
    env.mock_all_auths();
    let (pol_addr, admin, _guardian, pol, clm, _pool) = setup(&env);
    let holder = Address::generate(&env);

    pol.issue_policy(&holder, &1u64, &10_000_000i128, &100_000i128).unwrap();

    // Pause claims contract
    clm.set_pause_state(&admin, &true, &None).unwrap();
    assert!(clm.is_paused());

    // Try to submit claim
    let result = clm.submit_claim(&pol_addr, &1u64, &1u64, &5_000_000i128);
    assert_eq!(result.unwrap_err(), ClaimError::ContractPaused);

    // Unpause
    clm.set_pause_state(&admin, &false, &None).unwrap();
    assert!(!clm.is_paused());
    assert!(clm.submit_claim(&pol_addr, &1u64, &1u64, &5_000_000i128).is_ok());
}

#[test]
fn test_risk_pool_vesting_rewards() {
    let env = Env::default();
    env.mock_all_auths();
    let (pol_addr, admin, _guardian, _pol, _clm, pool) = setup(&env);

    let provider = Address::generate(&env);
    pool.deposit(&provider, &1_000_000i128).unwrap();
    assert_eq!(pool.get_balance(), 1_000_000i128);

    pool.set_vesting_parameters(&admin, &100, &1000, &500).unwrap();
    pool.allocate_rewards(&admin, &provider, &100i128).unwrap();

    env.ledger().set_timestamp(env.ledger().timestamp() + 50);
    assert_eq!(pool.get_provider_vested_rewards(&provider), 0);

    env.ledger().set_timestamp(env.ledger().timestamp() + 150); // now 200
    let vested = pool.get_provider_vested_rewards(&provider);
    assert_eq!(vested, 20);

    let claimed_early = pool.claim_vested_rewards(&provider).unwrap();
    assert_eq!(claimed_early, 19);

    let stats = pool.get_vesting_statistics();
    assert_eq!(stats.total_claimed_rewards, 19);
    assert_eq!(stats.total_penalty_collected, 1);

    env.ledger().set_timestamp(env.ledger().timestamp() + 1000); // now 1200
    let vested_remaining = pool.get_provider_vested_rewards(&provider);
    assert_eq!(vested_remaining, 80);

    let claimed_later = pool.claim_vested_rewards(&provider).unwrap();
    assert_eq!(claimed_later, 80);

    let stats_final = pool.get_vesting_statistics();
    assert_eq!(stats_final.total_claimed_rewards, 99);
    assert_eq!(stats_final.total_penalty_collected, 1);
}

#[test]
fn test_claim_evidence_management() {
    let env = Env::default();
    env.mock_all_auths();
    let (pol_addr, admin, guardian, pol, clm, _pool) = setup(&env);
    let holder = Address::generate(&env);

    pol.issue_policy(&holder, &1u64, &10_000_000i128, &100_000i128).unwrap();
    clm.submit_claim(&pol_addr, &1u64, &1u64, &5_000_000i128).unwrap();

    let evidence_id = clm.submit_evidence(&1u64, &"QmEvidenceHash".to_string(), &false, &Some("report".to_string()), &holder).unwrap();
    assert!(evidence_id > 0);

    let witness_ids = clm.get_claim_evidence_ids(&1u64).unwrap();
    assert_eq!(witness_ids.len(), 1);
    assert_eq!(witness_ids[0], evidence_id);

    let evidence = clm.get_evidence(&holder, &evidence_id).unwrap();
    assert_eq!(evidence.claim_id, 1u64);
    assert_eq!(evidence.ipfs_hash, "QmEvidenceHash".to_string());
    assert!(!evidence.verified);

    // Verify as admin
    clm.verify_evidence(&admin, &evidence_id, &true, &Some("validated".to_string())).unwrap();
    assert!(clm.is_evidence_verified(&evidence_id).unwrap());

    let v = clm.get_evidence_verification_details(&evidence_id).unwrap();
    assert_eq!(v.0, true);
    assert_eq!(v.1, Some(admin));

    // Sensitive evidence only visible to claimant/admin/guardian
    let sensitive_id = clm.submit_evidence(&1u64, &"QmSensitive".to_string(), &true, &Some("private".to_string()), &holder).unwrap();
    assert!(clm.get_evidence(&admin, &sensitive_id).is_ok());
    let outsider = Address::generate(&env);
    assert_eq!(clm.get_evidence(&outsider, &sensitive_id).unwrap_err(), ClaimError::Unauthorized);
}
