use soroban_sdk::Env;

mod policy { include!("../contracts/policy/src/lib.rs"); }
mod claims { include!("../contracts/claims/src/lib.rs"); }

use policy::{PolicyContract, PolicyContractClient};
use claims::{ClaimsContract, ClaimsContractClient, ClaimError};

fn setup(env: &Env) -> (soroban_sdk::Address, PolicyContractClient, ClaimsContractClient) {
    let pol_addr = env.register_contract(None, PolicyContract);
    let pol = PolicyContractClient::new(env, &pol_addr);
    let clm_addr = env.register_contract(None, ClaimsContract);
    let clm = ClaimsContractClient::new(env, &clm_addr);
    (pol_addr, pol, clm)
}

#[test]
fn test_claim_accepted_for_active_policy() {
    let env = Env::default();
    let (pol_addr, pol, clm) = setup(&env);
    pol.issue_policy(&1u64, &10_000_000i128, &100_000i128);
    assert!(clm.submit_claim(&pol_addr, &1u64, &1u64, &5_000_000i128).is_ok());
}

#[test]
fn test_claim_rejected_for_cancelled_policy() {
    let env = Env::default();
    let (pol_addr, pol, clm) = setup(&env);
    pol.issue_policy(&2u64, &10_000_000i128, &100_000i128);
    pol.cancel_policy(&2u64);
    assert_eq!(clm.submit_claim(&pol_addr, &2u64, &2u64, &5_000_000i128), Err(ClaimError::PolicyInactive));
}

#[test]
fn test_claim_rejected_for_expired_policy() {
    let env = Env::default();
    let (pol_addr, pol, clm) = setup(&env);
    pol.issue_policy(&3u64, &10_000_000i128, &100_000i128);
    pol.expire_policy(&3u64);
    assert_eq!(clm.submit_claim(&pol_addr, &3u64, &3u64, &5_000_000i128), Err(ClaimError::PolicyInactive));
}

#[test]
fn test_claim_rejected_for_insufficient_coverage() {
    let env = Env::default();
    let (pol_addr, pol, clm) = setup(&env);
    pol.issue_policy(&4u64, &1_000i128, &100i128);
    assert_eq!(clm.submit_claim(&pol_addr, &4u64, &4u64, &5_000i128), Err(ClaimError::InsufficientCoverage));
}

#[test]
fn test_cannot_settle_unapproved_claim() {
    let env = Env::default();
    let (pol_addr, pol, clm) = setup(&env);
    pol.issue_policy(&5u64, &10_000_000i128, &100_000i128);
    clm.submit_claim(&pol_addr, &5u64, &5u64, &1_000_000i128).unwrap();
    assert_eq!(clm.settle_claim(&5u64), Err(ClaimError::ClaimNotApproved));
}

#[test]
fn test_settle_approved_claim_succeeds() {
    let env = Env::default();
    let (pol_addr, pol, clm) = setup(&env);
    pol.issue_policy(&6u64, &10_000_000i128, &100_000i128);
    clm.submit_claim(&pol_addr, &6u64, &6u64, &1_000_000i128).unwrap();
    clm.approve_claim(&6u64).unwrap();
    assert!(clm.settle_claim(&6u64).is_ok());
}

#[test]
fn test_cannot_settle_claim_twice() {
    let env = Env::default();
    let (pol_addr, pol, clm) = setup(&env);
    pol.issue_policy(&7u64, &10_000_000i128, &100_000i128);
    clm.submit_claim(&pol_addr, &7u64, &7u64, &1_000_000i128).unwrap();
    clm.approve_claim(&7u64).unwrap();
    clm.settle_claim(&7u64).unwrap();
    assert_eq!(clm.settle_claim(&7u64), Err(ClaimError::AlreadySettled));
}
