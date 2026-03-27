#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

mod policy_client {
    use soroban_sdk::{contractclient, Env};
    #[contractclient(name = "PolicyClient")]
    pub trait PolicyInterface {
        fn is_policy_active(env: Env, policy_id: u64) -> bool;
        fn get_policy_coverage(env: Env, policy_id: u64) -> i128;
    }
}
use policy_client::PolicyClient;

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum ClaimStatus { Pending, Approved, Rejected, Settled }

#[contracttype]
#[derive(Clone)]
pub struct ClaimRecord {
    pub policy_id: u64,
    pub amount: i128,
    pub status: ClaimStatus,
}

const CLAIMS: Symbol = symbol_short!("CLAIMS");

#[derive(soroban_sdk::contracterror, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ClaimError {
    PolicyInactive = 1,
    InsufficientCoverage = 2,
    ClaimNotFound = 3,
    AlreadySettled = 4,
    ClaimNotApproved = 5,
}

#[contract]
pub struct ClaimsContract;

#[contractimpl]
impl ClaimsContract {
    pub fn submit_claim(env: Env, policy_address: Address, claim_id: u64, policy_id: u64, amount: i128) -> Result<(), ClaimError> {
        let policy = PolicyClient::new(&env, &policy_address);
        if !policy.is_policy_active(&policy_id) { return Err(ClaimError::PolicyInactive); }
        let coverage = policy.get_policy_coverage(&policy_id);
        let fee = amount / 100;
        if coverage <= amount + fee { return Err(ClaimError::InsufficientCoverage); }
        env.storage().persistent().set(&(CLAIMS, claim_id), &ClaimRecord { policy_id, amount, status: ClaimStatus::Pending });
        Ok(())
    }

    pub fn approve_claim(env: Env, claim_id: u64) -> Result<(), ClaimError> {
        let key = (CLAIMS, claim_id);
        let mut r: ClaimRecord = env.storage().persistent().get(&key).ok_or(ClaimError::ClaimNotFound)?;
        r.status = ClaimStatus::Approved;
        env.storage().persistent().set(&key, &r);
        Ok(())
    }

    pub fn settle_claim(env: Env, claim_id: u64) -> Result<(), ClaimError> {
        let key = (CLAIMS, claim_id);
        let mut r: ClaimRecord = env.storage().persistent().get(&key).ok_or(ClaimError::ClaimNotFound)?;
        if r.status == ClaimStatus::Settled { return Err(ClaimError::AlreadySettled); }
        if r.status != ClaimStatus::Approved { return Err(ClaimError::ClaimNotApproved); }
        r.status = ClaimStatus::Settled;
        env.storage().persistent().set(&key, &r);
        Ok(())
    }
}
