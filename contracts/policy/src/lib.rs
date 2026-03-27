#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Env, Symbol};

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum PolicyStatus { Active, Expired, Cancelled }

#[contracttype]
#[derive(Clone)]
pub struct PolicyRecord {
    pub coverage: i128,
    pub premium: i128,
    pub status: PolicyStatus,
}

const POLICIES: Symbol = symbol_short!("POLICIES");

#[contract]
pub struct PolicyContract;

#[contractimpl]
impl PolicyContract {
    pub fn issue_policy(env: Env, policy_id: u64, coverage: i128, premium: i128) {
        let key = (POLICIES, policy_id);
        env.storage().persistent().set(&key, &PolicyRecord { coverage, premium, status: PolicyStatus::Active });
    }

    pub fn cancel_policy(env: Env, policy_id: u64) {
        let key = (POLICIES, policy_id);
        let mut r: PolicyRecord = env.storage().persistent().get(&key).unwrap();
        r.status = PolicyStatus::Cancelled;
        env.storage().persistent().set(&key, &r);
    }

    pub fn expire_policy(env: Env, policy_id: u64) {
        let key = (POLICIES, policy_id);
        let mut r: PolicyRecord = env.storage().persistent().get(&key).unwrap();
        r.status = PolicyStatus::Expired;
        env.storage().persistent().set(&key, &r);
    }

    pub fn is_policy_active(env: Env, policy_id: u64) -> bool {
        let key = (POLICIES, policy_id);
        match env.storage().persistent().get::<_, PolicyRecord>(&key) {
            Some(r) => r.status == PolicyStatus::Active,
            None => false,
        }
    }

    pub fn get_policy_coverage(env: Env, policy_id: u64) -> i128 {
        let key = (POLICIES, policy_id);
        match env.storage().persistent().get::<_, PolicyRecord>(&key) {
            Some(r) => r.coverage,
            None => 0,
        }
    }
}
