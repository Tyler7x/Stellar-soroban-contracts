#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short, Symbol};

const ADMIN: Symbol = symbol_short!("ADMIN");

#[contract]
pub struct OracleContract;

#[contractimpl]
impl OracleContract {
    /// Initialize the contract with a real admin address.
    /// Prevents the [0x0; 32] zero-address backdoor.
    pub fn init(env: Env, admin: Address) {
        if env.storage().instance().has(&ADMIN) {
            panic!("Already initialized");
        }
        env.storage().instance().set(&ADMIN, &admin);
    }

    /// Admin-only function example
    pub fn update_data(env: Env, value: u32) {
        let admin: Address = env.storage().instance().get(&ADMIN).expect("Not initialized");
        admin.require_auth();
        
        // ... update logic
    }
}

// RUTHLESS FIX: Explicitly do NOT implement the Default trait.
// This forces the developer to handle initialization manually.