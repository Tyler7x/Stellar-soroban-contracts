use soroban_sdk::{contracttype, Symbol, Env, Address, contracterror, contractimpl};

#[contracterror]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    ContractPaused = 1,
    InvalidParameters = 2,
    Unauthorized = 3,
}

// Pause state key
const PAUSE_STATE_KEY: Symbol = Symbol::short("PAUSED");

// Pause state structure
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseState {
    pub is_paused: bool,
    pub paused_at: Option<u64>,
    pub paused_by: Option<Address>,
    pub pause_reason: Option<String>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyEvent {
    PolicyIssued(PolicyContext),
    PolicyRenewed(PolicyContext),
    PolicyCanceled(PolicyContext),
    PolicyExpired(PolicyContext),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyContext {
    pub policy_id: u64,
    pub holder: Address,
    pub coverage_amount: i128,
    pub premium_amount: i128,
    pub duration_days: u32,
    pub policy_type: Symbol,
    pub timestamp: u64,
}

pub struct PolicyContract;

#[contractimpl]
impl PolicyContract {
    // Initialize pause state
    pub fn initialize_pause(env: &Env) {
        if !env.storage().instance().has(&PAUSE_STATE_KEY) {
            let pause_state = PauseState {
                is_paused: false,
                paused_at: None,
                paused_by: None,
                pause_reason: None,
            };
            env.storage().instance().set(&PAUSE_STATE_KEY, &pause_state);
        }
    }

    // Set pause state (only callable by governance)
    pub fn set_pause_state(env: &Env, is_paused: bool, reason: Option<String>) {
        let caller = env.current_contract_address(); // In real implementation, check governance authorization
        let current_time = env.ledger().timestamp();
        
        let pause_state = PauseState {
            is_paused,
            paused_at: if is_paused { Some(current_time) } else { None },
            paused_by: if is_paused { Some(caller) } else { None },
            pause_reason: reason,
        };
        
        env.storage().instance().set(&PAUSE_STATE_KEY, &pause_state);
    }

    // Check if contract is paused
    pub fn is_paused(env: &Env) -> bool {
        let pause_state: PauseState = env.storage().instance().get(&PAUSE_STATE_KEY)
            .unwrap_or(PauseState {
                is_paused: false,
                paused_at: None,
                paused_by: None,
                pause_reason: None,
            });
        pause_state.is_paused
    }

    // Get pause status
    pub fn get_pause_status(env: &Env) -> PauseState {
        env.storage().instance().get(&PAUSE_STATE_KEY)
            .unwrap_or(PauseState {
                is_paused: false,
                paused_at: None,
                paused_by: None,
                pause_reason: None,
            })
    }

    // Issue policy (with pause guard)
    pub fn issue_policy(
        env: &Env,
        holder: Address,
        coverage_amount: i128,
        premium_amount: i128,
        duration_days: u32,
        policy_type: Symbol,
    ) -> Result<u64, PolicyError> {
        // Check if contract is paused
        if Self::is_paused(env) {
            return Err(PolicyError::ContractPaused);
        }

        // Policy issuance logic would go here
        let policy_id = env.ledger().sequence(); // Simple ID generation
        let timestamp = env.ledger().timestamp();

        let context = PolicyContext {
            policy_id,
            holder,
            coverage_amount,
            premium_amount,
            duration_days,
            policy_type,
            timestamp,
        };

        // Emit event
        env.events().publish((Symbol::short("POLICY"), Symbol::short("ISSUED")), context);
        
        Ok(policy_id)
    }

    // Renew policy (with pause guard)
    pub fn renew_policy(
        env: &Env,
        policy_id: u64,
        holder: Address,
        new_premium: i128,
    ) -> Result<(), PolicyError> {
        // Check if contract is paused
        if Self::is_paused(env) {
            return Err(PolicyError::ContractPaused);
        }

        let timestamp = env.ledger().timestamp();
        let context = PolicyContext {
            policy_id,
            holder,
            coverage_amount: 0, // Would fetch from storage
            premium_amount: new_premium,
            duration_days: 0, // Would fetch from storage
            policy_type: Symbol::short("RENEW"),
            timestamp,
        };

        // Emit event
        env.events().publish((Symbol::short("POLICY"), Symbol::short("RENEWED")), context);
        
        Ok(())
    }

    // Cancel policy (with pause guard)
    pub fn cancel_policy(
        env: &Env,
        policy_id: u64,
        holder: Address,
    ) -> Result<(), PolicyError> {
        // Check if contract is paused
        if Self::is_paused(env) {
            return Err(PolicyError::ContractPaused);
        }

        let timestamp = env.ledger().timestamp();
        let context = PolicyContext {
            policy_id,
            holder,
            coverage_amount: 0, // Would fetch from storage
            premium_amount: 0, // Would fetch from storage
            duration_days: 0, // Would fetch from storage
            policy_type: Symbol::short("CANCEL"),
            timestamp,
        };

        // Emit event
        env.events().publish((Symbol::short("POLICY"), Symbol::short("CANCELED")), context);
        
        Ok(())
    }
}