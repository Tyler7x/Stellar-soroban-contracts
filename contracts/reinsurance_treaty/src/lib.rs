#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token,
    Address, Env, Map, Symbol, Vec,
};

// =============================================================================
// Error Types
// =============================================================================

#[derive(soroban_sdk::contracterror, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TreatyError {
    ContractPaused = 1,
    InvalidParameters = 2,
    Unauthorized = 3,
    TreatyNotFound = 4,
    TreatyAlreadyActive = 5,
    TreatyNotActive = 6,
    TreatyExpired = 7,
    CessionNotFound = 8,
    InvalidTreatyType = 9,
    InvalidPercentage = 10,
    TreatyLimitExceeded = 11,
}

// =============================================================================
// Data Types
// =============================================================================

/// Treaty types supported by the contract
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreatyType {
    /// Quota Share - fixed percentage cession
    QuotaShare,
    /// Surplus - cession based on surplus above retention
    Surplus,
}

/// Status of a reinsurance treaty
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreatyStatus {
    Active,
    Suspended,
    Expired,
    Terminated,
}

/// Core treaty terms defining the reinsurance agreement
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreatyTerms {
    pub treaty_id: u64,
    pub treaty_type: TreatyType,
    pub reinsurer: Address,
    pub cession_percentage: u32,      // 0-100 for quota share
    pub retention_limit: i128,         // retention amount for surplus
    pub treaty_limit: i128,            // maximum coverage under treaty
    pub min_cession: i128,             // minimum cession amount
    pub start_date: u64,               // ledger timestamp
    pub end_date: Option<u64>,         // None for perpetual
    pub status: TreatyStatus,
}

/// Tracks a single cession (automatic placement) under a treaty
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CessionRecord {
    pub cession_id: u64,
    pub treaty_id: u64,
    pub policy_id: u64,
    pub original_amount: i128,
    pub ceded_amount: i128,
    pub premium_ceded: i128,
    pub ceded_at: u64,
    pub status: CessionStatus,
}

/// Status of a cession
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CessionStatus {
    Active,
    Claimed,
    Released,
}

/// Aggregate statistics for treaty utilization tracking
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreatyUtilization {
    pub treaty_id: u64,
    pub total_ceded: i128,
    pub total_premium_ceded: i128,
    pub total_claims_paid: i128,
    pub active_cessions: u64,
    pub utilization_percentage: u32,
    pub premium_settled: i128,         // premium already paid to reinsurer
    pub recovery_settled: i128,        // claim recovery already received from reinsurer
}

/// Report data for treaty reporting
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreatyReport {
    pub treaty_id: u64,
    pub reinsurer: Address,
    pub treaty_type: TreatyType,
    pub status: TreatyStatus,
    pub utilization: TreatyUtilization,
    pub cession_count: u64,
}

/// Pause state for emergency controls
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseState {
    pub is_paused: bool,
    pub paused_at: Option<u64>,
    pub paused_by: Option<Address>,
    pub reason: Option<Symbol>,
}

/// Tracks a settlement of premiums or claim recoveries
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementRecord {
    pub settlement_id: u64,
    pub treaty_id: u64,
    pub amount: i128,
    pub settled_at: u64,
    pub settlement_type: SettlementType,
}

/// Type of settlement
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettlementType {
    Premium,
    ClaimRecovery,
}

/// Events emitted by the contract
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreatyEvent {
    TreatyCreated(u64, Address, TreatyType),
    TreatyActivated(u64),
    TreatySuspended(u64, Address),
    TreatyTerminated(u64, Address),
    CessionCreated(u64, u64, i128, i128),
    CessionClaimed(u64, i128),
    CessionReleased(u64),
    TreatyRenewed(u64, Option<u64>),
    ContractPaused(Address, Option<Symbol>),
    ContractUnpaused(Address, Option<Symbol>),
    PremiumsSettled(u64, i128),
    ClaimRecoverySettled(u64, i128),
}

// =============================================================================
// Storage Keys
// =============================================================================

const TREATIES: Symbol = symbol_short!("TREATIES");
const TREATY_CNT: Symbol = symbol_short!("TREATY_CNT");
const TREATY_IDX: Symbol = symbol_short!("TREATY_IDX");
const CESSIONS: Symbol = symbol_short!("CESSIONS");
const CESSION_CNT: Symbol = symbol_short!("CESSION_CNT");
const CESSION_BY_TREATY: Symbol = symbol_short!("CESS_BY_TR");
const ADMIN: Symbol = symbol_short!("ADMIN");
const GUARDIAN: Symbol = symbol_short!("GUARDIAN");
const PAUSE_STATE: Symbol = symbol_short!("PAUSED");
const UTILIZATION: Symbol = symbol_short!("UTIL");
const TOKEN: Symbol = symbol_short!("TOKEN");
const SETTLE_CNT: Symbol = symbol_short!("SETL_CNT");
const SETTLEMENTS: Symbol = symbol_short!("SETL");

// =============================================================================
// Contract Implementation
// =============================================================================

#[contract]
pub struct ReinsuranceTreatyContract;

#[contractimpl]
impl ReinsuranceTreatyContract {
    // ---------------------------------------------------------------------
    // Initialization
    // ---------------------------------------------------------------------

    /// Initialize the contract with admin and guardian addresses
    pub fn initialize(env: Env, admin: Address, guardian: Address) {
        if env.storage().instance().has(&ADMIN) {
            panic!("Already initialized");
        }
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&GUARDIAN, &guardian);
        env.storage().instance().set(
            &PAUSE_STATE,
            &PauseState {
                is_paused: false,
                paused_at: None,
                paused_by: None,
                reason: None,
            },
        );
    }

    /// Set the SEP-41 token contract address used for settlements
    pub fn set_token(env: Env, admin: Address, token_address: Address) -> Result<(), TreatyError> {
        admin.require_auth();
        let current_admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        if admin != current_admin {
            return Err(TreatyError::Unauthorized);
        }
        env.storage().instance().set(&TOKEN, &token_address);
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Pause/Unpause Controls
    // ---------------------------------------------------------------------

    /// Set pause state for emergency controls
    pub fn set_pause_state(
        env: Env,
        caller: Address,
        is_paused: bool,
        reason: Option<Symbol>,
    ) -> Result<(), TreatyError> {
        caller.require_auth();

        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        let guardian: Address = env.storage().instance().get(&GUARDIAN).unwrap();

        if caller != admin && caller != guardian {
            return Err(TreatyError::Unauthorized);
        }

        let pause_state = PauseState {
            is_paused,
            paused_at: if is_paused {
                Some(env.ledger().timestamp())
            } else {
                None
            },
            paused_by: if is_paused {
                Some(caller.clone())
            } else {
                None
            },
            reason: reason.clone(),
        };
        env.storage().instance().set(&PAUSE_STATE, &pause_state);

        if is_paused {
            env.events().publish(
                (symbol_short!("PAUSE"), symbol_short!("PAUSED")),
                TreatyEvent::ContractPaused(caller, reason),
            );
        } else {
            env.events().publish(
                (symbol_short!("PAUSE"), symbol_short!("UNPAUSED")),
                TreatyEvent::ContractUnpaused(caller, reason),
            );
        }
        Ok(())
    }

    /// Check if contract is paused
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get::<_, PauseState>(&PAUSE_STATE)
            .map(|s| s.is_paused)
            .unwrap_or(false)
    }

    // ---------------------------------------------------------------------
    // Treaty Management
    // ---------------------------------------------------------------------

    /// Create a new reinsurance treaty with specified terms
    ///
    /// # Arguments
    /// * `creator` - Address creating the treaty (must be admin/guardian)
    /// * `reinsurer` - Address of the reinsurer
    /// * `treaty_type` - Type of treaty (QuotaShare or Surplus)
    /// * `cession_percentage` - Percentage to cede (0-100) for quota share
    /// * `retention_limit` - Amount retained before cession (for surplus)
    /// * `treaty_limit` - Maximum total coverage under treaty
    /// * `min_cession` - Minimum cession amount
    /// * `duration_days` - Duration in days (0 for perpetual)
    pub fn create_treaty(
        env: Env,
        creator: Address,
        reinsurer: Address,
        treaty_type: TreatyType,
        cession_percentage: u32,
        retention_limit: i128,
        treaty_limit: i128,
        min_cession: i128,
        duration_days: u64,
    ) -> Result<u64, TreatyError> {
        if Self::is_paused(env.clone()) {
            return Err(TreatyError::ContractPaused);
        }

        creator.require_auth();

        // Validate parameters
        if cession_percentage > 100 {
            return Err(TreatyError::InvalidPercentage);
        }
        if treaty_limit <= 0 || min_cession <= 0 {
            return Err(TreatyError::InvalidParameters);
        }
        if min_cession > treaty_limit {
            return Err(TreatyError::InvalidParameters);
        }

        // Generate treaty ID
        let treaty_id = Self::next_treaty_id(&env);
        let now = env.ledger().timestamp();
        let end_date = if duration_days > 0 {
            Some(now.saturating_add(duration_days * 86400))
        } else {
            None
        };

        let terms = TreatyTerms {
            treaty_id,
            treaty_type: treaty_type.clone(),
            reinsurer: reinsurer.clone(),
            cession_percentage,
            retention_limit,
            treaty_limit,
            min_cession,
            start_date: now,
            end_date,
            status: TreatyStatus::Active,
        };

        // Store treaty
        env.storage().persistent().set(&(TREATIES, treaty_id), &terms);

        // Index for listing
        let treaty_count: u64 = env.storage().instance().get(&TREATY_CNT).unwrap_or(0);
        env.storage().persistent().set(&(TREATY_IDX, treaty_count), &treaty_id);
        env.storage().instance().set(&TREATY_CNT, &(treaty_count + 1));

        // Initialize utilization
        let utilization = TreatyUtilization {
            treaty_id,
            total_ceded: 0,
            total_premium_ceded: 0,
            total_claims_paid: 0,
            active_cessions: 0,
            utilization_percentage: 0,
            premium_settled: 0,
            recovery_settled: 0,
        };
        env.storage().persistent().set(&(UTILIZATION, treaty_id), &utilization);

        env.events().publish(
            (TREATIES, symbol_short!("CREATE")),
            TreatyEvent::TreatyCreated(treaty_id, reinsurer, treaty_type),
        );

        Ok(treaty_id)
    }

    /// Suspend an active treaty (stops new cessions)
    pub fn suspend_treaty(
        env: Env,
        caller: Address,
        treaty_id: u64,
    ) -> Result<(), TreatyError> {
        if Self::is_paused(env.clone()) {
            return Err(TreatyError::ContractPaused);
        }

        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) {
            return Err(TreatyError::Unauthorized);
        }

        let mut terms: TreatyTerms = env
            .storage()
            .persistent()
            .get(&(TREATIES, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)?;

        if terms.status != TreatyStatus::Active {
            return Err(TreatyError::TreatyNotActive);
        }

        terms.status = TreatyStatus::Suspended;
        env.storage().persistent().set(&(TREATIES, treaty_id), &terms);

        env.events().publish(
            (TREATIES, symbol_short!("SUSPEND")),
            TreatyEvent::TreatySuspended(treaty_id, caller),
        );

        Ok(())
    }

    /// Terminate a treaty permanently
    pub fn terminate_treaty(
        env: Env,
        caller: Address,
        treaty_id: u64,
    ) -> Result<(), TreatyError> {
        if Self::is_paused(env.clone()) {
            return Err(TreatyError::ContractPaused);
        }

        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) {
            return Err(TreatyError::Unauthorized);
        }

        let mut terms: TreatyTerms = env
            .storage()
            .persistent()
            .get(&(TREATIES, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)?;

        terms.status = TreatyStatus::Terminated;
        env.storage().persistent().set(&(TREATIES, treaty_id), &terms);

        env.events().publish(
            (TREATIES, symbol_short!("TERMINATE")),
            TreatyEvent::TreatyTerminated(treaty_id, caller),
        );

        Ok(())
    }

    /// Renew a treaty extending its end date
    pub fn renew_treaty(
        env: Env,
        caller: Address,
        treaty_id: u64,
        extension_days: u64,
    ) -> Result<(), TreatyError> {
        if Self::is_paused(env.clone()) {
            return Err(TreatyError::ContractPaused);
        }

        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) {
            return Err(TreatyError::Unauthorized);
        }

        let mut terms: TreatyTerms = env
            .storage()
            .persistent()
            .get(&(TREATIES, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)?;

        let new_end_date = if extension_days > 0 {
            Some(env.ledger().timestamp().saturating_add(extension_days * 86400))
        } else {
            None
        };

        terms.end_date = new_end_date;
        env.storage().persistent().set(&(TREATIES, treaty_id), &terms);

        env.events().publish(
            (TREATIES, symbol_short!("RENEW")),
            TreatyEvent::TreatyRenewed(treaty_id, new_end_date),
        );

        Ok(())
    }

    // ---------------------------------------------------------------------
    // Automatic Cession Calculations
    // ---------------------------------------------------------------------

    /// Create an automatic cession under a treaty for a given policy amount
    ///
    /// This calculates the ceded amount based on treaty type:
    /// - QuotaShare: cedes fixed percentage of the amount
    /// - Surplus: cedes amount above retention limit up to treaty limit
    pub fn cede_risk(
        env: Env,
        caller: Address,
        treaty_id: u64,
        policy_id: u64,
        original_amount: i128,
        premium: i128,
    ) -> Result<u64, TreatyError> {
        if Self::is_paused(env.clone()) {
            return Err(TreatyError::ContractPaused);
        }

        caller.require_auth();

        // Load and validate treaty
        let terms: TreatyTerms = env
            .storage()
            .persistent()
            .get(&(TREATIES, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)?;

        if terms.status != TreatyStatus::Active {
            return Err(TreatyError::TreatyNotActive);
        }

        // Check expiration
        if let Some(end_date) = terms.end_date {
            if env.ledger().timestamp() > end_date {
                return Err(TreatyError::TreatyExpired);
            }
        }

        // Calculate ceded amount based on treaty type
        let ceded_amount = match terms.treaty_type {
            TreatyType::QuotaShare => {
                // Cede fixed percentage
                original_amount * terms.cession_percentage as i128 / 100
            }
            TreatyType::Surplus => {
                // Cede amount above retention, up to treaty limit
                if original_amount <= terms.retention_limit {
                    0
                } else {
                    let surplus = original_amount - terms.retention_limit;
                    surplus.min(terms.treaty_limit - terms.retention_limit)
                }
            }
        };

        // Validate minimum cession
        if ceded_amount > 0 && ceded_amount < terms.min_cession {
            return Err(TreatyError::InvalidParameters);
        }

        // Check treaty limit
        let utilization: TreatyUtilization = env
            .storage()
            .persistent()
            .get(&(UTILIZATION, treaty_id))
            .unwrap();

        if utilization.total_ceded + ceded_amount > terms.treaty_limit {
            return Err(TreatyError::TreatyLimitExceeded);
        }

        // Calculate ceded premium (proportional to ceded amount)
        let ceded_premium = if original_amount > 0 {
            premium * ceded_amount / original_amount
        } else {
            0
        };

        // Create cession record
        let cession_id = Self::next_cession_id(&env);
        let now = env.ledger().timestamp();

        let cession = CessionRecord {
            cession_id,
            treaty_id,
            policy_id,
            original_amount,
            ceded_amount,
            premium_ceded: ceded_premium,
            ceded_at: now,
            status: CessionStatus::Active,
        };

        env.storage()
            .persistent()
            .set(&(CESSIONS, cession_id), &cession);

        // Index by treaty
        let treaty_cession_count: u64 = env
            .storage()
            .persistent()
            .get(&(CESSION_BY_TREATY, treaty_id))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&(CESSION_BY_TREATY, treaty_id, treaty_cession_count), &cession_id);
        env.storage()
            .persistent()
            .set(&(CESSION_BY_TREATY, treaty_id), &(treaty_cession_count + 1));

        // Update utilization
        let new_utilization = TreatyUtilization {
            treaty_id,
            total_ceded: utilization.total_ceded + ceded_amount,
            total_premium_ceded: utilization.total_premium_ceded + ceded_premium,
            total_claims_paid: utilization.total_claims_paid,
            active_cessions: utilization.active_cessions + 1,
            utilization_percentage: Self::calculate_utilization_percentage(
                new_utilization.total_ceded,
                terms.treaty_limit,
            ),
            premium_settled: utilization.premium_settled,
            recovery_settled: utilization.recovery_settled,
        };
        env.storage()
            .persistent()
            .set(&(UTILIZATION, treaty_id), &new_utilization);

        env.events().publish(
            (CESSIONS, symbol_short!("CREATE")),
            TreatyEvent::CessionCreated(cession_id, treaty_id, ceded_amount, ceded_premium),
        );

        Ok(cession_id)
    }

    /// Process a claim against a cession (reduces available treaty capacity)
    pub fn process_cession_claim(
        env: Env,
        caller: Address,
        cession_id: u64,
        claim_amount: i128,
    ) -> Result<(), TreatyError> {
        if Self::is_paused(env.clone()) {
            return Err(TreatyError::ContractPaused);
        }

        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) {
            return Err(TreatyError::Unauthorized);
        }

        let mut cession: CessionRecord = env
            .storage()
            .persistent()
            .get(&(CESSIONS, cession_id))
            .ok_or(TreatyError::CessionNotFound)?;

        if cession.status != CessionStatus::Active {
            return Err(TreatyError::InvalidParameters);
        }

        cession.status = CessionStatus::Claimed;
        env.storage().persistent().set(&(CESSIONS, cession_id), &cession);

        // Update treaty utilization
        let mut utilization: TreatyUtilization = env
            .storage()
            .persistent()
            .get(&(UTILIZATION, cession.treaty_id))
            .unwrap();

        utilization.total_claims_paid += claim_amount;
        if utilization.active_cessions > 0 {
            utilization.active_cessions -= 1;
        }

        let terms: TreatyTerms = env
            .storage()
            .persistent()
            .get(&(TREATIES, cession.treaty_id))
            .unwrap();

        utilization.utilization_percentage = Self::calculate_utilization_percentage(
            utilization.total_ceded,
            terms.treaty_limit,
        );

        env.storage()
            .persistent()
            .set(&(UTILIZATION, cession.treaty_id), &utilization);

        env.events().publish(
            (CESSIONS, symbol_short!("CLAIM")),
            TreatyEvent::CessionClaimed(cession_id, claim_amount),
        );

        Ok(())
    }

    /// Release a cession (e.g., policy expired without claim)
    pub fn release_cession(
        env: Env,
        caller: Address,
        cession_id: u64,
    ) -> Result<(), TreatyError> {
        if Self::is_paused(env.clone()) {
            return Err(TreatyError::ContractPaused);
        }

        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) {
            return Err(TreatyError::Unauthorized);
        }

        let mut cession: CessionRecord = env
            .storage()
            .persistent()
            .get(&(CESSIONS, cession_id))
            .ok_or(TreatyError::CessionNotFound)?;

        if cession.status != CessionStatus::Active {
            return Err(TreatyError::InvalidParameters);
        }

        cession.status = CessionStatus::Released;
        env.storage().persistent().set(&(CESSIONS, cession_id), &cession);

        // Update utilization (ceded amount becomes available again)
        let mut utilization: TreatyUtilization = env
            .storage()
            .persistent()
            .get(&(UTILIZATION, cession.treaty_id))
            .unwrap();

        if utilization.active_cessions > 0 {
            utilization.active_cessions -= 1;
        }

        let terms: TreatyTerms = env
            .storage()
            .persistent()
            .get(&(TREATIES, cession.treaty_id))
            .unwrap();

        utilization.utilization_percentage = Self::calculate_utilization_percentage(
            utilization.total_ceded,
            terms.treaty_limit,
        );

        env.storage()
            .persistent()
            .set(&(UTILIZATION, cession.treaty_id), &utilization);

        env.events().publish(
            (CESSIONS, symbol_short!("RELEASE")),
            TreatyEvent::CessionReleased(cession_id),
        );

        Ok(())
    }

    // ---------------------------------------------------------------------
    // Integration with Accounting (Settlements)
    // ---------------------------------------------------------------------
    
    /// Settle outstanding premiums to the reinsurer
    pub fn settle_premiums(env: Env, admin: Address, treaty_id: u64, amount: i128) -> Result<u64, TreatyError> {
        admin.require_auth();
        if !Self::is_admin_or_guardian(&env, &admin) {
            return Err(TreatyError::Unauthorized);
        }

        let terms = Self::get_treaty(env.clone(), treaty_id)?;
        let mut utilization = Self::get_treaty_utilization(env.clone(), treaty_id)?;

        let token_address: Address = env.storage().instance().get(&TOKEN).ok_or(TreatyError::InvalidParameters)?;
        let token_client = token::Client::new(&env, &token_address);

        // Transfer from contract to reinsurer
        token_client.transfer(&env.current_contract_address(), &terms.reinsurer, &amount);

        // Update utilization
        utilization.premium_settled += amount;
        env.storage().persistent().set(&(UTILIZATION, treaty_id), &utilization);

        // Create settlement record
        let settlement_id = Self::next_settlement_id(&env);
        let record = SettlementRecord {
            settlement_id,
            treaty_id,
            amount,
            settled_at: env.ledger().timestamp(),
            settlement_type: SettlementType::Premium,
        };
        env.storage().persistent().set(&(SETTLEMENTS, settlement_id), &record);

        env.events().publish(
            (SETTLEMENTS, symbol_short!("PREMIUM")),
            TreatyEvent::PremiumsSettled(treaty_id, amount),
        );

        Ok(settlement_id)
    }

    /// Settle claim recovery from the reinsurer back to the contract
    pub fn settle_claim_recovery(env: Env, reinsurer: Address, treaty_id: u64, amount: i128) -> Result<u64, TreatyError> {
        reinsurer.require_auth();
        
        let terms = Self::get_treaty(env.clone(), treaty_id)?;
        if reinsurer != terms.reinsurer {
            return Err(TreatyError::Unauthorized);
        }

        let mut utilization = Self::get_treaty_utilization(env.clone(), treaty_id)?;

        let token_address: Address = env.storage().instance().get(&TOKEN).ok_or(TreatyError::InvalidParameters)?;
        let token_client = token::Client::new(&env, &token_address);

        // Transfer from reinsurer to contract
        token_client.transfer(&reinsurer, &env.current_contract_address(), &amount);

        // Update utilization
        utilization.recovery_settled += amount;
        env.storage().persistent().set(&(UTILIZATION, treaty_id), &utilization);

        // Create settlement record
        let settlement_id = Self::next_settlement_id(&env);
        let record = SettlementRecord {
            settlement_id,
            treaty_id,
            amount,
            settled_at: env.ledger().timestamp(),
            settlement_type: SettlementType::ClaimRecovery,
        };
        env.storage().persistent().set(&(SETTLEMENTS, settlement_id), &record);

        env.events().publish(
            (SETTLEMENTS, symbol_short!("RECOVERY")),
            TreatyEvent::ClaimRecoverySettled(treaty_id, amount),
        );

        Ok(settlement_id)
    }

    /// Get a settlement record by ID
    pub fn get_settlement(env: Env, settlement_id: u64) -> Result<SettlementRecord, TreatyError> {
        env.storage()
            .persistent()
            .get(&(SETTLEMENTS, settlement_id))
            .ok_or(TreatyError::InvalidParameters)
    }

    // ---------------------------------------------------------------------
    // Query Functions
    // ---------------------------------------------------------------------

    /// Get treaty terms by ID
    pub fn get_treaty(env: Env, treaty_id: u64) -> Result<TreatyTerms, TreatyError> {
        env.storage()
            .persistent()
            .get(&(TREATIES, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)
    }

    /// Get cession record by ID
    pub fn get_cession(env: Env, cession_id: u64) -> Result<CessionRecord, TreatyError> {
        env.storage()
            .persistent()
            .get(&(CESSIONS, cession_id))
            .ok_or(TreatyError::CessionNotFound)
    }

    /// Get treaty utilization statistics
    pub fn get_treaty_utilization(
        env: Env,
        treaty_id: u64,
    ) -> Result<TreatyUtilization, TreatyError> {
        env.storage()
            .persistent()
            .get(&(UTILIZATION, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)
    }

    /// Generate comprehensive treaty report
    pub fn generate_treaty_report(
        env: Env,
        treaty_id: u64,
    ) -> Result<TreatyReport, TreatyError> {
        let terms: TreatyTerms = env
            .storage()
            .persistent()
            .get(&(TREATIES, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)?;

        let utilization: TreatyUtilization = env
            .storage()
            .persistent()
            .get(&(UTILIZATION, treaty_id))
            .unwrap();

        let cession_count: u64 = env
            .storage()
            .persistent()
            .get(&(CESSION_BY_TREATY, treaty_id))
            .unwrap_or(0);

        Ok(TreatyReport {
            treaty_id,
            reinsurer: terms.reinsurer,
            treaty_type: terms.treaty_type,
            status: terms.status,
            utilization,
            cession_count,
        })
    }

    /// List all treaties (paginated)
    pub fn list_treaties(
        env: Env,
        start_index: u64,
        max_items: u64,
    ) -> Vec<u64> {
        let total = env.storage().instance().get(&TREATY_CNT).unwrap_or(0);
        let end_index = start_index + max_items;
        let end_index = if end_index > total { total } else { end_index };

        let mut ids = Vec::new(&env);
        for idx in start_index..end_index {
            let treaty_id: u64 = env.storage().persistent().get(&(TREATY_IDX, idx)).unwrap();
            ids.push_back(treaty_id);
        }
        ids
    }

    /// List cessions under a treaty (paginated)
    pub fn list_treaty_cessions(
        env: Env,
        treaty_id: u64,
        start_index: u64,
        max_items: u64,
    ) -> Result<Vec<u64>, TreatyError> {
        let total: u64 = env
            .storage()
            .persistent()
            .get(&(CESSION_BY_TREATY, treaty_id))
            .unwrap_or(0);

        let end_index = start_index + max_items;
        let end_index = if end_index > total { total } else { end_index };

        let mut ids = Vec::new(&env);
        for idx in start_index..end_index {
            let cession_id: u64 = env
                .storage()
                .persistent()
                .get(&(CESSION_BY_TREATY, treaty_id, idx))
                .unwrap();
            ids.push_back(cession_id);
        }
        ids
    }

    /// Get total number of treaties
    pub fn get_treaty_count(env: Env) -> u64 {
        env.storage().instance().get(&TREATY_CNT).unwrap_or(0)
    }

    /// Get total number of cessions under a treaty
    pub fn get_cession_count(env: Env, treaty_id: u64) -> u64 {
        env.storage()
            .persistent()
            .get(&(CESSION_BY_TREATY, treaty_id))
            .unwrap_or(0)
    }

    // ---------------------------------------------------------------------
    // Integration with Accounting (placeholder for external integration)
    // ---------------------------------------------------------------------

    /// Get total ceded premium for accounting integration
    pub fn get_total_ceded_premium(env: Env, treaty_id: u64) -> Result<i128, TreatyError> {
        let utilization: TreatyUtilization = env
            .storage()
            .persistent()
            .get(&(UTILIZATION, treaty_id))
            .ok_or(TreatyError::TreatyNotFound)?;
        Ok(utilization.total_premium_ceded)
    }

    // ---------------------------------------------------------------------
    // Helper Functions
    // ---------------------------------------------------------------------

    fn next_treaty_id(env: &Env) -> u64 {
        let count: u64 = env.storage().instance().get(&TREATY_CNT).unwrap_or(0);
        count
    }

    fn next_settlement_id(env: &Env) -> u64 {
        let count: u64 = env.storage().instance().get(&SETTLE_CNT).unwrap_or(0);
        let next = count + 1;
        env.storage().instance().set(&SETTLE_CNT, &next);
        next
    }

    fn next_cession_id(env: &Env) -> u64 {
        let count: u64 = env.storage().instance().get(&CESSION_CNT).unwrap_or(0);
        let next = count + 1;
        env.storage().instance().set(&CESSION_CNT, &next);
        next
    }

    fn is_admin_or_guardian(env: &Env, caller: &Address) -> bool {
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        let guardian: Address = env.storage().instance().get(&GUARDIAN).unwrap();
        caller == &admin || caller == &guardian
    }

    fn calculate_utilization_percentage(total_ceded: i128, treaty_limit: i128) -> u32 {
        if treaty_limit <= 0 {
            return 0;
        }
        ((total_ceded * 100) / treaty_limit) as u32
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let guardian = Address::generate(&env);
        ReinsuranceTreatyContract::initialize(env.clone(), admin.clone(), guardian.clone());
        (env, admin, guardian)
    }

    #[test]
    fn test_create_quota_share_treaty() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            40,    // 40% cession
            0,     // no retention for quota share
            1_000_000, // treaty limit
            1_000, // min cession
            365,   // 1 year
        )
        .unwrap();

        assert_eq!(treaty_id, 0);

        let treaty = ReinsuranceTreatyContract::get_treaty(env.clone(), treaty_id).unwrap();
        assert_eq!(treaty.treaty_type, TreatyType::QuotaShare);
        assert_eq!(treaty.cession_percentage, 40);
        assert_eq!(treaty.status, TreatyStatus::Active);
    }

    #[test]
    fn test_create_surplus_treaty() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::Surplus,
            0,     // percentage not used for surplus
            100_000, // retention limit
            1_000_000, // treaty limit
            1_000, // min cession
            365,   // 1 year
        )
        .unwrap();

        let treaty = ReinsuranceTreatyContract::get_treaty(env.clone(), treaty_id).unwrap();
        assert_eq!(treaty.treaty_type, TreatyType::Surplus);
        assert_eq!(treaty.retention_limit, 100_000);
    }

    #[test]
    fn test_cede_risk_quota_share() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let policy_holder = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            50,    // 50% cession
            0,
            1_000_000,
            1_000,
            365,
        )
        .unwrap();

        let cession_id = ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            1,     // policy_id
            200_000, // original amount
            2_000,   // premium
        )
        .unwrap();

        assert_eq!(cession_id, 1);

        let cession = ReinsuranceTreatyContract::get_cession(env.clone(), cession_id).unwrap();
        assert_eq!(cession.ceded_amount, 100_000); // 50% of 200k
        assert_eq!(cession.premium_ceded, 1_000);  // 50% of premium
    }

    #[test]
    fn test_cede_risk_surplus() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let policy_holder = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::Surplus,
            0,
            100_000, // retention
            500_000, // treaty limit
            1_000,
            365,
        )
        .unwrap();

        // Policy of 300k, retention 100k -> cede 200k surplus
        let cession_id = ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            1,
            300_000,
            3_000,
        )
        .unwrap();

        let cession = ReinsuranceTreatyContract::get_cession(env.clone(), cession_id).unwrap();
        assert_eq!(cession.ceded_amount, 200_000); // amount above retention
    }

    #[test]
    fn test_treaty_utilization_tracking() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let policy_holder = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            50,
            0,
            500_000, // treaty limit
            1_000,
            365,
        )
        .unwrap();

        // Create multiple cessions
        ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            1,
            200_000,
            2_000,
        )
        .unwrap();

        ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            2,
            300_000,
            3_000,
        )
        .unwrap();

        let utilization = ReinsuranceTreatyContract::get_treaty_utilization(env.clone(), treaty_id).unwrap();
        assert_eq!(utilization.total_ceded, 250_000); // 50% of 500k
        assert_eq!(utilization.active_cessions, 2);
        assert_eq!(utilization.utilization_percentage, 50); // 250k / 500k = 50%
    }

    #[test]
    fn test_treaty_limit_exceeded() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let policy_holder = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            100, // 100% cession
            0,
            100_000, // treaty limit
            1_000,
            365,
        )
        .unwrap();

        // First cession uses full limit
        ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            1,
            100_000,
            1_000,
        )
        .unwrap();

        // Second cession should fail - exceeds limit
        let result = ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            2,
            50_000,
            500,
        );

        assert_eq!(result.unwrap_err(), TreatyError::TreatyLimitExceeded);
    }

    #[test]
    fn test_generate_treaty_report() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let policy_holder = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            40,
            0,
            1_000_000,
            1_000,
            365,
        )
        .unwrap();

        ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            1,
            100_000,
            1_000,
        )
        .unwrap();

        let report = ReinsuranceTreatyContract::generate_treaty_report(env.clone(), treaty_id).unwrap();
        assert_eq!(report.cession_count, 1);
        assert_eq!(report.utilization.total_ceded, 40_000);
    }

    #[test]
    fn test_suspend_and_terminate_treaty() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            40,
            0,
            1_000_000,
            1_000,
            365,
        )
        .unwrap();

        // Suspend
        ReinsuranceTreatyContract::suspend_treaty(env.clone(), admin.clone(), treaty_id).unwrap();
        let treaty = ReinsuranceTreatyContract::get_treaty(env.clone(), treaty_id).unwrap();
        assert_eq!(treaty.status, TreatyStatus::Suspended);

        // Terminate
        ReinsuranceTreatyContract::terminate_treaty(env.clone(), admin.clone(), treaty_id).unwrap();
        let treaty = ReinsuranceTreatyContract::get_treaty(env.clone(), treaty_id).unwrap();
        assert_eq!(treaty.status, TreatyStatus::Terminated);
    }

    #[test]
    fn test_cession_cannot_be_created_on_suspended_treaty() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let policy_holder = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            40,
            0,
            1_000_000,
            1_000,
            365,
        )
        .unwrap();

        // Suspend treaty
        ReinsuranceTreatyContract::suspend_treaty(env.clone(), admin.clone(), treaty_id).unwrap();

        // Try to cede risk - should fail
        let result = ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            1,
            100_000,
            1_000,
        );

        assert_eq!(result.unwrap_err(), TreatyError::TreatyNotActive);
    }

    #[test]
    fn test_process_and_release_cession() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let policy_holder = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            50,
            0,
            1_000_000,
            1_000,
            365,
        )
        .unwrap();

        let cession_id = ReinsuranceTreatyContract::cede_risk(
            env.clone(),
            policy_holder.clone(),
            treaty_id,
            1,
            200_000,
            2_000,
        )
        .unwrap();

        // Process claim
        ReinsuranceTreatyContract::process_cession_claim(
            env.clone(),
            admin.clone(),
            cession_id,
            50_000,
        )
        .unwrap();

        let cession = ReinsuranceTreatyContract::get_cession(env.clone(), cession_id).unwrap();
        assert_eq!(cession.status, CessionStatus::Claimed);

        let utilization = ReinsuranceTreatyContract::get_treaty_utilization(env.clone(), treaty_id).unwrap();
        assert_eq!(utilization.total_claims_paid, 50_000);
    }

    #[test]
    fn test_list_treaties_pagination() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);

        // Create 5 treaties
        for i in 0..5 {
            ReinsuranceTreatyContract::create_treaty(
                env.clone(),
                admin.clone(),
                reinsurer.clone(),
                TreatyType::QuotaShare,
                40,
                0,
                1_000_000,
                1_000,
                365,
            )
            .unwrap();
        }

        // List first 3
        let page1 = ReinsuranceTreatyContract::list_treaties(env.clone(), 0, 3);
        assert_eq!(page1.len(), 3);

        // List remaining 2
        let page2 = ReinsuranceTreatyContract::list_treaties(env.clone(), 3, 3);
        assert_eq!(page2.len(), 2);
    }

    #[test]
    fn test_renew_treaty() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            40,
            0,
            1_000_000,
            1_000,
            365,
        )
        .unwrap();

        // Renew for additional 180 days
        ReinsuranceTreatyContract::renew_treaty(env.clone(), admin.clone(), treaty_id, 180).unwrap();

        let treaty = ReinsuranceTreatyContract::get_treaty(env.clone(), treaty_id).unwrap();
        assert!(treaty.end_date.is_some());
    }

    #[test]
    fn test_invalid_percentage_fails() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);

        let result = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            101, // Invalid: > 100
            0,
            1_000_000,
            1_000,
            365,
        );

        assert_eq!(result.unwrap_err(), TreatyError::InvalidPercentage);
    }

    #[test]
    fn test_pause_prevents_operations() {
        let (env, admin, guardian) = setup();
        let reinsurer = Address::generate(&env);

        // Pause contract
        ReinsuranceTreatyContract::set_pause_state(
            env.clone(),
            admin.clone(),
            true,
            Some(symbol_short!("MAINT")),
        )
        .unwrap();

        assert!(ReinsuranceTreatyContract::is_paused(env.clone()));

        // Try to create treaty - should fail
        let result = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            40,
            0,
            1_000_000,
            1_000,
            365,
        );

        assert_eq!(result.unwrap_err(), TreatyError::ContractPaused);
        
        // Unpause
        ReinsuranceTreatyContract::set_pause_state(
            env.clone(),
            guardian.clone(),
            false,
            Some(symbol_short!("MAINT")),
        )
        .unwrap();

        assert!(!ReinsuranceTreatyContract::is_paused(env.clone()));
    }

    #[test]
    fn test_settlement_workflow() {
        let (env, admin, _guardian) = setup();
        let reinsurer = Address::generate(&env);
        let token_address = Address::generate(&env);

        // Initialize token
        ReinsuranceTreatyContract::set_token(env.clone(), admin.clone(), token_address.clone()).unwrap();

        let treaty_id = ReinsuranceTreatyContract::create_treaty(
            env.clone(),
            admin.clone(),
            reinsurer.clone(),
            TreatyType::QuotaShare,
            50,
            0,
            1_000_000,
            1_000,
            365,
        )
        .unwrap();

        // 1. Settle Premiums
        // Admin settles 50,000 premium to reinsurer
        let settle_id = ReinsuranceTreatyContract::settle_premiums(
            env.clone(),
            admin.clone(),
            treaty_id,
            50_000,
        )
        .unwrap();

        let settlement = ReinsuranceTreatyContract::get_settlement(env.clone(), settle_id).unwrap();
        assert_eq!(settlement.amount, 50_000);
        assert_eq!(settlement.settlement_type, SettlementType::Premium);

        let utilization = ReinsuranceTreatyContract::get_treaty_utilization(env.clone(), treaty_id).unwrap();
        assert_eq!(utilization.premium_settled, 50_000);

        // 2. Settle Claim Recovery
        // Reinsurer pays back 20,000 in claim recovery
        let recovery_id = ReinsuranceTreatyContract::settle_claim_recovery(
            env.clone(),
            reinsurer.clone(),
            treaty_id,
            20_000,
        )
        .unwrap();

        let recovery = ReinsuranceTreatyContract::get_settlement(env.clone(), recovery_id).unwrap();
        assert_eq!(recovery.amount, 20_000);
        assert_eq!(recovery.settlement_type, SettlementType::ClaimRecovery);

        let utilization = ReinsuranceTreatyContract::get_treaty_utilization(env.clone(), treaty_id).unwrap();
        assert_eq!(utilization.recovery_settled, 20_000);
    }
}
