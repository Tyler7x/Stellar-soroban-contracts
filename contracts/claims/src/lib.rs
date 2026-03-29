#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Symbol, Vec};

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

/// Status of an automatic payout for an approved claim.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayoutStatus {
    /// Payout record created, transfer not yet attempted.
    Pending,
    /// Transfer executed successfully.
    Completed,
    /// Transfer failed; may be retried.
    Failed,
}

/// Tracks the lifecycle of a single claim payout.
#[contracttype]
#[derive(Clone)]
pub struct PayoutRecord {
    pub claim_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub status: PayoutStatus,
    pub initiated_at: u64,
    pub completed_at: Option<u64>,
    /// Number of times a retry has been attempted after an initial failure.
    pub retry_count: u32,
    /// Short symbol describing the reason for the last failure, if any.
    pub failure_reason: Option<Symbol>,
}

#[contracttype]
#[derive(Clone)]
pub struct ClaimRecord {
    pub policy_id: u64,
    pub amount: i128,
    pub status: ClaimStatus,
    pub claimant: Address,
    pub evidence_count: u32,
    pub fraud_score: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FraudStatus { Clean, Suspicious, Confirmed }

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimFraudInfo {
    pub is_duplicate: bool,
    pub velocity_score: u32,
    pub compliance_checked: bool,
    pub reputation_score: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct EvidenceItem {
    pub id: u64,
    pub claim_id: u64,
    pub ipfs_hash: String,
    pub description: Option<String>,
    pub submitter: Address,
    pub submitted_at: u64,
    pub verified: bool,
    pub verified_by: Option<Address>,
    pub verified_at: Option<u64>,
    pub verification_notes: Option<String>,
    pub sensitive: bool,
}

const CLAIMS: Symbol = symbol_short!("CLAIMS");
const EVIDENCE: Symbol = symbol_short!("EVIDENCE");
const EVIDENCE_BY_CLAIM: Symbol = symbol_short!("EV_BYCLM");
const EVIDENCE_SEQ: Symbol = symbol_short!("EV_SEQ");
const ADMIN: Symbol = symbol_short!("ADMIN");
const GUARDIAN: Symbol = symbol_short!("GUARDIAN");
const PAUSE_STATE: Symbol = symbol_short!("PAUSED");
const FRAUD_INFO: Symbol = symbol_short!("FRAUD");
const CLAIM_HISTORY: Symbol = symbol_short!("HISTORY");
const TOKEN: Symbol = symbol_short!("TOKEN");
const PAYOUT: Symbol = symbol_short!("PAYOUT");
const MAX_RETRIES: Symbol = symbol_short!("MAX_RETRY");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseState {
    pub is_paused: bool,
    pub paused_at: Option<u64>,
    pub paused_by: Option<Address>,
    pub reason: Option<Symbol>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimsEvent {
    ClaimSubmitted(u64, Address, i128),
    ClaimApproved(u64),
    ClaimSettled(u64),
    EvidenceSubmitted(u64, u64, Address), // claim_id, evidence_id, submitter
    EvidenceVerified(u64, Address, bool), // evidence_id, verifier, is_valid
    ContractPaused(Address, Option<Symbol>),
    ContractUnpaused(Address, Option<Symbol>),
    FraudFlagged(u64, u32),
    FraudConfirmed(u64),
    /// Fired when the contract begins processing a payout for an approved claim.
    PayoutInitiated(u64, Address, i128),  // claim_id, recipient, amount
    /// Fired when a token transfer completes successfully.
    PayoutCompleted(u64, Address, i128),  // claim_id, recipient, amount
    /// Fired when a payout attempt fails. Contains current retry_count.
    PayoutFailed(u64, u32),              // claim_id, retry_count
}

#[derive(soroban_sdk::contracterror, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ClaimError {
    PolicyInactive = 1,
    InsufficientCoverage = 2,
    ClaimNotFound = 3,
    EvidenceNotFound = 4,
    EvidenceAlreadyVerified = 5,
    InvalidParameters = 6,
    ClaimNotApproved = 7,
    AlreadySettled = 8,
    ContractPaused = 9,
    Unauthorized = 10,
    ClaimFlaggedAsFraud = 11,
    /// Token transfer to the recipient failed (e.g. insufficient contract balance).
    PayoutFailed = 12,
    /// The claim's payout has already been completed and cannot be retried.
    PayoutAlreadyProcessed = 13,
    /// Maximum retry attempts for a failed payout have been exhausted.
    MaxRetriesExceeded = 14,
    /// The recipient address is invalid (e.g. resolves to the contract itself).
    InvalidRecipient = 15,
    /// No payout token address has been configured via set_payout_token.
    TokenNotConfigured = 16,
}

#[contract]
pub struct ClaimsContract;

#[contractimpl]
impl ClaimsContract {
    pub fn initialize(env: Env, admin: Address, guardian: Address) {
        if env.storage().instance().has(&ADMIN) { panic!("Already initialized"); }
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&GUARDIAN, &guardian);
        env.storage().instance().set(&PAUSE_STATE, &PauseState { is_paused: false, paused_at: None, paused_by: None, reason: None });
    }

    /// Set the SEP-41 token contract address used for automatic payouts.
    /// Only the admin or guardian may call this.
    pub fn set_payout_token(env: Env, caller: Address, token_address: Address) -> Result<(), ClaimError> {
        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) { return Err(ClaimError::Unauthorized); }
        env.storage().instance().set(&TOKEN, &token_address);
        Ok(())
    }

    /// Override the maximum number of payout retry attempts (default: 3).
    /// Only the admin or guardian may call this.
    pub fn set_max_retries(env: Env, caller: Address, max: u32) -> Result<(), ClaimError> {
        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) { return Err(ClaimError::Unauthorized); }
        env.storage().instance().set(&MAX_RETRIES, &max);
        Ok(())
    }

    pub fn set_pause_state(env: Env, caller: Address, is_paused: bool, reason: Option<Symbol>) -> Result<(), ClaimError> {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        let guardian: Address = env.storage().instance().get(&GUARDIAN).unwrap();

        if caller != admin && caller != guardian { return Err(ClaimError::Unauthorized); }

        let pause_state = PauseState {
            is_paused,
            paused_at: if is_paused { Some(env.ledger().timestamp()) } else { None },
            paused_by: if is_paused { Some(caller.clone()) } else { None },
            reason: reason.clone(),
        };
        env.storage().instance().set(&PAUSE_STATE, &pause_state);

        if is_paused {
            env.events().publish((Symbol::short("PAUSE"), Symbol::short("PAUSED")), ClaimsEvent::ContractPaused(caller, reason));
        } else {
            env.events().publish((Symbol::short("PAUSE"), Symbol::short("UNPAUSED")), ClaimsEvent::ContractUnpaused(caller, reason));
        }
        Ok(())
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get::<_, PauseState>(&PAUSE_STATE).map(|s| s.is_paused).unwrap_or(false)
    }

    fn next_evidence_id(env: &Env) -> u64 {
        let next: u64 = env.storage().persistent().get(&EVIDENCE_SEQ).unwrap_or(1);
        env.storage().persistent().set(&EVIDENCE_SEQ, &(next + 1));
        next
    }

    fn load_claim_record(env: &Env, claim_id: u64) -> Result<ClaimRecord, ClaimError> {
        env.storage().persistent().get(&(CLAIMS, claim_id)).ok_or(ClaimError::ClaimNotFound)
    }

    fn is_admin_or_guardian(env: &Env, caller: &Address) -> bool {
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        let guardian: Address = env.storage().instance().get(&GUARDIAN).unwrap();
        caller == &admin || caller == &guardian
    }

    fn is_claim_access_allowed(env: &Env, caller: &Address, claim: &ClaimRecord) -> bool {
        caller == &claim.claimant || Self::is_admin_or_guardian(env, caller)
    }

    pub fn submit_claim(env: Env, policy_address: Address, claim_id: u64, policy_id: u64, amount: i128) -> Result<(), ClaimError> {
        if Self::is_paused(env.clone()) { return Err(ClaimError::ContractPaused); }
        let policy = PolicyClient::new(&env, &policy_address);
        if !policy.is_policy_active(&policy_id) { return Err(ClaimError::PolicyInactive); }
        let coverage = policy.get_policy_coverage(&policy_id);
        let fee = amount / 100;
        if coverage <= amount + fee { return Err(ClaimError::InsufficientCoverage); }

        // Duplicate Claim Detection
        let mut fraud_score = 0;
        let history_key = (CLAIM_HISTORY, policy_id, amount);
        if env.storage().persistent().has(&history_key) {
            fraud_score += 50; // High suspicion for same amount on same policy
        }

        // Velocity Check (simplified)
        let policy_claims_count: u32 = env.storage().persistent().get(&(CLAIM_HISTORY, policy_id)).unwrap_or(0);
        if policy_claims_count > 3 {
            fraud_score += 20;
        }

        env.storage().persistent().set(&(CLAIMS, claim_id), &ClaimRecord {
            policy_id,
            amount,
            status: ClaimStatus::Pending,
            claimant: policy_address.clone(),
            evidence_count: 0,
            fraud_score,
        });

        // Update history
        env.storage().persistent().set(&history_key, &claim_id);
        env.storage().persistent().set(&(CLAIM_HISTORY, policy_id), &(policy_claims_count + 1));

        if fraud_score >= 70 {
            env.events().publish((CLAIMS, symbol_short!("FRAUD")), ClaimsEvent::FraudFlagged(claim_id, fraud_score));
        }

        env.events().publish((CLAIMS, symbol_short!("SUBMIT")), ClaimsEvent::ClaimSubmitted(claim_id, policy_address, amount));
        Ok(())
    }

    pub fn submit_evidence(
        env: Env,
        claim_id: u64,
        ipfs_hash: String,
        sensitive: bool,
        description: Option<String>,
        submitter: Address,
    ) -> Result<u64, ClaimError> {
        if Self::is_paused(env.clone()) { return Err(ClaimError::ContractPaused); }
        let mut claim = Self::load_claim_record(&env, claim_id)?;

        if ipfs_hash.len() < 10 {
            return Err(ClaimError::InvalidParameters);
        }

        let evidence_id = Self::next_evidence_id(&env);
        let timestamp = env.ledger().timestamp();
        let evidence = EvidenceItem {
            id: evidence_id,
            claim_id,
            ipfs_hash: ipfs_hash.clone(),
            description,
            submitter: submitter.clone(),
            submitted_at: timestamp,
            verified: false,
            verified_by: None,
            verified_at: None,
            verification_notes: None,
            sensitive,
        };

        env.storage().persistent().set(&(EVIDENCE, evidence_id), &evidence);
        env.storage().persistent().set(&(EVIDENCE_BY_CLAIM, claim_id, claim.evidence_count), &evidence_id);
        claim.evidence_count = claim.evidence_count.checked_add(1).unwrap_or(claim.evidence_count);
        env.storage().persistent().set(&(CLAIMS, claim_id), &claim);

        env.events().publish((CLAIMS, Symbol::short("EVIDENCE")), ClaimsEvent::EvidenceSubmitted(claim_id, evidence_id, submitter));
        Ok(evidence_id)
    }

    pub fn get_evidence(env: Env, caller: Address, evidence_id: u64) -> Result<EvidenceItem, ClaimError> {
        let evidence: EvidenceItem = env.storage().persistent().get(&(EVIDENCE, evidence_id)).ok_or(ClaimError::EvidenceNotFound)?;
        let claim = Self::load_claim_record(&env, evidence.claim_id)?;

        if evidence.sensitive && !Self::is_claim_access_allowed(&env, &caller, &claim) {
            return Err(ClaimError::Unauthorized);
        }

        Ok(evidence)
    }

    pub fn get_claim_evidence_ids(env: Env, claim_id: u64) -> Result<Vec<u64>, ClaimError> {
        let claim = Self::load_claim_record(&env, claim_id)?;
        let mut ids: Vec<u64> = Vec::new(&env);
        for idx in 0..claim.evidence_count {
            let evidence_id: u64 = env.storage().persistent().get(&(EVIDENCE_BY_CLAIM, claim_id, idx)).unwrap();
            ids.push_back(evidence_id);
        }
        Ok(ids)
    }

    pub fn get_claim_evidence(env: Env, caller: Address, claim_id: u64) -> Result<Vec<EvidenceItem>, ClaimError> {
        let claim = Self::load_claim_record(&env, claim_id)?;
        let mut items: Vec<EvidenceItem> = Vec::new(&env);

        for idx in 0..claim.evidence_count {
            let evidence_id: u64 = env.storage().persistent().get(&(EVIDENCE_BY_CLAIM, claim_id, idx)).unwrap();
            let evidence: EvidenceItem = env.storage().persistent().get(&(EVIDENCE, evidence_id)).unwrap();
            if evidence.sensitive && !Self::is_claim_access_allowed(&env, &caller, &claim) {
                continue;
            }
            items.push_back(evidence);
        }

        Ok(items)
    }

    pub fn verify_evidence(
        env: Env,
        caller: Address,
        evidence_id: u64,
        is_valid: bool,
        notes: Option<String>,
    ) -> Result<(), ClaimError> {
        if Self::is_paused(env.clone()) { return Err(ClaimError::ContractPaused); }
        if !Self::is_admin_or_guardian(&env, &caller) { return Err(ClaimError::Unauthorized); }

        let mut evidence: EvidenceItem = env.storage().persistent().get(&(EVIDENCE, evidence_id)).ok_or(ClaimError::EvidenceNotFound)?;
        if evidence.verified { return Err(ClaimError::EvidenceAlreadyVerified); }

        evidence.verified = is_valid;
        evidence.verified_by = Some(caller.clone());
        evidence.verified_at = Some(env.ledger().timestamp());
        evidence.verification_notes = notes.clone();
        env.storage().persistent().set(&(EVIDENCE, evidence_id), &evidence);

        env.events().publish((CLAIMS, Symbol::short("VERIFY")), ClaimsEvent::EvidenceVerified(evidence_id, caller, is_valid));
        Ok(())
    }

    pub fn is_evidence_verified(env: Env, evidence_id: u64) -> Result<bool, ClaimError> {
        let evidence: EvidenceItem = env.storage().persistent().get(&(EVIDENCE, evidence_id)).ok_or(ClaimError::EvidenceNotFound)?;
        Ok(evidence.verified)
    }

    pub fn get_evidence_verification_details(env: Env, evidence_id: u64) -> Result<(bool, Option<Address>, Option<u64>, Option<String>), ClaimError> {
        let evidence: EvidenceItem = env.storage().persistent().get(&(EVIDENCE, evidence_id)).ok_or(ClaimError::EvidenceNotFound)?;
        Ok((evidence.verified, evidence.verified_by, evidence.verified_at, evidence.verification_notes))
    }

    pub fn approve_claim(env: Env, claim_id: u64) -> Result<(), ClaimError> {
        if Self::is_paused(env.clone()) { return Err(ClaimError::ContractPaused); }
        let key = (CLAIMS, claim_id);
        let mut r: ClaimRecord = env.storage().persistent().get(&key).ok_or(ClaimError::ClaimNotFound)?;
        r.status = ClaimStatus::Approved;
        env.storage().persistent().set(&key, &r);
        env.events().publish((CLAIMS, Symbol::short("APPROVE")), ClaimsEvent::ClaimApproved(claim_id));

        // Automatically initiate the payout. Any failure is captured in the
        // PayoutRecord so approval is never rolled back due to payout issues.
        let recipient = r.claimant.clone();
        let amount = r.amount;
        let _ = Self::initiate_payout_internal(&env, claim_id, recipient, amount);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Payout helpers
    // -----------------------------------------------------------------------

    /// Core payout logic shared by `approve_claim` and `retry_payout`.
    ///
    /// On success the claim is automatically moved to `Settled`.
    /// On failure the `PayoutRecord` is persisted with `PayoutStatus::Failed`
    /// and a descriptive `failure_reason` symbol so callers can retry.
    fn initiate_payout_internal(
        env: &Env,
        claim_id: u64,
        recipient: Address,
        amount: i128,
    ) -> Result<(), ClaimError> {
        let now = env.ledger().timestamp();

        // --- Validate recipient ---
        if recipient == env.current_contract_address() {
            let payout = PayoutRecord {
                claim_id,
                recipient,
                amount,
                status: PayoutStatus::Failed,
                initiated_at: now,
                completed_at: None,
                retry_count: 0,
                failure_reason: Some(symbol_short!("INV_RCPT")),
            };
            env.storage().persistent().set(&(PAYOUT, claim_id), &payout);
            env.events().publish(
                (PAYOUT, symbol_short!("FAIL")),
                ClaimsEvent::PayoutFailed(claim_id, 0),
            );
            return Err(ClaimError::InvalidRecipient);
        }

        if amount <= 0 {
            let payout = PayoutRecord {
                claim_id,
                recipient,
                amount,
                status: PayoutStatus::Failed,
                initiated_at: now,
                completed_at: None,
                retry_count: 0,
                failure_reason: Some(symbol_short!("INV_AMT")),
            };
            env.storage().persistent().set(&(PAYOUT, claim_id), &payout);
            env.events().publish(
                (PAYOUT, symbol_short!("FAIL")),
                ClaimsEvent::PayoutFailed(claim_id, 0),
            );
            return Err(ClaimError::InvalidParameters);
        }

        // Emit initiation event before attempting transfer
        env.events().publish(
            (PAYOUT, symbol_short!("INIT")),
            ClaimsEvent::PayoutInitiated(claim_id, recipient.clone(), amount),
        );

        // --- Resolve token contract ---
        let token_address: Option<Address> = env.storage().instance().get(&TOKEN);
        if token_address.is_none() {
            let payout = PayoutRecord {
                claim_id,
                recipient,
                amount,
                status: PayoutStatus::Failed,
                initiated_at: now,
                completed_at: None,
                retry_count: 0,
                failure_reason: Some(symbol_short!("NO_TOKEN")),
            };
            env.storage().persistent().set(&(PAYOUT, claim_id), &payout);
            env.events().publish(
                (PAYOUT, symbol_short!("FAIL")),
                ClaimsEvent::PayoutFailed(claim_id, 0),
            );
            return Err(ClaimError::TokenNotConfigured);
        }

        let token_addr = token_address.unwrap();
        let token_client = token::Client::new(env, &token_addr);

        // --- Pre-flight balance check (graceful failure) ---
        let contract_balance = token_client.balance(&env.current_contract_address());
        if contract_balance < amount {
            let payout = PayoutRecord {
                claim_id,
                recipient,
                amount,
                status: PayoutStatus::Failed,
                initiated_at: now,
                completed_at: None,
                retry_count: 0,
                failure_reason: Some(symbol_short!("LOW_BAL")),
            };
            env.storage().persistent().set(&(PAYOUT, claim_id), &payout);
            env.events().publish(
                (PAYOUT, symbol_short!("FAIL")),
                ClaimsEvent::PayoutFailed(claim_id, 0),
            );
            return Err(ClaimError::PayoutFailed);
        }

        // --- Execute transfer ---
        token_client.transfer(&env.current_contract_address(), &recipient, &amount);

        // --- Mark payout completed ---
        let payout = PayoutRecord {
            claim_id,
            recipient: recipient.clone(),
            amount,
            status: PayoutStatus::Completed,
            initiated_at: now,
            completed_at: Some(now),
            retry_count: 0,
            failure_reason: None,
        };
        env.storage().persistent().set(&(PAYOUT, claim_id), &payout);

        // Auto-settle the claim so callers observe the correct state
        let claim_key = (CLAIMS, claim_id);
        let mut claim: ClaimRecord = env.storage().persistent().get(&claim_key).unwrap();
        claim.status = ClaimStatus::Settled;
        env.storage().persistent().set(&claim_key, &claim);
        env.events().publish(
            (CLAIMS, Symbol::short("SETTLE")),
            ClaimsEvent::ClaimSettled(claim_id),
        );

        env.events().publish(
            (PAYOUT, symbol_short!("DONE")),
            ClaimsEvent::PayoutCompleted(claim_id, recipient, amount),
        );

        Ok(())
    }

    /// Retry a previously failed payout. Only callable when `PayoutStatus` is
    /// `Failed` and the retry count is below the configured maximum (default 3).
    pub fn retry_payout(env: Env, claim_id: u64) -> Result<(), ClaimError> {
        if Self::is_paused(env.clone()) { return Err(ClaimError::ContractPaused); }

        let payout_key = (PAYOUT, claim_id);
        let mut payout: PayoutRecord = env.storage()
            .persistent()
            .get(&payout_key)
            .ok_or(ClaimError::ClaimNotFound)?;

        if payout.status == PayoutStatus::Completed {
            return Err(ClaimError::PayoutAlreadyProcessed);
        }
        if payout.status != PayoutStatus::Failed {
            return Err(ClaimError::PayoutFailed);
        }

        let max_retries: u32 = env.storage().instance().get(&MAX_RETRIES).unwrap_or(3);
        if payout.retry_count >= max_retries {
            return Err(ClaimError::MaxRetriesExceeded);
        }

        // Validate recipient has not somehow become the contract address
        if payout.recipient == env.current_contract_address() {
            return Err(ClaimError::InvalidRecipient);
        }

        payout.retry_count += 1;
        payout.failure_reason = None;
        let now = env.ledger().timestamp();

        // Emit initiation event for this retry attempt
        env.events().publish(
            (PAYOUT, symbol_short!("INIT")),
            ClaimsEvent::PayoutInitiated(claim_id, payout.recipient.clone(), payout.amount),
        );

        // Resolve token
        let token_address: Option<Address> = env.storage().instance().get(&TOKEN);
        if token_address.is_none() {
            payout.status = PayoutStatus::Failed;
            payout.failure_reason = Some(symbol_short!("NO_TOKEN"));
            env.storage().persistent().set(&payout_key, &payout);
            env.events().publish(
                (PAYOUT, symbol_short!("FAIL")),
                ClaimsEvent::PayoutFailed(claim_id, payout.retry_count),
            );
            return Err(ClaimError::TokenNotConfigured);
        }

        let token_addr = token_address.unwrap();
        let token_client = token::Client::new(&env, &token_addr);

        // Pre-flight balance check
        let contract_balance = token_client.balance(&env.current_contract_address());
        if contract_balance < payout.amount {
            payout.status = PayoutStatus::Failed;
            payout.failure_reason = Some(symbol_short!("LOW_BAL"));
            env.storage().persistent().set(&payout_key, &payout);
            env.events().publish(
                (PAYOUT, symbol_short!("FAIL")),
                ClaimsEvent::PayoutFailed(claim_id, payout.retry_count),
            );
            return Err(ClaimError::PayoutFailed);
        }

        // Execute transfer
        token_client.transfer(&env.current_contract_address(), &payout.recipient, &payout.amount);

        payout.status = PayoutStatus::Completed;
        payout.completed_at = Some(now);
        env.storage().persistent().set(&payout_key, &payout);

        // Auto-settle
        let claim_key = (CLAIMS, claim_id);
        let mut claim: ClaimRecord = env.storage().persistent().get(&claim_key).unwrap();
        claim.status = ClaimStatus::Settled;
        env.storage().persistent().set(&claim_key, &claim);
        env.events().publish(
            (CLAIMS, Symbol::short("SETTLE")),
            ClaimsEvent::ClaimSettled(claim_id),
        );

        env.events().publish(
            (PAYOUT, symbol_short!("DONE")),
            ClaimsEvent::PayoutCompleted(claim_id, payout.recipient.clone(), payout.amount),
        );

        Ok(())
    }

    /// Return the full `PayoutRecord` for a given claim.
    pub fn get_payout(env: Env, claim_id: u64) -> Result<PayoutRecord, ClaimError> {
        env.storage()
            .persistent()
            .get(&(PAYOUT, claim_id))
            .ok_or(ClaimError::ClaimNotFound)
    }

    /// Return only the `PayoutStatus` for a given claim (cheaper read).
    pub fn get_payout_status(env: Env, claim_id: u64) -> Result<PayoutStatus, ClaimError> {
        let payout: PayoutRecord = env.storage()
            .persistent()
            .get(&(PAYOUT, claim_id))
            .ok_or(ClaimError::ClaimNotFound)?;
        Ok(payout.status)
    }

    pub fn settle_claim(env: Env, claim_id: u64) -> Result<(), ClaimError> {
        if Self::is_paused(env.clone()) { return Err(ClaimError::ContractPaused); }
        let key = (CLAIMS, claim_id);
        let mut r: ClaimRecord = env.storage().persistent().get(&key).ok_or(ClaimError::ClaimNotFound)?;
        if r.status == ClaimStatus::Settled { return Err(ClaimError::AlreadySettled); }
        if r.status != ClaimStatus::Approved { return Err(ClaimError::ClaimNotApproved); }
        if r.fraud_score >= 80 { return Err(ClaimError::ClaimFlaggedAsFraud); }
        r.status = ClaimStatus::Settled;
        env.storage().persistent().set(&key, &r);
        env.events().publish((CLAIMS, Symbol::short("SETTLE")), ClaimsEvent::ClaimSettled(claim_id));
        Ok(())
    }

    pub fn flag_claim_for_review(env: Env, caller: Address, claim_id: u64, score_adjustment: i32) -> Result<(), ClaimError> {
        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) { return Err(ClaimError::Unauthorized); }

        let key = (CLAIMS, claim_id);
        let mut r: ClaimRecord = env.storage().persistent().get(&key).ok_or(ClaimError::ClaimNotFound)?;
        
        let new_score = (r.fraud_score as i32).saturating_add(score_adjustment);
        r.fraud_score = if new_score < 0 { 0 } else { new_score as u32 };
        
        env.storage().persistent().set(&key, &r);
        env.events().publish((CLAIMS, symbol_short!("REVIEW")), ClaimsEvent::FraudFlagged(claim_id, r.fraud_score));
        Ok(())
    }

    pub fn report_fraud(env: Env, caller: Address, claim_id: u64) -> Result<(), ClaimError> {
        caller.require_auth();
        if !Self::is_admin_or_guardian(&env, &caller) { return Err(ClaimError::Unauthorized); }

        let key = (CLAIMS, claim_id);
        let mut r: ClaimRecord = env.storage().persistent().get(&key).ok_or(ClaimError::ClaimNotFound)?;
        r.status = ClaimStatus::Rejected;
        r.fraud_score = 100;

        env.storage().persistent().set(&key, &r);
        env.events().publish((CLAIMS, symbol_short!("FRAUD_CFM")), ClaimsEvent::FraudConfirmed(claim_id));
        Ok(())
    }
}
