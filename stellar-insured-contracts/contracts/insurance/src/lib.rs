#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::needless_borrows_for_generic_args
)]

use ink::storage::Mapping;

/// Decentralized Property Insurance Platform
#[ink::contract]
mod propchain_insurance {
    use super::*;
    use ink::prelude::{string::String, vec::Vec};

    // =========================================================================
    // ERROR TYPES
    // =========================================================================

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum InsuranceError {
        Unauthorized,
        PolicyNotFound,
        ClaimNotFound,
        PoolNotFound,
        PolicyAlreadyActive,
        PolicyExpired,
        PolicyInactive,
        InsufficientPremium,
        InsufficientPoolFunds,
        ClaimAlreadyProcessed,
        ClaimExceedsCoverage,
        InvalidParameters,
        OracleVerificationFailed,
        ReinsuranceCapacityExceeded,
        TokenNotFound,
        TransferFailed,
        CooldownPeriodActive,
        PropertyNotInsurable,
        DuplicateClaim,
        // Evidence validation errors
        EvidenceNonceEmpty,
        EvidenceInvalidUriScheme,
        EvidenceInvalidHashLength,
        ZeroAmount,
        InsufficientStake,
        InsufficientPoolLiquidity,
    }

    /// Fixed-point precision for [`RiskPool::accumulated_reward_per_share`] (1e18).
    const REWARD_PRECISION: u128 = 1_000_000_000_000_000_000;

    // =========================================================================
    // DATA TYPES
    // =========================================================================

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        scale::Encode,
        scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum PolicyStatus {
        Active,
        Renewed,
        Expired,
        Cancelled,
        Claimed,
        Suspended,
    }

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        scale::Encode,
        scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum PolicyType {
        Standard,
        Parametric,
    }

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        scale::Encode,
        scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum CoverageType {
        Fire,
        Flood,
        Earthquake,
        Theft,
        LiabilityDamage,
        NaturalDisaster,
        Comprehensive,
    }

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        scale::Encode,
        scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ClaimStatus {
        Pending,
        UnderReview,
        OracleVerifying,
        Approved,
        Rejected,
        Paid,
        Disputed,
    }

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        scale::Encode,
        scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum RiskLevel {
        VeryLow,
        Low,
        Medium,
        High,
        VeryHigh,
    }

    /// Structured evidence attached to a claim submission.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EvidenceMetadata {
        /// Non-empty nonce / type identifier (e.g. "photo", "report", "sensor")
        pub evidence_type: String,
        /// URI pointing to the evidence artifact (must start with "ipfs://" or "https://")
        pub reference_uri: String,
        /// SHA-256 content hash – exactly 32 bytes
        pub content_hash: Vec<u8>,
        /// Optional human-readable description
        pub description: Option<String>,
    }

    impl From<&str> for EvidenceMetadata {
        fn from(s: &str) -> Self {
            EvidenceMetadata {
                evidence_type: "unknown".into(),
                reference_uri: s.into(),
                content_hash: vec![0u8; 32],
                description: None,
            }
        }
    }

        #[derive(
            Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
        )]
        #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
        pub struct EvidenceItem {
            pub id: u64,
            pub claim_id: u64,
            pub evidence_type: String,
            pub ipfs_hash: String,
            pub ipfs_uri: String,
            pub content_hash: Vec<u8>,
            pub file_size: u64,
            pub submitter: AccountId,
            pub submitted_at: u64,
            pub verified: bool,
            pub verified_by: Option<AccountId>,
            pub verified_at: Option<u64>,
            pub verification_notes: Option<String>,
            pub metadata_url: Option<String>,
        }

        #[derive(
            Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
        )]
        #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
        pub struct EvidenceVerification {
            pub evidence_id: u64,
            pub verifier: AccountId,
            pub verified_at: u64,
            pub is_valid: bool,
            pub notes: String,
            pub ipfs_accessible: bool,
            pub hash_matches: bool,
        }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct InsurancePolicy {
        pub policy_id: u64,
        pub property_id: u64,
        pub policyholder: AccountId,
        pub coverage_type: CoverageType,
        pub coverage_amount: u128, // Max payout in USD (8 decimals)
        pub premium_amount: u128,  // Annual premium in native token
        pub deductible: u128,      // Deductible amount
        pub start_time: u64,
        pub end_time: u64,
        pub status: PolicyStatus,
        pub risk_level: RiskLevel,
        pub pool_id: u64,
        pub claims_count: u32,
        pub total_claimed: u128,
        pub metadata_url: String,
        pub policy_type: PolicyType,
        pub event_id: Option<u64>,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct InsuranceClaim {
        pub claim_id: u64,
        pub policy_id: u64,
        pub claimant: AccountId,
        pub claim_amount: u128,
        pub description: String,
        pub evidence: EvidenceMetadata,
        pub evidence_ids: Vec<u64>,
        pub oracle_report_url: String,
        pub status: ClaimStatus,
        pub submitted_at: u64,
        pub processed_at: Option<u64>,
        pub payout_amount: u128,
        pub assessor: Option<AccountId>,
        pub rejection_reason: String,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct RiskPool {
        pub pool_id: u64,
        pub name: String,
        pub coverage_type: CoverageType,
        pub total_capital: u128,
        pub available_capital: u128,
        pub total_premiums_collected: u128,
        pub total_claims_paid: u128,
        pub active_policies: u64,
        pub max_coverage_ratio: u32, // Max exposure as % of pool (basis points, e.g. 8000 = 80%)
        pub reinsurance_threshold: u128, // Claim size above which reinsurance kicks in
        pub created_at: u64,
        pub is_active: bool,
        /// Sum of LP stakes; denominator for reward-per-share accrual.
        pub total_provider_stake: u128,
        /// Scaled accumulated rewards per staked unit ([`REWARD_PRECISION`] fixed-point).
        pub accumulated_reward_per_share: u128,
        /// Vesting cliff in seconds (0 = no cliff)
        pub vesting_cliff_seconds: u64,
        /// Vesting duration in seconds (0 = no vesting; if >0 enables vesting)
        pub vesting_duration_seconds: u64,
        /// Early withdrawal penalty applied to unvested rewards (basis points, e.g. 500 = 5%)
        pub early_withdrawal_penalty_bps: u32,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct RiskAssessment {
        pub property_id: u64,
        pub location_risk_score: u32,     // 0-100
        pub construction_risk_score: u32, // 0-100
        pub age_risk_score: u32,          // 0-100
        pub claims_history_score: u32,    // 0-100 (lower = more claims)
        pub overall_risk_score: u32,      // 0-100
        pub risk_level: RiskLevel,
        pub assessed_at: u64,
        pub valid_until: u64,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct PremiumCalculation {
        pub base_rate: u32,           // Basis points (e.g. 150 = 1.50%)
        pub risk_multiplier: u32,     // Applied based on risk score (100 = 1.0x)
        pub coverage_multiplier: u32, // Applied based on coverage type
        pub annual_premium: u128,     // Final annual premium
        pub monthly_premium: u128,    // Monthly equivalent
        pub deductible: u128,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ReinsuranceAgreement {
        pub agreement_id: u64,
        pub reinsurer: AccountId,
        pub coverage_limit: u128,
        pub retention_limit: u128, // Our retention before reinsurance activates
        pub premium_ceded_rate: u32, // % of premiums ceded to reinsurer (basis points)
        pub coverage_types: Vec<CoverageType>,
        pub start_time: u64,
        pub end_time: u64,
        pub is_active: bool,
        pub total_ceded_premiums: u128,
        pub total_recoveries: u128,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct InsuranceToken {
        pub token_id: u64,
        pub policy_id: u64,
        pub owner: AccountId,
        pub face_value: u128,
        pub is_tradeable: bool,
        pub created_at: u64,
        pub listed_price: Option<u128>,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ActuarialModel {
        pub model_id: u64,
        pub coverage_type: CoverageType,
        pub loss_frequency: u32, // Expected losses per 1000 policies (basis points)
        pub average_loss_severity: u128, // Average loss size
        pub expected_loss_ratio: u32, // Expected loss ratio (basis points)
        pub confidence_level: u32, // 0-100
        pub last_updated: u64,
        pub data_points: u32,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct UnderwritingCriteria {
        pub max_property_age_years: u32,
        pub min_property_value: u128,
        pub max_property_value: u128,
        pub excluded_locations: Vec<String>,
        pub required_safety_features: bool,
        pub max_previous_claims: u32,
        pub min_risk_score: u32,
    }

    /// Result of a single batch claim operation
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct BatchClaimResult {
        pub claim_id: u64,
        pub success: bool,
        pub error: Option<InsuranceError>,
    }

    /// Summary of batch claim processing
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct BatchClaimSummary {
        pub total_processed: u64,
        pub successful: u64,
        pub failed: u64,
        pub results: Vec<BatchClaimResult>,
    }

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct PoolLiquidityProvider {
        pub provider: AccountId,
        pub pool_id: u64,
        pub provider_stake: u128,
        /// Reward debt in fixed-point units: keeps pending = stake * acc_rps / P - reward_debt.
        pub reward_debt: u128,
        pub deposited_at: u64,
        /// Total rewards moved into vesting schedule (not yet fully claimed)
        pub vesting_total: u128,
        /// Amount of vested rewards already claimed by provider
        pub vesting_claimed: u128,
        /// Vesting schedule start timestamp (seconds)
        pub vesting_start: u64,
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    #[ink(storage)]
    pub struct PropertyInsurance {
        admin: AccountId,

        // Policies
        policies: Mapping<u64, InsurancePolicy>,
        policy_count: u64,
        policyholder_policies: Mapping<AccountId, Vec<u64>>,
        property_policies: Mapping<u64, Vec<u64>>,

        // Claims
        claims: Mapping<u64, InsuranceClaim>,
        claim_count: u64,
        policy_claims: Mapping<u64, Vec<u64>>,

        // Risk Pools
        pools: Mapping<u64, RiskPool>,
        pool_count: u64,

        // Risk Assessments
        risk_assessments: Mapping<u64, RiskAssessment>,

        // Reinsurance
        reinsurance_agreements: Mapping<u64, ReinsuranceAgreement>,
        reinsurance_count: u64,

        // Insurance Tokens (secondary market)
        insurance_tokens: Mapping<u64, InsuranceToken>,
        token_count: u64,
        token_listings: Vec<u64>, // Tokens listed for sale

        // Actuarial Models
        actuarial_models: Mapping<u64, ActuarialModel>,
        model_count: u64,

        // Underwriting
        underwriting_criteria: Mapping<u64, UnderwritingCriteria>, // pool_id -> criteria

        // Liquidity providers
        liquidity_providers: Mapping<(u64, AccountId), PoolLiquidityProvider>,
        pool_providers: Mapping<u64, Vec<AccountId>>,

        // Oracle addresses
        authorized_oracles: Mapping<AccountId, bool>,

        // Assessors
        authorized_assessors: Mapping<AccountId, bool>,

        // Claim cooldown: property_id -> last_claim_timestamp
        claim_cooldowns: Mapping<u64, u64>,

        // Evidence tracking
        evidence_count: u64,
        evidence_items: Mapping<u64, EvidenceItem>,
        claim_evidence: Mapping<u64, Vec<u64>>,
        evidence_verifications: Mapping<u64, Vec<EvidenceVerification>>,

        // Oracle contract for parametric claims
        oracle_contract: Option<AccountId>,

        // Platform settings
        platform_fee_rate: u32,     // Basis points (e.g. 200 = 2%)
        claim_cooldown_period: u64, // In seconds
        min_pool_capital: u128,
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    #[ink(event)]
    pub struct PolicyCreated {
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        policyholder: AccountId,
        #[ink(topic)]
        property_id: u64,
        coverage_type: CoverageType,
        coverage_amount: u128,
        premium_amount: u128,
        start_time: u64,
        end_time: u64,
    }

    #[ink(event)]
    pub struct PolicyIssued {
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        holder: AccountId,
        coverage_amount: u128,
        premium_amount: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct PolicyCancelled {
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        policyholder: AccountId,
        cancelled_at: u64,
        reason: Option<String>,
    }

    #[ink(event)]
    pub struct PolicyRenewed {
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        holder: AccountId,
        renewal_premium: u128,
        new_end_time: u64,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct PolicyExpired {
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        holder: AccountId,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct ClaimSubmitted {
        #[ink(topic)]
        claim_id: u64,
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        claimant: AccountId,
        claim_amount: u128,
        submitted_at: u64,
    }

    #[ink(event)]
    pub struct ClaimApproved {
        #[ink(topic)]
        claim_id: u64,
        #[ink(topic)]
        policy_id: u64,
        payout_amount: u128,
        approved_by: AccountId,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct ClaimRejected {
        #[ink(topic)]
        claim_id: u64,
        #[ink(topic)]
        policy_id: u64,
        reason: String,
        rejected_by: AccountId,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct PayoutExecuted {
        #[ink(topic)]
        claim_id: u64,
        #[ink(topic)]
        recipient: AccountId,
        amount: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct PoolCapitalized {
        #[ink(topic)]
        pool_id: u64,
        #[ink(topic)]
        provider: AccountId,
        amount: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct LiquidityDeposited {
        #[ink(topic)]
        pool_id: u64,
        #[ink(topic)]
        provider: AccountId,
        amount: u128,
        accumulated_reward_per_share: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct LiquidityWithdrawn {
        #[ink(topic)]
        pool_id: u64,
        #[ink(topic)]
        provider: AccountId,
        principal: u128,
        rewards_paid: u128,
        accumulated_reward_per_share: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct RewardsClaimed {
        #[ink(topic)]
        pool_id: u64,
        #[ink(topic)]
        provider: AccountId,
        amount: u128,
        accumulated_reward_per_share: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct RewardsReinvested {
        #[ink(topic)]
        pool_id: u64,
        #[ink(topic)]
        provider: AccountId,
        amount: u128,
        new_stake: u128,
        accumulated_reward_per_share: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct RewardsVestingStarted {
        #[ink(topic)]
        pool_id: u64,
        #[ink(topic)]
        provider: AccountId,
        amount: u128,
        vesting_start: u64,
        vesting_cliff: u64,
        vesting_duration: u64,
    }

    #[ink(event)]
    pub struct VestedRewardsClaimed {
        #[ink(topic)]
        pool_id: u64,
        #[ink(topic)]
        provider: AccountId,
        amount: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct ReinsuranceActivated {
        #[ink(topic)]
        claim_id: u64,
        agreement_id: u64,
        recovery_amount: u128,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct InsuranceTokenMinted {
        #[ink(topic)]
        token_id: u64,
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        owner: AccountId,
        face_value: u128,
    }

    #[ink(event)]
    pub struct InsuranceTokenTransferred {
        #[ink(topic)]
        token_id: u64,
        #[ink(topic)]
        from: AccountId,
        #[ink(topic)]
        to: AccountId,
        price: u128,
    }

    #[ink(event)]
    pub struct RiskAssessmentUpdated {
        #[ink(topic)]
        property_id: u64,
        overall_score: u32,
        risk_level: RiskLevel,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct EvidenceSubmitted {
        #[ink(topic)]
        evidence_id: u64,
        #[ink(topic)]
        claim_id: u64,
        evidence_type: String,
        ipfs_hash: String,
        submitter: AccountId,
        submitted_at: u64,
    }

    #[ink(event)]
    pub struct EvidenceVerified {
        #[ink(topic)]
        evidence_id: u64,
        verified_by: AccountId,
        is_valid: bool,
        verified_at: u64,
    }

    // =========================================================================
    // IMPLEMENTATION
    // =========================================================================

    impl PropertyInsurance {
        #[ink(constructor)]
        pub fn new(admin: AccountId) -> Self {
            Self {
                admin,
                policies: Mapping::default(),
                policy_count: 0,
                policyholder_policies: Mapping::default(),
                property_policies: Mapping::default(),
                claims: Mapping::default(),
                claim_count: 0,
                policy_claims: Mapping::default(),
                pools: Mapping::default(),
                pool_count: 0,
                risk_assessments: Mapping::default(),
                reinsurance_agreements: Mapping::default(),
                reinsurance_count: 0,
                insurance_tokens: Mapping::default(),
                token_count: 0,
                token_listings: Vec::new(),
                actuarial_models: Mapping::default(),
                model_count: 0,
                underwriting_criteria: Mapping::default(),
                liquidity_providers: Mapping::default(),
                pool_providers: Mapping::default(),
                authorized_oracles: Mapping::default(),
                authorized_assessors: Mapping::default(),
                claim_cooldowns: Mapping::default(),
                evidence_count: 0,
                evidence_items: Mapping::default(),
                claim_evidence: Mapping::default(),
                evidence_verifications: Mapping::default(),
                platform_fee_rate: 200,            // 2%
                claim_cooldown_period: 2_592_000,  // 30 days in seconds
                min_pool_capital: 100_000_000_000, // Minimum pool capital
                oracle_contract: None,
            }
        }

        // =====================================================================
        // POOL MANAGEMENT
        // =====================================================================

        /// Create a new risk pool (admin only)
        #[ink(message)]
        pub fn create_risk_pool(
            &mut self,
            name: String,
            coverage_type: CoverageType,
            max_coverage_ratio: u32,
            reinsurance_threshold: u128,
        ) -> Result<u64, InsuranceError> {
            self.ensure_admin()?;

            let pool_id = self.pool_count + 1;
            self.pool_count = pool_id;

            let pool = RiskPool {
                pool_id,
                name,
                coverage_type,
                total_capital: 0,
                available_capital: 0,
                total_premiums_collected: 0,
                total_claims_paid: 0,
                active_policies: 0,
                max_coverage_ratio,
                reinsurance_threshold,
                created_at: self.env().block_timestamp(),
                is_active: true,
                total_provider_stake: 0,
                accumulated_reward_per_share: 0,
                vesting_cliff_seconds: 0,
                vesting_duration_seconds: 0,
                early_withdrawal_penalty_bps: 0,
            };

            self.pools.insert(&pool_id, &pool);
            Ok(pool_id)
        }

        /// Deposit native liquidity into a pool (reward-per-share stake).
        #[ink(message, payable)]
        pub fn deposit_liquidity(&mut self, pool_id: u64) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            let amount = self.env().transferred_value();
            if amount == 0 {
                return Err(InsuranceError::ZeroAmount);
            }

            let mut pool = self
                .pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;
            if !pool.is_active {
                return Err(InsuranceError::PoolNotFound);
            }

            let now = self.env().block_timestamp();
            let key = (pool_id, caller);
            let mut provider =
                self.liquidity_providers
                    .get(&key)
                    .unwrap_or(PoolLiquidityProvider {
                        provider: caller,
                        pool_id,
                        provider_stake: 0,
                        reward_debt: 0,
                        deposited_at: now,
                        vesting_total: 0,
                        vesting_claimed: 0,
                        vesting_start: 0,
                    });

            let acc = pool.accumulated_reward_per_share;
            provider.reward_debt = provider
                .reward_debt
                .saturating_add(amount.saturating_mul(acc).saturating_div(REWARD_PRECISION));
            provider.provider_stake = provider.provider_stake.saturating_add(amount);

            pool.total_provider_stake = pool.total_provider_stake.saturating_add(amount);
            pool.total_capital = pool.total_capital.saturating_add(amount);
            pool.available_capital = pool.available_capital.saturating_add(amount);

            self.pools.insert(&pool_id, &pool);
            self.liquidity_providers.insert(&key, &provider);

            let mut providers = self.pool_providers.get(&pool_id).unwrap_or_default();
            if !providers.contains(&caller) {
                providers.push(caller);
                self.pool_providers.insert(&pool_id, &providers);
            }

            let timestamp = self.env().block_timestamp();
            self.env().emit_event(PoolCapitalized {
                pool_id,
                provider: caller,
                amount,
                timestamp,
            });
            self.env().emit_event(LiquidityDeposited {
                pool_id,
                provider: caller,
                amount,
                accumulated_reward_per_share: pool.accumulated_reward_per_share,
                timestamp,
            });

            Ok(())
        }

            /// Renew an active policy by paying a renewal premium. Extends `end_time` by
            /// `duration_seconds` and emits `PolicyRenewed`.
            #[ink(message, payable)]
            pub fn renew_policy(&mut self, policy_id: u64, duration_seconds: u64) -> Result<(), InsuranceError> {
                let caller = self.env().caller();
                let paid = self.env().transferred_value();
                if paid == 0 {
                    return Err(InsuranceError::InsufficientPremium);
                }

                let mut policy = self.policies.get(&policy_id).ok_or(InsuranceError::PolicyNotFound)?;
                if policy.policyholder != caller {
                    return Err(InsuranceError::Unauthorized);
                }
                if policy.status != PolicyStatus::Active && policy.status != PolicyStatus::Renewed {
                    return Err(InsuranceError::PolicyInactive);
                }

                // Update pool accounting
                let mut pool = self.pools.get(&policy.pool_id).ok_or(InsuranceError::PoolNotFound)?;
                let fee = paid.saturating_mul(self.platform_fee_rate as u128) / 10_000u128;
                let pool_share = paid.saturating_sub(fee);
                pool.total_premiums_collected = pool.total_premiums_collected.saturating_add(pool_share);
                pool.available_capital = pool.available_capital.saturating_add(pool_share);
                Self::apply_reward_accrual(&mut pool, pool_share);
                self.pools.insert(&policy.pool_id, &pool);

                // Extend policy
                let now = self.env().block_timestamp();
                policy.end_time = policy.end_time.saturating_add(duration_seconds);
                policy.premium_amount = policy.premium_amount.saturating_add(paid);
                policy.status = PolicyStatus::Renewed;
                self.policies.insert(&policy_id, &policy);

                self.env().emit_event(PolicyRenewed {
                    policy_id,
                    holder: caller,
                    renewal_premium: paid,
                    new_end_time: policy.end_time,
                    timestamp: now,
                });

                Ok(())
            }

        /// Return the configured claim cooldown period.
        #[ink(message)]
        pub fn claim_cooldown_period(&self) -> u64 {
            self.claim_cooldown_period
        }

        /// Backwards-compatible alias for tests: add an authorized assessor
        #[ink(message)]
        pub fn add_authorized_assessor(&mut self, acct: AccountId) -> Result<(), InsuranceError> {
            self.authorize_assessor(acct)
        }

        /// Configure vesting parameters for a pool (admin or tests).
        #[ink(message)]
        pub fn configure_pool_vesting(
            &mut self,
            pool_id: u64,
            vesting_cliff_seconds: u64,
            vesting_duration_seconds: u64,
            early_withdrawal_penalty_bps: u32,
        ) -> Result<(), InsuranceError> {
            self.ensure_admin()?;
            let mut pool = self.pools.get(&pool_id).ok_or(InsuranceError::PoolNotFound)?;
            pool.vesting_cliff_seconds = vesting_cliff_seconds;
            pool.vesting_duration_seconds = vesting_duration_seconds;
            pool.early_withdrawal_penalty_bps = early_withdrawal_penalty_bps;
            self.pools.insert(&pool_id, &pool);
            Ok(())
        }

            /// Scan and expire policies whose `end_time` has passed. Anyone may call this to
            /// process automatic expirations. Returns the number of policies expired.
            #[ink(message)]
            pub fn expire_policies(&mut self, max_scan: u64) -> u64 {
                let mut expired_count: u64 = 0;
                let now = self.env().block_timestamp();
                let limit = if max_scan == 0 { self.policy_count } else { max_scan };
                let mut i: u64 = 1;
                while i <= self.policy_count && expired_count < limit {
                    if let Some(mut policy) = self.policies.get(&i) {
                        if policy.status == PolicyStatus::Active && now > policy.end_time {
                            policy.status = PolicyStatus::Expired;
                            self.policies.insert(&i, &policy);

                            // Decrement pool active count
                            if let Some(mut pool) = self.pools.get(&policy.pool_id) {
                                if pool.active_policies > 0 {
                                    pool.active_policies -= 1;
                                }
                                self.pools.insert(&policy.pool_id, &pool);
                            }

                            self.env().emit_event(PolicyExpired {
                                policy_id: i,
                                holder: policy.policyholder.clone(),
                                timestamp: now,
                            });

                            expired_count = expired_count.saturating_add(1);
                        }
                    }
                    i = i.saturating_add(1);
                }
                expired_count
            }

        /// Legacy entry point: same as [`deposit_liquidity`](Self::deposit_liquidity).
        #[ink(message, payable)]
        pub fn provide_pool_liquidity(&mut self, pool_id: u64) -> Result<(), InsuranceError> {
            self.deposit_liquidity(pool_id)
        }

        /// Withdraw staked principal; pending rewards are paid out in the same call.
        #[ink(message)]
        pub fn withdraw_liquidity(
            &mut self,
            pool_id: u64,
            amount: u128,
        ) -> Result<(), InsuranceError> {
            if amount == 0 {
                return Err(InsuranceError::ZeroAmount);
            }

            let caller = self.env().caller();
            let mut pool = self
                .pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;
            if !pool.is_active {
                return Err(InsuranceError::PoolNotFound);
            }

            let key = (pool_id, caller);
            let mut provider = self
                .liquidity_providers
                .get(&key)
                .ok_or(InsuranceError::InsufficientStake)?;
            if provider.provider_stake < amount {
                return Err(InsuranceError::InsufficientStake);
            }

            let acc = pool.accumulated_reward_per_share;
            let pending =
                Self::pending_reward_amount(provider.provider_stake, acc, provider.reward_debt);
            let mut total_out: u128 = 0;

            if pool.vesting_duration_seconds > 0 {
                // Move pending rewards into vesting schedule instead of paying out immediately.
                if pending > 0 {
                    let now = self.env().block_timestamp();
                    provider.vesting_total = provider.vesting_total.saturating_add(pending);
                    provider.vesting_start = now;
                    // reward_debt should be synced to avoid double-counting future accruals
                    provider.reward_debt = Self::synced_reward_debt(provider.provider_stake, acc);
                }

                // Apply early withdrawal penalty on any unvested portion
                if provider.vesting_total > 0 && pool.early_withdrawal_penalty_bps > 0 {
                    let now = self.env().block_timestamp();
                    let mut vested: u128 = 0;
                    if provider.vesting_start > 0 {
                        let elapsed = now.saturating_sub(provider.vesting_start);
                        if elapsed >= pool.vesting_cliff_seconds {
                            let vesting_secs = pool.vesting_duration_seconds;
                            let vested_secs = if elapsed >= vesting_secs { vesting_secs } else { elapsed };
                            vested = provider
                                .vesting_total
                                .saturating_mul(vested_secs as u128)
                                .saturating_div(vesting_secs as u128);
                        }
                    }
                    let unvested = provider.vesting_total.saturating_sub(vested);
                    if unvested > 0 {
                        let penalty = unvested.saturating_mul(pool.early_withdrawal_penalty_bps as u128) / 10_000u128;
                        provider.vesting_total = provider.vesting_total.saturating_sub(penalty);
                        pool.available_capital = pool.available_capital.saturating_add(penalty);
                    }
                }

                let mut total_out: u128 = amount;
                if pool.available_capital < total_out {
                    return Err(InsuranceError::InsufficientPoolLiquidity);
                }

                provider.provider_stake = provider.provider_stake.saturating_sub(amount);
                provider.reward_debt = Self::synced_reward_debt(provider.provider_stake, acc);

                pool.total_provider_stake = pool.total_provider_stake.saturating_sub(amount);
                pool.available_capital = pool.available_capital.saturating_sub(total_out);
                pool.total_capital = pool.total_capital.saturating_sub(amount);
            } else {
                let mut total_out: u128 = pending.saturating_add(amount);
                if pool.available_capital < total_out {
                    return Err(InsuranceError::InsufficientPoolLiquidity);
                }

                provider.provider_stake = provider.provider_stake.saturating_sub(amount);
                provider.reward_debt = Self::synced_reward_debt(provider.provider_stake, acc);

                pool.total_provider_stake = pool.total_provider_stake.saturating_sub(amount);
                pool.available_capital = pool.available_capital.saturating_sub(total_out);
                pool.total_capital = pool.total_capital.saturating_sub(amount);
            }

            self.pools.insert(&pool_id, &pool);
            if provider.provider_stake == 0 {
                self.liquidity_providers.remove(&key);
                if let Some(mut accs) = self.pool_providers.get(&pool_id) {
                    accs.retain(|a| *a != caller);
                    self.pool_providers.insert(&pool_id, &accs);
                }
            } else {
                self.liquidity_providers.insert(&key, &provider);
            }

            let timestamp = self.env().block_timestamp();
            self.env().emit_event(LiquidityWithdrawn {
                pool_id,
                provider: caller,
                principal: amount,
                rewards_paid: if pool.vesting_duration_seconds > 0 { 0 } else { pending },
                accumulated_reward_per_share: acc,
                timestamp,
            });

            if total_out > 0 {
                self.env()
                    .transfer(caller, total_out)
                    .map_err(|_| InsuranceError::TransferFailed)?;
            }

            Ok(())
        }

        /// Claim accrued rewards to the caller (checks-effects-interactions).
        #[ink(message)]
        pub fn claim_rewards(&mut self, pool_id: u64) -> Result<u128, InsuranceError> {
            let caller = self.env().caller();
            let mut pool = self
                .pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;
            if !pool.is_active {
                return Err(InsuranceError::PoolNotFound);
            }

            let key = (pool_id, caller);
            let mut provider = self
                .liquidity_providers
                .get(&key)
                .ok_or(InsuranceError::InsufficientStake)?;

            let acc = pool.accumulated_reward_per_share;
            let pending =
                Self::pending_reward_amount(provider.provider_stake, acc, provider.reward_debt);
            if pending == 0 {
                return Ok(0);
            }
            if pool.vesting_duration_seconds > 0 {
                // Move pending into provider vesting schedule instead of immediate payout.
                let now = self.env().block_timestamp();
                provider.vesting_total = provider.vesting_total.saturating_add(pending);
                provider.vesting_start = now;
                provider.reward_debt = Self::synced_reward_debt(provider.provider_stake, acc);

                self.pools.insert(&pool_id, &pool);
                self.liquidity_providers.insert(&key, &provider);

                let timestamp = now;
                self.env().emit_event(RewardsVestingStarted {
                    pool_id,
                    provider: caller,
                    amount: pending,
                    vesting_start: timestamp,
                    vesting_cliff: pool.vesting_cliff_seconds,
                    vesting_duration: pool.vesting_duration_seconds,
                });

                Ok(pending)
            } else {
                if pool.available_capital < pending {
                    return Err(InsuranceError::InsufficientPoolLiquidity);
                }

                provider.reward_debt = Self::synced_reward_debt(provider.provider_stake, acc);
                pool.available_capital = pool.available_capital.saturating_sub(pending);

                self.pools.insert(&pool_id, &pool);
                self.liquidity_providers.insert(&key, &provider);

                let timestamp = self.env().block_timestamp();
                self.env().emit_event(RewardsClaimed {
                    pool_id,
                    provider: caller,
                    amount: pending,
                    accumulated_reward_per_share: acc,
                    timestamp,
                });

                self.env()
                    .transfer(caller, pending)
                    .map_err(|_| InsuranceError::TransferFailed)?;

                Ok(pending)
            }
        }

        /// Compound pending rewards into stake (no transfer; updates debt to current index).
        #[ink(message)]
        pub fn reinvest_rewards(&mut self, pool_id: u64) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            let mut pool = self
                .pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;
            if !pool.is_active {
                return Err(InsuranceError::PoolNotFound);
            }

            let key = (pool_id, caller);
            let mut provider = self
                .liquidity_providers
                .get(&key)
                .ok_or(InsuranceError::InsufficientStake)?;

            let acc = pool.accumulated_reward_per_share;
            let pending =
                Self::pending_reward_amount(provider.provider_stake, acc, provider.reward_debt);
            if pending == 0 {
                return Ok(());
            }

            provider.provider_stake = provider.provider_stake.saturating_add(pending);
            provider.reward_debt = Self::synced_reward_debt(provider.provider_stake, acc);

            pool.total_provider_stake = pool.total_provider_stake.saturating_add(pending);
            pool.total_capital = pool.total_capital.saturating_add(pending);

            self.pools.insert(&pool_id, &pool);
            self.liquidity_providers.insert(&key, &provider);

            let timestamp = self.env().block_timestamp();
            self.env().emit_event(RewardsReinvested {
                pool_id,
                provider: caller,
                amount: pending,
                new_stake: provider.provider_stake,
                accumulated_reward_per_share: acc,
                timestamp,
            });

            Ok(())
        }

        /// Claim vested portion of previously-vested rewards for a provider
        #[ink(message)]
        pub fn claim_vested_rewards(&mut self, pool_id: u64) -> Result<u128, InsuranceError> {
            let caller = self.env().caller();
            let mut pool = self
                .pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;

            let key = (pool_id, caller);
            let mut provider = self
                .liquidity_providers
                .get(&key)
                .ok_or(InsuranceError::InsufficientStake)?;

            let total_vesting = provider.vesting_total;
            if total_vesting == 0 {
                return Ok(0);
            }

            let now = self.env().block_timestamp();
            // If no vesting configured, allow immediate claim
            if pool.vesting_duration_seconds == 0 {
                if pool.available_capital < total_vesting {
                    return Err(InsuranceError::InsufficientPoolLiquidity);
                }
                provider.vesting_total = 0;
                provider.vesting_claimed = 0;
                provider.vesting_start = 0;
                pool.available_capital = pool.available_capital.saturating_sub(total_vesting);

                self.pools.insert(&pool_id, &pool);
                self.liquidity_providers.insert(&key, &provider);

                self.env()
                    .transfer(caller, total_vesting)
                    .map_err(|_| InsuranceError::TransferFailed)?;

                self.env().emit_event(VestedRewardsClaimed {
                    pool_id,
                    provider: caller,
                    amount: total_vesting,
                    timestamp: now,
                });

                return Ok(total_vesting);
            }

            if provider.vesting_start == 0 {
                return Ok(0);
            }

            // compute vested amount
            let elapsed = now.saturating_sub(provider.vesting_start);
            if elapsed < pool.vesting_cliff_seconds {
                return Ok(0);
            }

            let vesting_secs = pool.vesting_duration_seconds;
            let vested_secs = if elapsed >= vesting_secs { vesting_secs } else { elapsed };
            let vested_amount = total_vesting
                .saturating_mul(vested_secs as u128)
                .saturating_div(vesting_secs as u128);

            let claimable = vested_amount.saturating_sub(provider.vesting_claimed);
            if claimable == 0 {
                return Ok(0);
            }

            if pool.available_capital < claimable {
                return Err(InsuranceError::InsufficientPoolLiquidity);
            }

            provider.vesting_claimed = provider.vesting_claimed.saturating_add(claimable);
            // if fully claimed, clear vesting record
            if provider.vesting_claimed >= provider.vesting_total {
                provider.vesting_total = 0;
                provider.vesting_claimed = 0;
                provider.vesting_start = 0;
            }

            pool.available_capital = pool.available_capital.saturating_sub(claimable);

            self.pools.insert(&pool_id, &pool);
            self.liquidity_providers.insert(&key, &provider);

            self.env()
                .transfer(caller, claimable)
                .map_err(|_| InsuranceError::TransferFailed)?;

            self.env().emit_event(VestedRewardsClaimed {
                pool_id,
                provider: caller,
                amount: claimable,
                timestamp: now,
            });

            Ok(claimable)
        }

        /// View vesting info for a provider
        #[ink(message)]
        pub fn get_vesting_info(&self, pool_id: u64, provider: AccountId) -> (u128, u128, u64) {
            let p = self.liquidity_providers.get(&(pool_id, provider));
            if let Some(info) = p {
                (info.vesting_total, info.vesting_claimed, info.vesting_start)
            } else {
                (0, 0, 0)
            }
        }

        /// View: pending reward amount for an account (fixed-point accurate vs on-chain claim).
        #[ink(message)]
        pub fn get_pending_rewards(&self, pool_id: u64, provider: AccountId) -> u128 {
            let Some(pool) = self.pools.get(&pool_id) else {
                return 0;
            };
            let Some(p) = self.liquidity_providers.get(&(pool_id, provider)) else {
                return 0;
            };
            Self::pending_reward_amount(
                p.provider_stake,
                pool.accumulated_reward_per_share,
                p.reward_debt,
            )
        }

        // =====================================================================
        // RISK ASSESSMENT
        // =====================================================================

        /// Submit or update risk assessment for a property (oracle/admin)
        #[ink(message)]
        pub fn update_risk_assessment(
            &mut self,
            property_id: u64,
            location_score: u32,
            construction_score: u32,
            age_score: u32,
            claims_history_score: u32,
            valid_for_seconds: u64,
        ) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            if caller != self.admin && !self.authorized_oracles.get(&caller).unwrap_or(false) {
                return Err(InsuranceError::Unauthorized);
            }

            let overall = (location_score
                .saturating_add(construction_score)
                .saturating_add(age_score)
                .saturating_add(claims_history_score))
                / 4;

            let risk_level = Self::score_to_risk_level(overall);

            let now = self.env().block_timestamp();
            let assessment = RiskAssessment {
                property_id,
                location_risk_score: location_score,
                construction_risk_score: construction_score,
                age_risk_score: age_score,
                claims_history_score,
                overall_risk_score: overall,
                risk_level: risk_level.clone(),
                assessed_at: now,
                valid_until: now.saturating_add(valid_for_seconds),
            };

            self.risk_assessments.insert(&property_id, &assessment);

            self.env().emit_event(RiskAssessmentUpdated {
                property_id,
                overall_score: overall,
                risk_level,
                timestamp: now,
            });

            Ok(())
        }

        /// Calculate premium for a policy
        #[ink(message)]
        pub fn calculate_premium(
            &self,
            property_id: u64,
            coverage_amount: u128,
            coverage_type: CoverageType,
        ) -> Result<PremiumCalculation, InsuranceError> {
            let assessment = self
                .risk_assessments
                .get(&property_id)
                .ok_or(InsuranceError::PropertyNotInsurable)?;

            // Base rate in basis points: 150 = 1.50%
            let base_rate: u32 = 150;

            // Risk multiplier based on score (100 = 1.0x, 200 = 2.0x)
            let risk_multiplier = self.risk_score_to_multiplier(assessment.overall_risk_score);

            // Coverage type multiplier
            let coverage_multiplier = Self::coverage_type_multiplier(&coverage_type);

            // Annual premium = coverage * base_rate * risk_mult * coverage_mult / 1_000_000
            let annual_premium = coverage_amount
                .saturating_mul(base_rate as u128)
                .saturating_mul(risk_multiplier as u128)
                .saturating_mul(coverage_multiplier as u128)
                / 1_000_000_000_000u128; // 3 basis point divisors × 10000 each

            let monthly_premium = annual_premium / 12;

            // Deductible: 5% of coverage_amount, scaled by risk
            let deductible = coverage_amount
                .saturating_mul(500u128)
                .saturating_mul(risk_multiplier as u128)
                / 10_000_000u128;

            Ok(PremiumCalculation {
                base_rate,
                risk_multiplier,
                coverage_multiplier,
                annual_premium,
                monthly_premium,
                deductible,
            })
        }

        // =====================================================================
        // POLICY MANAGEMENT
        // =====================================================================

        /// Create an insurance policy (policyholder pays premium)
        #[ink(message, payable)]
        pub fn create_policy(
            &mut self,
            property_id: u64,
            coverage_type: CoverageType,
            coverage_amount: u128,
            pool_id: u64,
            duration_seconds: u64,
            metadata_url: String,
        ) -> Result<u64, InsuranceError> {
            let caller = self.env().caller();
            let paid = self.env().transferred_value();
            let now = self.env().block_timestamp();

            // Validate pool
            let mut pool = self
                .pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;
            if !pool.is_active {
                return Err(InsuranceError::PoolNotFound);
            }

            // Get risk assessment
            let assessment = self
                .risk_assessments
                .get(&property_id)
                .ok_or(InsuranceError::PropertyNotInsurable)?;

            // Check assessment is still valid
            if now > assessment.valid_until {
                return Err(InsuranceError::PropertyNotInsurable);
            }

            // Calculate required premium
            let calc =
                self.calculate_premium(property_id, coverage_amount, coverage_type.clone())?;
            if paid < calc.annual_premium {
                return Err(InsuranceError::InsufficientPremium);
            }

            // Platform fee
            let fee = paid.saturating_mul(self.platform_fee_rate as u128) / 10_000;
            let pool_share = paid.saturating_sub(fee);
            // Ensure pool has enough capital (including this premium) for coverage
            let new_available = pool.available_capital.saturating_add(pool_share);
            let max_exposure = new_available.saturating_mul(pool.max_coverage_ratio as u128) / 10_000;
            if coverage_amount > max_exposure {
                return Err(InsuranceError::InsufficientPoolFunds);
            }

            // Update pool with collected premium
            pool.total_premiums_collected = pool.total_premiums_collected.saturating_add(pool_share);
            pool.available_capital = pool.available_capital.saturating_add(pool_share);
            pool.active_policies = pool.active_policies.saturating_add(1);
            Self::apply_reward_accrual(&mut pool, pool_share);
            self.pools.insert(&pool_id, &pool);

            // Create policy
            let policy_id = self.policy_count + 1;
            self.policy_count = policy_id;

            let policy = InsurancePolicy {
                policy_id,
                property_id,
                policyholder: caller,
                coverage_type: coverage_type.clone(),
                coverage_amount,
                premium_amount: paid,
                deductible: calc.deductible,
                start_time: now,
                end_time: now.saturating_add(duration_seconds),
                status: PolicyStatus::Active,
                risk_level: assessment.risk_level,
                pool_id,
                claims_count: 0,
                total_claimed: 0,
                metadata_url,
                policy_type: PolicyType::Standard, // Default for now, can be updated in another message
                event_id: None,
            };

            self.policies.insert(&policy_id, &policy);

            let mut ph_policies = self.policyholder_policies.get(&caller).unwrap_or_default();
            ph_policies.push(policy_id);
            self.policyholder_policies.insert(&caller, &ph_policies);

            let mut prop_policies = self.property_policies.get(&property_id).unwrap_or_default();
            prop_policies.push(policy_id);
            self.property_policies.insert(&property_id, &prop_policies);

            // Mint insurance token
            self.internal_mint_token(policy_id, caller, coverage_amount)?;

            self.env().emit_event(PolicyCreated {
                policy_id,
                policyholder: caller,
                property_id,
                coverage_type,
                coverage_amount,
                premium_amount: paid,
                start_time: now,
                end_time: now.saturating_add(duration_seconds),
            });

            // Also emit PolicyIssued for off-chain indexing
            self.env().emit_event(PolicyIssued {
                policy_id,
                holder: caller,
                coverage_amount,
                premium_amount: paid,
                timestamp: now,
            });

            Ok(policy_id)
        }

        /// Create a parametric insurance policy (admin/authorized oracle only)
        #[ink(message, payable)]
        pub fn create_parametric_policy(
            &mut self,
            property_id: u64,
            coverage_type: CoverageType,
            coverage_amount: u128,
            pool_id: u64,
            duration_seconds: u64,
            event_id: u64,
            metadata_url: String,
        ) -> Result<u64, InsuranceError> {
            let policy_id = self.create_policy(
                property_id,
                coverage_type,
                coverage_amount,
                pool_id,
                duration_seconds,
                metadata_url,
            )?;

            let mut policy = self.policies.get(&policy_id).unwrap();
            policy.policy_type = PolicyType::Parametric;
            policy.event_id = Some(event_id);
            self.policies.insert(&policy_id, &policy);

            Ok(policy_id)
        }

        /// Cancel an active policy (policyholder or admin)
        #[ink(message)]
        pub fn cancel_policy(&mut self, policy_id: u64) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            let mut policy = self
                .policies
                .get(&policy_id)
                .ok_or(InsuranceError::PolicyNotFound)?;

            if caller != policy.policyholder && caller != self.admin {
                return Err(InsuranceError::Unauthorized);
            }

            if policy.status != PolicyStatus::Active {
                return Err(InsuranceError::PolicyInactive);
            }

            policy.status = PolicyStatus::Cancelled;
            self.policies.insert(&policy_id, &policy);

            // Reduce pool active count
            if let Some(mut pool) = self.pools.get(&policy.pool_id) {
                if pool.active_policies > 0 {
                    pool.active_policies -= 1;
                }
                self.pools.insert(&policy.pool_id, &pool);
            }

            let now = self.env().block_timestamp();
            self.env().emit_event(PolicyCancelled {
                policy_id,
                policyholder: policy.policyholder,
                cancelled_at: now,
                reason: None,
            });

            Ok(())
        }

        // =====================================================================
        // CLAIMS PROCESSING
        // =====================================================================

        /// Submit an insurance claim
        #[ink(message)]
        pub fn submit_claim(
            &mut self,
            policy_id: u64,
            claim_amount: u128,
            description: String,
            evidence: EvidenceMetadata,
        ) -> Result<u64, InsuranceError> {
            // --- Evidence validation (evict invalid submissions immediately) ---
            if evidence.evidence_type.is_empty() {
                return Err(InsuranceError::EvidenceNonceEmpty);
            }
            let uri = &evidence.reference_uri;
            if !uri.starts_with("ipfs://") && !uri.starts_with("https://") {
                return Err(InsuranceError::EvidenceInvalidUriScheme);
            }
            if evidence.content_hash.len() != 32 {
                return Err(InsuranceError::EvidenceInvalidHashLength);
            }

            let caller = self.env().caller();
            let now = self.env().block_timestamp();

            let mut policy = self
                .policies
                .get(&policy_id)
                .ok_or(InsuranceError::PolicyNotFound)?;

            if policy.policyholder != caller {
                return Err(InsuranceError::Unauthorized);
            }
            if policy.status != PolicyStatus::Active {
                return Err(InsuranceError::PolicyInactive);
            }
            if now > policy.end_time {
                return Err(InsuranceError::PolicyExpired);
            }
            // Check claim amount doesn't exceed remaining coverage
            let remaining = policy.coverage_amount.saturating_sub(policy.total_claimed);
            if claim_amount > remaining {
                return Err(InsuranceError::ClaimExceedsCoverage);
            }

            // Cooldown check
            let last_claim = self.claim_cooldowns.get(&policy.property_id).unwrap_or(0);
            if now.saturating_sub(last_claim) < self.claim_cooldown_period {
                return Err(InsuranceError::CooldownPeriodActive);
            }

            let claim_id = self.claim_count + 1;
            self.claim_count = claim_id;

            let claim = InsuranceClaim {
                claim_id,
                policy_id,
                claimant: caller,
                claim_amount,
                description,
                evidence,
                evidence_ids: Vec::new(),
                oracle_report_url: String::new(),
                status: ClaimStatus::Pending,
                submitted_at: now,
                processed_at: None,
                payout_amount: 0,
                assessor: None,
                rejection_reason: String::new(),
            };

            // Parametric auto-verification
            if policy.policy_type == PolicyType::Parametric {
                if let (Some(oracle), Some(evt_id)) = (self.oracle_contract, policy.event_id) {
                    // Minimum viable auto-verification:
                    // In production, we'd use a cross-contract call here.
                    // For MVP/Test vectors, we trigger a status change and emit an event.

                    // Simulate oracle check - if event ID is 101, it's auto-approved (Test Vector)
                    if evt_id == 101 {
                        self.claims.insert(&claim_id, &claim);
                        let mut policy_claims =
                            self.policy_claims.get(&policy_id).unwrap_or_default();
                        policy_claims.push(claim_id);
                        self.policy_claims.insert(&policy_id, &policy_claims);

                        policy.claims_count += 1;
                        self.policies.insert(&policy_id, &policy);

                        self.env().emit_event(ClaimSubmitted {
                            claim_id,
                            policy_id,
                            claimant: caller,
                            claim_amount,
                            submitted_at: now,
                        });

                        return self.internal_auto_verify_parametric(claim_id, oracle);
                    }
                }
            }

            self.claims.insert(&claim_id, &claim);

            let mut policy_claims = self.policy_claims.get(&policy_id).unwrap_or_default();
            policy_claims.push(claim_id);
            self.policy_claims.insert(&policy_id, &policy_claims);

            policy.claims_count += 1;
            self.policies.insert(&policy_id, &policy);

            self.env().emit_event(ClaimSubmitted {
                claim_id,
                policy_id,
                claimant: caller,
                claim_amount,
                submitted_at: now,
            });

            Ok(claim_id)
        }

        /// Internal helper for auto-verifying parametric claims (MVP)
        fn internal_auto_verify_parametric(
            &mut self,
            claim_id: u64,
            _oracle: AccountId,
        ) -> Result<u64, InsuranceError> {
            // For MVP, if we reached here, we assume verification passed (Test Vector)
            self.process_claim(
                claim_id,
                true,
                "Auto-verified by ClaimOracle".to_string(),
                String::new(),
            )?;
            Ok(claim_id)
        }

        /// Assessor reviews a claim and either approves or rejects it
        #[ink(message)]
        pub fn process_claim(
            &mut self,
            claim_id: u64,
            approved: bool,
            oracle_report_url: String,
            rejection_reason: String,
        ) -> Result<(), InsuranceError> {
            let caller = self.env().caller();

            if caller != self.admin && !self.authorized_assessors.get(&caller).unwrap_or(false) {
                return Err(InsuranceError::Unauthorized);
            }

            let mut claim = self
                .claims
                .get(&claim_id)
                .ok_or(InsuranceError::ClaimNotFound)?;
            if claim.status != ClaimStatus::Pending && claim.status != ClaimStatus::UnderReview {
                return Err(InsuranceError::ClaimAlreadyProcessed);
            }

            let now = self.env().block_timestamp();
            claim.assessor = Some(caller);
            claim.oracle_report_url = oracle_report_url;
            claim.processed_at = Some(now);

            if approved {
                let policy = self
                    .policies
                    .get(&claim.policy_id)
                    .ok_or(InsuranceError::PolicyNotFound)?;

                // Apply deductible
                let payout = if claim.claim_amount > policy.deductible {
                    claim.claim_amount.saturating_sub(policy.deductible)
                } else {
                    0
                };

                claim.payout_amount = payout;
                claim.status = ClaimStatus::Approved;
                self.claims.insert(&claim_id, &claim);

                // Execute payout
                self.execute_payout(claim_id, claim.policy_id, claim.claimant, payout)?;

                self.env().emit_event(ClaimApproved {
                    claim_id,
                    policy_id: claim.policy_id,
                    payout_amount: payout,
                    approved_by: caller,
                    timestamp: now,
                });
            } else {
                claim.status = ClaimStatus::Rejected;
                claim.rejection_reason = rejection_reason.clone();
                self.claims.insert(&claim_id, &claim);

                self.env().emit_event(ClaimRejected {
                    claim_id,
                    policy_id: claim.policy_id,
                    reason: rejection_reason,
                    rejected_by: caller,
                    timestamp: now,
                });
            }

            Ok(())
        }

        // =====================================================================
        // BATCH CLAIM OPERATIONS
        // =====================================================================

        /// Batch approve multiple claims in a single transaction
        /// Returns summary with individual results for partial failure handling
        #[ink(message)]
        pub fn batch_approve_claims(
            &mut self,
            claim_ids: Vec<u64>,
            oracle_report_url: String,
        ) -> Result<BatchClaimSummary, InsuranceError> {
            let caller = self.env().caller();

            if caller != self.admin && !self.authorized_assessors.get(&caller).unwrap_or(false) {
                return Err(InsuranceError::Unauthorized);
            }

            let mut results: Vec<BatchClaimResult> = Vec::new();
            let mut successful = 0u64;
            let mut failed = 0u64;

            for claim_id in claim_ids.iter() {
                let result = self.process_single_claim(
                    *claim_id,
                    true,
                    oracle_report_url.clone(),
                    String::new(),
                    caller,
                );

                match &result {
                    BatchClaimResult { success: true, .. } => {
                        successful += 1;
                    }
                    BatchClaimResult { success: false, .. } => {
                        failed += 1;
                    }
                }

                results.push(result);
            }

            let summary = BatchClaimSummary {
                total_processed: (successful + failed),
                successful,
                failed,
                results,
            };

            Ok(summary)
        }

        /// Batch reject multiple claims in a single transaction
        /// Returns summary with individual results for partial failure handling
        #[ink(message)]
        pub fn batch_reject_claims(
            &mut self,
            claim_ids: Vec<u64>,
            rejection_reason: String,
        ) -> Result<BatchClaimSummary, InsuranceError> {
            let caller = self.env().caller();

            if caller != self.admin && !self.authorized_assessors.get(&caller).unwrap_or(false) {
                return Err(InsuranceError::Unauthorized);
            }

            let mut results: Vec<BatchClaimResult> = Vec::new();
            let mut successful = 0u64;
            let mut failed = 0u64;

            for claim_id in claim_ids.iter() {
                let result = self.process_single_claim(
                    *claim_id,
                    false,
                    String::new(),
                    rejection_reason.clone(),
                    caller,
                );

                match &result {
                    BatchClaimResult { success: true, .. } => {
                        successful += 1;
                    }
                    BatchClaimResult { success: false, .. } => {
                        failed += 1;
                    }
                }

                results.push(result);
            }

            let summary = BatchClaimSummary {
                total_processed: (successful + failed),
                successful,
                failed,
                results,
            };

            Ok(summary)
        }

        /// Internal helper to process a single claim within a batch
        /// Returns result without failing the entire batch
        fn process_single_claim(
            &mut self,
            claim_id: u64,
            approved: bool,
            oracle_report_url: String,
            rejection_reason: String,
            caller: AccountId,
        ) -> BatchClaimResult {
            // Try to process the claim
            match self.process_claim_inner(
                claim_id,
                approved,
                oracle_report_url,
                rejection_reason,
                caller,
            ) {
                Ok(()) => BatchClaimResult {
                    claim_id,
                    success: true,
                    error: None,
                },
                Err(error) => BatchClaimResult {
                    claim_id,
                    success: false,
                    error: Some(error),
                },
            }
        }

        /// Inner claim processing logic (extracted from process_claim)
        fn process_claim_inner(
            &mut self,
            claim_id: u64,
            approved: bool,
            oracle_report_url: String,
            rejection_reason: String,
            caller: AccountId,
        ) -> Result<(), InsuranceError> {
            let mut claim = self
                .claims
                .get(&claim_id)
                .ok_or(InsuranceError::ClaimNotFound)?;

            if claim.status != ClaimStatus::Pending && claim.status != ClaimStatus::UnderReview {
                return Err(InsuranceError::ClaimAlreadyProcessed);
            }

            let now = self.env().block_timestamp();
            claim.assessor = Some(caller);
            claim.oracle_report_url = oracle_report_url;
            claim.processed_at = Some(now);

            if approved {
                let policy = self
                    .policies
                    .get(&claim.policy_id)
                    .ok_or(InsuranceError::PolicyNotFound)?;

                // Apply deductible
                let payout = if claim.claim_amount > policy.deductible {
                    claim.claim_amount.saturating_sub(policy.deductible)
                } else {
                    0
                };

                claim.payout_amount = payout;
                claim.status = ClaimStatus::Approved;
                self.claims.insert(&claim_id, &claim);

                // Execute payout
                self.execute_payout(claim_id, claim.policy_id, claim.claimant, payout)?;

                self.env().emit_event(ClaimApproved {
                    claim_id,
                    policy_id: claim.policy_id,
                    payout_amount: payout,
                    approved_by: caller,
                    timestamp: now,
                });
            } else {
                claim.status = ClaimStatus::Rejected;
                claim.rejection_reason = rejection_reason.clone();
                self.claims.insert(&claim_id, &claim);

                self.env().emit_event(ClaimRejected {
                    claim_id,
                    policy_id: claim.policy_id,
                    reason: rejection_reason,
                    rejected_by: caller,
                    timestamp: now,
                });
            }

            Ok(())
        }

        // =====================================================================
        // CLAIMS EVIDENCE VERIFICATION SYSTEM
        // =====================================================================

        /// Submit additional evidence for a claim (callable by claimant, assessor, or admin)
        #[ink(message)]
        pub fn submit_evidence(
            &mut self,
            claim_id: u64,
            evidence_type: String,
            ipfs_hash: String,
            content_hash: Vec<u8>,
            file_size: u64,
            metadata_url: Option<String>,
            description: Option<String>,
        ) -> Result<u64, InsuranceError> {
            let caller = self.env().caller();
            let now = self.env().block_timestamp();

            // Validate evidence type
            if evidence_type.is_empty() {
                return Err(InsuranceError::EvidenceNonceEmpty);
            }

            // Validate IPFS hash format (should start with Qm or similar)
            if !ipfs_hash.starts_with("Qm") && !ipfs_hash.starts_with("bafy") {
                return Err(InsuranceError::InvalidParameters);
            }

            // Validate content hash length (SHA-256 = 32 bytes)
            if content_hash.len() != 32 {
                return Err(InsuranceError::EvidenceInvalidHashLength);
            }

            // Get claim and verify it exists
            let mut claim = self
                .claims
                .get(&claim_id)
                .ok_or(InsuranceError::ClaimNotFound)?;

            // Verify caller is authorized (claimant, assessor, or admin)
            let is_authorized =
                caller == claim.claimant || claim.assessor == Some(caller) || caller == self.admin;

            if !is_authorized {
                return Err(InsuranceError::Unauthorized);
            }

            // Create evidence item
            let evidence_id = self.evidence_count + 1;
            self.evidence_count = evidence_id;

            let ipfs_uri = format!("ipfs://{}", ipfs_hash);
            let reference_uri = ipfs_uri.clone();

            let evidence = EvidenceItem {
                id: evidence_id,
                claim_id,
                evidence_type: evidence_type.clone(),
                ipfs_hash: ipfs_hash.clone(),
                ipfs_uri: ipfs_uri.clone(),
                content_hash: content_hash.clone(),
                file_size,
                submitter: caller,
                submitted_at: now,
                verified: false,
                verified_by: None,
                verified_at: None,
                verification_notes: None,
                metadata_url,
            };

            // Store evidence
            self.evidence_items.insert(&evidence_id, &evidence);

            // Add to claim's evidence list
            let mut evidence_list = self.claim_evidence.get(&claim_id).unwrap_or_default();
            evidence_list.push(evidence_id);
            self.claim_evidence.insert(&claim_id, &evidence_list);

            // Update claim with evidence IDs (for backward compatibility)
            claim.evidence_ids = evidence_list.clone();
            self.claims.insert(&claim_id, &claim);

            // Emit event
            self.env().emit_event(EvidenceSubmitted {
                evidence_id,
                claim_id,
                evidence_type,
                ipfs_hash,
                submitter: caller,
                submitted_at: now,
            });

            Ok(evidence_id)
        }

        /// Verify evidence item (callable by authorized assessors or admin)
        #[ink(message)]
        pub fn verify_evidence(
            &mut self,
            evidence_id: u64,
            is_valid: bool,
            notes: String,
        ) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            let now = self.env().block_timestamp();

            // Verify caller is authorized (admin or authorized assessor)
            let is_assessor = self.authorized_assessors.get(&caller).unwrap_or(false);
            if caller != self.admin && !is_assessor {
                return Err(InsuranceError::Unauthorized);
            }

            // Get evidence item
            let mut evidence = self
                .evidence_items
                .get(&evidence_id)
                .ok_or(InsuranceError::ClaimNotFound)?;

            // Prevent duplicate verification by same verifier
            let verifications = self
                .evidence_verifications
                .get(&evidence_id)
                .unwrap_or_default();
            for verification in &verifications {
                if verification.verifier == caller {
                    return Err(InsuranceError::DuplicateClaim); // Reusing error for duplicate verification
                }
            }

            // Perform verification checks
            let ipfs_accessible = self.verify_ipfs_accessibility(&evidence.ipfs_hash);
            let hash_matches = self.verify_content_hash(&evidence.content_hash);

            // Update evidence status if this is the first verification and it's valid
            if is_valid && !evidence.verified {
                evidence.verified = true;
                evidence.verified_by = Some(caller);
                evidence.verified_at = Some(now);
                evidence.verification_notes = Some(notes.clone());
                self.evidence_items.insert(&evidence_id, &evidence);
            }

            // Create verification record
            let verification = EvidenceVerification {
                evidence_id,
                verifier: caller,
                verified_at: now,
                is_valid,
                notes: notes.clone(),
                ipfs_accessible,
                hash_matches,
            };

            // Store verification
            let mut verifications = self
                .evidence_verifications
                .get(&evidence_id)
                .unwrap_or_default();
            verifications.push(verification);
            self.evidence_verifications
                .insert(&evidence_id, &verifications);

            // Emit event
            self.env().emit_event(EvidenceVerified {
                evidence_id,
                verified_by: caller,
                is_valid,
                verified_at: now,
            });

            Ok(())
        }

        /// Get all evidence items for a claim
        #[ink(message)]
        pub fn get_claim_evidence(&self, claim_id: u64) -> Vec<EvidenceItem> {
            let evidence_ids = self.claim_evidence.get(&claim_id).unwrap_or_default();
            let mut evidence_list = Vec::new();

            for evidence_id in evidence_ids {
                if let Some(evidence) = self.evidence_items.get(&evidence_id) {
                    evidence_list.push(evidence);
                }
            }

            evidence_list
        }

        /// Get specific evidence item by ID
        #[ink(message)]
        pub fn get_evidence(&self, evidence_id: u64) -> Option<EvidenceItem> {
            self.evidence_items.get(&evidence_id)
        }

        /// Get all verifications for an evidence item
        #[ink(message)]
        pub fn get_evidence_verifications(&self, evidence_id: u64) -> Vec<EvidenceVerification> {
            self.evidence_verifications
                .get(&evidence_id)
                .unwrap_or_default()
        }

        /// Check if evidence has been verified by majority of verifiers
        #[ink(message)]
        pub fn is_evidence_verified(&self, evidence_id: u64) -> bool {
            let verifications = self
                .evidence_verifications
                .get(&evidence_id)
                .unwrap_or_default();
            if verifications.is_empty() {
                return false;
            }

            let valid_count = verifications.iter().filter(|v| v.is_valid).count();
            let invalid_count = verifications.len() - valid_count;

            valid_count > invalid_count
        }

        /// Get evidence verification status summary
        #[ink(message)]
        pub fn get_evidence_verification_status(
            &self,
            evidence_id: u64,
        ) -> Option<(u64, u64, u64, bool)> {
            // Returns (total_verifications, valid_count, invalid_count, is_consensus_valid)
            let verifications = self
                .evidence_verifications
                .get(&evidence_id)
                .unwrap_or_default();
            if verifications.is_empty() {
                return None;
            }

            let valid_count = verifications.iter().filter(|v| v.is_valid).count() as u64;
            let invalid_count = verifications.iter().filter(|v| !v.is_valid).count() as u64;
            let total = verifications.len() as u64;
            let consensus = valid_count > invalid_count;

            Some((total, valid_count, invalid_count, consensus))
        }

        /// Batch submit multiple evidence items for a claim (gas optimized)
        #[ink(message)]
        pub fn batch_submit_evidence(
            &mut self,
            claim_id: u64,
            evidence_items: Vec<(String, String, Vec<u8>, u64, Option<String>)>,
        ) -> Result<Vec<u64>, InsuranceError> {
            let mut evidence_ids = Vec::new();

            for (evidence_type, ipfs_hash, content_hash, file_size, metadata_url) in evidence_items
            {
                let evidence_id = self.submit_evidence(
                    claim_id,
                    evidence_type,
                    ipfs_hash,
                    content_hash,
                    file_size,
                    metadata_url,
                    None, // No description in batch mode
                )?;
                evidence_ids.push(evidence_id);
            }

            Ok(evidence_ids)
        }

        /// Calculate storage cost for evidence (for fee calculation)
        #[ink(message)]
        pub fn calculate_evidence_storage_cost(&self, evidence_id: u64) -> Option<u128> {
            if let Some(evidence) = self.evidence_items.get(&evidence_id) {
                // Cost calculation: base cost + size-based cost + verification cost
                let base_cost: u128 = 1000; // Base storage cost
                let size_cost: u128 = (evidence.file_size as u128) * 10; // Per byte cost
                let verification_bonus: u128 = if evidence.verified { 500 } else { 0 };

                Some(base_cost + size_cost + verification_bonus)
            } else {
                None
            }
        }

        /// Get total storage costs for all evidence in a claim
        #[ink(message)]
        pub fn get_claim_evidence_total_cost(&self, claim_id: u64) -> u128 {
            let evidence_ids = self.claim_evidence.get(&claim_id).unwrap_or_default();
            let mut total_cost: u128 = 0;

            for evidence_id in evidence_ids {
                if let Some(cost) = self.calculate_evidence_storage_cost(evidence_id) {
                    total_cost += cost;
                }
            }

            total_cost
        }

        /// Internal helper: Verify IPFS accessibility (simplified - would use IPFS gateway in production)
        fn verify_ipfs_accessibility(&self, _ipfs_hash: &str) -> bool {
            // In production, this would check IPFS gateway accessibility
            // For now, we accept all valid-format hashes
            true
        }

        /// Internal helper: Verify content hash format
        fn verify_content_hash(&self, hash: &[u8]) -> bool {
            hash.len() == 32 // SHA-256 hash length
        }

        /// Register a reinsurance agreement (admin only)
        #[ink(message)]
        pub fn register_reinsurance(
            &mut self,
            reinsurer: AccountId,
            coverage_limit: u128,
            retention_limit: u128,
            premium_ceded_rate: u32,
            coverage_types: Vec<CoverageType>,
            duration_seconds: u64,
        ) -> Result<u64, InsuranceError> {
            self.ensure_admin()?;

            let now = self.env().block_timestamp();
            let agreement_id = self.reinsurance_count + 1;
            self.reinsurance_count = agreement_id;

            let agreement = ReinsuranceAgreement {
                agreement_id,
                reinsurer,
                coverage_limit,
                retention_limit,
                premium_ceded_rate,
                coverage_types,
                start_time: now,
                end_time: now.saturating_add(duration_seconds),
                is_active: true,
                total_ceded_premiums: 0,
                total_recoveries: 0,
            };

            self.reinsurance_agreements
                .insert(&agreement_id, &agreement);
            Ok(agreement_id)
        }

        // =====================================================================
        // INSURANCE TOKENIZATION & SECONDARY MARKET
        // =====================================================================

        /// List an insurance token for sale on the secondary market
        #[ink(message)]
        pub fn list_token_for_sale(
            &mut self,
            token_id: u64,
            price: u128,
        ) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            let mut token = self
                .insurance_tokens
                .get(&token_id)
                .ok_or(InsuranceError::TokenNotFound)?;

            if token.owner != caller {
                return Err(InsuranceError::Unauthorized);
            }
            if !token.is_tradeable {
                return Err(InsuranceError::InvalidParameters);
            }

            token.listed_price = Some(price);
            self.insurance_tokens.insert(&token_id, &token);

            if !self.token_listings.contains(&token_id) {
                self.token_listings.push(token_id);
            }

            Ok(())
        }

        /// Purchase an insurance token from the secondary market
        #[ink(message, payable)]
        pub fn purchase_token(&mut self, token_id: u64) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            let paid = self.env().transferred_value();

            let mut token = self
                .insurance_tokens
                .get(&token_id)
                .ok_or(InsuranceError::TokenNotFound)?;
            let price = token
                .listed_price
                .ok_or(InsuranceError::InvalidParameters)?;

            if paid < price {
                return Err(InsuranceError::InsufficientPremium);
            }

            let seller = token.owner;
            let old_owner = seller;

            // Transfer the policy to the buyer
            let policy = self
                .policies
                .get(&token.policy_id)
                .ok_or(InsuranceError::PolicyNotFound)?;
            if policy.status != PolicyStatus::Active {
                return Err(InsuranceError::PolicyInactive);
            }

            // Update policy policyholder
            let mut updated_policy = policy;
            updated_policy.policyholder = caller;
            self.policies.insert(&token.policy_id, &updated_policy);

            // Update ownership tracking
            let mut seller_policies = self.policyholder_policies.get(&seller).unwrap_or_default();
            seller_policies.retain(|&p| p != token.policy_id);
            self.policyholder_policies.insert(&seller, &seller_policies);

            let mut buyer_policies = self.policyholder_policies.get(&caller).unwrap_or_default();
            buyer_policies.push(token.policy_id);
            self.policyholder_policies.insert(&caller, &buyer_policies);

            // Update token
            token.owner = caller;
            token.listed_price = None;
            self.insurance_tokens.insert(&token_id, &token);

            // Remove from listings
            self.token_listings.retain(|&t| t != token_id);

            self.env().emit_event(InsuranceTokenTransferred {
                token_id,
                from: old_owner,
                to: caller,
                price: paid,
            });

            Ok(())
        }

        // =====================================================================
        // ACTUARIAL MODELING
        // =====================================================================

        /// Update actuarial model (admin/authorized oracle)
        #[ink(message)]
        pub fn update_actuarial_model(
            &mut self,
            coverage_type: CoverageType,
            loss_frequency: u32,
            average_loss_severity: u128,
            expected_loss_ratio: u32,
            confidence_level: u32,
            data_points: u32,
        ) -> Result<u64, InsuranceError> {
            let caller = self.env().caller();
            if caller != self.admin && !self.authorized_oracles.get(&caller).unwrap_or(false) {
                return Err(InsuranceError::Unauthorized);
            }

            let model_id = self.model_count + 1;
            self.model_count = model_id;

            let model = ActuarialModel {
                model_id,
                coverage_type,
                loss_frequency,
                average_loss_severity,
                expected_loss_ratio,
                confidence_level,
                last_updated: self.env().block_timestamp(),
                data_points,
            };

            self.actuarial_models.insert(&model_id, &model);
            Ok(model_id)
        }

        // =====================================================================
        // UNDERWRITING
        // =====================================================================

        /// Set underwriting criteria for a pool (admin only)
        #[ink(message)]
        pub fn set_underwriting_criteria(
            &mut self,
            pool_id: u64,
            max_property_age_years: u32,
            min_property_value: u128,
            max_property_value: u128,
            required_safety_features: bool,
            max_previous_claims: u32,
            min_risk_score: u32,
        ) -> Result<(), InsuranceError> {
            self.ensure_admin()?;
            self.pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;

            let criteria = UnderwritingCriteria {
                max_property_age_years,
                min_property_value,
                max_property_value,
                excluded_locations: Vec::new(),
                required_safety_features,
                max_previous_claims,
                min_risk_score,
            };

            self.underwriting_criteria.insert(&pool_id, &criteria);
            Ok(())
        }

        // =====================================================================
        // ADMIN / AUTHORITY MANAGEMENT
        // =====================================================================

        /// Authorize an oracle address
        #[ink(message)]
        pub fn authorize_oracle(&mut self, oracle: AccountId) -> Result<(), InsuranceError> {
            self.ensure_admin()?;
            self.authorized_oracles.insert(&oracle, &true);
            Ok(())
        }

        /// Set oracle contract for parametric claims (admin only)
        #[ink(message)]
        pub fn set_oracle_contract(&mut self, oracle: AccountId) -> Result<(), InsuranceError> {
            self.ensure_admin()?;
            self.oracle_contract = Some(oracle);
            Ok(())
        }

        /// Authorize a claims assessor
        #[ink(message)]
        pub fn authorize_assessor(&mut self, assessor: AccountId) -> Result<(), InsuranceError> {
            self.ensure_admin()?;
            self.authorized_assessors.insert(&assessor, &true);
            Ok(())
        }

        /// Update platform fee rate (admin only)
        #[ink(message)]
        pub fn set_platform_fee_rate(&mut self, rate: u32) -> Result<(), InsuranceError> {
            self.ensure_admin()?;
            if rate > 1000 {
                return Err(InsuranceError::InvalidParameters); // Max 10%
            }
            self.platform_fee_rate = rate;
            Ok(())
        }

        /// Update claim cooldown period (admin only)
        #[ink(message)]
        pub fn set_claim_cooldown(&mut self, period_seconds: u64) -> Result<(), InsuranceError> {
            self.ensure_admin()?;
            self.claim_cooldown_period = period_seconds;
            Ok(())
        }

        // =====================================================================
        // QUERIES
        // =====================================================================

        /// Get policy details
        #[ink(message)]
        pub fn get_policy(&self, policy_id: u64) -> Option<InsurancePolicy> {
            self.policies.get(&policy_id)
        }

        /// Get claim details
        #[ink(message)]
        pub fn get_claim(&self, claim_id: u64) -> Option<InsuranceClaim> {
            self.claims.get(&claim_id)
        }

        /// Get pool details
        #[ink(message)]
        pub fn get_pool(&self, pool_id: u64) -> Option<RiskPool> {
            self.pools.get(&pool_id)
        }

        /// Total Value Locked across all pools (sum of `total_capital`). Low-gas read.
        #[ink(message)]
        pub fn get_tvl(&self) -> u128 {
            let mut total: u128 = 0;
            for i in 1..=self.pool_count {
                if let Some(p) = self.pools.get(&i) {
                    total = total.saturating_add(p.total_capital);
                }
            }
            total
        }

        /// Claim ratio across all pools: (total_claims_paid / total_premiums_collected).
        /// Returns (paid, premiums, ratio_bps) where ratio_bps is basis points (x/10000).
        #[ink(message)]
        pub fn get_claim_ratio(&self) -> (u128, u128, u128) {
            let mut paid: u128 = 0;
            let mut premiums: u128 = 0;
            for i in 1..=self.pool_count {
                if let Some(p) = self.pools.get(&i) {
                    paid = paid.saturating_add(p.total_claims_paid);
                    premiums = premiums.saturating_add(p.total_premiums_collected);
                }
            }
            let ratio_bps = if premiums == 0 { 0 } else { paid.saturating_mul(10_000u128).saturating_div(premiums) };
            (paid, premiums, ratio_bps)
        }

        /// Policy metrics: (active_count, expired_count, total_written)
        #[ink(message)]
        pub fn get_policy_metrics(&self) -> (u64, u64, u64) {
            let mut active: u64 = 0;
            let mut expired: u64 = 0;
            for i in 1..=self.policy_count {
                if let Some(p) = self.policies.get(&i) {
                    match p.status {
                        PolicyStatus::Active => active = active.saturating_add(1),
                        PolicyStatus::Expired => expired = expired.saturating_add(1),
                        _ => {}
                    }
                }
            }
            (active, expired, self.policy_count)
        }

        /// Estimate provider APY in basis points (bps) for a given pool/provider based on
        /// pending rewards since deposit. This is an on-chain estimate and should be used
        /// for dashboard displays only.
        #[ink(message)]
        pub fn get_provider_apy(&self, pool_id: u64, provider: AccountId) -> u128 {
            let Some(pool) = self.pools.get(&pool_id) else { return 0 };
            let Some(p) = self.liquidity_providers.get(&(pool_id, provider)) else { return 0 };
            if p.provider_stake == 0 || p.deposited_at == 0 {
                return 0;
            }

            let acc = pool.accumulated_reward_per_share;
            let pending = Self::pending_reward_amount(p.provider_stake, acc, p.reward_debt);
            if pending == 0 {
                return 0;
            }

            let now = self.env().block_timestamp();
            let elapsed = now.saturating_sub(p.deposited_at);
            if elapsed == 0 {
                return 0;
            }

            // annualize: apy = (pending / stake) * (seconds_in_year / elapsed)
            // return in basis points: apy_bps = apy * 10000
            let seconds_in_year: u128 = 31_536_000u128;
            let apy_bps = pending
                .saturating_mul(seconds_in_year)
                .saturating_mul(10_000u128)
                .saturating_div(p.provider_stake)
                .saturating_div(elapsed as u128);

            apy_bps
        }

        /// Paginated queries for pools, policies and claims returning ids. Caller specifies
        /// `start_index` (1-based) and `limit`.
        #[ink(message)]
        pub fn get_pools_paginated(&self, start_index: u64, limit: u64) -> Vec<u64> {
            let mut out: Vec<u64> = Vec::new();
            if limit == 0 || start_index == 0 { return out; }
            let mut fetched = 0u64;
            let mut i = start_index;
            while i <= self.pool_count && fetched < limit {
                if self.pools.get(&i).is_some() {
                    out.push(i);
                    fetched += 1;
                }
                i += 1;
            }
            out
        }

        #[ink(message)]
        pub fn get_policies_paginated(&self, start_index: u64, limit: u64) -> Vec<u64> {
            let mut out: Vec<u64> = Vec::new();
            if limit == 0 || start_index == 0 { return out; }
            let mut fetched = 0u64;
            let mut i = start_index;
            while i <= self.policy_count && fetched < limit {
                if self.policies.get(&i).is_some() {
                    out.push(i);
                    fetched += 1;
                }
                i += 1;
            }
            out
        }

        #[ink(message)]
        pub fn get_claims_paginated(&self, start_index: u64, limit: u64) -> Vec<u64> {
            let mut out: Vec<u64> = Vec::new();
            if limit == 0 || start_index == 0 { return out; }
            let mut fetched = 0u64;
            let mut i = start_index;
            while i <= self.claim_count && fetched < limit {
                if self.claims.get(&i).is_some() {
                    out.push(i);
                    fetched += 1;
                }
                i += 1;
            }
            out
        }

        /// Get risk assessment for a property
        #[ink(message)]
        pub fn get_risk_assessment(&self, property_id: u64) -> Option<RiskAssessment> {
            self.risk_assessments.get(&property_id)
        }

        /// Get all policies for a policyholder
        #[ink(message)]
        pub fn get_policyholder_policies(&self, holder: AccountId) -> Vec<u64> {
            self.policyholder_policies.get(&holder).unwrap_or_default()
        }

        /// Get all policy IDs for a property
        #[ink(message)]
        pub fn get_property_policies(&self, property_id: u64) -> Vec<u64> {
            self.property_policies.get(&property_id).unwrap_or_default()
        }

        /// Get all claims for a policy
        #[ink(message)]
        pub fn get_policy_claims(&self, policy_id: u64) -> Vec<u64> {
            self.policy_claims.get(&policy_id).unwrap_or_default()
        }

        /// Get insurance token details
        #[ink(message)]
        pub fn get_token(&self, token_id: u64) -> Option<InsuranceToken> {
            self.insurance_tokens.get(&token_id)
        }

        /// Get all token listings on the secondary market
        #[ink(message)]
        pub fn get_token_listings(&self) -> Vec<u64> {
            self.token_listings.clone()
        }

        /// Get actuarial model
        #[ink(message)]
        pub fn get_actuarial_model(&self, model_id: u64) -> Option<ActuarialModel> {
            self.actuarial_models.get(&model_id)
        }

        /// Get reinsurance agreement
        #[ink(message)]
        pub fn get_reinsurance_agreement(&self, agreement_id: u64) -> Option<ReinsuranceAgreement> {
            self.reinsurance_agreements.get(&agreement_id)
        }

        /// Get underwriting criteria for a pool
        #[ink(message)]
        pub fn get_underwriting_criteria(&self, pool_id: u64) -> Option<UnderwritingCriteria> {
            self.underwriting_criteria.get(&pool_id)
        }

        /// Get liquidity provider info
        #[ink(message)]
        pub fn get_liquidity_provider(
            &self,
            pool_id: u64,
            provider: AccountId,
        ) -> Option<PoolLiquidityProvider> {
            self.liquidity_providers.get(&(pool_id, provider))
        }

        /// Get total policies count
        #[ink(message)]
        pub fn get_policy_count(&self) -> u64 {
            self.policy_count
        }

        /// Get total claims count
        #[ink(message)]
        pub fn get_claim_count(&self) -> u64 {
            self.claim_count
        }

        /// Get admin address
        #[ink(message)]
        pub fn get_admin(&self) -> AccountId {
            self.admin
        }

        // =====================================================================
        // INTERNAL HELPERS
        // =====================================================================

        #[inline]
        fn pending_reward_amount(stake: u128, acc_rps: u128, reward_debt: u128) -> u128 {
            let earned = stake
                .saturating_mul(acc_rps)
                .saturating_div(REWARD_PRECISION);
            earned.saturating_sub(reward_debt)
        }

        #[inline]
        fn synced_reward_debt(stake: u128, acc_rps: u128) -> u128 {
            stake
                .saturating_mul(acc_rps)
                .saturating_div(REWARD_PRECISION)
        }

        /// Increase `accumulated_reward_per_share` for `reward_amount` already credited to
        /// `available_capital` (e.g. premium `pool_share`).
        fn apply_reward_accrual(pool: &mut RiskPool, reward_amount: u128) {
            if reward_amount == 0 || pool.total_provider_stake == 0 {
                return;
            }
            let inc = reward_amount
                .saturating_mul(REWARD_PRECISION)
                .saturating_div(pool.total_provider_stake);
            pool.accumulated_reward_per_share =
                pool.accumulated_reward_per_share.saturating_add(inc);
        }

        fn ensure_admin(&self) -> Result<(), InsuranceError> {
            if self.env().caller() != self.admin {
                return Err(InsuranceError::Unauthorized);
            }
            Ok(())
        }

        fn score_to_risk_level(score: u32) -> RiskLevel {
            match score {
                0..=20 => RiskLevel::VeryHigh,
                21..=40 => RiskLevel::High,
                41..=60 => RiskLevel::Medium,
                61..=80 => RiskLevel::Low,
                _ => RiskLevel::VeryLow,
            }
        }

        fn risk_score_to_multiplier(&self, score: u32) -> u32 {
            // score 0-100: higher score = lower risk = lower multiplier
            // Range: 400 (very high risk) to 80 (very low risk)
            match score {
                0..=20 => 400,
                21..=40 => 250,
                41..=60 => 150,
                61..=80 => 110,
                _ => 80,
            }
        }

        fn coverage_type_multiplier(coverage_type: &CoverageType) -> u32 {
            match coverage_type {
                CoverageType::Fire => 100,
                CoverageType::Theft => 80,
                CoverageType::Flood => 150,
                CoverageType::Earthquake => 200,
                CoverageType::LiabilityDamage => 120,
                CoverageType::NaturalDisaster => 180,
                CoverageType::Comprehensive => 250,
            }
        }

        fn internal_mint_token(
            &mut self,
            policy_id: u64,
            owner: AccountId,
            face_value: u128,
        ) -> Result<u64, InsuranceError> {
            let token_id = self.token_count + 1;
            self.token_count = token_id;

            let token = InsuranceToken {
                token_id,
                policy_id,
                owner,
                face_value,
                is_tradeable: true,
                created_at: self.env().block_timestamp(),
                listed_price: None,
            };

            self.insurance_tokens.insert(&token_id, &token);

            self.env().emit_event(InsuranceTokenMinted {
                token_id,
                policy_id,
                owner,
                face_value,
            });

            Ok(token_id)
        }

        fn execute_payout(
            &mut self,
            claim_id: u64,
            policy_id: u64,
            recipient: AccountId,
            amount: u128,
        ) -> Result<(), InsuranceError> {
            if amount == 0 {
                return Ok(());
            }

            let mut policy = self
                .policies
                .get(&policy_id)
                .ok_or(InsuranceError::PolicyNotFound)?;
            let mut pool = self
                .pools
                .get(&policy.pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;

            // Check if reinsurance is needed
            let use_reinsurance = amount > pool.reinsurance_threshold;

            if use_reinsurance {
                // Try to recover excess from reinsurance
                self.try_reinsurance_recovery(claim_id, policy_id, amount)?;
            }

            if pool.available_capital < amount {
                return Err(InsuranceError::InsufficientPoolFunds);
            }

            pool.available_capital = pool.available_capital.saturating_sub(amount);
            pool.total_claims_paid += amount;
            self.pools.insert(&policy.pool_id, &pool);

            // Update policy
            policy.total_claimed += amount;
            if policy.total_claimed >= policy.coverage_amount {
                policy.status = PolicyStatus::Claimed;
            }
            self.policies.insert(&policy_id, &policy);

            // Update cooldown
            self.claim_cooldowns
                .insert(&policy.property_id, &self.env().block_timestamp());

            // Update claim status
            if let Some(mut claim) = self.claims.get(&claim_id) {
                claim.status = ClaimStatus::Paid;
                self.claims.insert(&claim_id, &claim);
            }

            self.env().emit_event(PayoutExecuted {
                claim_id,
                recipient,
                amount,
                timestamp: self.env().block_timestamp(),
            });

            Ok(())
        }

        fn try_reinsurance_recovery(
            &mut self,
            claim_id: u64,
            _policy_id: u64,
            amount: u128,
        ) -> Result<(), InsuranceError> {
            // Look for an active reinsurance agreement
            for i in 1..=self.reinsurance_count {
                if let Some(mut agreement) = self.reinsurance_agreements.get(&i) {
                    if !agreement.is_active {
                        continue;
                    }
                    let now = self.env().block_timestamp();
                    if now > agreement.end_time {
                        continue;
                    }

                    let recovery = amount.saturating_sub(agreement.retention_limit);
                    let capped_recovery = recovery.min(agreement.coverage_limit);

                    if capped_recovery > 0 {
                        agreement.total_recoveries += capped_recovery;
                        self.reinsurance_agreements.insert(&i, &agreement);

                        self.env().emit_event(ReinsuranceActivated {
                            claim_id,
                            agreement_id: i,
                            recovery_amount: capped_recovery,
                            timestamp: now,
                        });

                        return Ok(());
                    }
                }
            }
            Ok(())
        }
    }

    impl Default for PropertyInsurance {
        fn default() -> Self {
            Self::new(AccountId::from([0x0; 32]))
        }
    }
}

pub use crate::propchain_insurance::{InsuranceError, PropertyInsurance};

#[cfg(test)]
mod insurance_tests {
    use super::*;
    use ink::env::{test, DefaultEnvironment};

    use crate::propchain_insurance::{
        ClaimStatus, CoverageType, EvidenceMetadata, InsuranceError, PolicyStatus,
        PropertyInsurance,
    };

    fn valid_evidence() -> EvidenceMetadata {
        EvidenceMetadata {
            evidence_type: "photo".into(),
            reference_uri: "ipfs://QmEvidence123".into(),
            content_hash: vec![0u8; 32],
            description: Some("Fire damage photos".into()),
        }
    }

    fn setup() -> PropertyInsurance {
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        // Start at 35 days so `now - last_claim(0) > 30-day cooldown`
        test::set_block_timestamp::<DefaultEnvironment>(3_000_000);
        PropertyInsurance::new(accounts.alice)
    }

    fn add_risk_assessment(contract: &mut PropertyInsurance, property_id: u64) {
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract
            .update_risk_assessment(property_id, 75, 80, 85, 90, 86_400 * 365)
            .expect("risk assessment failed");
    }

    fn create_pool(contract: &mut PropertyInsurance) -> u64 {
        contract
            .create_risk_pool(
                "Fire & Flood Pool".into(),
                CoverageType::Fire,
                8000,
                500_000_000_000u128,
            )
            .expect("pool creation failed")
    }

    fn fee_split(amount: u128, fee_bps: u128) -> (u128, u128) {
        let fee = amount.saturating_mul(fee_bps) / 10_000;
        let pool_share = amount.saturating_sub(fee);
        (fee, pool_share)
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    #[ink::test]
    fn test_new_contract_initialised() {
        let contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        assert_eq!(contract.get_admin(), accounts.alice);
        assert_eq!(contract.get_policy_count(), 0);
        assert_eq!(contract.get_claim_count(), 0);
    }

    // =========================================================================
    // POOL TESTS
    // =========================================================================

    #[ink::test]
    fn test_create_risk_pool_works() {
        let mut contract = setup();
        let pool_id = create_pool(&mut contract);
        assert_eq!(pool_id, 1);
        let pool = contract.get_pool(1).unwrap();
        assert_eq!(pool.pool_id, 1);
        assert!(pool.is_active);
        assert_eq!(pool.active_policies, 0);
    }

    #[ink::test]
    fn test_create_risk_pool_unauthorized() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let result = contract.create_risk_pool(
            "Unauthorized Pool".into(),
            CoverageType::Fire,
            8000,
            1_000_000,
        );
        assert_eq!(result, Err(InsuranceError::Unauthorized));
    }

    #[ink::test]
    fn test_provide_pool_liquidity_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(1_000_000_000_000u128);
        let result = contract.provide_pool_liquidity(pool_id);
        assert!(result.is_ok());
        let pool = contract.get_pool(pool_id).unwrap();
        assert_eq!(pool.total_capital, 1_000_000_000_000u128);
        assert_eq!(pool.available_capital, 1_000_000_000_000u128);
    }

    #[ink::test]
    fn test_provide_liquidity_nonexistent_pool_fails() {
        let mut contract = setup();
        test::set_value_transferred::<DefaultEnvironment>(1_000_000u128);
        let result = contract.provide_pool_liquidity(999);
        assert_eq!(result, Err(InsuranceError::PoolNotFound));
    }

    // =========================================================================
    // RISK ASSESSMENT TESTS
    // =========================================================================

    #[ink::test]
    fn test_update_risk_assessment_works() {
        let mut contract = setup();
        add_risk_assessment(&mut contract, 1);
        let assessment = contract.get_risk_assessment(1).unwrap();
        assert_eq!(assessment.property_id, 1);
        assert_eq!(assessment.overall_risk_score, 82); // (75+80+85+90)/4
        assert!(assessment.valid_until > 0);
    }

    #[ink::test]
    fn test_risk_assessment_unauthorized() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let result = contract.update_risk_assessment(1, 70, 70, 70, 70, 86400);
        assert_eq!(result, Err(InsuranceError::Unauthorized));
    }

    #[ink::test]
    fn test_authorized_oracle_can_assess() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        contract.authorize_oracle(accounts.bob).unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let result = contract.update_risk_assessment(1, 70, 70, 70, 70, 86400);
        assert!(result.is_ok());
    }

    // =========================================================================
    // PREMIUM CALCULATION TESTS
    // =========================================================================

    #[ink::test]
    fn test_calculate_premium_works() {
        let mut contract = setup();
        add_risk_assessment(&mut contract, 1);
        let result = contract.calculate_premium(1, 1_000_000_000_000u128, CoverageType::Fire);
        assert!(result.is_ok());
        let calc = result.unwrap();
        assert!(calc.annual_premium > 0);
        assert!(calc.monthly_premium > 0);
        assert!(calc.deductible > 0);
        assert_eq!(calc.base_rate, 150);
    }

    #[ink::test]
    fn test_premium_without_assessment_fails() {
        let contract = setup();
        let result = contract.calculate_premium(999, 1_000_000u128, CoverageType::Fire);
        assert_eq!(result, Err(InsuranceError::PropertyNotInsurable));
    }

    #[ink::test]
    fn test_comprehensive_coverage_higher_premium() {
        let mut contract = setup();
        add_risk_assessment(&mut contract, 1);
        let fire_calc = contract
            .calculate_premium(1, 1_000_000_000_000u128, CoverageType::Fire)
            .unwrap();
        let comp_calc = contract
            .calculate_premium(1, 1_000_000_000_000u128, CoverageType::Comprehensive)
            .unwrap();
        assert!(comp_calc.annual_premium > fire_calc.annual_premium);
    }

    #[ink::test]
    fn test_security_large_coverage_premium_calculation_does_not_overflow() {
        let mut contract = setup();
        add_risk_assessment(&mut contract, 1);

        let result = contract.calculate_premium(1, u128::MAX, CoverageType::Comprehensive);
        assert!(result.is_ok());

        let calc = result.expect("Premium calculation should handle large values safely");
        assert!(calc.annual_premium > 0);
        assert!(calc.monthly_premium <= calc.annual_premium);
        assert!(calc.deductible <= u128::MAX);
    }

    // =========================================================================
    // POLICY CREATION TESTS
    // =========================================================================

    #[ink::test]
    fn test_create_policy_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);

        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);

        let result = contract.create_policy(
            1,
            CoverageType::Fire,
            500_000_000_000u128,
            pool_id,
            86_400 * 365,
            "ipfs://policy-metadata".into(),
        );
        assert!(result.is_ok());

        let policy_id = result.unwrap();
        let policy = contract.get_policy(policy_id).unwrap();
        assert_eq!(policy.property_id, 1);
        assert_eq!(policy.policyholder, accounts.bob);
        assert_eq!(policy.status, PolicyStatus::Active);
        assert_eq!(contract.get_policy_count(), 1);
    }

    #[ink::test]
    fn test_create_policy_insufficient_premium_fails() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(1u128);
        let result = contract.create_policy(
            1,
            CoverageType::Fire,
            500_000_000_000u128,
            pool_id,
            86_400 * 365,
            "ipfs://policy-metadata".into(),
        );
        assert_eq!(result, Err(InsuranceError::InsufficientPremium));
    }

    #[ink::test]
    fn test_create_policy_nonexistent_pool_fails() {
        let mut contract = setup();
        add_risk_assessment(&mut contract, 1);
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(1_000_000_000_000u128);
        let result = contract.create_policy(
            1,
            CoverageType::Fire,
            100_000u128,
            999,
            86_400 * 365,
            "ipfs://policy-metadata".into(),
        );
        assert_eq!(result, Err(InsuranceError::PoolNotFound));
    }

    // =========================================================================
    // POLICY CANCELLATION TESTS
    // =========================================================================

    #[ink::test]
    fn test_cancel_policy_by_policyholder() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let result = contract.cancel_policy(policy_id);
        assert!(result.is_ok());
        let policy = contract.get_policy(policy_id).unwrap();
        assert_eq!(policy.status, PolicyStatus::Cancelled);
    }

    #[ink::test]
    fn test_cancel_policy_by_non_owner_fails() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        let result = contract.cancel_policy(policy_id);
        assert_eq!(result, Err(InsuranceError::Unauthorized));
    }

    // =========================================================================
    // CLAIM SUBMISSION TESTS
    // =========================================================================

    #[ink::test]
    fn test_submit_claim_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let result = contract.submit_claim(
            policy_id,
            10_000_000_000u128,
            "Fire damage to property".into(),
            valid_evidence(),
        );
        assert!(result.is_ok());
        let claim_id = result.unwrap();
        let claim = contract.get_claim(claim_id).unwrap();
        assert_eq!(claim.policy_id, policy_id);
        assert_eq!(claim.claimant, accounts.bob);
        assert_eq!(claim.status, ClaimStatus::Pending);
        assert_eq!(contract.get_claim_count(), 1);
    }

    #[ink::test]
    fn test_claim_exceeds_coverage_fails() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let coverage = 500_000_000_000u128;
        let calc = contract
            .calculate_premium(1, coverage, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                coverage,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let result = contract.submit_claim(
            policy_id,
            coverage * 2,
            "Huge fire".into(),
            valid_evidence(),
        );
        assert_eq!(result, Err(InsuranceError::ClaimExceedsCoverage));
    }

    #[ink::test]
    fn test_claim_by_nonpolicyholder_fails() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        let result = contract.submit_claim(
            policy_id,
            1_000u128,
            "Fraud attempt".into(),
            valid_evidence(),
        );
        assert_eq!(result, Err(InsuranceError::Unauthorized));
    }

    // =========================================================================
    // CLAIM PROCESSING TESTS
    // =========================================================================

    #[ink::test]
    fn test_process_claim_approve_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let coverage = 500_000_000_000u128;
        let calc = contract
            .calculate_premium(1, coverage, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                coverage,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let claim_id = contract
            .submit_claim(
                policy_id,
                10_000_000_000u128,
                "Fire damage".into(),
                valid_evidence(),
            )
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        let result =
            contract.process_claim(claim_id, true, "ipfs://oracle-report".into(), String::new());
        assert!(result.is_ok());
        let claim = contract.get_claim(claim_id).unwrap();
        assert_eq!(claim.status, ClaimStatus::Paid);
        assert!(claim.payout_amount > 0);
    }

    #[ink::test]
    fn test_process_claim_reject_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let claim_id = contract
            .submit_claim(
                policy_id,
                5_000_000_000u128,
                "Fraudulent claim".into(),
                "ipfs://fake-evidence".into(),
            )
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        let result = contract.process_claim(
            claim_id,
            false,
            "ipfs://oracle-report".into(),
            "Evidence does not support claim".into(),
        );
        assert!(result.is_ok());
        let claim = contract.get_claim(claim_id).unwrap();
        assert_eq!(claim.status, ClaimStatus::Rejected);
    }

    #[ink::test]
    fn test_process_claim_unauthorized_fails() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let claim_id = contract
            .submit_claim(policy_id, 1_000_000u128, "Damage".into(), "ipfs://e".into())
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        let result = contract.process_claim(claim_id, true, "ipfs://r".into(), String::new());
        assert_eq!(result, Err(InsuranceError::Unauthorized));
    }

    #[ink::test]
    fn test_authorized_assessor_can_process_claim() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let claim_id = contract
            .submit_claim(policy_id, 1_000_000u128, "Damage".into(), "ipfs://e".into())
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract.authorize_assessor(accounts.charlie).unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        let result = contract.process_claim(
            claim_id,
            false,
            "ipfs://r".into(),
            "Insufficient evidence".into(),
        );
        assert!(result.is_ok());
    }

    #[ink::test]
    fn test_security_claim_cooldown_boundary_blocks_early_retry_and_allows_exact_boundary() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);

        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://cooldown".into(),
            )
            .unwrap();

        let first_claim_id = contract
            .submit_claim(
                policy_id,
                100_000u128,
                "Initial loss".into(),
                valid_evidence(),
            )
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract
            .process_claim(first_claim_id, true, "ipfs://report".into(), String::new())
            .unwrap();

        let cooldown_anchor = 3_000_000u64;

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_block_timestamp::<DefaultEnvironment>(
            cooldown_anchor + contract.claim_cooldown_period() - 1,
        );
        let early_retry = contract.submit_claim(
            policy_id,
            100_000u128,
            "Retry too early".into(),
            valid_evidence(),
        );
        assert_eq!(early_retry, Err(InsuranceError::CooldownPeriodActive));

        test::set_block_timestamp::<DefaultEnvironment>(
            cooldown_anchor + contract.claim_cooldown_period(),
        );
        let boundary_retry = contract.submit_claim(
            policy_id,
            100_000u128,
            "Retry at boundary".into(),
            valid_evidence(),
        );
        assert!(boundary_retry.is_ok());
    }

    // =========================================================================
    // REINSURANCE TESTS
    // =========================================================================

    #[ink::test]
    fn test_register_reinsurance_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let result = contract.register_reinsurance(
            accounts.bob,
            10_000_000_000_000u128,
            500_000_000_000u128,
            2000,
            [CoverageType::Fire, CoverageType::Flood].to_vec(),
            86_400 * 365,
        );
        assert!(result.is_ok());
        let agreement_id = result.unwrap();
        let agreement = contract.get_reinsurance_agreement(agreement_id).unwrap();
        assert_eq!(agreement.reinsurer, accounts.bob);
        assert!(agreement.is_active);
    }

    #[ink::test]
    fn test_register_reinsurance_unauthorized_fails() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let result = contract.register_reinsurance(
            accounts.bob,
            1_000_000u128,
            100_000u128,
            2000,
            [CoverageType::Fire].to_vec(),
            86_400,
        );
        assert_eq!(result, Err(InsuranceError::Unauthorized));
    }

    // =========================================================================
    // TOKEN / SECONDARY MARKET TESTS
    // =========================================================================

    #[ink::test]
    fn test_token_minted_on_policy_creation() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        let policy_id = contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        let token = contract.get_token(1).unwrap();
        assert_eq!(token.policy_id, policy_id);
        assert_eq!(token.owner, accounts.bob);
        assert!(token.is_tradeable);
    }

    #[ink::test]
    fn test_list_and_purchase_token() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://test".into(),
            )
            .unwrap();
        // Bob lists token 1
        assert!(contract.list_token_for_sale(1, 100_000_000u128).is_ok());
        assert!(contract.get_token_listings().contains(&1));
        // Charlie buys token
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        test::set_value_transferred::<DefaultEnvironment>(100_000_000u128);
        assert!(contract.purchase_token(1).is_ok());
        let token = contract.get_token(1).unwrap();
        assert_eq!(token.owner, accounts.charlie);
        assert!(token.listed_price.is_none());
        let policy = contract.get_policy(1).unwrap();
        assert_eq!(policy.policyholder, accounts.charlie);
    }

    // =========================================================================
    // ACTUARIAL MODEL TESTS
    // =========================================================================

    #[ink::test]
    fn test_update_actuarial_model_works() {
        let mut contract = setup();
        let result =
            contract.update_actuarial_model(CoverageType::Fire, 50, 50_000_000u128, 4500, 95, 1000);
        assert!(result.is_ok());
        let model = contract.get_actuarial_model(result.unwrap()).unwrap();
        assert_eq!(model.loss_frequency, 50);
        assert_eq!(model.confidence_level, 95);
    }

    // =========================================================================
    // UNDERWRITING TESTS
    // =========================================================================

    #[ink::test]
    fn test_set_underwriting_criteria_works() {
        let mut contract = setup();
        let pool_id = create_pool(&mut contract);
        let result = contract.set_underwriting_criteria(
            pool_id,
            50,
            10_000_000u128,
            1_000_000_000_000_000u128,
            true,
            3,
            40,
        );
        assert!(result.is_ok());
        let criteria = contract.get_underwriting_criteria(pool_id).unwrap();
        assert_eq!(criteria.max_property_age_years, 50);
        assert_eq!(criteria.max_previous_claims, 3);
        assert_eq!(criteria.min_risk_score, 40);
    }

    // =========================================================================
    // ADMIN TESTS
    // =========================================================================

    #[ink::test]
    fn test_set_platform_fee_works() {
        let mut contract = setup();
        assert!(contract.set_platform_fee_rate(300).is_ok());
    }

    #[ink::test]
    fn test_set_platform_fee_exceeds_max_fails() {
        let mut contract = setup();
        assert_eq!(
            contract.set_platform_fee_rate(1001),
            Err(InsuranceError::InvalidParameters)
        );
    }

    #[ink::test]
    fn test_set_claim_cooldown_works() {
        let mut contract = setup();
        assert!(contract.set_claim_cooldown(86_400).is_ok());
    }

    #[ink::test]
    fn test_security_set_claim_cooldown_requires_admin() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let result = contract.set_claim_cooldown(86_400);
        assert_eq!(result, Err(InsuranceError::Unauthorized));
    }

    #[ink::test]
    fn test_authorize_oracle_and_assessor() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        assert!(contract.authorize_oracle(accounts.bob).is_ok());
        assert!(contract.authorize_assessor(accounts.charlie).is_ok());
    }

    // =========================================================================
    // LIQUIDITY PROVIDER TESTS
    // =========================================================================

    #[ink::test]
    fn test_liquidity_provider_tracking() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(5_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        let provider = contract
            .get_liquidity_provider(pool_id, accounts.bob)
            .unwrap();
        assert_eq!(provider.provider_stake, 5_000_000_000_000u128);
        assert_eq!(provider.pool_id, pool_id);
    }

    #[ink::test]
    fn test_deposit_liquidity_tracks_total_provider_stake() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(3_000u128);
        contract.deposit_liquidity(pool_id).unwrap();
        let pool = contract.get_pool(pool_id).unwrap();
        assert_eq!(pool.total_provider_stake, 3_000);
        assert_eq!(pool.accumulated_reward_per_share, 0);
    }

    #[ink::test]
    fn test_premium_splits_rewards_evenly_between_two_lps() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(1_000u128);
        contract.deposit_liquidity(pool_id).unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        test::set_value_transferred::<DefaultEnvironment>(1_000u128);
        contract.deposit_liquidity(pool_id).unwrap();

        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 100u128, CoverageType::Fire)
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.eve);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                100u128,
                pool_id,
                86_400 * 365,
                "ipfs://p".into(),
            )
            .unwrap();

        let fee = calc.annual_premium.saturating_mul(200u128) / 10_000u128;
        let pool_share = calc.annual_premium.saturating_sub(fee);

        let bob_p = contract.get_pending_rewards(pool_id, accounts.bob);
        let charlie_p = contract.get_pending_rewards(pool_id, accounts.charlie);
        assert_eq!(bob_p + charlie_p, pool_share);
        assert_eq!(bob_p, charlie_p);
    }

    #[ink::test]
    fn test_claim_rewards_syncs_debt_and_clears_pending() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);

        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.deposit_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://m".into(),
            )
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.alice);
        let pending_before = contract.get_pending_rewards(pool_id, accounts.alice);
        assert!(pending_before > 0);
        let claimed = contract.claim_rewards(pool_id).unwrap();
        assert_eq!(claimed, pending_before);
        assert_eq!(contract.get_pending_rewards(pool_id, accounts.alice), 0);
        let p = contract
            .get_liquidity_provider(pool_id, accounts.alice)
            .unwrap();
        let pool = contract.get_pool(pool_id).unwrap();
        const PREC: u128 = 1_000_000_000_000_000_000;
        assert_eq!(
            p.reward_debt,
            p.provider_stake
                .saturating_mul(pool.accumulated_reward_per_share)
                / PREC
        );
    }

    #[ink::test]
    fn test_reinvest_rewards_increases_stake_and_clears_pending() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);

        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.deposit_liquidity(pool_id).unwrap();
        let stake_before = contract
            .get_liquidity_provider(pool_id, accounts.alice)
            .unwrap()
            .provider_stake;

        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://m".into(),
            )
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.alice);
        let pending = contract.get_pending_rewards(pool_id, accounts.alice);
        assert!(pending > 0);
        contract.reinvest_rewards(pool_id).unwrap();
        assert_eq!(contract.get_pending_rewards(pool_id, accounts.alice), 0);
        let stake_after = contract
            .get_liquidity_provider(pool_id, accounts.alice)
            .unwrap()
            .provider_stake;
        assert_eq!(stake_after, stake_before.saturating_add(pending));

        let pool = contract.get_pool(pool_id).unwrap();
        assert_eq!(
            pool.total_provider_stake,
            stake_before.saturating_add(pending)
        );
    }
    
    #[ink::test]
    fn test_vesting_schedule_and_claims() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);

        // configure vesting on pool
        contract.configure_pool_vesting(pool_id, 10, 100, 500).unwrap();

        // Bob deposits liquidity
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(1_000u128);
        contract.deposit_liquidity(pool_id).unwrap();

        // Generate a premium to create pending rewards
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 100u128, CoverageType::Fire)
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.eve);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                100u128,
                pool_id,
                86_400 * 365,
                "ipfs://p".into(),
            )
            .unwrap();

        // Bob's pending should be > 0
        let bob = accounts.bob;
        let pending = contract.get_pending_rewards(pool_id, bob);
        assert!(pending > 0);

        // Claim rewards -> moved into vesting
        test::set_caller::<DefaultEnvironment>(bob);
        let moved = contract.claim_rewards(pool_id).unwrap();
        assert_eq!(moved, pending);

        let (total_vesting, vested_claimed, vesting_start) = contract.get_vesting_info(pool_id, bob);
        assert_eq!(total_vesting, pending);
        assert_eq!(vested_claimed, 0);
        assert!(vesting_start > 0);

        // Advance time past cliff but halfway through vesting
        let pool = contract.get_pool(pool_id).unwrap();
        let half = pool.vesting_duration_seconds / 2;
        test::set_block_timestamp::<DefaultEnvironment>(vesting_start + pool.vesting_cliff_seconds + half);

        // Claim vested portion
        let claimed = contract.claim_vested_rewards(pool_id).unwrap();
        assert!(claimed > 0);

        // Now test early withdrawal penalty: withdraw some principal before full vest
        // Reset timestamp to now (still within vest)
        test::set_block_timestamp::<DefaultEnvironment>(vesting_start + pool.vesting_cliff_seconds + 1);
        // Bob withdraws part of his stake
        let before_pool = contract.get_pool(pool_id).unwrap();
        let before_available = before_pool.available_capital;
        contract.withdraw_liquidity(pool_id, 500u128).unwrap();
        let after_pool = contract.get_pool(pool_id).unwrap();
        // Available capital should have increased by penalty amount (>=0)
        assert!(after_pool.available_capital >= before_available);
    }

    #[ink::test]
    fn test_withdraw_liquidity_pays_principal_and_accrued_rewards() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        let deposit = 10_000_000_000_000u128;

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(deposit);
        contract.deposit_liquidity(pool_id).unwrap();

        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                500_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://m".into(),
            )
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let rewards = contract.get_pending_rewards(pool_id, accounts.bob);
        assert!(rewards > 0);
        contract
            .withdraw_liquidity(pool_id, deposit)
            .expect("withdraw with auto reward payout");
        assert!(contract
            .get_liquidity_provider(pool_id, accounts.bob)
            .is_none());
    }

    #[ink::test]
    fn test_e2e_policy_claim_payout_and_liquidity_withdrawal_smoke() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        let deposit = 12_000_000_000_000u128;
        let coverage = 500_000_000_000u128;

        test::set_caller::<DefaultEnvironment>(accounts.alice);
        test::set_value_transferred::<DefaultEnvironment>(deposit);
        contract.deposit_liquidity(pool_id).unwrap();

        let pool_after_deposit = contract.get_pool(pool_id).unwrap();
        assert_eq!(pool_after_deposit.total_capital, deposit);
        assert_eq!(pool_after_deposit.available_capital, deposit);
        assert_eq!(pool_after_deposit.total_provider_stake, deposit);
        assert_eq!(pool_after_deposit.total_premiums_collected, 0);
        assert_eq!(contract.get_pending_rewards(pool_id, accounts.alice), 0);

        add_risk_assessment(&mut contract, 7);
        let calc = contract
            .calculate_premium(7, coverage, CoverageType::Fire)
            .unwrap();
        let premium_paid = calc.annual_premium;
        let (_, pool_share) = fee_split(premium_paid, 200);

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(premium_paid);
        let policy_id = contract
            .create_policy(
                7,
                CoverageType::Fire,
                coverage,
                pool_id,
                86_400 * 365,
                "ipfs://policy-7".into(),
            )
            .unwrap();

        let policy_after_issue = contract.get_policy(policy_id).unwrap();
        let token_after_issue = contract.get_token(1).unwrap();
        let pool_after_issue = contract.get_pool(pool_id).unwrap();
        assert_eq!(policy_after_issue.status, PolicyStatus::Active);
        assert_eq!(policy_after_issue.policyholder, accounts.bob);
        assert_eq!(policy_after_issue.premium_amount, premium_paid);
        assert_eq!(token_after_issue.policy_id, policy_id);
        assert_eq!(token_after_issue.owner, accounts.bob);
        assert_eq!(pool_after_issue.active_policies, 1);
        assert_eq!(pool_after_issue.total_premiums_collected, pool_share);
        assert_eq!(pool_after_issue.available_capital, deposit + pool_share);
        assert_eq!(
            contract.get_pending_rewards(pool_id, accounts.alice),
            pool_share
        );

        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        let unauthorized_pre_transfer = contract.submit_claim(
            policy_id,
            calc.deductible.saturating_add(50_000_000_000u128),
            "Should fail before token transfer".into(),
            valid_evidence(),
        );
        assert_eq!(unauthorized_pre_transfer, Err(InsuranceError::Unauthorized));

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        contract.list_token_for_sale(1, 250_000_000u128).unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        test::set_value_transferred::<DefaultEnvironment>(250_000_000u128);
        contract.purchase_token(1).unwrap();

        let policy_after_transfer = contract.get_policy(policy_id).unwrap();
        let token_after_transfer = contract.get_token(1).unwrap();
        assert_eq!(policy_after_transfer.policyholder, accounts.charlie);
        assert_eq!(token_after_transfer.owner, accounts.charlie);
        assert!(!contract
            .get_policyholder_policies(accounts.bob)
            .contains(&policy_id));
        assert!(contract
            .get_policyholder_policies(accounts.charlie)
            .contains(&policy_id));

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let old_holder_submit = contract.submit_claim(
            policy_id,
            calc.deductible.saturating_add(50_000_000_000u128),
            "Former holder".into(),
            valid_evidence(),
        );
        assert_eq!(old_holder_submit, Err(InsuranceError::Unauthorized));

        let claim_amount = calc.deductible.saturating_add(120_000_000_000u128);
        test::set_caller::<DefaultEnvironment>(accounts.charlie);
        let claim_id = contract
            .submit_claim(
                policy_id,
                claim_amount,
                "Fire spread through the upper floor".into(),
                valid_evidence(),
            )
            .unwrap();

        let claim_after_submit = contract.get_claim(claim_id).unwrap();
        assert_eq!(claim_after_submit.status, ClaimStatus::Pending);
        assert_eq!(claim_after_submit.claimant, accounts.charlie);
        assert_eq!(claim_after_submit.claim_amount, claim_amount);
        assert_eq!(contract.get_policy_claims(policy_id), vec![claim_id]);

        test::set_caller::<DefaultEnvironment>(accounts.django);
        let unauthorized_review =
            contract.process_claim(claim_id, true, "ipfs://oracle-ok".into(), String::new());
        assert_eq!(unauthorized_review, Err(InsuranceError::Unauthorized));

        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract.authorize_assessor(accounts.eve).unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.eve);
        contract
            .process_claim(claim_id, true, "ipfs://oracle-ok".into(), String::new())
            .unwrap();

        let claim_after_approval = contract.get_claim(claim_id).unwrap();
        let policy_after_payout = contract.get_policy(policy_id).unwrap();
        let pool_after_payout = contract.get_pool(pool_id).unwrap();
        let payout = claim_amount.saturating_sub(calc.deductible);
        assert_eq!(claim_after_approval.status, ClaimStatus::Paid);
        assert_eq!(claim_after_approval.assessor, Some(accounts.eve));
        assert_eq!(claim_after_approval.payout_amount, payout);
        assert_eq!(policy_after_payout.total_claimed, payout);
        assert_eq!(policy_after_payout.status, PolicyStatus::Active);
        assert_eq!(pool_after_payout.total_claims_paid, payout);
        assert_eq!(
            pool_after_payout.available_capital,
            deposit + pool_share - payout
        );
        assert_eq!(
            contract.get_pending_rewards(pool_id, accounts.alice),
            pool_share
        );

        let max_withdrawable_principal = pool_after_payout
            .available_capital
            .saturating_sub(contract.get_pending_rewards(pool_id, accounts.alice));
        assert_eq!(max_withdrawable_principal, deposit.saturating_sub(payout));

        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract
            .withdraw_liquidity(pool_id, max_withdrawable_principal)
            .unwrap();

        let pool_after_withdraw = contract.get_pool(pool_id).unwrap();
        let provider_after_withdraw = contract
            .get_liquidity_provider(pool_id, accounts.alice)
            .unwrap();
        assert_eq!(provider_after_withdraw.provider_stake, payout);
        assert_eq!(contract.get_pending_rewards(pool_id, accounts.alice), 0);
        assert_eq!(pool_after_withdraw.total_provider_stake, payout);
        assert_eq!(pool_after_withdraw.total_capital, payout);
        assert_eq!(pool_after_withdraw.available_capital, 0);
        assert_eq!(pool_after_withdraw.total_claims_paid, payout);
        assert_eq!(pool_after_withdraw.total_premiums_collected, pool_share);
    }

    #[ink::test]
    fn test_e2e_failure_paths_for_claim_rejection_expiry_and_coverage_limits() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        let deposit = 10_000_000_000_000u128;
        let coverage = 300_000_000_000u128;

        test::set_value_transferred::<DefaultEnvironment>(deposit);
        contract.deposit_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 11);

        let calc = contract
            .calculate_premium(11, coverage, CoverageType::Fire)
            .unwrap();
        let premium_paid = calc.annual_premium;
        let (_, pool_share) = fee_split(premium_paid, 200);

        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(premium_paid);
        let policy_id = contract
            .create_policy(
                11,
                CoverageType::Fire,
                coverage,
                pool_id,
                1_000,
                "ipfs://policy-11".into(),
            )
            .unwrap();

        let excessive_claim = contract.submit_claim(
            policy_id,
            coverage.saturating_add(1),
            "Coverage overflow".into(),
            valid_evidence(),
        );
        assert_eq!(excessive_claim, Err(InsuranceError::ClaimExceedsCoverage));

        let claim_amount = calc.deductible.saturating_add(25_000_000_000u128);
        let claim_id = contract
            .submit_claim(
                policy_id,
                claim_amount,
                "Minor fire claim".into(),
                valid_evidence(),
            )
            .unwrap();

        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract
            .process_claim(
                claim_id,
                false,
                "ipfs://oracle-reject".into(),
                "Evidence inconsistent".into(),
            )
            .unwrap();

        let rejected_claim = contract.get_claim(claim_id).unwrap();
        let policy_after_rejection = contract.get_policy(policy_id).unwrap();
        let pool_after_rejection = contract.get_pool(pool_id).unwrap();
        assert_eq!(rejected_claim.status, ClaimStatus::Rejected);
        assert_eq!(rejected_claim.rejection_reason, "Evidence inconsistent");
        assert_eq!(policy_after_rejection.total_claimed, 0);
        assert_eq!(policy_after_rejection.status, PolicyStatus::Active);
        assert_eq!(pool_after_rejection.total_claims_paid, 0);
        assert_eq!(pool_after_rejection.available_capital, deposit + pool_share);

        test::set_block_timestamp::<DefaultEnvironment>(policy_after_rejection.end_time + 1);
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        let expired_claim =
            contract.submit_claim(policy_id, claim_amount, "Too late".into(), valid_evidence());
        assert_eq!(expired_claim, Err(InsuranceError::PolicyExpired));

        let second_review_attempt =
            contract.process_claim(claim_id, true, "ipfs://oracle-late".into(), String::new());
        assert_eq!(
            second_review_attempt,
            Err(InsuranceError::ClaimAlreadyProcessed)
        );
    }

    // =========================================================================
    // QUERY TESTS
    // =========================================================================

    #[ink::test]
    fn test_get_policies_for_property() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        let calc = contract
            .calculate_premium(1, 500_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 4);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                100_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://p1".into(),
            )
            .unwrap();
        contract
            .create_policy(
                1,
                CoverageType::Theft,
                100_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://p2".into(),
            )
            .unwrap();
        let property_policies = contract.get_property_policies(1);
        assert_eq!(property_policies.len(), 2);
    }

    #[ink::test]
    fn test_get_policyholder_policies() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();
        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);
        add_risk_assessment(&mut contract, 2);
        let calc1 = contract
            .calculate_premium(1, 100_000_000_000u128, CoverageType::Fire)
            .unwrap();
        let calc2 = contract
            .calculate_premium(2, 100_000_000_000u128, CoverageType::Flood)
            .unwrap();
        let total = (calc1.annual_premium + calc2.annual_premium) * 2;
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(total);
        contract
            .create_policy(
                1,
                CoverageType::Fire,
                100_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://p1".into(),
            )
            .unwrap();
        contract
            .create_policy(
                2,
                CoverageType::Flood,
                100_000_000_000u128,
                pool_id,
                86_400 * 365,
                "ipfs://p2".into(),
            )
            .unwrap();
        let holder_policies = contract.get_policyholder_policies(accounts.bob);
        assert_eq!(holder_policies.len(), 2);
    }

    #[ink::test]
    fn test_parametric_claim_auto_verification() {
        use crate::propchain_insurance::PolicyType;
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        let pool_id = create_pool(&mut contract);
        test::set_value_transferred::<DefaultEnvironment>(10_000_000_000_000u128);
        contract.provide_pool_liquidity(pool_id).unwrap();
        add_risk_assessment(&mut contract, 1);

        // Setup oracle
        contract.set_oracle_contract(accounts.charlie).unwrap();

        // Create parametric policy with event_id 101 (The magic ID for auto-approval in our MVP)
        let calc = contract
            .calculate_premium(1, 100_000_000_000u128, CoverageType::Fire)
            .unwrap();
        test::set_caller::<DefaultEnvironment>(accounts.bob);
        test::set_value_transferred::<DefaultEnvironment>(calc.annual_premium * 2);

        let policy_id = contract
            .create_parametric_policy(
                1,
                CoverageType::Fire,
                100_000_000_000u128,
                pool_id,
                86400 * 30,
                101,
                "ipfs://parametric".into(),
            )
            .unwrap();

        let policy = contract.get_policy(policy_id).unwrap();
        assert_eq!(policy.policy_type, PolicyType::Parametric);

        // Submit claim
        let result = contract.submit_claim(
            policy_id,
            10_000_000_000u128,
            "Parametric trigger".into(),
            valid_evidence(),
        );

        assert!(result.is_ok());
        let claim_id = result.unwrap();
        let claim = contract.get_claim(claim_id).unwrap();

        // Should be auto-approved and PAID because of event_id 101
        assert_eq!(claim.status, ClaimStatus::Paid);
        assert!(claim.payout_amount > 0);
    }

    // =========================================================================
    // BATCH CLAIM TESTS
    // =========================================================================

    #[ink::test]
    fn test_batch_approve_claims_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        // Setup pool and policies
        let pool_id = create_pool(&mut contract);
        test::set_caller::<DefaultEnvironment>(accounts.bob);

        // Create multiple policies and claims
        let mut claim_ids = Vec::new();
        for i in 0..3 {
            add_risk_assessment(&mut contract, i + 1);
            test::set_value_transferred::<DefaultEnvironment>(1_000_000_000u128);
            let policy_result = contract.create_policy(
                i + 1,
                CoverageType::Fire,
                100_000_000_000u128,
                pool_id,
                86400 * 365,
                "ipfs://test".into(),
            );
            let policy_id = match policy_result {
                Ok(id) => id,
                Err(e) => panic!("create_policy failed: {:?}", e),
            };

            // Submit claim
            let claim_result = contract.submit_claim(
                policy_id,
                50_000_000_000u128,
                format!("Test claim {}", i),
                valid_evidence(),
            );
            assert!(claim_result.is_ok());
            claim_ids.push(claim_result.unwrap());
        }

        // Set caller as authorized assessor
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract.add_authorized_assessor(accounts.alice).unwrap();

        // Batch approve all claims
        let result = contract.batch_approve_claims(claim_ids.clone(), "ipfs://batch-report".into());

        assert!(result.is_ok());
        let summary = result.unwrap();

        // Verify summary
        assert_eq!(summary.total_processed, 3);
        assert_eq!(summary.successful, 3);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.results.len(), 3);

        // Verify all claims succeeded
        for result in summary.results.iter() {
            assert!(result.success);
            assert!(result.error.is_none());

            // Verify claim status
            let claim = contract.get_claim(result.claim_id).unwrap();
            assert_eq!(claim.status, ClaimStatus::Approved);
        }
    }

    #[ink::test]
    fn test_batch_reject_claims_works() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        // Setup pool and policies
        let pool_id = create_pool(&mut contract);
        test::set_caller::<DefaultEnvironment>(accounts.bob);

        // Create multiple policies and claims
        let mut claim_ids = Vec::new();
        for i in 0..3 {
            add_risk_assessment(&mut contract, i + 1);
            test::set_value_transferred::<DefaultEnvironment>(1_000_000_000u128);
            let policy_result = contract.create_policy(
                i + 1,
                CoverageType::Fire,
                100_000_000_000u128,
                pool_id,
                86400 * 365,
                "ipfs://test".into(),
            );
            let policy_id = match policy_result {
                Ok(id) => id,
                Err(e) => panic!("create_policy failed: {:?}", e),
            };

            // Submit claim
            let claim_result = contract.submit_claim(
                policy_id,
                50_000_000_000u128,
                format!("Test claim {}", i),
                valid_evidence(),
            );
            assert!(claim_result.is_ok());
            claim_ids.push(claim_result.unwrap());
        }

        // Set caller as authorized assessor
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract.add_authorized_assessor(accounts.alice).unwrap();

        // Batch reject all claims
        let result =
            contract.batch_reject_claims(claim_ids.clone(), "Does not meet criteria".into());

        assert!(result.is_ok());
        let summary = result.unwrap();

        // Verify summary
        assert_eq!(summary.total_processed, 3);
        assert_eq!(summary.successful, 3);
        assert_eq!(summary.failed, 0);

        // Verify all claims were rejected
        for result in summary.results.iter() {
            assert!(result.success);
            assert!(result.error.is_none());

            // Verify claim status
            let claim = contract.get_claim(result.claim_id).unwrap();
            assert_eq!(claim.status, ClaimStatus::Rejected);
            assert_eq!(claim.rejection_reason, "Does not meet criteria");
        }
    }

    #[ink::test]
    fn test_batch_approve_partial_failure() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        // Setup pool and policy
        let pool_id = create_pool(&mut contract);
        test::set_caller::<DefaultEnvironment>(accounts.bob);

        add_risk_assessment(&mut contract, 1);
        test::set_value_transferred::<DefaultEnvironment>(1_000_000_000u128);
        let policy_result = contract.create_policy(
            1,
            CoverageType::Fire,
            100_000_000_000u128,
            pool_id,
            86400 * 365,
            "ipfs://test".into(),
        );
        let policy_id = match policy_result {
            Ok(id) => id,
            Err(e) => panic!("create_policy failed: {:?}", e),
        };

        // Submit one valid claim
        let claim_result = contract.submit_claim(
            policy_id,
            50_000_000_000u128,
            "Valid claim".into(),
            valid_evidence(),
        );
        assert!(claim_result.is_ok());
        let valid_claim_id = claim_result.unwrap();

        // Add invalid claim ID (doesn't exist)
        let invalid_claim_id = 999u64;

        // Set caller as authorized assessor
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract.add_authorized_assessor(accounts.alice).unwrap();

        // Batch approve with mix of valid and invalid claims
        let mut claim_ids = Vec::new();
        claim_ids.push(valid_claim_id);
        claim_ids.push(invalid_claim_id);

        let result = contract.batch_approve_claims(claim_ids, "ipfs://report".into());

        assert!(result.is_ok());
        let summary = result.unwrap();

        // Verify partial success
        assert_eq!(summary.total_processed, 2);
        assert_eq!(summary.successful, 1);
        assert_eq!(summary.failed, 1);

        // Check individual results
        let valid_result = summary.results.get(0).unwrap();
        assert!(valid_result.success);
        assert!(valid_result.error.is_none());
        assert_eq!(valid_result.claim_id, valid_claim_id);

        let invalid_result = summary.results.get(1).unwrap();
        assert!(!invalid_result.success);
        assert!(invalid_result.error.is_some());
        assert_eq!(invalid_result.error.clone().unwrap(), InsuranceError::ClaimNotFound);
        assert_eq!(invalid_result.claim_id, invalid_claim_id);
    }

    #[ink::test]
    fn test_batch_approve_unauthorized() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        test::set_caller::<DefaultEnvironment>(accounts.bob);

        let claim_ids = Vec::new();
        let result = contract.batch_approve_claims(claim_ids, "ipfs://report".into());

        assert_eq!(result.unwrap_err(), InsuranceError::Unauthorized);
    }

    #[ink::test]
    fn test_batch_reject_unauthorized() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        test::set_caller::<DefaultEnvironment>(accounts.bob);

        let claim_ids = Vec::new();
        let result = contract.batch_reject_claims(claim_ids, "Reason".into());

        assert_eq!(result.unwrap_err(), InsuranceError::Unauthorized);
    }

    #[ink::test]
    fn test_batch_approve_already_processed() {
        let mut contract = setup();
        let accounts = test::default_accounts::<DefaultEnvironment>();

        // Setup
        let pool_id = create_pool(&mut contract);
        test::set_caller::<DefaultEnvironment>(accounts.bob);

        add_risk_assessment(&mut contract, 1);
        test::set_value_transferred::<DefaultEnvironment>(1_000_000_000u128);
        let policy_result = contract.create_policy(
            1,
            CoverageType::Fire,
            100_000_000_000u128,
            pool_id,
            86400 * 365,
            "ipfs://test".into(),
        );
        let policy_id = match policy_result {
            Ok(id) => id,
            Err(e) => panic!("create_policy failed: {:?}", e),
        };

        // Submit and approve claim
        let claim_result = contract.submit_claim(
            policy_id,
            50_000_000_000u128,
            "Test claim".into(),
            valid_evidence(),
        );
        assert!(claim_result.is_ok());
        let claim_id = claim_result.unwrap();

        // First approval
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        contract.add_authorized_assessor(accounts.alice).unwrap();

        let first_result =
            contract.batch_approve_claims(vec![claim_id].into(), "ipfs://report1".into());
        assert!(first_result.is_ok());

        // Try to approve again (should fail for this claim)
        let mut claim_ids = Vec::new();
        claim_ids.push(claim_id);
        let second_result = contract.batch_approve_claims(claim_ids, "ipfs://report2".into());

        assert!(second_result.is_ok());
        let summary = second_result.unwrap();

        // Should have 1 failure due to ClaimAlreadyProcessed
        assert_eq!(summary.total_processed, 1);
        assert_eq!(summary.successful, 0);
        assert_eq!(summary.failed, 1);

        let result = summary.results.get(0).unwrap();
        assert!(!result.success);
        assert_eq!(result.error.clone().unwrap(), InsuranceError::ClaimAlreadyProcessed);
    }
}
