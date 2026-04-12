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

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
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
    }

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
        pub evidence_url: String,
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

    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode, ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct PoolLiquidityProvider {
        pub provider: AccountId,
        pub pool_id: u64,
        pub deposited_amount: u128,
        pub share_percentage: u32, // In basis points (10000 = 100%)
        pub deposited_at: u64,
        pub last_reward_claim: u64,
        pub accumulated_rewards: u128,
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
    pub struct PolicyCancelled {
        #[ink(topic)]
        policy_id: u64,
        #[ink(topic)]
        policyholder: AccountId,
        cancelled_at: u64,
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
                platform_fee_rate: 200,            // 2%
                claim_cooldown_period: 2_592_000,  // 30 days in seconds
                min_pool_capital: 100_000_000_000, // Minimum pool capital
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
            };

            self.pools.insert(&pool_id, &pool);
            Ok(pool_id)
        }

        /// Provide liquidity to a pool
        #[ink(message, payable)]
        pub fn provide_pool_liquidity(&mut self, pool_id: u64) -> Result<(), InsuranceError> {
            let caller = self.env().caller();
            let amount = self.env().transferred_value();

            let mut pool = self
                .pools
                .get(&pool_id)
                .ok_or(InsuranceError::PoolNotFound)?;
            if !pool.is_active {
                return Err(InsuranceError::PoolNotFound);
            }

            pool.total_capital += amount;
            pool.available_capital += amount;
            self.pools.insert(&pool_id, &pool);

            // Update liquidity provider record
            let key = (pool_id, caller);
            let mut provider =
                self.liquidity_providers
                    .get(&key)
                    .unwrap_or(PoolLiquidityProvider {
                        provider: caller,
                        pool_id,
                        deposited_amount: 0,
                        share_percentage: 0,
                        deposited_at: self.env().block_timestamp(),
                        last_reward_claim: self.env().block_timestamp(),
                        accumulated_rewards: 0,
                    });
            provider.deposited_amount += amount;
            self.liquidity_providers.insert(&key, &provider);

            // Track providers per pool
            let mut providers = self.pool_providers.get(&pool_id).unwrap_or_default();
            if !providers.contains(&caller) {
                providers.push(caller);
                self.pool_providers.insert(&pool_id, &providers);
            }

            self.env().emit_event(PoolCapitalized {
                pool_id,
                provider: caller,
                amount,
                timestamp: self.env().block_timestamp(),
            });

            Ok(())
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

            // Check pool has enough capital for coverage
            let max_exposure = pool
                .available_capital
                .saturating_mul(pool.max_coverage_ratio as u128)
                / 10_000;
            if coverage_amount > max_exposure {
                return Err(InsuranceError::InsufficientPoolFunds);
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

            // Update pool
            pool.total_premiums_collected += pool_share;
            pool.available_capital += pool_share;
            pool.active_policies += 1;
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

            self.env().emit_event(PolicyCancelled {
                policy_id,
                policyholder: policy.policyholder,
                cancelled_at: self.env().block_timestamp(),
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
            evidence_url: String,
        ) -> Result<u64, InsuranceError> {
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
                evidence_url,
                oracle_report_url: String::new(),
                status: ClaimStatus::Pending,
                submitted_at: now,
                processed_at: None,
                payout_amount: 0,
                assessor: None,
                rejection_reason: String::new(),
            };

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
        // REINSURANCE
        // =====================================================================

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
        ClaimStatus, CoverageType, InsuranceError, PolicyStatus, PropertyInsurance,
    };

    fn setup() -> PropertyInsurance {
        let accounts = test::default_accounts::<DefaultEnvironment>();
        test::set_caller::<DefaultEnvironment>(accounts.alice);
        // Start at 35 days so `now - last_claim(0) > 30-day cooldown`
        test::set_block_timestamp::<DefaultEnvironment>(3_000_000);
        PropertyInsurance::new(accounts.alice)
    }

    fn add_risk_assessment(contract: &mut PropertyInsurance, property_id: u64) {
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
            "ipfs://evidence123".into(),
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
            "ipfs://evidence".into(),
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
            "ipfs://x".into(),
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
                "ipfs://evidence".into(),
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
        assert_eq!(provider.deposited_amount, 5_000_000_000_000u128);
        assert_eq!(provider.pool_id, pool_id);
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
}
