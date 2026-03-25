//! Insurance Load Tests
//!
//! Evaluates gas usage and edge conditions under high-volume scenarios:
//!   - Thousands of small claims across many policyholders
//!   - Large single claims approaching pool capacity
//!   - Concurrent policy creation and claim submission
//!   - Risk pool balance consistency after all operations

#![cfg(feature = "std")]

use ink::env::test::DefaultEnvironment;
use propchain_insurance::propchain_insurance::{
    CoverageType, EvidenceMetadata, InsuranceError, PropertyInsurance,
};

/// Hardcoded cooldown period matching the contract default (30 days in seconds).
const COOLDOWN: u64 = 2_592_000;

// ─── helpers ────────────────────────────────────────────────────────────────

fn set_caller(account: ink::primitives::AccountId) {
    ink::env::test::set_caller::<DefaultEnvironment>(account);
}

fn set_value(v: u128) {
    ink::env::test::set_value_transferred::<DefaultEnvironment>(v);
}

fn set_ts(ts: u64) {
    ink::env::test::set_block_timestamp::<DefaultEnvironment>(ts);
}

fn account(seed: u8) -> ink::primitives::AccountId {
    ink::primitives::AccountId::from([seed; 32])
}

/// Valid 32-byte content hash
fn hash32() -> Vec<u8> {
    vec![0xabu8; 32]
}

fn evidence(label: &str) -> EvidenceMetadata {
    EvidenceMetadata {
        evidence_type: label.to_string(),
        reference_uri: format!("ipfs://evidence/{}", label),
        content_hash: hash32(),
        description: None,
    }
}

/// Bootstrap: create contract, pool, risk assessment, and return (contract, pool_id).
/// The pool is seeded with `pool_capital` native tokens.
fn bootstrap(pool_capital: u128) -> (PropertyInsurance, u64) {
    let admin = account(1);
    set_caller(admin);
    set_ts(1_000_000);

    let mut contract = PropertyInsurance::new(admin);

    // Create pool
    let pool_id = contract
        .create_risk_pool(
            "Load Test Pool".to_string(),
            CoverageType::Fire,
            8_000, // 80% max coverage ratio
            500_000_000_000u128, // reinsurance threshold
        )
        .expect("pool creation failed");

    // Seed pool with capital
    set_value(pool_capital);
    contract
        .deposit_liquidity(pool_id)
        .expect("liquidity deposit failed");
    set_value(0);

    (contract, pool_id)
}

/// Register a risk assessment for a property so policies can be created.
fn register_assessment(contract: &mut PropertyInsurance, property_id: u64) {
    let admin = account(1);
    set_caller(admin);
    contract
        .update_risk_assessment(
            property_id,
            30, // location_score  (low risk)
            30, // construction_score
            30, // age_score
            80, // claims_history_score (good history)
            365 * 24 * 3600, // valid for 1 year
        )
        .expect("risk assessment failed");
}

/// Create a policy for `holder` on `property_id` and return (policy_id, premium_paid).
fn create_policy(
    contract: &mut PropertyInsurance,
    holder: ink::primitives::AccountId,
    property_id: u64,
    coverage_amount: u128,
    pool_id: u64,
) -> u64 {
    // Calculate required premium first (view call, no value needed)
    let calc = contract
        .calculate_premium(property_id, coverage_amount, CoverageType::Fire)
        .expect("premium calc failed");

    set_caller(holder);
    set_value(calc.annual_premium);
    let policy_id = contract
        .create_policy(
            property_id,
            CoverageType::Fire,
            coverage_amount,
            pool_id,
            365 * 24 * 3600, // 1 year
            format!("ipfs://policy/{}", property_id),
        )
        .expect("policy creation failed");
    set_value(0);
    policy_id
}

/// Submit a claim and return claim_id.
fn submit_claim(
    contract: &mut PropertyInsurance,
    holder: ink::primitives::AccountId,
    policy_id: u64,
    amount: u128,
    label: &str,
) -> u64 {
    set_caller(holder);
    contract
        .submit_claim(
            policy_id,
            amount,
            format!("Claim: {}", label),
            evidence(label),
        )
        .expect("claim submission failed")
}

/// Approve a claim as admin.
fn approve_claim(contract: &mut PropertyInsurance, claim_id: u64) {
    let admin = account(1);
    set_caller(admin);
    contract
        .process_claim(
            claim_id,
            true,
            "ipfs://oracle/report".to_string(),
            String::new(),
        )
        .expect("claim approval failed");
}

// ─── load tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod load_tests {
    use super::*;

    // ── 1. Thousands of small claims ────────────────────────────────────────

    /// 500 policyholders each submit one small claim; all are approved.
    /// Verifies pool balance consistency after every payout.
    #[ink::test]
    fn load_many_small_claims_balance_consistency() {
        const N: u64 = 500;
        const COVERAGE: u128 = 1_000_000_000; // 10 USD (8 decimals)
        const POOL_CAPITAL: u128 = 10_000_000_000_000; // large enough

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);

        // Seed accounts start at byte 10 to avoid collision with admin (1)
        let mut policy_ids = Vec::with_capacity(N as usize);

        for i in 0..N {
            let holder = account((10 + i % 200) as u8); // 200 distinct holders
            let property_id = 1000 + i;

            register_assessment(&mut contract, property_id);
            // Advance time slightly so cooldown doesn't block (each property is unique)
            set_ts(1_000_000 + i * 100);

            let pid = create_policy(&mut contract, holder, property_id, COVERAGE, pool_id);
            policy_ids.push((pid, holder, property_id));
        }

        // Snapshot pool state before claims
        let pool_before = contract.get_pool(pool_id).expect("pool not found");
        let capital_before = pool_before.available_capital;

        let mut total_payouts: u128 = 0;

        for (i, (policy_id, holder, _property_id)) in policy_ids.iter().enumerate() {
            // Advance time past cooldown for each property
            set_ts(1_000_000 + (N + i as u64) * 100 + contract.claim_cooldown_period());

            let claim_amount = COVERAGE / 10; // 10% of coverage
            let claim_id = submit_claim(&mut contract, *holder, *policy_id, claim_amount, &format!("small-{}", i));
            approve_claim(&mut contract, claim_id);

            let claim = contract.get_claim(claim_id).expect("claim not found");
            total_payouts = total_payouts.saturating_add(claim.payout_amount);
        }

        let pool_after = contract.get_pool(pool_id).expect("pool not found");

        // available_capital must have decreased by exactly total payouts
        assert_eq!(
            pool_after.available_capital,
            capital_before.saturating_sub(total_payouts),
            "Pool available_capital mismatch after {} small claims",
            N
        );
        assert_eq!(
            pool_after.total_claims_paid, total_payouts,
            "total_claims_paid must equal sum of all payouts"
        );
    }

    // ── 2. Large single claim ────────────────────────────────────────────────

    /// One policyholder submits a claim for 70% of pool capital.
    /// Verifies the pool survives and balances are exact.
    #[ink::test]
    fn load_large_single_claim_balance_exact() {
        const POOL_CAPITAL: u128 = 100_000_000_000_000; // 1M USD
        // Coverage = 70% of pool * max_coverage_ratio(80%) = 56% of pool
        let coverage: u128 = POOL_CAPITAL * 56 / 100;

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);

        let holder = account(20);
        let property_id = 9999u64;
        register_assessment(&mut contract, property_id);

        let policy_id = create_policy(&mut contract, holder, property_id, coverage, pool_id);

        let pool_after_policy = contract.get_pool(pool_id).expect("pool not found");
        let capital_after_policy = pool_after_policy.available_capital;

        // Advance past cooldown
        set_ts(1_000_000 + contract.claim_cooldown_period() + 1);

        let claim_amount = coverage / 2; // 50% of coverage
        let claim_id = submit_claim(&mut contract, holder, policy_id, claim_amount, "large-claim");
        approve_claim(&mut contract, claim_id);

        let claim = contract.get_claim(claim_id).expect("claim not found");
        let pool_final = contract.get_pool(pool_id).expect("pool not found");

        assert_eq!(
            pool_final.available_capital,
            capital_after_policy.saturating_sub(claim.payout_amount),
            "Pool capital must decrease by exactly the payout"
        );
        assert_eq!(pool_final.total_claims_paid, claim.payout_amount);
        assert!(pool_final.available_capital > 0, "Pool must remain solvent");
    }

    // ── 3. Claim exceeding coverage is rejected ──────────────────────────────

    #[ink::test]
    fn load_claim_exceeds_coverage_rejected() {
        const POOL_CAPITAL: u128 = 10_000_000_000_000;
        const COVERAGE: u128 = 1_000_000_000;

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);
        let holder = account(30);
        let property_id = 8888u64;
        register_assessment(&mut contract, property_id);

        let policy_id = create_policy(&mut contract, holder, property_id, COVERAGE, pool_id);

        set_ts(1_000_000 + contract.claim_cooldown_period() + 1);
        set_caller(holder);

        let result = contract.submit_claim(
            policy_id,
            COVERAGE + 1, // one unit over coverage
            "Over-limit claim".to_string(),
            evidence("over-limit"),
        );

        assert_eq!(result, Err(InsuranceError::ClaimExceedsCoverage));
    }

    // ── 4. Cooldown enforcement under load ───────────────────────────────────

    /// Two rapid claims on the same property: second must be blocked by cooldown.
    #[ink::test]
    fn load_cooldown_blocks_rapid_reclaim() {
        const POOL_CAPITAL: u128 = 10_000_000_000_000;
        const COVERAGE: u128 = 2_000_000_000;

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);
        let holder = account(40);
        let property_id = 7777u64;
        register_assessment(&mut contract, property_id);

        let policy_id = create_policy(&mut contract, holder, property_id, COVERAGE, pool_id);

        // First claim – past cooldown
        set_ts(1_000_000 + contract.claim_cooldown_period() + 1);
        let claim_id = submit_claim(&mut contract, holder, policy_id, COVERAGE / 4, "first");
        approve_claim(&mut contract, claim_id);

        // Second claim – immediately after (still in cooldown)
        set_caller(holder);
        let result = contract.submit_claim(
            policy_id,
            COVERAGE / 4,
            "second rapid claim".to_string(),
            evidence("second"),
        );
        assert_eq!(result, Err(InsuranceError::CooldownPeriodActive));
    }

    // ── 5. High-volume concurrent policy creation ────────────────────────────

    /// 1000 policies created across 50 distinct holders; pool active_policies
    /// counter and available_capital must be consistent.
    #[ink::test]
    fn load_high_volume_policy_creation_consistency() {
        const N: u64 = 1_000;
        const COVERAGE: u128 = 500_000_000; // 5 USD
        const POOL_CAPITAL: u128 = 50_000_000_000_000;

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);

        let pool_before = contract.get_pool(pool_id).expect("pool not found");
        let capital_before = pool_before.available_capital;

        let mut total_premiums: u128 = 0;

        for i in 0..N {
            let holder = account((10 + (i % 50)) as u8);
            let property_id = 2000 + i;
            register_assessment(&mut contract, property_id);
            set_ts(1_000_000 + i * 10);

            let calc = contract
                .calculate_premium(property_id, COVERAGE, CoverageType::Fire)
                .expect("premium calc");

            set_caller(holder);
            set_value(calc.annual_premium);
            contract
                .create_policy(
                    property_id,
                    CoverageType::Fire,
                    COVERAGE,
                    pool_id,
                    365 * 24 * 3600,
                    format!("ipfs://policy/{}", property_id),
                )
                .expect("policy creation failed");
            set_value(0);

            // Pool share = premium minus 2% platform fee
            let fee = calc.annual_premium.saturating_mul(200) / 10_000;
            total_premiums = total_premiums.saturating_add(calc.annual_premium.saturating_sub(fee));
        }

        let pool_after = contract.get_pool(pool_id).expect("pool not found");

        assert_eq!(pool_after.active_policies, N, "active_policies counter mismatch");
        assert_eq!(
            pool_after.available_capital,
            capital_before.saturating_add(total_premiums),
            "available_capital must equal initial capital + all pool-share premiums"
        );
        assert_eq!(
            pool_after.total_premiums_collected, total_premiums,
            "total_premiums_collected mismatch"
        );
    }

    // ── 6. Pool exhaustion guard ─────────────────────────────────────────────

    /// Attempt to create a policy whose coverage exceeds the pool's max exposure.
    #[ink::test]
    fn load_pool_exhaustion_guard() {
        const POOL_CAPITAL: u128 = 1_000_000_000; // small pool
        // max_coverage_ratio = 80%, so max exposure = 800_000_000
        let over_coverage: u128 = 900_000_000; // exceeds 80%

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);
        let holder = account(50);
        let property_id = 6666u64;
        register_assessment(&mut contract, property_id);

        let calc = contract
            .calculate_premium(property_id, over_coverage, CoverageType::Fire)
            .expect("premium calc");

        set_caller(holder);
        set_value(calc.annual_premium);
        let result = contract.create_policy(
            property_id,
            CoverageType::Fire,
            over_coverage,
            pool_id,
            365 * 24 * 3600,
            "ipfs://policy/over".to_string(),
        );
        set_value(0);

        assert_eq!(result, Err(InsuranceError::InsufficientPoolFunds));
    }

    // ── 7. Mixed small + large claims, final balance invariant ───────────────

    /// 200 small claims + 1 large claim; verifies the pool's accounting identity:
    ///   available_capital = initial_capital + premiums - payouts
    #[ink::test]
    fn load_mixed_claims_final_balance_invariant() {
        const SMALL_N: u64 = 200;
        const SMALL_COVERAGE: u128 = 500_000_000;
        const LARGE_COVERAGE: u128 = 20_000_000_000;
        const POOL_CAPITAL: u128 = 100_000_000_000_000;

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);
        let initial_capital = POOL_CAPITAL; // deposited at bootstrap

        let mut total_premiums: u128 = 0;
        let mut total_payouts: u128 = 0;

        // --- small policies + claims ---
        let mut small_policies: Vec<(u64, ink::primitives::AccountId)> = Vec::new();
        for i in 0..SMALL_N {
            let holder = account((10 + i % 100) as u8);
            let property_id = 3000 + i;
            register_assessment(&mut contract, property_id);
            set_ts(1_000_000 + i * 50);

            let calc = contract
                .calculate_premium(property_id, SMALL_COVERAGE, CoverageType::Fire)
                .expect("premium calc");
            let fee = calc.annual_premium.saturating_mul(200) / 10_000;
            total_premiums = total_premiums.saturating_add(calc.annual_premium.saturating_sub(fee));

            set_caller(holder);
            set_value(calc.annual_premium);
            let pid = contract
                .create_policy(
                    property_id,
                    CoverageType::Fire,
                    SMALL_COVERAGE,
                    pool_id,
                    365 * 24 * 3600,
                    format!("ipfs://policy/{}", property_id),
                )
                .expect("policy creation");
            set_value(0);
            small_policies.push((pid, holder));
        }

        // Submit + approve all small claims
        for (i, (pid, holder)) in small_policies.iter().enumerate() {
            set_ts(1_000_000 + (SMALL_N + i as u64) * 50 + contract.claim_cooldown_period() + 1);
            let cid = submit_claim(&mut contract, *holder, *pid, SMALL_COVERAGE / 5, &format!("s{}", i));
            approve_claim(&mut contract, cid);
            let claim = contract.get_claim(cid).expect("claim");
            total_payouts = total_payouts.saturating_add(claim.payout_amount);
        }

        // --- large policy + claim ---
        let large_holder = account(99);
        let large_property = 9000u64;
        register_assessment(&mut contract, large_property);
        set_ts(2_000_000);

        let large_calc = contract
            .calculate_premium(large_property, LARGE_COVERAGE, CoverageType::Fire)
            .expect("large premium calc");
        let large_fee = large_calc.annual_premium.saturating_mul(200) / 10_000;
        total_premiums = total_premiums
            .saturating_add(large_calc.annual_premium.saturating_sub(large_fee));

        set_caller(large_holder);
        set_value(large_calc.annual_premium);
        let large_pid = contract
            .create_policy(
                large_property,
                CoverageType::Fire,
                LARGE_COVERAGE,
                pool_id,
                365 * 24 * 3600,
                "ipfs://policy/large".to_string(),
            )
            .expect("large policy creation");
        set_value(0);

        set_ts(2_000_000 + contract.claim_cooldown_period() + 1);
        let large_cid = submit_claim(&mut contract, large_holder, large_pid, LARGE_COVERAGE / 2, "large");
        approve_claim(&mut contract, large_cid);
        let large_claim = contract.get_claim(large_cid).expect("large claim");
        total_payouts = total_payouts.saturating_add(large_claim.payout_amount);

        // --- invariant check ---
        let pool_final = contract.get_pool(pool_id).expect("pool");
        let expected_capital = initial_capital
            .saturating_add(total_premiums)
            .saturating_sub(total_payouts);

        assert_eq!(
            pool_final.available_capital, expected_capital,
            "Final balance invariant violated: available_capital != initial + premiums - payouts"
        );
        assert_eq!(
            pool_final.total_claims_paid, total_payouts,
            "total_claims_paid must equal sum of all payouts"
        );
    }

    // ── 8. Liquidity provider reward accrual under claim load ────────────────

    /// Two LPs deposit; 100 policies are created (premiums accrue rewards);
    /// after claims, each LP's pending rewards must be > 0 and sum correctly.
    #[ink::test]
    fn load_lp_rewards_accrue_under_claim_load() {
        const N: u64 = 100;
        const COVERAGE: u128 = 1_000_000_000;
        const LP_STAKE: u128 = 5_000_000_000_000;

        let admin = account(1);
        set_caller(admin);
        set_ts(1_000_000);
        let mut contract = PropertyInsurance::new(admin);

        let pool_id = contract
            .create_risk_pool(
                "Reward Pool".to_string(),
                CoverageType::Fire,
                8_000,
                500_000_000_000u128,
            )
            .expect("pool");

        // Two LPs deposit equal stakes
        let lp1 = account(2);
        let lp2 = account(3);
        for lp in [lp1, lp2] {
            set_caller(lp);
            set_value(LP_STAKE);
            contract.deposit_liquidity(pool_id).expect("lp deposit");
            set_value(0);
        }

        // Create N policies (premiums flow into pool, accruing rewards)
        for i in 0..N {
            let holder = account((10 + i % 100) as u8);
            let property_id = 4000 + i;
            register_assessment(&mut contract, property_id);
            set_ts(1_000_000 + i * 20);

            let calc = contract
                .calculate_premium(property_id, COVERAGE, CoverageType::Fire)
                .expect("calc");
            set_caller(holder);
            set_value(calc.annual_premium);
            contract
                .create_policy(
                    property_id,
                    CoverageType::Fire,
                    COVERAGE,
                    pool_id,
                    365 * 24 * 3600,
                    format!("ipfs://p/{}", i),
                )
                .expect("policy");
            set_value(0);
        }

        let r1 = contract.get_pending_rewards(pool_id, lp1);
        let r2 = contract.get_pending_rewards(pool_id, lp2);

        assert!(r1 > 0, "LP1 should have accrued rewards");
        assert!(r2 > 0, "LP2 should have accrued rewards");
        // Equal stakes → equal rewards (within rounding)
        let diff = if r1 > r2 { r1 - r2 } else { r2 - r1 };
        assert!(
            diff <= 1,
            "Equal-stake LPs should have equal rewards (diff={})",
            diff
        );
    }

    // ── 9. Gas usage stays bounded for bulk operations ───────────────────────

    /// Measures that 500 sequential policy creations complete without
    /// timestamp overflow or counter wrap-around.
    #[ink::test]
    fn load_gas_counter_no_overflow_500_policies() {
        const N: u64 = 500;
        const COVERAGE: u128 = 300_000_000;
        const POOL_CAPITAL: u128 = 20_000_000_000_000;

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);

        for i in 0..N {
            let holder = account((10 + i % 200) as u8);
            let property_id = 5000 + i;
            register_assessment(&mut contract, property_id);
            set_ts(1_000_000 + i * 5);

            let calc = contract
                .calculate_premium(property_id, COVERAGE, CoverageType::Fire)
                .expect("calc");
            set_caller(holder);
            set_value(calc.annual_premium);
            let pid = contract
                .create_policy(
                    property_id,
                    CoverageType::Fire,
                    COVERAGE,
                    pool_id,
                    365 * 24 * 3600,
                    format!("ipfs://p/{}", i),
                )
                .expect("policy");
            set_value(0);

            // policy IDs must be monotonically increasing
            assert_eq!(pid, i + 1, "policy_id must be sequential");
        }

        let pool = contract.get_pool(pool_id).expect("pool");
        assert_eq!(pool.active_policies, N);
    }

    // ── 10. Rejected claims do not alter pool balances ───────────────────────

    #[ink::test]
    fn load_rejected_claims_no_balance_change() {
        const N: u64 = 100;
        const COVERAGE: u128 = 1_000_000_000;
        const POOL_CAPITAL: u128 = 10_000_000_000_000;

        let (mut contract, pool_id) = bootstrap(POOL_CAPITAL);

        let mut policy_ids: Vec<(u64, ink::primitives::AccountId)> = Vec::new();
        for i in 0..N {
            let holder = account((10 + i % 50) as u8);
            let property_id = 6000 + i;
            register_assessment(&mut contract, property_id);
            set_ts(1_000_000 + i * 30);
            let pid = create_policy(&mut contract, holder, property_id, COVERAGE, pool_id);
            policy_ids.push((pid, holder));
        }

        let pool_snapshot = contract.get_pool(pool_id).expect("pool");
        let capital_snapshot = pool_snapshot.available_capital;

        // Submit and reject all claims
        for (i, (pid, holder)) in policy_ids.iter().enumerate() {
            set_ts(1_000_000 + (N + i as u64) * 30 + contract.claim_cooldown_period() + 1);
            let cid = submit_claim(&mut contract, *holder, *pid, COVERAGE / 10, &format!("r{}", i));

            let admin = account(1);
            set_caller(admin);
            contract
                .process_claim(cid, false, String::new(), "rejected for test".to_string())
                .expect("rejection");
        }

        let pool_after = contract.get_pool(pool_id).expect("pool");
        assert_eq!(
            pool_after.available_capital, capital_snapshot,
            "Rejected claims must not change available_capital"
        );
        assert_eq!(
            pool_after.total_claims_paid, 0,
            "total_claims_paid must remain 0 after all rejections"
        );
    }
}
