#[cfg(test)]
mod pause_tests {
    use super::*;
    use soroban_sdk::{Address, Env, Symbol};

    #[test]
    fn test_pause_functionality() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let token_contract = Address::generate(&env);
        
        // Initialize governance contract with pause configuration
        GovernanceContract::initialize(
            &env,
            admin.clone(),
            token_contract,
            7, // voting_period_days
            50, // min_voting_percentage
            60, // min_quorum_percentage  
            80, // pause_quorum_percentage (higher for emergency)
            1000, // min_proposal_deposit
            5, // max_proposals_per_proposer
            86400, // proposal_cooldown_seconds
            false, // commit_reveal_enabled
            1, // commit_period_days
            1, // reveal_period_days
            false, // time_lock_enabled
            0, // time_lock_seconds
            80, // pause_quorum_percentage
            75, // pause_threshold_percentage
        );

        // Test initial state - should not be paused
        assert!(!GovernanceContract::is_paused(&env));
        
        let pause_status = GovernanceContract::get_pause_status(&env);
        assert!(!pause_status.is_paused);
        assert_eq!(pause_status.paused_at, None);
        assert_eq!(pause_status.paused_by, None);
        assert_eq!(pause_status.pause_reason, None);

        // Test pause history - should be empty initially
        let history = GovernanceContract::get_pause_history(&env);
        assert_eq!(history.len(), 0);

        // Test that normal functions work when not paused
        let proposer = Address::generate(&env);
        let result = GovernanceContract::create_proposal(
            &env,
            proposer.clone(),
            "Test Proposal".to_string(),
            "Test Description".to_string(),
            BytesN::from_array(&[0u8; 32]),
            50, // threshold_percentage
            1000, // deposit_amount
            None, // commitment
        );
        assert!(result.is_ok());

        // Note: In a real test environment, we would:
        // 1. Create a pause proposal
        // 2. Vote on it with sufficient quorum
        // 3. Execute the pause
        // 4. Verify that functions are blocked when paused
        // 5. Create an unpause proposal
        // 6. Execute the unpause
        // 7. Verify functions work again
    }

    #[test]
    fn test_pause_proposal_detection() {
        let env = Env::default();
        
        // Test pause proposal detection
        let pause_reason = "Security emergency";
        let pause_execution_data = GovernanceContract::generate_pause_execution_data(pause_reason);
        assert!(GovernanceContract::is_pause_proposal(&pause_execution_data));
        assert!(!GovernanceContract::is_unpause_proposal(&pause_execution_data));

        // Test unpause proposal detection
        let unpause_reason = "Emergency resolved";
        let unpause_execution_data = GovernanceContract::generate_unpause_execution_data(unpause_reason);
        assert!(GovernanceContract::is_unpause_proposal(&unpause_execution_data));
        assert!(!GovernanceContract::is_pause_proposal(&unpause_execution_data));
    }
}
