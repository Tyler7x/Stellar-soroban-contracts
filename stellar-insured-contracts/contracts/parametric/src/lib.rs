#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![allow(clippy::arithmetic_side_effects)]

use ink::prelude::vec::Vec;
use ink::storage::Mapping;

/// Parametric Insurance Triggers Contract
///
/// Enables automatic claim payouts based on verifiable external data
/// (weather events, oracle feeds). A trigger fires when an observed
/// value crosses a pre-set threshold, initiating a payout after a
/// configurable dispute window.
#[ink::contract]
mod parametric {
    use super::*;

    // ── Data types ────────────────────────────────────────────────────────────

    /// Category of external data the trigger monitors.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum TriggerType {
        /// Rainfall below threshold (mm)
        Rainfall,
        /// Wind speed above threshold (km/h)
        WindSpeed,
        /// Temperature below threshold (°C × 10)
        Temperature,
        /// Custom oracle metric
        Custom,
    }

    /// Current lifecycle state of a parametric claim.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ClaimStatus {
        /// Trigger condition met; waiting for dispute window to close
        Pending,
        /// Someone raised a dispute during the dispute window
        Disputed,
        /// Dispute window passed with no challenge; payout approved
        Approved,
        /// Payout transferred to policy holder
        Paid,
        /// Claim was rejected after dispute resolution
        Rejected,
    }

    /// Definition of a parametric trigger attached to a policy.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ParametricTrigger {
        /// Unique trigger identifier
        pub id: u64,
        /// Policy holder who receives the payout
        pub policy_holder: AccountId,
        /// Type of event being monitored
        pub trigger_type: TriggerType,
        /// Value that must be reached or exceeded to fire the trigger
        pub threshold: i64,
        /// Payout amount in base units when trigger fires
        pub payout_amount: Balance,
        /// Duration (in seconds) during which a claim can be disputed
        pub dispute_window_seconds: u64,
        /// Whether the trigger is still active
        pub active: bool,
    }

    /// A claim raised because a trigger condition was observed.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ParametricClaim {
        /// Associated trigger
        pub trigger_id: u64,
        /// Observed value that caused the trigger to fire
        pub observed_value: i64,
        /// Block timestamp when the trigger fired
        pub fired_at: u64,
        /// Block timestamp after which the claim can be paid out
        pub dispute_deadline: u64,
        /// Current status of the claim
        pub status: ClaimStatus,
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    #[ink(storage)]
    pub struct ParametricInsurance {
        /// Contract administrator
        admin: AccountId,
        /// Authorised oracle that submits external data readings
        oracle: AccountId,
        /// All registered triggers
        triggers: Mapping<u64, ParametricTrigger>,
        /// Claims indexed by trigger id
        claims: Mapping<u64, ParametricClaim>,
        /// Auto-incrementing trigger counter
        next_trigger_id: u64,
    }

    // ── Events ────────────────────────────────────────────────────────────────

    #[ink(event)]
    pub struct TriggerRegistered {
        #[ink(topic)]
        pub trigger_id: u64,
        pub policy_holder: AccountId,
        pub trigger_type: TriggerType,
        pub threshold: i64,
    }

    #[ink(event)]
    pub struct TriggerFired {
        #[ink(topic)]
        pub trigger_id: u64,
        pub observed_value: i64,
        pub dispute_deadline: u64,
    }

    #[ink(event)]
    pub struct ClaimDisputed {
        #[ink(topic)]
        pub trigger_id: u64,
        pub disputed_by: AccountId,
    }

    #[ink(event)]
    pub struct ClaimPaid {
        #[ink(topic)]
        pub trigger_id: u64,
        pub policy_holder: AccountId,
        pub amount: Balance,
    }

    // ── Errors ────────────────────────────────────────────────────────────────

    #[derive(Debug, PartialEq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        Unauthorised,
        TriggerNotFound,
        TriggerInactive,
        ClaimNotFound,
        DisputeWindowOpen,
        DisputeWindowClosed,
        ClaimAlreadyExists,
        InvalidStatus,
        TransferFailed,
    }

    // ── Implementation ────────────────────────────────────────────────────────

    impl ParametricInsurance {
        /// Deploy the contract, designating an admin and an oracle account.
        #[ink(constructor)]
        pub fn new(oracle: AccountId) -> Self {
            Self {
                admin: Self::env().caller(),
                oracle,
                triggers: Mapping::default(),
                claims: Mapping::default(),
                next_trigger_id: 1,
            }
        }

        /// Register a new parametric trigger for a policy holder.
        ///
        /// Only the admin may call this.
        #[ink(message)]
        pub fn register_trigger(
            &mut self,
            policy_holder: AccountId,
            trigger_type: TriggerType,
            threshold: i64,
            payout_amount: Balance,
            dispute_window_seconds: u64,
        ) -> Result<u64, Error> {
            self.require_admin()?;

            let id = self.next_trigger_id;
            self.next_trigger_id += 1;

            let trigger = ParametricTrigger {
                id,
                policy_holder,
                trigger_type: trigger_type.clone(),
                threshold,
                payout_amount,
                dispute_window_seconds,
                active: true,
            };

            self.triggers.insert(id, &trigger);

            self.env().emit_event(TriggerRegistered {
                trigger_id: id,
                policy_holder,
                trigger_type,
                threshold,
            });

            Ok(id)
        }

        /// Submit an oracle reading for a trigger.
        ///
        /// If `observed_value` meets or exceeds the threshold the trigger fires
        /// and a pending claim is created. Only the designated oracle may call this.
        #[ink(message)]
        pub fn submit_oracle_data(
            &mut self,
            trigger_id: u64,
            observed_value: i64,
        ) -> Result<(), Error> {
            self.require_oracle()?;

            let trigger = self.triggers.get(trigger_id).ok_or(Error::TriggerNotFound)?;

            if !trigger.active {
                return Err(Error::TriggerInactive);
            }

            // A claim already exists for this trigger
            if self.claims.get(trigger_id).is_some() {
                return Err(Error::ClaimAlreadyExists);
            }

            // Check threshold condition
            if observed_value <= trigger.threshold {
                return Ok(()); // Condition not met; nothing to do
            }

            let now = self.env().block_timestamp();
            let dispute_deadline = now + trigger.dispute_window_seconds * 1_000; // ms

            let claim = ParametricClaim {
                trigger_id,
                observed_value,
                fired_at: now,
                dispute_deadline,
                status: ClaimStatus::Pending,
            };

            self.claims.insert(trigger_id, &claim);

            self.env().emit_event(TriggerFired {
                trigger_id,
                observed_value,
                dispute_deadline,
            });

            Ok(())
        }

        /// Raise a dispute against a pending claim within the dispute window.
        #[ink(message)]
        pub fn dispute_claim(&mut self, trigger_id: u64) -> Result<(), Error> {
            let mut claim = self.claims.get(trigger_id).ok_or(Error::ClaimNotFound)?;

            if claim.status != ClaimStatus::Pending {
                return Err(Error::InvalidStatus);
            }

            let now = self.env().block_timestamp();
            if now >= claim.dispute_deadline {
                return Err(Error::DisputeWindowClosed);
            }

            claim.status = ClaimStatus::Disputed;
            self.claims.insert(trigger_id, &claim);

            self.env().emit_event(ClaimDisputed {
                trigger_id,
                disputed_by: self.env().caller(),
            });

            Ok(())
        }

        /// Process payout for an approved claim once the dispute window has closed.
        ///
        /// Anyone may call this; the contract verifies the window has passed.
        #[ink(message)]
        pub fn process_payout(&mut self, trigger_id: u64) -> Result<(), Error> {
            let mut claim = self.claims.get(trigger_id).ok_or(Error::ClaimNotFound)?;
            let trigger = self.triggers.get(trigger_id).ok_or(Error::TriggerNotFound)?;

            if claim.status != ClaimStatus::Pending {
                return Err(Error::InvalidStatus);
            }

            let now = self.env().block_timestamp();
            if now < claim.dispute_deadline {
                return Err(Error::DisputeWindowOpen);
            }

            claim.status = ClaimStatus::Approved;
            self.claims.insert(trigger_id, &claim);

            // Transfer payout to policy holder
            if self
                .env()
                .transfer(trigger.policy_holder, trigger.payout_amount)
                .is_err()
            {
                return Err(Error::TransferFailed);
            }

            let mut paid_claim = self.claims.get(trigger_id).ok_or(Error::ClaimNotFound)?;
            paid_claim.status = ClaimStatus::Paid;
            self.claims.insert(trigger_id, &paid_claim);

            self.env().emit_event(ClaimPaid {
                trigger_id,
                policy_holder: trigger.policy_holder,
                amount: trigger.payout_amount,
            });

            Ok(())
        }

        /// Deactivate a trigger so it no longer fires. Admin only.
        #[ink(message)]
        pub fn deactivate_trigger(&mut self, trigger_id: u64) -> Result<(), Error> {
            self.require_admin()?;
            let mut trigger = self.triggers.get(trigger_id).ok_or(Error::TriggerNotFound)?;
            trigger.active = false;
            self.triggers.insert(trigger_id, &trigger);
            Ok(())
        }

        /// Read a trigger definition.
        #[ink(message)]
        pub fn get_trigger(&self, trigger_id: u64) -> Option<ParametricTrigger> {
            self.triggers.get(trigger_id)
        }

        /// Read the current claim for a trigger.
        #[ink(message)]
        pub fn get_claim(&self, trigger_id: u64) -> Option<ParametricClaim> {
            self.claims.get(trigger_id)
        }

        /// Return the active oracle account.
        #[ink(message)]
        pub fn get_oracle(&self) -> AccountId {
            self.oracle
        }

        /// Update the oracle account. Admin only.
        #[ink(message)]
        pub fn set_oracle(&mut self, new_oracle: AccountId) -> Result<(), Error> {
            self.require_admin()?;
            self.oracle = new_oracle;
            Ok(())
        }

        // ── Private helpers ───────────────────────────────────────────────────

        fn require_admin(&self) -> Result<(), Error> {
            if self.env().caller() != self.admin {
                return Err(Error::Unauthorised);
            }
            Ok(())
        }

        fn require_oracle(&self) -> Result<(), Error> {
            if self.env().caller() != self.oracle {
                return Err(Error::Unauthorised);
            }
            Ok(())
        }
    }
}
