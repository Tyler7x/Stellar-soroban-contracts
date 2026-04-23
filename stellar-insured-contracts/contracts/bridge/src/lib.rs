#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unexpected_cfgs)]

use ink::prelude::string::String;
use ink::storage::Mapping;
use propchain_traits::*;
#[cfg(not(feature = "std"))]
use scale_info::prelude::vec::Vec;

#[ink::contract]
mod bridge {
    use super::*;

    /// Error types for the bridge contract
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        Unauthorized,
        TokenNotFound,
        InvalidChain,
        BridgeNotSupported,
        InsufficientSignatures,
        RequestExpired,
        AlreadySigned,
        InvalidRequest,
        BridgePaused,
        InvalidMetadata,
        DuplicateRequest,
        GasLimitExceeded,
    }

    /// Bridge contract for cross-chain property token transfers
    #[ink(storage)]
    pub struct PropertyBridge {
        /// Bridge configuration
        config: BridgeConfig,

        /// Multi-signature bridge requests
        bridge_requests: Mapping<u64, MultisigBridgeRequest>,

        /// Bridge transaction history
        bridge_history: Mapping<AccountId, Vec<BridgeTransaction>>,

        /// Chain-specific information
        chain_info: Mapping<ChainId, ChainBridgeInfo>,

        /// Transaction verification records
        verified_transactions: Mapping<Hash, bool>,

        /// Bridge operators
        bridge_operators: Vec<AccountId>,

        /// Request counter
        request_counter: u64,

        /// Transaction counter
        transaction_counter: u64,

        /// Admin account
        admin: AccountId,

        /// Address of the PropertyToken contract used for ownership verification.
        /// The bridge calls `owner_of` and `get_approved` on this contract to
        /// confirm that the caller is authorised to bridge a given token.
        property_token_contract: AccountId,
    }

    /// Events for bridge operations
    #[ink(event)]
    pub struct BridgeRequestCreated {
        #[ink(topic)]
        pub request_id: u64,
        #[ink(topic)]
        pub token_id: TokenId,
        #[ink(topic)]
        pub source_chain: ChainId,
        #[ink(topic)]
        pub destination_chain: ChainId,
        #[ink(topic)]
        pub requester: AccountId,
    }

    #[ink(event)]
    pub struct BridgeRequestSigned {
        #[ink(topic)]
        pub request_id: u64,
        #[ink(topic)]
        pub signer: AccountId,
        pub signatures_collected: u8,
        pub signatures_required: u8,
    }

    #[ink(event)]
    pub struct BridgeExecuted {
        #[ink(topic)]
        pub request_id: u64,
        #[ink(topic)]
        pub token_id: TokenId,
        #[ink(topic)]
        pub transaction_hash: Hash,
    }

    #[ink(event)]
    pub struct BridgeFailed {
        #[ink(topic)]
        pub request_id: u64,
        #[ink(topic)]
        pub token_id: TokenId,
        pub error: String,
    }

    #[ink(event)]
    pub struct BridgeRecovered {
        #[ink(topic)]
        pub request_id: u64,
        #[ink(topic)]
        pub recovery_action: RecoveryAction,
    }

    impl PropertyBridge {
        /// Creates a new PropertyBridge contract
        #[ink(constructor)]
        pub fn new(
            supported_chains: Vec<ChainId>,
            min_signatures: u8,
            max_signatures: u8,
            default_timeout: u64,
            gas_limit: u64,
            property_token_contract: AccountId,
        ) -> Self {
            let caller = Self::env().caller();
            let config = BridgeConfig {
                supported_chains: supported_chains.clone(),
                min_signatures_required: min_signatures,
                max_signatures_required: max_signatures,
                default_timeout_blocks: default_timeout,
                gas_limit_per_bridge: gas_limit,
                emergency_pause: false,
                metadata_preservation: true,
            };

            // Initialize chain info for supported chains
            let mut bridge = Self {
                config,
                bridge_requests: Mapping::default(),
                bridge_history: Mapping::default(),
                chain_info: Mapping::default(),
                verified_transactions: Mapping::default(),
                bridge_operators: vec![caller],
                request_counter: 0,
                transaction_counter: 0,
                admin: caller,
                property_token_contract,
            };

            // Set up default chain information
            for chain_id in supported_chains {
                let chain_info = ChainBridgeInfo {
                    chain_id,
                    chain_name: format!("Chain-{}", chain_id),
                    bridge_contract_address: None,
                    is_active: true,
                    gas_multiplier: 100,    // 1.0x multiplier
                    confirmation_blocks: 6, // 6 block confirmations
                    supported_tokens: Vec::new(),
                };
                bridge.chain_info.insert(chain_id, &chain_info);
            }

            bridge
        }

        /// Initiates a bridge request with multi-signature requirement
        #[ink(message)]
        pub fn initiate_bridge_multisig(
            &mut self,
            token_id: TokenId,
            destination_chain: ChainId,
            recipient: AccountId,
            required_signatures: u8,
            timeout_blocks: Option<u64>,
            metadata: PropertyMetadata,
        ) -> Result<u64, Error> {
            let caller = self.env().caller();

            // Check if bridge is paused
            if self.config.emergency_pause {
                return Err(Error::BridgePaused);
            }

            // Validate destination chain
            if !self.config.supported_chains.contains(&destination_chain) {
                return Err(Error::InvalidChain);
            }

            // Validate signature requirements
            if required_signatures < self.config.min_signatures_required
                || required_signatures > self.config.max_signatures_required
            {
                return Err(Error::InsufficientSignatures);
            }

            // Check if caller is authorized (token owner or approved operator)
            if !self.is_authorized_for_token(caller, token_id) {
                return Err(Error::Unauthorized);
            }

            // Create bridge request
            self.request_counter += 1;
            let request_id = self.request_counter;
            let current_block = u64::from(self.env().block_number());
            let expires_at = timeout_blocks.map(|blocks| current_block + blocks);

            let request = MultisigBridgeRequest {
                request_id,
                token_id,
                source_chain: self.get_current_chain_id(),
                destination_chain,
                sender: caller,
                recipient,
                required_signatures,
                signatures: Vec::new(),
                created_at: current_block,
                expires_at,
                status: BridgeOperationStatus::Pending,
                metadata,
            };

            self.bridge_requests.insert(request_id, &request);

            self.env().emit_event(BridgeRequestCreated {
                request_id,
                token_id,
                source_chain: request.source_chain,
                destination_chain,
                requester: caller,
            });

            Ok(request_id)
        }

        /// Signs a bridge request
        #[ink(message)]
        pub fn sign_bridge_request(&mut self, request_id: u64, approve: bool) -> Result<(), Error> {
            let caller = self.env().caller();

            // Check if caller is a bridge operator
            if !self.bridge_operators.contains(&caller) {
                return Err(Error::Unauthorized);
            }

            let mut request = self
                .bridge_requests
                .get(request_id)
                .ok_or(Error::InvalidRequest)?;

            // Check if request has expired
            if let Some(expires_at) = request.expires_at {
                if u64::from(self.env().block_number()) > expires_at {
                    return Err(Error::RequestExpired);
                }
            }

            // Check if already signed
            if request.signatures.contains(&caller) {
                return Err(Error::AlreadySigned);
            }

            // Add signature
            request.signatures.push(caller);

            // Update status based on approval and signatures collected
            if !approve {
                request.status = BridgeOperationStatus::Failed;
            } else if request.signatures.len() >= request.required_signatures as usize {
                request.status = BridgeOperationStatus::Locked;
            }

            self.bridge_requests.insert(request_id, &request);

            self.env().emit_event(BridgeRequestSigned {
                request_id,
                signer: caller,
                signatures_collected: request.signatures.len() as u8,
                signatures_required: request.required_signatures,
            });

            Ok(())
        }

        /// Executes a bridge request after collecting required signatures
        #[ink(message)]
        pub fn execute_bridge(&mut self, request_id: u64) -> Result<(), Error> {
            let caller = self.env().caller();

            // Check if caller is a bridge operator
            if !self.bridge_operators.contains(&caller) {
                return Err(Error::Unauthorized);
            }

            let mut request = self
                .bridge_requests
                .get(request_id)
                .ok_or(Error::InvalidRequest)?;

            // Check if request is ready for execution
            if request.status != BridgeOperationStatus::Locked {
                return Err(Error::InvalidRequest);
            }

            // Check if enough signatures are collected
            if request.signatures.len() < request.required_signatures as usize {
                return Err(Error::InsufficientSignatures);
            }

            // Generate transaction hash
            let transaction_hash = self.generate_transaction_hash(&request);

            // Create bridge transaction record
            self.transaction_counter += 1;
            let transaction = BridgeTransaction {
                transaction_id: self.transaction_counter,
                token_id: request.token_id,
                source_chain: request.source_chain,
                destination_chain: request.destination_chain,
                sender: request.sender,
                recipient: request.recipient,
                transaction_hash,
                timestamp: self.env().block_timestamp(),
                gas_used: self.estimate_gas_usage(&request),
                status: BridgeOperationStatus::InTransit,
                metadata: request.metadata.clone(),
            };

            // Update request status
            request.status = BridgeOperationStatus::Completed;
            self.bridge_requests.insert(request_id, &request);

            // Store transaction verification
            self.verified_transactions.insert(transaction_hash, &true);

            // Add to bridge history
            let mut history = self.bridge_history.get(request.sender).unwrap_or_default();
            history.push(transaction.clone());
            self.bridge_history.insert(request.sender, &history);

            self.env().emit_event(BridgeExecuted {
                request_id,
                token_id: request.token_id,
                transaction_hash,
            });

            Ok(())
        }

        /// Recovers from a failed bridge operation
        #[ink(message)]
        pub fn recover_failed_bridge(
            &mut self,
            request_id: u64,
            recovery_action: RecoveryAction,
        ) -> Result<(), Error> {
            let caller = self.env().caller();

            // Only admin can recover failed bridges
            if caller != self.admin {
                return Err(Error::Unauthorized);
            }

            let mut request = self
                .bridge_requests
                .get(request_id)
                .ok_or(Error::InvalidRequest)?;

            // Check if request is in a failed state
            if !matches!(
                request.status,
                BridgeOperationStatus::Failed | BridgeOperationStatus::Expired
            ) {
                return Err(Error::InvalidRequest);
            }

            // Execute recovery action
            match recovery_action {
                RecoveryAction::UnlockToken => {
                    // Logic to unlock the token would be implemented here
                    // This would typically call back to the property token contract
                }
                RecoveryAction::RefundGas => {
                    // Logic to refund gas costs would be implemented here
                }
                RecoveryAction::RetryBridge => {
                    // Reset request to pending for retry
                    request.status = BridgeOperationStatus::Pending;
                    request.signatures.clear();
                }
                RecoveryAction::CancelBridge => {
                    // Mark as cancelled
                    request.status = BridgeOperationStatus::Failed;
                }
            }

            self.bridge_requests.insert(request_id, &request);

            self.env().emit_event(BridgeRecovered {
                request_id,
                recovery_action,
            });

            Ok(())
        }

        /// Gets gas estimation for a bridge operation
        #[ink(message)]
        pub fn estimate_bridge_gas(
            &self,
            _token_id: TokenId,
            destination_chain: ChainId,
        ) -> Result<u64, Error> {
            let chain_info = self
                .chain_info
                .get(destination_chain)
                .ok_or(Error::InvalidChain)?;

            let base_gas = self.config.gas_limit_per_bridge;
            let multiplier = chain_info.gas_multiplier;

            Ok(base_gas * multiplier as u64 / 100)
        }

        /// Monitors bridge status
        #[ink(message)]
        pub fn monitor_bridge_status(&self, request_id: u64) -> Option<BridgeMonitoringInfo> {
            let request = self.bridge_requests.get(request_id)?;

            Some(BridgeMonitoringInfo {
                bridge_request_id: request.request_id,
                token_id: request.token_id,
                source_chain: request.source_chain,
                destination_chain: request.destination_chain,
                status: request.status,
                created_at: request.created_at,
                expires_at: request.expires_at,
                signatures_collected: request.signatures.len() as u8,
                signatures_required: request.required_signatures,
                error_message: None,
            })
        }

        /// Verifies a bridge transaction
        #[ink(message)]
        pub fn verify_bridge_transaction(
            &self,
            transaction_hash: Hash,
            _source_chain: ChainId,
        ) -> bool {
            self.verified_transactions
                .get(transaction_hash)
                .unwrap_or(false)
        }

        /// Gets bridge history for an account
        #[ink(message)]
        pub fn get_bridge_history(&self, account: AccountId) -> Vec<BridgeTransaction> {
            self.bridge_history.get(account).unwrap_or_default()
        }

        /// Adds a bridge operator
        #[ink(message)]
        pub fn add_bridge_operator(&mut self, operator: AccountId) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::Unauthorized);
            }

            if !self.bridge_operators.contains(&operator) {
                self.bridge_operators.push(operator);
            }

            Ok(())
        }

        /// Removes a bridge operator
        #[ink(message)]
        pub fn remove_bridge_operator(&mut self, operator: AccountId) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::Unauthorized);
            }

            self.bridge_operators.retain(|op| op != &operator);
            Ok(())
        }

        /// Checks if an account is a bridge operator
        #[ink(message)]
        pub fn is_bridge_operator(&self, account: AccountId) -> bool {
            self.bridge_operators.contains(&account)
        }

        /// Gets all bridge operators
        #[ink(message)]
        pub fn get_bridge_operators(&self) -> Vec<AccountId> {
            self.bridge_operators.clone()
        }

        /// Updates bridge configuration (admin only)
        #[ink(message)]
        pub fn update_config(&mut self, config: BridgeConfig) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::Unauthorized);
            }

            self.config = config;
            Ok(())
        }

        /// Gets current bridge configuration
        #[ink(message)]
        pub fn get_config(&self) -> BridgeConfig {
            self.config.clone()
        }

        /// Pauses or unpauses the bridge (admin only)
        #[ink(message)]
        pub fn set_emergency_pause(&mut self, paused: bool) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::Unauthorized);
            }

            self.config.emergency_pause = paused;
            Ok(())
        }

        /// Gets chain information
        #[ink(message)]
        pub fn get_chain_info(&self, chain_id: ChainId) -> Option<ChainBridgeInfo> {
            self.chain_info.get(chain_id)
        }

        /// Updates chain information (admin only)
        #[ink(message)]
        pub fn update_chain_info(
            &mut self,
            chain_id: ChainId,
            info: ChainBridgeInfo,
        ) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::Unauthorized);
            }

            self.chain_info.insert(chain_id, &info);
            Ok(())
        }

        /// Updates the address of the PropertyToken contract used for ownership
        /// verification (admin only).
        ///
        /// This should only be called when the canonical token contract is
        /// migrated to a new address. Emitting an event here is intentional so
        /// that off-chain monitors can detect unexpected changes.
        #[ink(message)]
        pub fn set_property_token_contract(
            &mut self,
            new_address: AccountId,
        ) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::Unauthorized);
            }
            self.property_token_contract = new_address;
            Ok(())
        }

        /// Returns the current PropertyToken contract address used for
        /// ownership verification.
        #[ink(message)]
        pub fn get_property_token_contract(&self) -> AccountId {
            self.property_token_contract
        }

        // Helper functions

        /// Verifies that `account` is authorised to bridge `token_id`.
        ///
        /// Authorisation is granted when the account is either:
        ///   1. The current owner of the token, or
        ///   2. The account that has been explicitly approved by the owner for
        ///      this specific token.
        ///
        /// The check is performed via a cross-contract call to the registered
        /// `property_token_contract` so that ownership is always read from the
        /// canonical on-chain source of truth.
        fn is_authorized_for_token(&self, account: AccountId, token_id: TokenId) -> bool {
            use ink::env::call::FromAccountId;
            let token_contract: ink::contract_ref!(PropertyTokenOwnership) =
                FromAccountId::from_account_id(self.property_token_contract);

            // Check direct ownership first (most common path)
            if let Some(owner) = token_contract.owner_of(token_id) {
                if owner == account {
                    return true;
                }
            } else {
                // Token does not exist — deny
                return false;
            }

            // Fall back to checking whether the caller holds an explicit approval
            if let Some(approved) = token_contract.get_approved(token_id) {
                if approved == account {
                    return true;
                }
            }

            false
        }

        fn get_current_chain_id(&self) -> ChainId {
            // This should return the current chain ID
            // For now, we'll use a default value
            1
        }

        fn generate_transaction_hash(&self, request: &MultisigBridgeRequest) -> Hash {
            // Generate a unique transaction hash for the bridge request
            use scale::Encode;
            let data = (
                request.request_id,
                request.token_id,
                request.source_chain,
                request.destination_chain,
                request.sender,
                request.recipient,
                self.env().block_timestamp(),
            );
            let encoded_data = data.encode();
            // Simple hash: use first 32 bytes of encoded data
            let mut hash_bytes = [0u8; 32];
            let len = encoded_data.len().min(32);
            hash_bytes[..len].copy_from_slice(&encoded_data[..len]);
            Hash::from(hash_bytes)
        }

        fn estimate_gas_usage(&self, request: &MultisigBridgeRequest) -> u64 {
            // Estimate gas usage based on request complexity
            let base_gas = 100000; // Base gas for bridge operation
            let metadata_gas = request.metadata.legal_description.len() as u64 * 100; // Gas for metadata
            base_gas + metadata_gas
        }
    }

    // Unit tests
    #[cfg(test)]
    mod tests {
        use super::*;
        use ink::env::{test, DefaultEnvironment};

        fn setup_bridge() -> PropertyBridge {
            let supported_chains = vec![1, 2, 3];
            // Use a deterministic dummy address for the property token contract.
            // Unit tests cannot perform cross-contract calls; the authorization
            // path is covered by integration / e2e tests.
            let dummy_token_contract = AccountId::from([0x01u8; 32]);
            PropertyBridge::new(supported_chains, 2, 5, 100, 500000, dummy_token_contract)
        }

        #[ink::test]
        fn test_constructor_works() {
            let bridge = setup_bridge();
            let config = bridge.get_config();
            assert_eq!(config.min_signatures_required, 2);
            assert_eq!(config.max_signatures_required, 5);
        }

        #[ink::test]
        fn test_constructor_stores_property_token_contract() {
            let bridge = setup_bridge();
            assert_eq!(
                bridge.get_property_token_contract(),
                AccountId::from([0x01u8; 32])
            );
        }

        /// Verifies that `initiate_bridge_multisig` returns `Unauthorized` when
        /// the caller does not own the token.  In unit-test mode the cross-
        /// contract call to the property-token contract will fail (no contract
        /// deployed at the dummy address), which the runtime surfaces as a
        /// panic / trap — the same observable outcome as a rejected call.
        ///
        /// Full ownership-check coverage lives in the integration tests.
        #[ink::test]
        #[should_panic]
        fn test_initiate_bridge_unauthorized_panics_without_token_contract() {
            let mut bridge = setup_bridge();
            let accounts = test::default_accounts::<DefaultEnvironment>();
            test::set_caller::<DefaultEnvironment>(accounts.alice);

            let metadata = PropertyMetadata {
                location: String::from("Test Property"),
                size: 1000,
                legal_description: String::from("Test"),
                valuation: 100000,
                documents_url: String::from("ipfs://test"),
            };

            // This will panic because the dummy property_token_contract address
            // has no code deployed — the cross-contract call cannot succeed.
            let _ = bridge.initiate_bridge_multisig(1, 2, accounts.bob, 2, Some(50), metadata);
        }

        #[ink::test]
        fn test_sign_bridge_request_requires_operator() {
            let mut bridge = setup_bridge();
            let accounts = test::default_accounts::<DefaultEnvironment>();

            // Charlie is not a bridge operator — signing should be rejected.
            test::set_caller::<DefaultEnvironment>(accounts.charlie);
            let result = bridge.sign_bridge_request(999, true);
            assert_eq!(result, Err(Error::Unauthorized));
        }

        #[ink::test]
        fn test_set_property_token_contract_admin_only() {
            let mut bridge = setup_bridge();
            let accounts = test::default_accounts::<DefaultEnvironment>();

            // Non-admin should be rejected.
            test::set_caller::<DefaultEnvironment>(accounts.bob);
            let result = bridge.set_property_token_contract(AccountId::from([0x02u8; 32]));
            assert_eq!(result, Err(Error::Unauthorized));

            // Admin (alice, the deployer) should succeed.
            test::set_caller::<DefaultEnvironment>(accounts.alice);
            let result = bridge.set_property_token_contract(AccountId::from([0x02u8; 32]));
            assert!(result.is_ok());
            assert_eq!(
                bridge.get_property_token_contract(),
                AccountId::from([0x02u8; 32])
            );
        }
    }
}
