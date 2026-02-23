//! Cross-Network Configuration Contract for Veritasor
//!
//! This contract stores network-specific parameters needed for deploying
//! Veritasor contracts across multiple Stellar networks (e.g., testnet, mainnet).
//! It allows for centralized network configuration management with governance
//! controls and supports adding new networks without contract redeployment.
//!
//! # Features
//! - Per-network configuration storage (assets, fee policies, registry addresses)
//! - Admin and DAO-based governance for updates
//! - Read APIs for other contracts to query network parameters
//! - Network migration support
//! - Emergency pause/unpause functionality

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec, Map, Symbol};

/// Unique identifier for a Stellar network
pub type NetworkId = u32;

/// Role constants for access control
pub const ROLE_ADMIN: u32 = 1;
pub const ROLE_GOVERNANCE: u32 = 2;
pub const ROLE_OPERATOR: u32 = 4;

/// Data keys for contract storage
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum DataKey {
    /// Contract initialization flag
    Initialized,
    /// Admin address
    Admin,
    /// Governance DAO address
    GovernanceDao,
    /// Emergency pause state
    Paused,
    /// Network configuration for a specific network
    NetworkConfig(NetworkId),
    /// List of all registered network IDs
    RegisteredNetworks,
    /// Default network ID
    DefaultNetwork,
    /// Role bitmap for an address
    Role(Address),
    /// List of all addresses with any role
    RoleHolders,
    /// Network version counter for tracking updates
    NetworkVersion(NetworkId),
    /// Global configuration version
    GlobalVersion,
}

/// Fee policy configuration for a network
/// 
/// Defines how fees are calculated and collected on this network
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct FeePolicy {
    /// Token contract address used for fee payments
    pub fee_token: Address,
    /// Address that receives collected fees
    pub fee_collector: Address,
    /// Base fee amount in token smallest units
    pub base_fee: i128,
    /// Whether fee collection is enabled on this network
    pub enabled: bool,
    /// Maximum fee cap (0 = no cap)
    pub max_fee: i128,
    /// Minimum fee floor
    pub min_fee: i128,
}

/// Asset configuration for a network
///
/// Defines properties of an allowed asset on a specific network
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct AssetConfig {
    /// Asset contract address
    pub asset_address: Address,
    /// Asset code (e.g., "USDC", "XLM")
    pub asset_code: String,
    /// Number of decimal places
    pub decimals: u32,
    /// Whether this asset is approved for attestations
    pub is_active: bool,
    /// Maximum attestation amount for this asset (0 = unlimited)
    pub max_attestation_value: i128,
}

/// Contract registry addresses for a network
///
/// Stores addresses of related Veritasor contracts deployed on this network
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ContractRegistry {
    /// Attestation contract address
    pub attestation_contract: Option<Address>,
    /// Revenue stream contract address
    pub revenue_stream_contract: Option<Address>,
    /// Audit log contract address
    pub audit_log_contract: Option<Address>,
    /// Aggregated attestations contract address
    pub aggregated_attestations_contract: Option<Address>,
    /// Integration registry contract address
    pub integration_registry_contract: Option<Address>,
    /// Attestation snapshot contract address
    pub attestation_snapshot_contract: Option<Address>,
}

/// Network-specific configuration
///
/// Complete configuration for deploying and operating on a specific Stellar network
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct NetworkConfig {
    /// Human-readable network name (e.g., "Testnet", "Mainnet", "Futurenet")
    pub name: String,
    /// Network passphrase (e.g., "Test SDF Network ; September 2015")
    pub network_passphrase: String,
    /// Whether this network is currently active and supported
    pub is_active: bool,
    /// Fee policy for this network
    pub fee_policy: FeePolicy,
    /// List of allowed assets for attestations
    pub allowed_assets: Vec<AssetConfig>,
    /// Contract registry for this network
    pub contracts: ContractRegistry,
    /// Network-specific parameters (e.g., block time, finality threshold)
    pub block_time_seconds: u32,
    /// Minimum attestations required for aggregation
    pub min_attestations_for_aggregate: u32,
    /// Dispute resolution timeout in seconds
    pub dispute_timeout_seconds: u64,
    /// Maximum attestation period length in seconds
    pub max_period_length_seconds: u64,
    /// Timestamp when this config was created
    pub created_at: u64,
    /// Timestamp when this config was last updated
    pub updated_at: u64,
}

/// Governance proposal for configuration changes
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum ConfigProposal {
    /// Add or update a network configuration
    SetNetworkConfig(NetworkId, NetworkConfig),
    /// Update fee policy for an existing network
    UpdateFeePolicy(NetworkId, FeePolicy),
    /// Add or update an asset for a network
    SetAssetConfig(NetworkId, AssetConfig),
    /// Update contract registry
    UpdateContractRegistry(NetworkId, ContractRegistry),
    /// Activate or deactivate a network
    SetNetworkActive(NetworkId, bool),
    /// Set the default network
    SetDefaultNetwork(NetworkId),
    /// Emergency pause all networks
    EmergencyPause,
    /// Emergency unpause all networks
    EmergencyUnpause,
}

/// Events emitted by the contract
mod events {
    use super::*;

    /// Symbol for initialization event
    pub const INITIALIZED: Symbol = symbol_short!("init");
    /// Symbol for network config set event
    pub const NETWORK_SET: Symbol = symbol_short!("net_set");
    /// Symbol for network activated event
    pub const NETWORK_ACTIVE: Symbol = symbol_short!("net_act");
    /// Symbol for fee policy updated event
    pub const FEE_POLICY: Symbol = symbol_short!("fee_pol");
    /// Symbol for asset config set event
    pub const ASSET_SET: Symbol = symbol_short!("asset");
    /// Symbol for registry updated event
    pub const REGISTRY: Symbol = symbol_short!("reg");
    /// Symbol for role granted event
    pub const ROLE_GRANTED: Symbol = symbol_short!("role_g");
    /// Symbol for role revoked event
    pub const ROLE_REVOKED: Symbol = symbol_short!("role_r");
    /// Symbol for pause event
    pub const PAUSED: Symbol = symbol_short!("pause");
    /// Symbol for unpause event
    pub const UNPAUSED: Symbol = symbol_short!("unpause");
    /// Symbol for governance DAO set event
    pub const DAO_SET: Symbol = symbol_short!("dao_set");
    /// Symbol for default network changed event
    pub const DEFAULT_NET: Symbol = symbol_short!("def_net");

    /// Emit initialization event
    pub fn emit_initialized(env: &Env, admin: &Address) {
        env.events().publish((INITIALIZED,), admin.clone());
    }

    /// Emit network configuration set event
    pub fn emit_network_set(env: &Env, network_id: NetworkId, name: &String) {
        env.events().publish((NETWORK_SET, network_id), name.clone());
    }

    /// Emit network activation changed event
    pub fn emit_network_active(env: &Env, network_id: NetworkId, active: bool) {
        env.events().publish((NETWORK_ACTIVE, network_id), active);
    }

    /// Emit fee policy updated event
    pub fn emit_fee_policy(env: &Env, network_id: NetworkId, enabled: bool) {
        env.events().publish((FEE_POLICY, network_id), enabled);
    }

    /// Emit asset configuration set event
    pub fn emit_asset_set(env: &Env, network_id: NetworkId, asset_code: &String) {
        env.events().publish((ASSET_SET, network_id), asset_code.clone());
    }

    /// Emit contract registry updated event
    pub fn emit_registry(env: &Env, network_id: NetworkId) {
        env.events().publish((REGISTRY, network_id), ());
    }

    /// Emit role granted event
    pub fn emit_role_granted(env: &Env, account: &Address, role: u32, granter: &Address) {
        env.events().publish((ROLE_GRANTED, account.clone()), (role, granter.clone()));
    }

    /// Emit role revoked event
    pub fn emit_role_revoked(env: &Env, account: &Address, role: u32, revoker: &Address) {
        env.events().publish((ROLE_REVOKED, account.clone()), (role, revoker.clone()));
    }

    /// Emit pause event
    pub fn emit_paused(env: &Env, caller: &Address) {
        env.events().publish((PAUSED,), caller.clone());
    }

    /// Emit unpause event
    pub fn emit_unpaused(env: &Env, caller: &Address) {
        env.events().publish((UNPAUSED,), caller.clone());
    }

    /// Emit governance DAO set event
    pub fn emit_dao_set(env: &Env, dao: &Address) {
        env.events().publish((DAO_SET,), dao.clone());
    }

    /// Emit default network changed event
    pub fn emit_default_network(env: &Env, network_id: NetworkId) {
        env.events().publish((DEFAULT_NET,), network_id);
    }
}

/// Access control helper functions
mod access_control {
    use super::*;

    /// Check if an address has a specific role
    pub fn has_role(env: &Env, account: &Address, role: u32) -> bool {
        let roles: u32 = env.storage().instance().get(&DataKey::Role(account.clone())).unwrap_or(0);
        (roles & role) != 0
    }

    /// Grant a role to an address
    pub fn grant_role(env: &Env, account: &Address, role: u32) {
        let key = DataKey::Role(account.clone());
        let mut roles: u32 = env.storage().instance().get(&key).unwrap_or(0);
        roles |= role;
        env.storage().instance().set(&key, &roles);

        // Add to role holders list if this is their first role
        if roles == role {
            let holders_key = DataKey::RoleHolders;
            let mut holders: Vec<Address> = env.storage().instance().get(&holders_key).unwrap_or(Vec::new(env));
            holders.push_back(account.clone());
            env.storage().instance().set(&holders_key, &holders);
        }
    }

    /// Revoke a role from an address
    pub fn revoke_role(env: &Env, account: &Address, role: u32) {
        let key = DataKey::Role(account.clone());
        let mut roles: u32 = env.storage().instance().get(&key).unwrap_or(0);
        roles &= !role;
        env.storage().instance().set(&key, &roles);

        // Remove from role holders if no roles remain
        if roles == 0 {
            let holders_key = DataKey::RoleHolders;
            let mut holders: Vec<Address> = env.storage().instance().get(&holders_key).unwrap_or(Vec::new(env));
            if let Some(pos) = holders.iter().position(|a| a == *account) {
                holders.remove(pos as u32);
                env.storage().instance().set(&holders_key, &holders);
            }
        }
    }

    /// Get all roles for an address as a bitmap
    pub fn get_roles(env: &Env, account: &Address) -> u32 {
        env.storage().instance().get(&DataKey::Role(account.clone())).unwrap_or(0)
    }

    /// Get all addresses with any role
    pub fn get_role_holders(env: &Env) -> Vec<Address> {
        env.storage().instance().get(&DataKey::RoleHolders).unwrap_or(Vec::new(env))
    }

    /// Require admin role
    pub fn require_admin(env: &Env, account: &Address) {
        assert!(has_role(env, account, ROLE_ADMIN), "caller must have ADMIN role");
        account.require_auth();
    }

    /// Require governance or admin role
    pub fn require_governance(env: &Env, account: &Address) {
        let roles = get_roles(env, account);
        assert!(
            (roles & (ROLE_ADMIN | ROLE_GOVERNANCE)) != 0,
            "caller must have ADMIN or GOVERNANCE role"
        );
        account.require_auth();
    }

    /// Require operator, governance, or admin role
    pub fn require_operator(env: &Env, account: &Address) {
        let roles = get_roles(env, account);
        assert!(
            (roles & (ROLE_ADMIN | ROLE_GOVERNANCE | ROLE_OPERATOR)) != 0,
            "caller must have ADMIN, GOVERNANCE, or OPERATOR role"
        );
        account.require_auth();
    }

    /// Check if contract is paused
    pub fn is_paused(env: &Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    /// Set pause state
    pub fn set_paused(env: &Env, paused: bool) {
        env.storage().instance().set(&DataKey::Paused, &paused);
    }

    /// Require not paused
    pub fn require_not_paused(env: &Env) {
        assert!(!is_paused(env), "contract is paused");
    }
}

/// Storage helper functions
mod storage {
    use super::*;

    /// Check if contract is initialized
    pub fn is_initialized(env: &Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    /// Set initialized flag
    pub fn set_initialized(env: &Env) {
        env.storage().instance().set(&DataKey::Initialized, &true);
    }

    /// Set admin address
    pub fn set_admin(env: &Env, admin: &Address) {
        env.storage().instance().set(&DataKey::Admin, admin);
    }

    /// Get admin address
    pub fn get_admin(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).expect("admin not set")
    }

    /// Set governance DAO address
    pub fn set_governance_dao(env: &Env, dao: &Address) {
        env.storage().instance().set(&DataKey::GovernanceDao, dao);
    }

    /// Get governance DAO address
    pub fn get_governance_dao(env: &Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::GovernanceDao)
    }

    /// Set network configuration
    pub fn set_network_config(env: &Env, network_id: NetworkId, config: &NetworkConfig) {
        env.storage().instance().set(&DataKey::NetworkConfig(network_id), config);
        
        // Update version
        let version: u32 = env.storage().instance().get(&DataKey::NetworkVersion(network_id)).unwrap_or(0);
        env.storage().instance().set(&DataKey::NetworkVersion(network_id), &(version + 1));
        
        // Add to registered networks if new
        let networks_key = DataKey::RegisteredNetworks;
        let mut networks: Vec<NetworkId> = env.storage().instance().get(&networks_key).unwrap_or(Vec::new(env));
        if !networks.contains(&network_id) {
            networks.push_back(network_id);
            env.storage().instance().set(&networks_key, &networks);
        }
    }

    /// Get network configuration
    pub fn get_network_config(env: &Env, network_id: NetworkId) -> Option<NetworkConfig> {
        env.storage().instance().get(&DataKey::NetworkConfig(network_id))
    }

    /// Get list of registered networks
    pub fn get_registered_networks(env: &Env) -> Vec<NetworkId> {
        env.storage().instance().get(&DataKey::RegisteredNetworks).unwrap_or(Vec::new(env))
    }

    /// Set default network
    pub fn set_default_network(env: &Env, network_id: NetworkId) {
        env.storage().instance().set(&DataKey::DefaultNetwork, &network_id);
    }

    /// Get default network
    pub fn get_default_network(env: &Env) -> Option<NetworkId> {
        env.storage().instance().get(&DataKey::DefaultNetwork)
    }

    /// Get network config version
    pub fn get_network_version(env: &Env, network_id: NetworkId) -> u32 {
        env.storage().instance().get(&DataKey::NetworkVersion(network_id)).unwrap_or(0)
    }

    /// Increment global version
    pub fn increment_global_version(env: &Env) -> u32 {
        let version: u32 = env.storage().instance().get(&DataKey::GlobalVersion).unwrap_or(0);
        let new_version = version + 1;
        env.storage().instance().set(&DataKey::GlobalVersion, &new_version);
        new_version
    }

    /// Get global version
    pub fn get_global_version(env: &Env) -> u32 {
        env.storage().instance().get(&DataKey::GlobalVersion).unwrap_or(0)
    }
}

/// Validation helper functions
mod validation {
    use super::*;

    /// Validate network configuration
    pub fn validate_network_config(env: &Env, config: &NetworkConfig) {
        // Validate name is not empty
        assert!(!config.name.is_empty(), "network name cannot be empty");
        
        // Validate network passphrase is not empty
        assert!(!config.network_passphrase.is_empty(), "network passphrase cannot be empty");
        
        // Validate fee policy
        assert!(config.fee_policy.base_fee >= 0, "base fee must be non-negative");
        assert!(config.fee_policy.min_fee >= 0, "min fee must be non-negative");
        assert!(config.fee_policy.max_fee >= 0, "max fee must be non-negative");
        
        // If max fee is set, it must be >= min fee
        if config.fee_policy.max_fee > 0 {
            assert!(
                config.fee_policy.max_fee >= config.fee_policy.min_fee,
                "max fee must be >= min fee"
            );
        }
        
        // Validate block time is reasonable (between 1 second and 1 hour)
        assert!(
            config.block_time_seconds > 0 && config.block_time_seconds <= 3600,
            "block time must be between 1 and 3600 seconds"
        );
        
        // Validate dispute timeout is reasonable (at least 1 hour)
        assert!(
            config.dispute_timeout_seconds >= 3600,
            "dispute timeout must be at least 1 hour"
        );
        
        // Validate max period length is reasonable (at least 1 day)
        assert!(
            config.max_period_length_seconds >= 86400,
            "max period length must be at least 1 day"
        );
        
        // Validate min attestations for aggregate
        assert!(
            config.min_attestations_for_aggregate > 0,
            "min attestations for aggregate must be > 0"
        );
    }

    /// Validate asset configuration
    pub fn validate_asset_config(env: &Env, config: &AssetConfig) {
        assert!(!config.asset_code.is_empty(), "asset code cannot be empty");
        assert!(config.decimals <= 18, "decimals must be <= 18");
    }

    /// Validate fee policy update
    pub fn validate_fee_policy(policy: &FeePolicy) {
        assert!(policy.base_fee >= 0, "base fee must be non-negative");
        assert!(policy.min_fee >= 0, "min fee must be non-negative");
        assert!(policy.max_fee >= 0, "max fee must be non-negative");
        
        if policy.max_fee > 0 {
            assert!(
                policy.max_fee >= policy.min_fee,
                "max fee must be >= min fee"
            );
        }
    }
}

/// Contract definition
#[contract]
pub struct NetworkConfigContract;

#[contractimpl]
impl NetworkConfigContract {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the network configuration contract.
    ///
    /// Must be called once before any other method. The `admin` address
    /// is granted the ADMIN role and must authorize this call.
    ///
    /// # Arguments
    /// * `admin` - The initial admin address
    /// * `governance_dao` - Optional governance DAO address for DAO-based updates
    pub fn initialize(env: Env, admin: Address, governance_dao: Option<Address>) {
        if storage::is_initialized(&env) {
            panic!("already initialized");
        }
        admin.require_auth();
        
        storage::set_initialized(&env);
        storage::set_admin(&env, &admin);
        access_control::grant_role(&env, &admin, ROLE_ADMIN);
        
        if let Some(dao) = governance_dao.clone() {
            storage::set_governance_dao(&env, &dao);
            access_control::grant_role(&env, &dao, ROLE_GOVERNANCE);
        }
        
        // Set default network to 0 (unset)
        storage::set_default_network(&env, 0);
        
        events::emit_initialized(&env, &admin);
        if let Some(dao) = governance_dao {
            events::emit_dao_set(&env, &dao);
        }
    }

    // ── Admin: Role Management ───────────────────────────────────────

    /// Grant a role to an address.
    ///
    /// Only addresses with ADMIN role can grant roles.
    ///
    /// # Arguments
    /// * `caller` - The admin address authorizing this action
    /// * `account` - The address to grant the role to
    /// * `role` - The role to grant (ROLE_ADMIN, ROLE_GOVERNANCE, or ROLE_OPERATOR)
    pub fn grant_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        access_control::grant_role(&env, &account, role);
        events::emit_role_granted(&env, &account, role, &caller);
    }

    /// Revoke a role from an address.
    ///
    /// Only addresses with ADMIN role can revoke roles. Admin cannot revoke
    /// their own ADMIN role to prevent lockout.
    ///
    /// # Arguments
    /// * `caller` - The admin address authorizing this action
    /// * `account` - The address to revoke the role from
    /// * `role` - The role to revoke
    pub fn revoke_role(env: Env, caller: Address, account: Address, role: u32) {
        access_control::require_admin(&env, &caller);
        
        // Prevent self-lockout: admin cannot revoke their own ADMIN role
        if account == caller && role == ROLE_ADMIN {
            // Check if there are other admins
            let holders = access_control::get_role_holders(&env);
            let admin_count = holders.iter().filter(|h| {
                access_control::has_role(&env, &h, ROLE_ADMIN)
            }).count();
            assert!(admin_count > 1, "cannot revoke last admin role");
        }
        
        access_control::revoke_role(&env, &account, role);
        events::emit_role_revoked(&env, &account, role, &caller);
    }

    /// Check if an address has a specific role.
    ///
    /// # Arguments
    /// * `account` - The address to check
    /// * `role` - The role to check for
    ///
    /// # Returns
    /// `true` if the address has the role, `false` otherwise
    pub fn has_role(env: Env, account: Address, role: u32) -> bool {
        access_control::has_role(&env, &account, role)
    }

    /// Get all roles for an address as a bitmap.
    ///
    /// # Arguments
    /// * `account` - The address to query
    ///
    /// # Returns
    /// Bitmap of all roles assigned to the address
    pub fn get_roles(env: Env, account: Address) -> u32 {
        access_control::get_roles(&env, &account)
    }

    /// Get all addresses with any role.
    ///
    /// # Returns
    /// Vector of all addresses that have been granted any role
    pub fn get_role_holders(env: Env) -> Vec<Address> {
        access_control::get_role_holders(&env)
    }

    // ── Admin: Governance Configuration ─────────────────────────────

    /// Set or update the governance DAO address.
    ///
    /// Only addresses with ADMIN role can set the governance DAO.
    /// The DAO address will be granted GOVERNANCE role.
    ///
    /// # Arguments
    /// * `caller` - The admin address authorizing this action
    /// * `dao` - The new governance DAO address
    pub fn set_governance_dao(env: Env, caller: Address, dao: Address) {
        access_control::require_admin(&env, &caller);
        
        // Revoke old DAO's governance role if exists
        if let Some(old_dao) = storage::get_governance_dao(&env) {
            access_control::revoke_role(&env, &old_dao, ROLE_GOVERNANCE);
        }
        
        storage::set_governance_dao(&env, &dao);
        access_control::grant_role(&env, &dao, ROLE_GOVERNANCE);
        events::emit_dao_set(&env, &dao);
    }

    /// Get the current governance DAO address.
    ///
    /// # Returns
    /// The governance DAO address, or None if not set
    pub fn get_governance_dao(env: Env) -> Option<Address> {
        storage::get_governance_dao(&env)
    }

    // ── Admin/Operator: Pause/Unpause ───────────────────────────────

    /// Pause the contract. Only ADMIN, GOVERNANCE, or OPERATOR can pause.
    ///
    /// When paused, all state-modifying operations are blocked while
    /// read-only queries remain available.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    pub fn pause(env: Env, caller: Address) {
        access_control::require_operator(&env, &caller);
        access_control::set_paused(&env, true);
        events::emit_paused(&env, &caller);
    }

    /// Unpause the contract. Only ADMIN or GOVERNANCE can unpause.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    pub fn unpause(env: Env, caller: Address) {
        access_control::require_governance(&env, &caller);
        access_control::set_paused(&env, false);
        events::emit_unpaused(&env, &caller);
    }

    /// Check if the contract is paused.
    ///
    /// # Returns
    /// `true` if the contract is paused, `false` otherwise
    pub fn is_paused(env: Env) -> bool {
        access_control::is_paused(&env)
    }

    // ── Admin/Governance: Network Configuration ─────────────────────

    /// Set or update a complete network configuration.
    ///
    /// Creates a new network configuration or updates an existing one.
    /// Only ADMIN or GOVERNANCE can set network configurations.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    /// * `network_id` - Unique identifier for the network (e.g., 1 for testnet, 2 for mainnet)
    /// * `config` - The complete network configuration
    pub fn set_network_config(env: Env, caller: Address, network_id: NetworkId, config: NetworkConfig) {
        access_control::require_governance(&env, &caller);
        access_control::require_not_paused(&env);
        
        // Validate network_id is not 0 (reserved for unset default)
        assert!(network_id != 0, "network_id cannot be 0");
        
        // Validate the configuration
        validation::validate_network_config(&env, &config);
        
        storage::set_network_config(&env, network_id, &config);
        storage::increment_global_version(&env);
        
        events::emit_network_set(&env, network_id, &config.name);
    }

    /// Update only the fee policy for an existing network.
    ///
    /// This is a lighter-weight operation than full config update for
    /// common fee adjustments.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    /// * `network_id` - The network to update
    /// * `fee_policy` - The new fee policy
    pub fn update_fee_policy(env: Env, caller: Address, network_id: NetworkId, fee_policy: FeePolicy) {
        access_control::require_governance(&env, &caller);
        access_control::require_not_paused(&env);
        
        validation::validate_fee_policy(&fee_policy);
        
        let mut config = storage::get_network_config(&env, network_id)
            .expect("network config not found");
        
        config.fee_policy = fee_policy.clone();
        config.updated_at = env.ledger().timestamp();
        
        storage::set_network_config(&env, network_id, &config);
        storage::increment_global_version(&env);
        
        events::emit_fee_policy(&env, network_id, fee_policy.enabled);
    }

    /// Add or update an asset configuration for a network.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    /// * `network_id` - The network to update
    /// * `asset_config` - The asset configuration to add or update
    pub fn set_asset_config(env: Env, caller: Address, network_id: NetworkId, asset_config: AssetConfig) {
        access_control::require_governance(&env, &caller);
        access_control::require_not_paused(&env);
        
        validation::validate_asset_config(&env, &asset_config);
        
        let mut config = storage::get_network_config(&env, network_id)
            .expect("network config not found");
        
        // Check if asset already exists and update, otherwise add
        let asset_address = asset_config.asset_address.clone();
        let mut found = false;
        let mut assets = Vec::new(&env);
        
        for existing in config.allowed_assets.iter() {
            if existing.asset_address == asset_address {
                assets.push_back(asset_config.clone());
                found = true;
            } else {
                assets.push_back(existing);
            }
        }
        
        if !found {
            assets.push_back(asset_config.clone());
        }
        
        config.allowed_assets = assets;
        config.updated_at = env.ledger().timestamp();
        
        storage::set_network_config(&env, network_id, &config);
        storage::increment_global_version(&env);
        
        events::emit_asset_set(&env, network_id, &asset_config.asset_code);
    }

    /// Remove an asset from a network's allowed assets.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    /// * `network_id` - The network to update
    /// * `asset_address` - The address of the asset to remove
    pub fn remove_asset(env: Env, caller: Address, network_id: NetworkId, asset_address: Address) {
        access_control::require_governance(&env, &caller);
        access_control::require_not_paused(&env);
        
        let mut config = storage::get_network_config(&env, network_id)
            .expect("network config not found");
        
        let mut assets = Vec::new(&env);
        let mut removed = false;
        
        for existing in config.allowed_assets.iter() {
            if existing.asset_address != asset_address {
                assets.push_back(existing);
            } else {
                removed = true;
            }
        }
        
        assert!(removed, "asset not found");
        
        config.allowed_assets = assets;
        config.updated_at = env.ledger().timestamp();
        
        storage::set_network_config(&env, network_id, &config);
        storage::increment_global_version(&env);
        
        events::emit_asset_set(&env, network_id, &String::from_str(&env, "REMOVED"));
    }

    /// Update the contract registry for a network.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    /// * `network_id` - The network to update
    /// * `contracts` - The new contract registry
    pub fn update_contract_registry(env: Env, caller: Address, network_id: NetworkId, contracts: ContractRegistry) {
        access_control::require_governance(&env, &caller);
        access_control::require_not_paused(&env);
        
        let mut config = storage::get_network_config(&env, network_id)
            .expect("network config not found");
        
        config.contracts = contracts;
        config.updated_at = env.ledger().timestamp();
        
        storage::set_network_config(&env, network_id, &config);
        storage::increment_global_version(&env);
        
        events::emit_registry(&env, network_id);
    }

    /// Activate or deactivate a network.
    ///
    /// Deactivating a network prevents new attestations but preserves
    /// existing data for queries.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    /// * `network_id` - The network to update
    /// * `active` - `true` to activate, `false` to deactivate
    pub fn set_network_active(env: Env, caller: Address, network_id: NetworkId, active: bool) {
        access_control::require_governance(&env, &caller);
        access_control::require_not_paused(&env);
        
        let mut config = storage::get_network_config(&env, network_id)
            .expect("network config not found");
        
        config.is_active = active;
        config.updated_at = env.ledger().timestamp();
        
        storage::set_network_config(&env, network_id, &config);
        storage::increment_global_version(&env);
        
        events::emit_network_active(&env, network_id, active);
    }

    /// Set the default network ID.
    ///
    /// The default network is used when a specific network is not specified.
    /// Must reference an existing, active network.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action
    /// * `network_id` - The network ID to set as default
    pub fn set_default_network(env: Env, caller: Address, network_id: NetworkId) {
        access_control::require_governance(&env, &caller);
        access_control::require_not_paused(&env);
        
        // Verify network exists and is active
        if network_id != 0 {
            let config = storage::get_network_config(&env, network_id)
                .expect("network config not found");
            assert!(config.is_active, "cannot set inactive network as default");
        }
        
        storage::set_default_network(&env, network_id);
        storage::increment_global_version(&env);
        
        events::emit_default_network(&env, network_id);
    }

    /// Remove a network configuration.
    ///
    /// Only inactive networks can be removed. This is irreversible.
    ///
    /// # Arguments
    /// * `caller` - The address authorizing this action (must be ADMIN)
    /// * `network_id` - The network to remove
    pub fn remove_network(env: Env, caller: Address, network_id: NetworkId) {
        access_control::require_admin(&env, &caller);
        access_control::require_not_paused(&env);
        
        // Cannot remove default network
        let default = storage::get_default_network(&env).unwrap_or(0);
        assert!(network_id != default, "cannot remove default network");
        
        let config = storage::get_network_config(&env, network_id)
            .expect("network config not found");
        assert!(!config.is_active, "cannot remove active network; deactivate first");
        
        // Remove from storage
        env.storage().instance().remove(&DataKey::NetworkConfig(network_id));
        
        // Remove from registered networks list
        let networks_key = DataKey::RegisteredNetworks;
        let mut networks: Vec<NetworkId> = env.storage().instance().get(&networks_key).unwrap_or(Vec::new(&env));
        if let Some(pos) = networks.iter().position(|n| n == network_id) {
            networks.remove(pos as u32);
            env.storage().instance().set(&networks_key, &networks);
        }
        
        storage::increment_global_version(&env);
    }

    // ── Read APIs ───────────────────────────────────────────────────

    /// Get the complete configuration for a network.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    ///
    /// # Returns
    /// The network configuration, or None if not found
    pub fn get_network_config(env: Env, network_id: NetworkId) -> Option<NetworkConfig> {
        storage::get_network_config(&env, network_id)
    }

    /// Check if a network is active.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to check
    ///
    /// # Returns
    /// `true` if the network exists and is active, `false` otherwise
    pub fn is_network_active(env: Env, network_id: NetworkId) -> bool {
        storage::get_network_config(&env, network_id)
            .map(|c| c.is_active)
            .unwrap_or(false)
    }

    /// Get the fee policy for a network.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    ///
    /// # Returns
    /// The fee policy, or None if network not found
    pub fn get_fee_policy(env: Env, network_id: NetworkId) -> Option<FeePolicy> {
        storage::get_network_config(&env, network_id)
            .map(|c| c.fee_policy)
    }

    /// Get all allowed assets for a network.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    ///
    /// # Returns
    /// Vector of asset configurations, or empty vector if network not found
    pub fn get_allowed_assets(env: Env, network_id: NetworkId) -> Vec<AssetConfig> {
        storage::get_network_config(&env, network_id)
            .map(|c| c.allowed_assets)
            .unwrap_or(Vec::new(&env))
    }

    /// Get a specific asset configuration.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    /// * `asset_address` - The asset contract address
    ///
    /// # Returns
    /// The asset configuration, or None if not found
    pub fn get_asset_config(env: Env, network_id: NetworkId, asset_address: Address) -> Option<AssetConfig> {
        storage::get_network_config(&env, network_id)
            .and_then(|c| {
                c.allowed_assets.iter().find(|a| a.asset_address == asset_address)
            })
    }

    /// Get the contract registry for a network.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    ///
    /// # Returns
    /// The contract registry, or None if network not found
    pub fn get_contract_registry(env: Env, network_id: NetworkId) -> Option<ContractRegistry> {
        storage::get_network_config(&env, network_id)
            .map(|c| c.contracts)
    }

    /// Get a specific contract address from the registry.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    /// * `contract_name` - One of: "attestation", "revenue_stream", "audit_log",
    ///                     "aggregated_attestations", "integration_registry", "attestation_snapshot"
    ///
    /// # Returns
    /// The contract address, or None if not found
    pub fn get_contract_address(env: Env, network_id: NetworkId, contract_name: String) -> Option<Address> {
        storage::get_network_config(&env, network_id)
            .and_then(|c| {
                let name = contract_name.to_string();
                match name.as_str() {
                    "attestation" => c.contracts.attestation_contract,
                    "revenue_stream" => c.contracts.revenue_stream_contract,
                    "audit_log" => c.contracts.audit_log_contract,
                    "aggregated_attestations" => c.contracts.aggregated_attestations_contract,
                    "integration_registry" => c.contracts.integration_registry_contract,
                    "attestation_snapshot" => c.contracts.attestation_snapshot_contract,
                    _ => None,
                }
            })
    }

    /// Get all registered network IDs.
    ///
    /// # Returns
    /// Vector of all registered network IDs
    pub fn get_registered_networks(env: Env) -> Vec<NetworkId> {
        storage::get_registered_networks(&env)
    }

    /// Get the default network ID.
    ///
    /// # Returns
    /// The default network ID, or 0 if not set
    pub fn get_default_network(env: Env) -> NetworkId {
        storage::get_default_network(&env).unwrap_or(0)
    }

    /// Get network configuration version.
    ///
    /// The version increments each time a network's configuration is updated.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    ///
    /// # Returns
    /// The current version number
    pub fn get_network_version(env: Env, network_id: NetworkId) -> u32 {
        storage::get_network_version(&env, network_id)
    }

    /// Get global configuration version.
    ///
    /// The global version increments with any configuration change across
    /// any network. Useful for caching strategies.
    ///
    /// # Returns
    /// The current global version number
    pub fn get_global_version(env: Env) -> u32 {
        storage::get_global_version(&env)
    }

    /// Get the admin address.
    ///
    /// # Returns
    /// The admin address
    pub fn get_admin(env: Env) -> Address {
        storage::get_admin(&env)
    }

    /// Get network parameters (block time, timeouts, limits).
    ///
    /// # Arguments
    /// * `network_id` - The network ID to query
    ///
    /// # Returns
    /// Tuple of (block_time_seconds, dispute_timeout_seconds, max_period_length_seconds,
    ///           min_attestations_for_aggregate), or None if network not found
    pub fn get_network_parameters(env: Env, network_id: NetworkId) -> Option<(u32, u64, u64, u32)> {
        storage::get_network_config(&env, network_id)
            .map(|c| (
                c.block_time_seconds,
                c.dispute_timeout_seconds,
                c.max_period_length_seconds,
                c.min_attestations_for_aggregate,
            ))
    }

    /// Validate if an asset is allowed and active for attestations on a network.
    ///
    /// # Arguments
    /// * `network_id` - The network ID to check
    /// * `asset_address` - The asset contract address
    /// * `amount` - The attestation amount to validate
    ///
    /// # Returns
    /// `true` if the asset is allowed and the amount is within limits
    pub fn is_asset_valid_for_attestation(
        env: Env,
        network_id: NetworkId,
        asset_address: Address,
        amount: i128,
    ) -> bool {
        storage::get_network_config(&env, network_id)
            .and_then(|c| {
                c.allowed_assets.iter().find(|a| {
                    a.asset_address == asset_address && a.is_active
                })
            })
            .map(|asset| {
                if asset.max_attestation_value > 0 {
                    amount > 0 && amount <= asset.max_attestation_value
                } else {
                    amount > 0
                }
            })
            .unwrap_or(false)
    }

    // ─── End of public API ───
}

// ─── Re-exports for external use ───
pub use access_control::{ROLE_ADMIN, ROLE_GOVERNANCE, ROLE_OPERATOR};
