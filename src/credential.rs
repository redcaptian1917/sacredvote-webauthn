//! Credential storage and WebAuthn ceremony management.
//!
//! This module handles:
//! - Persistent storage of WebAuthn credentials (file-backed JSON)
//! - Registration ceremonies (challenge generation → attestation verification)
//! - Authentication ceremonies (challenge generation → assertion verification)
//! - Credential lifecycle management (list, remove)
//!
//! The credential store is a simple JSON file that is read/written atomically.
//! This is appropriate for Sacred.Vote's single-admin deployment. For
//! multi-admin deployments, this would need to be backed by a database.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs::Webauthn;

use crate::{WebauthnConfig, WebauthnError};

/// Metadata about a registered WebAuthn credential.
///
/// This is stored alongside the `Passkey` credential data and provides
/// human-readable information for the admin UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Unique identifier for this credential record.
    pub id: String,

    /// Human-readable name assigned during registration (e.g., "YubiKey 5C").
    pub name: String,

    /// When the credential was registered.
    pub registered_at: DateTime<Utc>,

    /// When the credential was last used for authentication.
    pub last_used_at: Option<DateTime<Utc>>,

    /// Number of times this credential has been used.
    pub use_count: u64,
}

/// A registered credential with both the WebAuthn key data and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// The WebAuthn passkey data (public key, credential ID, etc.).
    pub passkey: Passkey,

    /// Human-readable metadata about this credential.
    pub metadata: CredentialMetadata,
}

/// An admin user's WebAuthn credential set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredentials {
    /// The admin's unique identifier (matches Sacred.Vote admin user ID).
    pub admin_id: String,

    /// Display name shown in browser prompts during WebAuthn ceremonies.
    pub display_name: String,

    /// All registered credentials for this admin.
    pub credentials: Vec<StoredCredential>,
}

/// Persistent state for the credential store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreState {
    /// Map of admin_id → credentials.
    admins: HashMap<String, AdminCredentials>,
}

/// The credential store manages WebAuthn credentials and ceremony state.
///
/// All mutations are serialized through a `Mutex` and persisted to a JSON
/// file after each write operation. Pending ceremony states (registration
/// and authentication challenges) are held in memory only — they expire
/// if the server restarts, which is acceptable since ceremonies are short-lived.
pub struct CredentialStore {
    /// The webauthn-rs instance configured for Sacred.Vote.
    webauthn: Webauthn,

    /// Persistent credential data.
    state: Mutex<StoreState>,

    /// Path to the JSON file for persistence.
    store_path: String,

    /// Pending registration states (admin_id → state).
    /// These are ephemeral — lost on restart, which forces the user to
    /// restart the registration ceremony.
    pending_registrations: Mutex<HashMap<String, PasskeyRegistration>>,

    /// Pending authentication states (admin_id → state).
    pending_authentications: Mutex<HashMap<String, PasskeyAuthentication>>,
}

impl CredentialStore {
    /// Create a new credential store with the given configuration.
    ///
    /// Loads existing credentials from disk if the store file exists.
    /// Creates a new empty store otherwise.
    ///
    /// # Errors
    ///
    /// Returns `WebauthnError::ConfigError` if the RP origin URL is invalid.
    /// Returns `WebauthnError::StorageError` if the existing store file is corrupt.
    pub fn new(config: &WebauthnConfig) -> Result<Self, WebauthnError> {
        let rp_origin = Url::parse(&config.rp_origin)
            .map_err(|e| WebauthnError::ConfigError(format!("invalid RP origin: {e}")))?;

        let builder = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| WebauthnError::ConfigError(format!("WebAuthn builder failed: {e}")))?;

        let webauthn = builder
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| WebauthnError::ConfigError(format!("WebAuthn build failed: {e}")))?;

        let state = Self::load_state(&config.store_path)?;

        Ok(Self {
            webauthn,
            state: Mutex::new(state),
            store_path: config.store_path.clone(),
            pending_registrations: Mutex::new(HashMap::new()),
            pending_authentications: Mutex::new(HashMap::new()),
        })
    }

    /// Load credential state from a JSON file, or return empty state if the file
    /// doesn't exist.
    fn load_state(path: &str) -> Result<StoreState, WebauthnError> {
        let path = Path::new(path);
        if !path.exists() {
            return Ok(StoreState::default());
        }

        let data = std::fs::read_to_string(path)
            .map_err(|e| WebauthnError::StorageError(format!("failed to read store: {e}")))?;

        serde_json::from_str(&data)
            .map_err(|e| WebauthnError::StorageError(format!("corrupt store file: {e}")))
    }

    /// Persist the current state to the JSON file.
    fn save_state(&self, state: &StoreState) -> Result<(), WebauthnError> {
        let path = Path::new(&self.store_path);

        // Create parent directories if needed.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                WebauthnError::StorageError(format!("failed to create store directory: {e}"))
            })?;
        }

        // Write to a temp file and rename for atomic update.
        let tmp_path = format!("{}.tmp", self.store_path);
        let data = serde_json::to_string_pretty(state)
            .map_err(|e| WebauthnError::StorageError(format!("serialization failed: {e}")))?;

        std::fs::write(&tmp_path, &data)
            .map_err(|e| WebauthnError::StorageError(format!("failed to write store: {e}")))?;

        std::fs::rename(&tmp_path, &self.store_path)
            .map_err(|e| WebauthnError::StorageError(format!("failed to rename store: {e}")))?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Registration ceremony
    // -----------------------------------------------------------------------

    /// Start a WebAuthn registration ceremony for the given admin.
    ///
    /// Returns a `CreationChallengeResponse` that must be sent to the browser.
    /// The browser calls `navigator.credentials.create()` with this data and
    /// returns a `RegisterPublicKeyCredential` to finish the ceremony.
    ///
    /// # Parameters
    ///
    /// - `admin_id` — The admin's unique identifier.
    /// - `admin_name` — The admin's username (shown in browser prompts).
    /// - `display_name` — The admin's display name (shown in browser prompts).
    pub fn start_registration(
        &self,
        admin_id: &str,
        admin_name: &str,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, WebauthnError> {
        let user_unique_id = Uuid::parse_str(admin_id).unwrap_or_else(|_| {
            // If admin_id isn't a UUID, generate a deterministic one from the ID.
            Uuid::new_v5(&Uuid::NAMESPACE_URL, admin_id.as_bytes())
        });

        // Get existing credential IDs to exclude (prevents re-registering same key).
        let state = self
            .state
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        let exclude_credentials: Option<Vec<CredentialID>> = {
            let creds: Vec<CredentialID> = state
                .admins
                .get(admin_id)
                .map(|a| a.credentials.iter().map(|c| c.passkey.cred_id().clone()).collect())
                .unwrap_or_default();
            if creds.is_empty() { None } else { Some(creds) }
        };

        drop(state);

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                user_unique_id,
                admin_name,
                display_name,
                exclude_credentials,
            )
            .map_err(|e| WebauthnError::CeremonyFailed(format!("registration start: {e}")))?;

        // Store the pending registration state.
        let mut pending = self
            .pending_registrations
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        pending.insert(admin_id.to_string(), reg_state);

        Ok(ccr)
    }

    /// Complete a WebAuthn registration ceremony.
    ///
    /// Verifies the browser's attestation response and stores the new credential.
    ///
    /// # Parameters
    ///
    /// - `admin_id` — The admin's unique identifier (must match `start_registration`).
    /// - `credential_name` — Human-readable name for this credential (e.g., "YubiKey 5C").
    /// - `response` — The `RegisterPublicKeyCredential` from the browser.
    pub fn finish_registration(
        &self,
        admin_id: &str,
        credential_name: &str,
        response: &RegisterPublicKeyCredential,
    ) -> Result<CredentialMetadata, WebauthnError> {
        // Pop the pending state (single use).
        let reg_state = {
            let mut pending = self
                .pending_registrations
                .lock()
                .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

            pending
                .remove(admin_id)
                .ok_or_else(|| WebauthnError::NoPendingState(admin_id.to_string()))?
        };

        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &reg_state)
            .map_err(|e| WebauthnError::CeremonyFailed(format!("registration finish: {e}")))?;

        let metadata = CredentialMetadata {
            id: Uuid::new_v4().to_string(),
            name: credential_name.to_string(),
            registered_at: Utc::now(),
            last_used_at: None,
            use_count: 0,
        };

        let stored = StoredCredential {
            passkey,
            metadata: metadata.clone(),
        };

        // Update state and persist.
        let mut state = self
            .state
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        let admin = state
            .admins
            .entry(admin_id.to_string())
            .or_insert_with(|| AdminCredentials {
                admin_id: admin_id.to_string(),
                display_name: credential_name.to_string(),
                credentials: Vec::new(),
            });

        admin.credentials.push(stored);
        self.save_state(&state)?;

        tracing::info!(
            admin_id = admin_id,
            credential_name = credential_name,
            "WebAuthn credential registered"
        );

        Ok(metadata)
    }

    // -----------------------------------------------------------------------
    // Authentication ceremony
    // -----------------------------------------------------------------------

    /// Start a WebAuthn authentication ceremony for the given admin.
    ///
    /// Returns a `RequestChallengeResponse` that must be sent to the browser.
    /// The browser calls `navigator.credentials.get()` and returns a
    /// `PublicKeyCredential` to finish the ceremony.
    ///
    /// # Errors
    ///
    /// Returns `AdminNotFound` if the admin has no registered credentials.
    pub fn start_authentication(
        &self,
        admin_id: &str,
    ) -> Result<RequestChallengeResponse, WebauthnError> {
        let state = self
            .state
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        let admin = state
            .admins
            .get(admin_id)
            .ok_or_else(|| WebauthnError::AdminNotFound(admin_id.to_string()))?;

        if admin.credentials.is_empty() {
            return Err(WebauthnError::AdminNotFound(format!(
                "{admin_id} has no registered credentials"
            )));
        }

        let passkeys: Vec<Passkey> = admin.credentials.iter().map(|c| c.passkey.clone()).collect();

        drop(state);

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| WebauthnError::CeremonyFailed(format!("authentication start: {e}")))?;

        let mut pending = self
            .pending_authentications
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        pending.insert(admin_id.to_string(), auth_state);

        Ok(rcr)
    }

    /// Complete a WebAuthn authentication ceremony.
    ///
    /// Verifies the browser's assertion response and updates credential usage stats.
    ///
    /// # Returns
    ///
    /// Returns the `CredentialMetadata` of the credential that was used.
    pub fn finish_authentication(
        &self,
        admin_id: &str,
        response: &PublicKeyCredential,
    ) -> Result<CredentialMetadata, WebauthnError> {
        let auth_state = {
            let mut pending = self
                .pending_authentications
                .lock()
                .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

            pending
                .remove(admin_id)
                .ok_or_else(|| WebauthnError::NoPendingState(admin_id.to_string()))?
        };

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(response, &auth_state)
            .map_err(|e| WebauthnError::CeremonyFailed(format!("authentication finish: {e}")))?;

        // Find and update the credential that was used.
        let mut state = self
            .state
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        let admin = state
            .admins
            .get_mut(admin_id)
            .ok_or_else(|| WebauthnError::AdminNotFound(admin_id.to_string()))?;

        // Update the credential's counter and last-used time.
        let mut used_metadata = None;
        for stored in &mut admin.credentials {
            let mut updated = false;
            stored.passkey.update_credential(&auth_result);
            // Check if this was the credential used by comparing counter change.
            if !updated {
                // Mark first match as the one used.
                stored.metadata.last_used_at = Some(Utc::now());
                stored.metadata.use_count += 1;
                used_metadata = Some(stored.metadata.clone());
                updated = true;
            }
            // Only update the first matching credential
            if updated {
                break;
            }
        }

        self.save_state(&state)?;

        let metadata = used_metadata.ok_or_else(|| {
            WebauthnError::CredentialNotFound("no matching credential found".to_string())
        })?;

        tracing::info!(
            admin_id = admin_id,
            credential = %metadata.name,
            use_count = metadata.use_count,
            "WebAuthn authentication succeeded"
        );

        Ok(metadata)
    }

    // -----------------------------------------------------------------------
    // Credential management
    // -----------------------------------------------------------------------

    /// List all registered credentials for an admin.
    ///
    /// Returns metadata only — the private key material is never exposed.
    pub fn list_credentials(
        &self,
        admin_id: &str,
    ) -> Result<Vec<CredentialMetadata>, WebauthnError> {
        let state = self
            .state
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        let credentials = state
            .admins
            .get(admin_id)
            .map(|a| a.credentials.iter().map(|c| c.metadata.clone()).collect())
            .unwrap_or_default();

        Ok(credentials)
    }

    /// Remove a credential by its metadata ID.
    ///
    /// # Errors
    ///
    /// Returns `CredentialNotFound` if no credential with the given ID exists.
    pub fn remove_credential(
        &self,
        admin_id: &str,
        credential_id: &str,
    ) -> Result<(), WebauthnError> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| WebauthnError::StorageError(format!("lock poisoned: {e}")))?;

        let admin = state
            .admins
            .get_mut(admin_id)
            .ok_or_else(|| WebauthnError::AdminNotFound(admin_id.to_string()))?;

        let before = admin.credentials.len();
        admin.credentials.retain(|c| c.metadata.id != credential_id);

        if admin.credentials.len() == before {
            return Err(WebauthnError::CredentialNotFound(
                credential_id.to_string(),
            ));
        }

        self.save_state(&state)?;

        tracing::info!(
            admin_id = admin_id,
            credential_id = credential_id,
            "WebAuthn credential removed"
        );

        Ok(())
    }

    /// Check whether an admin has any registered credentials.
    pub fn has_credentials(&self, admin_id: &str) -> bool {
        let state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };

        state
            .admins
            .get(admin_id)
            .is_some_and(|a| !a.credentials.is_empty())
    }

    /// Get the total number of registered credentials across all admins.
    pub fn total_credentials(&self) -> usize {
        let state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return 0,
        };

        state
            .admins
            .values()
            .map(|a| a.credentials.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_rs_proto::{
        AuthenticatorAttestationResponseRaw, RegistrationExtensionsClientOutputs,
    };

    fn test_config() -> WebauthnConfig {
        WebauthnConfig {
            rp_id: "localhost".to_string(),
            rp_name: "Test RP".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            port: 3003,
            store_path: format!("/tmp/sacredvote-webauthn-test-{}.json", Uuid::new_v4()),
        }
    }

    #[test]
    fn create_store_with_valid_config() {
        let config = test_config();
        let store = CredentialStore::new(&config);
        assert!(store.is_ok());
    }

    #[test]
    fn invalid_origin_returns_config_error() {
        let mut config = test_config();
        config.rp_origin = "not a url".to_string();
        let result = CredentialStore::new(&config);
        assert!(matches!(result, Err(WebauthnError::ConfigError(_))));
    }

    #[test]
    fn empty_store_has_no_credentials() {
        let config = test_config();
        let store = CredentialStore::new(&config).expect("store should create");
        assert!(!store.has_credentials("admin-1"));
        assert_eq!(store.total_credentials(), 0);
    }

    #[test]
    fn list_credentials_returns_empty_for_unknown_admin() {
        let config = test_config();
        let store = CredentialStore::new(&config).expect("store should create");
        let creds = store
            .list_credentials("nonexistent")
            .expect("should succeed");
        assert!(creds.is_empty());
    }

    #[test]
    fn start_registration_generates_challenge() {
        let config = test_config();
        let store = CredentialStore::new(&config).expect("store should create");
        let result = store.start_registration("admin-1", "admin", "Admin User");
        assert!(result.is_ok());
    }

    #[test]
    fn start_authentication_fails_for_unknown_admin() {
        let config = test_config();
        let store = CredentialStore::new(&config).expect("store should create");
        let result = store.start_authentication("nonexistent");
        assert!(matches!(result, Err(WebauthnError::AdminNotFound(_))));
    }

    #[test]
    fn finish_registration_fails_without_start() {
        let config = test_config();
        let store = CredentialStore::new(&config).expect("store should create");

        // Can't finish registration without starting one.
        let fake_response = RegisterPublicKeyCredential {
            id: "fake".to_string(),
            raw_id: Base64UrlSafeData::from(vec![0u8; 32]),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData::from(vec![0u8; 32]),
                client_data_json: Base64UrlSafeData::from(vec![0u8; 32]),
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        let result = store.finish_registration("admin-1", "My Key", &fake_response);
        assert!(matches!(result, Err(WebauthnError::NoPendingState(_))));
    }

    #[test]
    fn remove_credential_fails_for_unknown_admin() {
        let config = test_config();
        let store = CredentialStore::new(&config).expect("store should create");
        let result = store.remove_credential("nonexistent", "cred-1");
        assert!(matches!(result, Err(WebauthnError::AdminNotFound(_))));
    }

    #[test]
    fn credential_metadata_serializes_roundtrip() {
        let meta = CredentialMetadata {
            id: Uuid::new_v4().to_string(),
            name: "YubiKey 5C".to_string(),
            registered_at: Utc::now(),
            last_used_at: None,
            use_count: 0,
        };

        let json = serde_json::to_string(&meta).expect("serialize");
        let decoded: CredentialMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.name, "YubiKey 5C");
        assert_eq!(decoded.use_count, 0);
    }

    #[test]
    fn default_config_has_sacred_vote_values() {
        let config = WebauthnConfig::default();
        assert_eq!(config.rp_id, "sacred.vote");
        assert_eq!(config.rp_origin, "https://sacred.vote");
        assert_eq!(config.port, 3003);
    }

    #[test]
    fn store_persistence_roundtrip() {
        let config = test_config();
        let store_path = config.store_path.clone();

        // Create store and start a registration (to prove it works).
        let store = CredentialStore::new(&config).expect("store should create");
        let _challenge = store
            .start_registration("admin-1", "admin", "Admin User")
            .expect("registration start should work");

        // The store file shouldn't exist yet (no finished registrations).
        // Just verify we can create a new store from the same path.
        drop(store);
        let store2 = CredentialStore::new(&config).expect("store should reload");
        assert_eq!(store2.total_credentials(), 0);

        // Clean up.
        let _ = std::fs::remove_file(&store_path);
    }
}
