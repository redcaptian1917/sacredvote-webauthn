//! # sacredvote-webauthn
//!
//! WebAuthn/FIDO2 authentication service for Sacred.Vote admin access.
//!
//! Hardware security keys (YubiKey, Titan, SoloKeys) provide phishing-resistant
//! multi-factor authentication that defeats nation-state MFA relay attacks
//! (e.g., APT42-style real-time TOTP phishing). Unlike TOTP codes, WebAuthn
//! credentials are cryptographically bound to the origin and cannot be replayed
//! from a different domain.
//!
//! ## Architecture
//!
//! ```text
//! Sacred.Vote Express.js
//!   |
//!   |-- POST /webauthn/register/start   --> sacredvote-webauthn (Axum, port 3003)
//!   |-- POST /webauthn/register/finish  --> sacredvote-webauthn
//!   |-- POST /webauthn/auth/start       --> sacredvote-webauthn
//!   |-- POST /webauthn/auth/finish      --> sacredvote-webauthn
//!   |-- GET  /webauthn/credentials      --> sacredvote-webauthn
//!   |-- DELETE /webauthn/credentials/:id --> sacredvote-webauthn
//! ```
//!
//! ## Security Model
//!
//! - **Origin binding**: Credentials are bound to `https://sacred.vote` and
//!   cannot be used on phishing domains.
//! - **Attestation**: Supports both `none` (privacy-preserving) and `direct`
//!   (hardware verification) attestation.
//! - **Resident keys**: Supports discoverable credentials (passkeys) and
//!   non-discoverable credentials (security keys).
//! - **User verification**: Configurable — can require PIN/biometric on
//!   the authenticator itself.

#![forbid(unsafe_code)]

pub mod credential;

#[cfg(feature = "server")]
pub mod server;

use thiserror::Error;

/// Errors from the WebAuthn service.
#[derive(Debug, Error)]
pub enum WebauthnError {
    /// The WebAuthn library returned an error during a ceremony.
    #[error("webauthn ceremony failed: {0}")]
    CeremonyFailed(String),

    /// The requested admin user was not found.
    #[error("admin not found: {0}")]
    AdminNotFound(String),

    /// The credential ID was not found for the given admin.
    #[error("credential not found: {0}")]
    CredentialNotFound(String),

    /// No pending registration or authentication state for this admin.
    #[error("no pending ceremony state for admin: {0}")]
    NoPendingState(String),

    /// The credential store encountered an I/O error.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Configuration error (invalid RP ID, origin, etc.).
    #[error("configuration error: {0}")]
    ConfigError(String),
}

/// Configuration for the WebAuthn relying party.
///
/// In production, the RP ID is `sacred.vote` and the origin is
/// `https://sacred.vote`. For local development, these can be
/// overridden via environment variables.
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    /// The relying party identifier (e.g., "sacred.vote").
    /// Must match the domain the browser uses.
    pub rp_id: String,

    /// The relying party display name shown in browser prompts.
    pub rp_name: String,

    /// The allowed origin URL (e.g., "https://sacred.vote").
    pub rp_origin: String,

    /// Port for the HTTP sidecar service.
    pub port: u16,

    /// Path to the credential store file.
    pub store_path: String,
}

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "sacred.vote".to_string(),
            rp_name: "Sacred.Vote".to_string(),
            rp_origin: "https://sacred.vote".to_string(),
            port: 3003,
            store_path: "/var/lib/sacredvote-webauthn/credentials.json".to_string(),
        }
    }
}

impl WebauthnConfig {
    /// Create a configuration from environment variables, falling back to defaults.
    ///
    /// Environment variables:
    /// - `WEBAUTHN_RP_ID` — Relying party ID (default: "sacred.vote")
    /// - `WEBAUTHN_RP_NAME` — Display name (default: "Sacred.Vote")
    /// - `WEBAUTHN_RP_ORIGIN` — Origin URL (default: "https://sacred.vote")
    /// - `WEBAUTHN_PORT` — HTTP port (default: 3003)
    /// - `WEBAUTHN_STORE_PATH` — Credential file path
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            rp_id: std::env::var("WEBAUTHN_RP_ID").unwrap_or(defaults.rp_id),
            rp_name: std::env::var("WEBAUTHN_RP_NAME").unwrap_or(defaults.rp_name),
            rp_origin: std::env::var("WEBAUTHN_RP_ORIGIN").unwrap_or(defaults.rp_origin),
            port: std::env::var("WEBAUTHN_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(defaults.port),
            store_path: std::env::var("WEBAUTHN_STORE_PATH").unwrap_or(defaults.store_path),
        }
    }
}
