//! Binary entry point for the sacredvote-webauthn HTTP sidecar.
//!
//! Reads configuration from environment variables and starts the Axum server.
//! See `WebauthnConfig::from_env()` for available variables.

use sacredvote_webauthn::WebauthnConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = WebauthnConfig::from_env();
    sacredvote_webauthn::server::serve(&config).await?;
    Ok(())
}
