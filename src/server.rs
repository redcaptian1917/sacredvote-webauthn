//! Axum HTTP server exposing WebAuthn registration and authentication endpoints.
//!
//! Runs on port 3003 by default. The Sacred.Vote Express.js server proxies
//! WebAuthn requests to this sidecar during admin login.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use webauthn_rs::prelude::*;

use crate::credential::CredentialStore;
use crate::WebauthnConfig;

/// Shared application state.
struct AppState {
    store: CredentialStore,
}

/// Request body for starting a registration ceremony.
#[derive(Debug, Deserialize)]
struct StartRegistrationRequest {
    admin_id: String,
    admin_name: String,
    display_name: String,
}

/// Request body for finishing a registration ceremony.
#[derive(Debug, Deserialize)]
struct FinishRegistrationRequest {
    admin_id: String,
    credential_name: String,
    response: RegisterPublicKeyCredential,
}

/// Request body for starting an authentication ceremony.
#[derive(Debug, Deserialize)]
struct StartAuthRequest {
    admin_id: String,
}

/// Request body for finishing an authentication ceremony.
#[derive(Debug, Deserialize)]
struct FinishAuthRequest {
    admin_id: String,
    response: PublicKeyCredential,
}

/// Standard API response wrapper.
#[derive(Debug, Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }
}

fn error_response(status: StatusCode, msg: &str) -> impl IntoResponse {
    (
        status,
        Json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }),
    )
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /register/start
///
/// Begin a WebAuthn registration ceremony. Returns a challenge that the
/// browser passes to `navigator.credentials.create()`.
async fn start_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartRegistrationRequest>,
) -> impl IntoResponse {
    match state
        .store
        .start_registration(&req.admin_id, &req.admin_name, &req.display_name)
    {
        Ok(ccr) => (StatusCode::OK, Json(serde_json::to_value(ccr).unwrap())).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "registration start failed");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "registration start failed")
                .into_response()
        }
    }
}

/// POST /register/finish
///
/// Complete a WebAuthn registration ceremony. Verifies the browser's
/// attestation and stores the new credential.
async fn finish_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FinishRegistrationRequest>,
) -> impl IntoResponse {
    match state
        .store
        .finish_registration(&req.admin_id, &req.credential_name, &req.response)
    {
        Ok(meta) => ApiResponse::ok(meta).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "registration finish failed");
            error_response(StatusCode::BAD_REQUEST, "registration verification failed")
                .into_response()
        }
    }
}

/// POST /authenticate/start
///
/// Begin a WebAuthn authentication ceremony. Returns a challenge that the
/// browser passes to `navigator.credentials.get()`.
async fn start_authentication(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartAuthRequest>,
) -> impl IntoResponse {
    match state.store.start_authentication(&req.admin_id) {
        Ok(rcr) => (StatusCode::OK, Json(serde_json::to_value(rcr).unwrap())).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "authentication start failed");
            let status = if matches!(e, crate::WebauthnError::AdminNotFound(_)) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error_response(status, "authentication start failed").into_response()
        }
    }
}

/// POST /authenticate/finish
///
/// Complete a WebAuthn authentication ceremony. Verifies the browser's
/// assertion and returns the credential metadata.
async fn finish_authentication(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FinishAuthRequest>,
) -> impl IntoResponse {
    match state
        .store
        .finish_authentication(&req.admin_id, &req.response)
    {
        Ok(meta) => ApiResponse::ok(meta).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "authentication finish failed");
            error_response(StatusCode::UNAUTHORIZED, "authentication failed").into_response()
        }
    }
}

/// GET /credentials/:admin_id
///
/// List all registered credentials for an admin (metadata only).
async fn list_credentials(
    State(state): State<Arc<AppState>>,
    Path(admin_id): Path<String>,
) -> impl IntoResponse {
    match state.store.list_credentials(&admin_id) {
        Ok(creds) => ApiResponse::ok(creds).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "list credentials failed");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to list credentials")
                .into_response()
        }
    }
}

/// DELETE /credentials/:admin_id/:credential_id
///
/// Remove a specific credential.
async fn remove_credential(
    State(state): State<Arc<AppState>>,
    Path((admin_id, credential_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.store.remove_credential(&admin_id, &credential_id) {
        Ok(()) => ApiResponse::ok("credential removed").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "remove credential failed");
            let status = match &e {
                crate::WebauthnError::AdminNotFound(_)
                | crate::WebauthnError::CredentialNotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            error_response(status, "failed to remove credential").into_response()
        }
    }
}

/// GET /health
///
/// Health check endpoint. Returns the number of registered credentials
/// and whether the store is operational.
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Health {
        status: &'static str,
        service: &'static str,
        total_credentials: usize,
    }

    ApiResponse::ok(Health {
        status: "healthy",
        service: "sacredvote-webauthn",
        total_credentials: state.store.total_credentials(),
    })
}

/// Build the Axum router with all WebAuthn endpoints.
pub fn router(config: &WebauthnConfig) -> Result<Router, crate::WebauthnError> {
    let store = CredentialStore::new(config)?;
    let state = Arc::new(AppState { store });

    let app = Router::new()
        .route("/register/start", post(start_registration))
        .route("/register/finish", post(finish_registration))
        .route("/authenticate/start", post(start_authentication))
        .route("/authenticate/finish", post(finish_authentication))
        .route("/credentials/{admin_id}", get(list_credentials))
        .route(
            "/credentials/{admin_id}/{credential_id}",
            delete(remove_credential),
        )
        .route("/health", get(health))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    Ok(app)
}

/// Start the HTTP server on the configured port.
pub async fn serve(config: &WebauthnConfig) -> Result<(), crate::WebauthnError> {
    let app = router(config)?;
    let addr = format!("127.0.0.1:{}", config.port);

    tracing::info!(
        addr = %addr,
        rp_id = %config.rp_id,
        "sacredvote-webauthn listening"
    );

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| crate::WebauthnError::ConfigError(format!("bind failed: {e}")))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| crate::WebauthnError::ConfigError(format!("server error: {e}")))?;

    Ok(())
}
