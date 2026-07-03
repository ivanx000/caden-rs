//! Minimal Axum HTTP server demonstrating real-world WebAuthn integration.
//!
//! Run with:
//! ```bash
//! cargo run --example server
//! ```
//!
//! The server starts on `http://localhost:3000`. All state is in-memory — restart
//! clears all registered credentials. This is a demo; a production server would
//! persist credentials to a database.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{routing::get, routing::post, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, Challenge, Credential,
    RelyingParty,
};

// ─── App state ────────────────────────────────────────────────────────────────

struct AppState {
    /// pending challenges: session_id → Challenge
    pending_challenges: Mutex<HashMap<String, Challenge>>,
    /// stored credentials: credential_id (hex) → Credential
    credentials: Mutex<HashMap<String, Credential>>,
    relying_party: RelyingParty,
}

type SharedState = Arc<AppState>;

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterBeginRequest {
    user_id: String,
    username: String,
}

#[derive(Serialize)]
struct PubKeyCredParam {
    r#type: &'static str,
    alg: i64,
}

#[derive(Serialize)]
struct RpInfo {
    id: &'static str,
    name: &'static str,
}

#[derive(Serialize)]
struct UserInfo {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct RegisterBeginResponse {
    session_id: String,
    challenge: String,
    rp: RpInfo,
    user: UserInfo,
    #[serde(rename = "pubKeyCredParams")]
    pub_key_cred_params: Vec<PubKeyCredParam>,
}

#[derive(Deserialize)]
struct RegisterCompleteRequest {
    session_id: String,
    client_data_json: String,
    attestation_object: String,
}

#[derive(Serialize)]
struct RegisterCompleteResponse {
    credential_id: String,
    status: &'static str,
}

#[derive(Deserialize)]
struct AuthBeginRequest {
    credential_id: String,
}

#[derive(Serialize)]
struct AllowCredential {
    r#type: &'static str,
    id: String,
}

#[derive(Serialize)]
struct AuthBeginResponse {
    session_id: String,
    challenge: String,
    #[serde(rename = "allowCredentials")]
    allow_credentials: Vec<AllowCredential>,
}

#[derive(Deserialize)]
struct AuthCompleteRequest {
    session_id: String,
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

#[derive(Serialize)]
struct AuthCompleteResponse {
    status: &'static str,
    new_sign_count: u32,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: &'static str,
}

// ─── Error helpers ────────────────────────────────────────────────────────────

fn client_error(message: impl Into<String>, code: &'static str) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: message.into(),
            code,
        }),
    )
}

fn server_error(message: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: message.into(),
            code: "INTERNAL_ERROR",
        }),
    )
}

fn decode_b64url(
    value: &str,
    field: &'static str,
) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    URL_SAFE_NO_PAD.decode(value).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("{field}: {e}"),
                code: "BASE64_DECODE_ERROR",
            }),
        )
    })
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a random session ID as 16 random bytes encoded as 32 hex chars.
fn new_session_id() -> String {
    let bytes = webauthn::random_bytes(16).expect("RNG failure");
    to_hex(&bytes)
}

// ─── Endpoints ────────────────────────────────────────────────────────────────

/// GET /health — liveness check.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// POST /register/begin — issue a registration challenge.
async fn register_begin(
    State(state): State<SharedState>,
    Json(req): Json<RegisterBeginRequest>,
) -> impl IntoResponse {
    let challenge = match Challenge::new() {
        Ok(c) => c,
        Err(e) => return server_error(format!("challenge generation failed: {e}")).into_response(),
    };

    let session_id = new_session_id();
    let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge.bytes);

    state
        .pending_challenges
        .lock()
        .await
        .insert(session_id.clone(), challenge);

    let response = RegisterBeginResponse {
        session_id,
        challenge: challenge_b64,
        rp: RpInfo {
            id: "localhost",
            name: "Caden Demo",
        },
        user: UserInfo {
            id: req.user_id,
            name: req.username,
        },
        pub_key_cred_params: vec![
            PubKeyCredParam {
                r#type: "public-key",
                alg: -7,
            },
            PubKeyCredParam {
                r#type: "public-key",
                alg: -35,
            },
            PubKeyCredParam {
                r#type: "public-key",
                alg: -257,
            },
        ],
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// POST /register/complete — verify registration and store the credential.
async fn register_complete(
    State(state): State<SharedState>,
    Json(req): Json<RegisterCompleteRequest>,
) -> impl IntoResponse {
    let challenge = {
        let mut map = state.pending_challenges.lock().await;
        match map.remove(&req.session_id) {
            Some(c) => c,
            None => {
                return client_error("session not found or expired", "SESSION_NOT_FOUND")
                    .into_response()
            }
        }
    };

    let client_data_json = match decode_b64url(&req.client_data_json, "client_data_json") {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let attestation_object = match decode_b64url(&req.attestation_object, "attestation_object") {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    let response = AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object,
    };

    // Use the session_id bytes as user_id for this demo.
    let user_id = req.session_id.as_bytes().to_vec();

    let result = match state
        .relying_party
        .verify_registration(&challenge, &response, &user_id)
    {
        Ok(r) => r,
        Err(e) => {
            return client_error(format!("registration failed: {e}"), "VERIFICATION_FAILED")
                .into_response()
        }
    };

    let credential_id_hex = to_hex(&result.credential.id);
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&result.credential.id);

    state
        .credentials
        .lock()
        .await
        .insert(credential_id_hex, result.credential);

    (
        StatusCode::OK,
        Json(RegisterCompleteResponse {
            credential_id: credential_id_b64,
            status: "ok",
        }),
    )
        .into_response()
}

/// POST /authenticate/begin — issue an authentication challenge.
async fn authenticate_begin(
    State(state): State<SharedState>,
    Json(req): Json<AuthBeginRequest>,
) -> impl IntoResponse {
    let cred_id_bytes = match decode_b64url(&req.credential_id, "credential_id") {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let cred_id_hex = to_hex(&cred_id_bytes);

    {
        let creds = state.credentials.lock().await;
        if !creds.contains_key(&cred_id_hex) {
            return client_error("credential not found", "CREDENTIAL_NOT_FOUND").into_response();
        }
    }

    let challenge = match Challenge::new() {
        Ok(c) => c,
        Err(e) => return server_error(format!("challenge generation failed: {e}")).into_response(),
    };

    let session_id = new_session_id();
    let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge.bytes);

    state
        .pending_challenges
        .lock()
        .await
        .insert(session_id.clone(), challenge);

    let response = AuthBeginResponse {
        session_id,
        challenge: challenge_b64,
        allow_credentials: vec![AllowCredential {
            r#type: "public-key",
            id: req.credential_id,
        }],
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// POST /authenticate/complete — verify authentication and update sign count.
async fn authenticate_complete(
    State(state): State<SharedState>,
    Json(req): Json<AuthCompleteRequest>,
) -> impl IntoResponse {
    let challenge = {
        let mut map = state.pending_challenges.lock().await;
        match map.remove(&req.session_id) {
            Some(c) => c,
            None => {
                return client_error("session not found or expired", "SESSION_NOT_FOUND")
                    .into_response()
            }
        }
    };

    let cred_id_bytes = match decode_b64url(&req.credential_id, "credential_id") {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let cred_id_hex = to_hex(&cred_id_bytes);

    let stored_credential = {
        let creds = state.credentials.lock().await;
        match creds.get(&cred_id_hex).cloned() {
            Some(c) => c,
            None => {
                return client_error("credential not found", "CREDENTIAL_NOT_FOUND").into_response()
            }
        }
    };

    let client_data_json = match decode_b64url(&req.client_data_json, "client_data_json") {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let authenticator_data = match decode_b64url(&req.authenticator_data, "authenticator_data") {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let signature = match decode_b64url(&req.signature, "signature") {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    let assertion = AuthenticatorAssertionResponse {
        client_data_json,
        authenticator_data,
        signature,
        user_handle: None,
    };

    let result =
        match state
            .relying_party
            .verify_authentication(&stored_credential, &challenge, &assertion)
        {
            Ok(r) => r,
            Err(e) => {
                return client_error(format!("authentication failed: {e}"), "VERIFICATION_FAILED")
                    .into_response()
            }
        };

    // Update the stored sign count.
    {
        let mut creds = state.credentials.lock().await;
        if let Some(cred) = creds.get_mut(&cred_id_hex) {
            cred.sign_count = result.new_sign_count;
        }
    }

    (
        StatusCode::OK,
        Json(AuthCompleteResponse {
            status: "ok",
            new_sign_count: result.new_sign_count,
        }),
    )
        .into_response()
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState {
        pending_challenges: Mutex::new(HashMap::new()),
        credentials: Mutex::new(HashMap::new()),
        relying_party: RelyingParty::new("localhost", "http://localhost:3000", "Caden Demo"),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/register/begin", post(register_begin))
        .route("/register/complete", post(register_complete))
        .route("/authenticate/begin", post(authenticate_begin))
        .route("/authenticate/complete", post(authenticate_complete))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind to port 3000");

    println!("Caden demo server running on http://localhost:3000");
    println!();
    println!("Endpoints:");
    println!("  GET  /health");
    println!("  POST /register/begin");
    println!("  POST /register/complete");
    println!("  POST /authenticate/begin");
    println!("  POST /authenticate/complete");

    axum::serve(listener, app).await.expect("server failed");
}
