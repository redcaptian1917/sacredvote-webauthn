# Architecture

## System Diagram

```
sacredvote-webauthn (Rust, Axum, port 3003)
├── credential.rs  — Credential store + WebAuthn ceremony management
│   ├── CredentialStore     — Thread-safe store with Mutex<StoreState>
│   ├── start_registration  — Generate challenge for navigator.credentials.create()
│   ├── finish_registration — Verify attestation, store credential
│   ├── start_authentication — Generate challenge for navigator.credentials.get()
│   └── finish_authentication — Verify assertion, update usage stats
├── server.rs      — Axum HTTP endpoints (behind "server" feature)
│   ├── POST /register/{start,finish}
│   ├── POST /authenticate/{start,finish}
│   ├── GET/DELETE /credentials/{admin_id}[/{id}]
│   └── GET /health
└── lib.rs         — Public API, error types, configuration
```

## Data Flow

### Registration

1. Admin clicks "Register Security Key" in Sacred.Vote admin panel
2. Express.js proxies to `POST /register/start` with admin ID
3. `webauthn-rs` generates a challenge (CreationChallengeResponse)
4. Challenge is returned to browser, which calls `navigator.credentials.create()`
5. Browser prompts user to touch security key
6. Browser returns RegisterPublicKeyCredential to Express.js
7. Express.js proxies to `POST /register/finish`
8. `webauthn-rs` verifies attestation, stores Passkey in credential store
9. Credential metadata returned (name, registration time)

### Authentication

1. Admin enters password, Express.js verifies
2. Express.js proxies to `POST /authenticate/start` with admin ID
3. `webauthn-rs` generates challenge with allowed credential IDs
4. Browser calls `navigator.credentials.get()`, user touches key
5. Browser returns PublicKeyCredential assertion
6. Express.js proxies to `POST /authenticate/finish`
7. `webauthn-rs` verifies assertion cryptographically
8. Counter updated, metadata returned, admin session created

## Threat Model

### Defended Against

- **MFA relay/phishing**: WebAuthn credentials are origin-bound; a phishing domain cannot trigger them
- **TOTP interception**: Hardware keys don't use shared secrets that can be intercepted
- **Credential replay**: Each authentication includes a counter and server challenge
- **Key extraction**: Private keys never leave the hardware authenticator

### Out of Scope

- **Physical key theft**: Mitigated by requiring PIN/biometric on the authenticator
- **Supply chain attacks on authenticators**: Mitigated by attestation verification
- **Browser compromise**: If the browser is compromised, all bets are off regardless

## Key Design Decisions

1. **File-backed storage**: Sacred.Vote has a single admin. A JSON file with atomic writes is simpler and more auditable than a database for this use case.

2. **Ephemeral ceremony state**: Registration and authentication challenges are held in memory, not persisted. If the server restarts mid-ceremony, the user simply retries. This avoids storing temporary secrets on disk.

3. **HTTP sidecar pattern**: Matches sacredvote-crypto and sacredvote-analytics. Express.js proxies to Rust; if the sidecar is down, the admin can still log in with TOTP (graceful degradation).

4. **webauthn-rs**: The most mature Rust WebAuthn implementation, maintained by the Kanidm project. Uses audited OpenSSL for cryptographic operations.

## Future Directions

- **Multi-admin support**: Scale credential store to multiple admins (database-backed)
- **Attestation CA verification**: Verify that keys come from known manufacturers
- **Client-side WASM**: Expose WebAuthn helpers for the Leptos frontend migration
