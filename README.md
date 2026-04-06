# sacredvote-webauthn

Hardware security keys provide the strongest form of multi-factor authentication available today. Unlike TOTP codes or SMS, WebAuthn credentials are cryptographically bound to the origin and cannot be phished, replayed, or intercepted by nation-state adversaries running real-time MFA relay attacks. This crate brings phishing-resistant FIDO2/WebAuthn authentication to Sacred.Vote's admin interface.

[![CI](https://github.com/redcaptian1917/sacredvote-webauthn/actions/workflows/ci.yml/badge.svg)](https://github.com/redcaptian1917/sacredvote-webauthn/actions)

## Problem

Sacred.Vote administrators manage election infrastructure — a high-value target for state-sponsored attackers. APT42-style attacks intercept TOTP codes in real time, defeating traditional 2FA. WebAuthn/FIDO2 eliminates this attack vector entirely: the browser's cryptographic origin check means a phishing page on `sacred-vote.evil.com` cannot trigger a credential bound to `sacred.vote`.

## How It Works

The crate runs as an Axum HTTP sidecar on port 3003, following the same architecture as `sacredvote-crypto` (port 3001) and `sacredvote-analytics` (port 3002). The Sacred.Vote Express.js server proxies WebAuthn requests during admin login.

```
Browser                    Express.js             sacredvote-webauthn
  |                           |                          |
  |-- Admin clicks login ---->|                          |
  |                           |-- POST /auth/start ----->|
  |<-- Challenge -------------|<-- Challenge ------------|
  |                           |                          |
  |-- Touch security key ---->|                          |
  |-- Assertion ------------->|-- POST /auth/finish ---->|
  |                           |<-- Verified + metadata --|
  |<-- Logged in -------------|                          |
```

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/register/start` | POST | Begin credential registration ceremony |
| `/register/finish` | POST | Complete registration with attestation |
| `/authenticate/start` | POST | Begin authentication ceremony |
| `/authenticate/finish` | POST | Complete authentication with assertion |
| `/credentials/{admin_id}` | GET | List registered credentials (metadata only) |
| `/credentials/{admin_id}/{id}` | DELETE | Remove a credential |
| `/health` | GET | Health check with credential count |

### Security Model

- **Origin binding**: Credentials are bound to `https://sacred.vote`
- **Attestation**: Supports `none` (privacy-preserving) and `direct` (hardware verification)
- **Credential storage**: File-backed JSON with atomic writes (appropriate for single-admin deployment)
- **No secrets in responses**: Only credential metadata is exposed via API, never key material

## Current Status

| Component | Status |
|-----------|--------|
| Registration ceremony | Working, 11 tests |
| Authentication ceremony | Working |
| Credential management | Working (list, remove) |
| File-backed persistence | Working (atomic JSON writes) |
| Axum HTTP sidecar | Working (port 3003) |
| Express.js proxy integration | Planned |
| Frontend WebAuthn UI | Planned |

## Quick Start

```bash
# Build the library
cargo build

# Run tests
cargo test

# Build and run the HTTP sidecar
cargo run --features server

# Or with custom configuration
WEBAUTHN_RP_ID=localhost \
WEBAUTHN_RP_ORIGIN=http://localhost:8080 \
WEBAUTHN_PORT=3003 \
cargo run --features server
```

## The PlausiDen Ecosystem

This crate is part of Sacred.Vote's security stack:
- **sacredvote-crypto** — SHA-512/HMAC/TOTP cryptographic operations (port 3001)
- **sacredvote-analytics** — Funnel/timing/health analytics engine (port 3002)
- **sacredvote-webauthn** — FIDO2/WebAuthn admin authentication (port 3003)
- **sacredvote-zktls** — Zero-knowledge TLS voter identity verification
- **sacredvote-gatekeeper** — Belenios election lifecycle management

## License

Apache-2.0
