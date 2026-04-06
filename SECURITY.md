# Security Policy

## Reporting Vulnerabilities

Report security vulnerabilities to **security@sacredvote.org**.

Expected response time: 48 hours for acknowledgment, 7 days for initial assessment.

## Scope

This policy covers the sacredvote-webauthn crate, including:
- WebAuthn ceremony implementation
- Credential storage and management
- HTTP API endpoints

## Cryptographic Dependencies

All cryptographic operations are delegated to `webauthn-rs` which uses OpenSSL. No custom cryptography is implemented in this crate.
