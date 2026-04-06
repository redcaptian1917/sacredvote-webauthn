# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- WebAuthn registration and authentication ceremonies via `webauthn-rs` 0.5
- File-backed credential storage with atomic JSON writes
- Axum HTTP sidecar on port 3003 (behind `server` feature)
- 11 unit tests covering store creation, ceremony lifecycle, error paths
- Master-standard documentation (README, ARCHITECTURE, CONTRIBUTING, SECURITY)
