# Contributing

## Setup

```bash
# Clone
git clone https://github.com/redcaptian1917/sacredvote-webauthn.git
cd sacredvote-webauthn

# Build
cargo build

# Test
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

## Code Style

- `rustfmt` for formatting
- `clippy` with `-D warnings`
- Doc comments (`///`) on all public items
- `thiserror` for error types
- `tracing` for structured logging

## Testing

Every public function must have at least one test. WebAuthn ceremonies can be tested using `webauthn-rs`'s built-in test types.

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`feature/your-feature`)
3. Write tests for new functionality
4. Ensure `cargo clippy -- -D warnings` passes
5. Submit a pull request

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
