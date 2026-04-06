test:
    TMPDIR=/home/admin/tmp cargo test

test-verbose:
    TMPDIR=/home/admin/tmp cargo test -- --nocapture

fmt:
    cargo fmt

lint:
    cargo clippy -- -D warnings

lint-all:
    cargo clippy --features server -- -D warnings

build:
    cargo build --release --features server

run:
    cargo run --features server

docs:
    cargo doc --no-deps --open

audit:
    cargo audit

check-all: fmt lint-all test build
