set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

macos_target := "aarch64-apple-darwin"
linux_target := "x86_64-unknown-linux-musl"
windows_target := "x86_64-pc-windows-msvc"

# List available jobs.
default:
    @just --list

# Build all workspace binaries for the current platform.
build:
    cargo build --locked --release --workspace

build-debug:
    cargo build --locked --workspace

build-macos:
    cargo build --locked --release --workspace --target {{ macos_target }}

# Cross-compile static Linux binaries using cargo-zigbuild and Zig.
build-linux:
    cargo zigbuild --locked --release --workspace --target {{ linux_target }}

# Cross-compile Windows binaries using cargo-xwin and the MSVC SDK.
build-windows:
    cargo xwin build --locked --release --workspace --target {{ windows_target }}

fmt:
    cargo fmt --all

check:
    cargo check --locked --workspace --all-targets

test:
    cargo test --locked --workspace --all-targets

# Set the shared release version and refresh Cargo.lock (Python 3.11+).
release-version version:
    python3 scripts/release.py bump {{ quote(version) }}

# Verify VERSION, workspace manifests and Cargo.lock agree.
check-version:
    python3 scripts/release.py check
