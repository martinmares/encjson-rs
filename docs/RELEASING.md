# CI and releases

All five crates share one product version. The root `Cargo.toml` contains
`workspace.package.version`; every member uses `version.workspace = true`.
`VERSION` is the explicit release trigger and must contain the same version.
The tracked `Cargo.lock` must also contain that version for every workspace
package. No Git hook is required.

## Change the version

With Rust, Python 3.11+ and `just` installed:

```sh
just release-version 0.10.0
just check-version
```

The first command updates `VERSION`, the shared Cargo version and `Cargo.lock`.
It runs `cargo update --offline --workspace` to update local packages without
upgrading external dependencies. If it fails, those three files are restored.
Individual crate manifests do not change. Commit the three files together with
the changes you want to release. Stable versions (`0.10.0`) and prereleases
(`0.10.0-rc.1`) are supported; build metadata (`+...`) is not supported.

Pushing that commit to `main` starts the GitHub release workflow. GitLab uses its
configured default branch. Each platform publishes its own release using the
same source commit, with tag `v0.10.0`. Push the release commit to each remote
where you want to publish. Pipelines do not push source changes or generated
changelogs back to Git.

A GitHub `workflow_dispatch` on `main`, or a GitLab pipeline started through
**Run pipeline** on its default branch, also requests a release. Use this to
publish the initial `0.9.0` or retry a failed release at the same commit. An
existing tag pointing at another commit is rejected: change the version to
publish new source. Do not move an existing release tag.

## Verification

Normal GitHub pushes to `main`, pull requests, GitLab default-branch pipelines
and merge requests verify shared versions, release scripts, Rust formatting and
`cargo test --locked --workspace --all-targets`. Release pipelines run the same
checks before building. PostgreSQL 16 is provided in CI so the existing database
integration tests run rather than silently skip.

The Rust toolchain is pinned in `rust-toolchain.toml`. When upgrading it, update
the GitHub workflow toolchain settings and the GitLab image/cache prefix too.
Linux and Windows cross-compilation tools also have explicit versions in CI.

## Release packages

Every archive contains all four binaries: `encjson`, `encjson-keys-ctl`,
`encjson-keys-server` and `encjson-keys-web`, plus `README.md`, `LICENSE`,
`VERSION` and `BUILD.json` (version, source commit, target and binary names).
Release builds strip symbols to reduce download sizes. PostgreSQL migrations
are embedded in the keys server by SQLx.

| Platform | Archive | GitHub | GitLab |
| --- | --- | --- | --- |
| Linux x86_64 MUSL | `encjson-X.Y.Z-linux-amd64.tar.gz` | Yes | Yes |
| macOS Apple Silicon | `encjson-X.Y.Z-darwin-arm64.tar.gz` | Yes | Optional runner |
| Windows x86_64 MSVC | `encjson-X.Y.Z-windows-amd64.zip` | Yes | Yes, cross-compiled |

These targets match the existing `justfile`. Release notes list commits since
the previous reachable release tag. `SHA256SUMS` covers all published archives.
GitHub marks versions containing a prerelease suffix as prereleases; GitLab
exposes them as ordinary releases with the suffix in the name and tag.

GitHub assembles archives on hosted runners, creates or verifies the Git tag
on the release commit, creates a draft release, uploads assets, then publishes
it. Explicit tag creation allows commit verification before the draft is
published and supports retries of existing drafts. Only the publishing job has
`contents: write`; it
uses the built-in `GITHUB_TOKEN`. No extra token is needed. Retrying the same
commit can replace its assets.

GitLab builds Linux and Windows with a Linux Docker runner. The Windows job
installs `llvm` in addition to Clang and LLD: C/C++ dependencies require
`llvm-lib` to create MSVC static libraries. It checks for `clang`, `lld-link`
and `llvm-lib` before compiling. Archives are passed
as short-lived CI artifacts, then uploaded individually to the persistent
Generic Package Registry. Release links point to registry files, so they keep
working after CI artifacts expire. The built-in `CI_JOB_TOKEN` authenticates
package uploads and release creation. Enable the Package Registry and allow
release creation under your project's protected-tag policy. On instances that
disable duplicate generic package files, adjust that setting if same-commit
retries should replace uploads.

To include macOS on GitLab, register an Apple Silicon **shell executor** runner
with tag `macos-arm64`, install rustup, Xcode command-line tools and Python
3.11+, and set CI/CD variable `RUN_MACOS_RELEASE=true`. Without that variable,
macOS is omitted and Linux/Windows releases proceed. When enabled, publication
waits for the macOS build too. The macOS job does not use the Linux container's
`before_script`.

## Local verification and packaging

```sh
just check-version
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo fmt --all -- --check
just test
# Set DATABASE_URL to a disposable PostgreSQL database to include DB tests.

just build-macos
python3 scripts/release.py package aarch64-apple-darwin
python3 scripts/release.py prepare
python3 scripts/release.py checksums
```

The packaging commands only write `dist/`; publishing is a separate CI step.
