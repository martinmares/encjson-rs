#!/usr/bin/env python3
"""Shared version checks and release packaging; requires Python 3.11+."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")
TARGETS = {
    "x86_64-unknown-linux-musl": "linux-amd64",
    "aarch64-apple-darwin": "darwin-arm64",
    "x86_64-pc-windows-msvc": "windows-amd64",
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def toml(path):
    return tomllib.loads(path.read_text())


def valid_version(version):
    match = SEMVER.fullmatch(version)
    if not match or any(part.isdigit() and len(part) > 1 and part.startswith("0")
                        for part in (match[4] or "").split(".")):
        raise ValueError(f"Invalid release version: {version!r}; use X.Y.Z or X.Y.Z-prerelease")
    return version


def manifests():
    workspace = toml(ROOT / "Cargo.toml")["workspace"]
    return [ROOT / member / "Cargo.toml" for member in workspace["members"]]


def check(release=False):
    version = valid_version((ROOT / "VERSION").read_text().strip())
    assert toml(ROOT / "Cargo.toml")["workspace"]["package"]["version"] == version, "VERSION differs from workspace.package.version"
    lock = {p["name"]: p["version"] for p in toml(ROOT / "Cargo.lock")["package"] if "source" not in p}
    for path in manifests():
        package = toml(path)["package"]
        assert package["version"] == {"workspace": True}, f"{path}: version must inherit from workspace"
        assert lock.get(package["name"]) == version, f"Cargo.lock has a stale version for {package['name']}"
    if release:
        tag = f"v{version}"
        ref = f"refs/tags/{tag}"
        found = subprocess.run(["git", "show-ref", "--verify", "--quiet", ref], cwd=ROOT)
        if found.returncode == 0:
            assert git("rev-parse", f"{ref}^{{commit}}") == git("rev-parse", "HEAD"), f"{tag} belongs to another commit; bump VERSION"
        elif found.returncode != 1:
            raise ValueError(f"Cannot inspect {ref}")
    return version


def bump(version):
    valid_version(version)
    paths = [ROOT / "VERSION", ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    originals = {p: p.read_bytes() for p in paths}
    try:
        text = paths[1].read_text()
        text, count = re.subn(r'(\[workspace\.package\]\s*\nversion = ")[^"]+(")',
                             lambda m: m[1] + version + m[2], text, count=1)
        assert count == 1, "Expected workspace.package.version immediately after the section header"
        paths[1].write_text(text)
        paths[0].write_text(version + "\n")
        # Updating workspace package versions does not require upgrading dependencies.
        subprocess.run(["cargo", "update", "--offline", "--workspace"],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
        check()
    except BaseException:
        for path, content in originals.items():
            path.write_bytes(content)
        raise
    print(f"Set all workspace crates to {version}. Commit VERSION, Cargo.toml and Cargo.lock together.")


def prepare():
    version = check(release=True)
    tag = f"v{version}"
    commit = git("rev-parse", "HEAD")
    tags = git("tag", "--merged", commit, "--list", "v[0-9]*", "--sort=-version:refname").splitlines()
    previous = next((t for t in tags if t != tag), "")
    log = git("log", "--no-merges", "--format=- %s (%h)", f"{previous}..{commit}" if previous else commit)
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    notes = f"# encjson {tag}\n\n" + (f"Changes since {previous}:\n\n" if previous else "Initial release:\n\n") + log + "\n"
    (dist / "release_notes.md").write_text(notes)
    (dist / "release.env").write_text(f"RELEASE_VERSION={version}\nRELEASE_TAG={tag}\nRELEASE_COMMIT={commit}\n")
    print(notes)


def package(target):
    version = check(release=True)
    base = f"encjson-{version}-{TARGETS[target]}"
    binaries = [b["name"] for p in manifests() for b in toml(p).get("bin", [])]
    dist = ROOT / "dist" / "release"
    dist.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="encjson-release-") as temp:
        folder = Path(temp) / base
        folder.mkdir()
        for binary in binaries:
            name = binary + (".exe" if target.endswith("msvc") else "")
            source = ROOT / "target" / target / "release" / name
            assert source.is_file(), f"Missing release binary: {source}"
            shutil.copy2(source, folder / name)
            if not target.endswith("msvc"):
                (folder / name).chmod(0o755)
        for name in ("README.md", "LICENSE"):
            shutil.copy2(ROOT / name, folder / name)
        (folder / "VERSION").write_text(version + "\n")
        (folder / "BUILD.json").write_text(json.dumps({
            "version": version, "commit": git("rev-parse", "HEAD"), "target": target,
            "binaries": binaries,
        }, indent=2) + "\n")
        if target.endswith("msvc"):
            archive = dist / f"{base}.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
                for file in sorted(folder.iterdir()):
                    output.write(file, f"{base}/{file.name}")
        else:
            archive = dist / f"{base}.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(folder, arcname=base)
        print(archive.relative_to(ROOT))


def checksums():
    version = check(release=True)
    dist = ROOT / "dist" / "release"
    files = sorted([*dist.glob(f"encjson-{version}-*.tar.gz"), *dist.glob(f"encjson-{version}-*.zip")])
    assert files, "No release archives found"
    lines = []
    for file in files:
        with file.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        lines.append(f"{digest}  {file.name}\n")
    (dist / "SHA256SUMS").write_text("".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check").add_argument("--release", action="store_true")
    commands.add_parser("bump").add_argument("version")
    commands.add_parser("prepare")
    commands.add_parser("package").add_argument("target", choices=TARGETS)
    commands.add_parser("checksums")
    args = parser.parse_args()
    try:
        if args.command == "check":
            print(check(args.release))
        elif args.command == "bump":
            bump(args.version)
        elif args.command == "prepare":
            prepare()
        elif args.command == "package":
            package(args.target)
        else:
            checksums()
    except (AssertionError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"release: {error}\n")


if __name__ == "__main__":
    main()
