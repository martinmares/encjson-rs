"""Exercise release invariants in isolated workspaces, without publishing."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patch = patch.object(release, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        members = ["crates/core", "crates/cli", "crates/ctl", "crates/server", "crates/web"]
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nresolver = "2"\nmembers = ' + json.dumps(members) +
            '\n[workspace.package]\nversion = "0.9.0"\n')
        (self.root / "VERSION").write_text("0.9.0\n")
        self.binaries = ["encjson", "encjson-keys-ctl", "encjson-keys-server", "encjson-keys-web"]
        for index, member in enumerate(members):
            folder = self.root / member
            (folder / "src").mkdir(parents=True)
            manifest = f'[package]\nname = "test-{index}"\nversion.workspace = true\nedition = "2024"\n'
            if index:
                manifest += f'[[bin]]\nname = "{self.binaries[index-1]}"\npath = "src/main.rs"\n'
                (folder / "src/main.rs").write_text("fn main() {}\n")
            else:
                (folder / "src/lib.rs").write_text("")
            (folder / "Cargo.toml").write_text(manifest)
        self.command("cargo", "generate-lockfile", "--offline")
        for name in ("README.md", "LICENSE"):
            (self.root / name).write_text(name + "\n")
        self.command("git", "init", "-q")
        self.command("git", "config", "user.name", "Release test")
        self.command("git", "config", "user.email", "release@example.invalid")
        self.command("git", "config", "commit.gpgSign", "false")
        self.command("git", "add", ".")
        self.command("git", "commit", "-qm", "Initial test fixture")

    def command(self, *args):
        return subprocess.run(args, cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_bump_updates_all_packages_without_editing_member_manifests(self):
        originals = {p: p.read_bytes() for p in release.manifests()}
        with contextlib.redirect_stdout(io.StringIO()):
            release.bump("0.10.0-rc.1")
        self.assertEqual(release.check(), "0.10.0-rc.1")
        self.assertEqual(originals, {p: p.read_bytes() for p in release.manifests()})

    def test_failed_bump_restores_all_files(self):
        files = [self.root / name for name in ("VERSION", "Cargo.toml", "Cargo.lock")]
        originals = [p.read_bytes() for p in files]
        with patch.object(release.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cargo")):
            with self.assertRaises(subprocess.CalledProcessError):
                release.bump("0.10.0")
        self.assertEqual(originals, [p.read_bytes() for p in files])

    def test_mismatched_version_and_lock_are_rejected(self):
        (self.root / "VERSION").write_text("0.10.0\n")
        with self.assertRaisesRegex(AssertionError, "VERSION differs"):
            release.check()
        (self.root / "VERSION").write_text("0.9.0\n")
        p = self.root / "Cargo.lock"
        p.write_text(p.read_text().replace('version = "0.9.0"', 'version = "0.8.0"', 1))
        with self.assertRaisesRegex(AssertionError, "stale version"):
            release.check()

    def test_member_must_inherit_version(self):
        p = release.manifests()[0]
        p.write_text(p.read_text().replace('version.workspace = true', 'version = "0.9.0"'))
        with self.assertRaisesRegex(AssertionError, "inherit"):
            release.check()

    def test_tag_on_another_commit_is_rejected(self):
        self.command("git", "tag", "v0.9.0")
        self.assertEqual(release.check(release=True), "0.9.0")
        self.command("git", "commit", "--allow-empty", "-qm", "Another commit")
        with self.assertRaisesRegex(AssertionError, "another commit"):
            release.check(release=True)

    def test_invalid_version_is_rejected_without_changes(self):
        for version in ("01.2.3", "1.2", "v1.2.3", "1.2.3-01", "1.2.3+meta", "1.2.3\nmalicious"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.bump(version)
        self.assertEqual(release.check(), "0.9.0")

    def test_archives_contain_four_binaries_and_build_metadata(self):
        for target in release.TARGETS:
            folder = self.root / "target" / target / "release"
            folder.mkdir(parents=True)
            suffix = ".exe" if target.endswith("msvc") else ""
            for binary in self.binaries:
                (folder / (binary + suffix)).write_bytes(b"test binary")
            with contextlib.redirect_stdout(io.StringIO()):
                release.package(target)
            base = f"encjson-0.9.0-{release.TARGETS[target]}"
            dist = self.root / "dist/release"
            if suffix:
                with zipfile.ZipFile(dist / (base + ".zip")) as archive:
                    names = archive.namelist()
                    metadata = archive.read(base + "/BUILD.json")
            else:
                with tarfile.open(dist / (base + ".tar.gz")) as archive:
                    names = archive.getnames()
                    metadata = archive.extractfile(base + "/BUILD.json").read()
                    self.assertEqual(archive.getmember(base + "/encjson").mode, 0o755)
            for binary in self.binaries:
                self.assertIn(base + "/" + binary + suffix, names)
            self.assertEqual(json.loads(metadata)["target"], target)
        release.checksums()
        for line in (self.root / "dist/release/SHA256SUMS").read_text().splitlines():
            checksum, name = line.split("  ")
            self.assertEqual(checksum, hashlib.sha256((self.root / "dist/release" / name).read_bytes()).hexdigest())

    def test_missing_binary_prevents_archive(self):
        with self.assertRaisesRegex(AssertionError, "Missing release binary"):
            release.package("x86_64-unknown-linux-musl")
        self.assertEqual(list((self.root / "dist/release").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
