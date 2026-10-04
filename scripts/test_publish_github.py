"""Run the publisher against a fake gh service; never contact GitHub."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PUBLISHER = Path(__file__).resolve().parent / "publish_github.sh"
FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

path = Path(os.environ["GH_FAKE_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
state["calls"].append(args)

def finish(code=0, output=""):
    path.write_text(json.dumps(state))
    if output:
        print(output)
    sys.exit(code)

if args[0] == "api":
    endpoint = next(a for a in args if a.startswith("repos/"))
    if endpoint.endswith("/git/refs"):
        if state["tag"]:
            finish(1)
        state["tag"] = next(a[4:] for a in args if a.startswith("sha="))
        finish()
    if "/git/ref/tags/" in endpoint:
        finish(0 if state["tag"] else 1)
    if "/commits/" in endpoint:
        # GitHub cannot resolve a draft release's tag before it exists.
        finish(0 if state["tag"] else 1, state["tag"] or "")
    finish(2)

if args[:2] == ["release", "view"]:
    finish(0 if state["release"] else 1)
if args[:2] == ["release", "create"]:
    if state["release"] or ("--verify-tag" in args and not state["tag"]):
        finish(1)
    state["release"] = True
    state["draft"] = True
    # Creating a draft does not itself create the tag.
    finish()
if args[:2] == ["release", "upload"]:
    if not state["release"] or not state["tag"]:
        finish(1)
    state["uploaded"] = True
    finish()
if args[:2] == ["release", "edit"]:
    if not state["uploaded"]:
        finish(1)
    state["draft"] = False
    finish()
finish(2)
'''


class PublishGitHubTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        if not shutil.which("sha256sum"):
            sha = self.bin / "sha256sum"
            sha.write_text('#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n')
            sha.chmod(0o755)
        dist = self.root / "dist"
        assets = dist / "release"
        assets.mkdir(parents=True)
        (dist / "release.env").write_text("RELEASE_VERSION=0.9.1\nRELEASE_TAG=v0.9.1\nRELEASE_COMMIT=expected-commit\n")
        (dist / "release_notes.md").write_text("Release notes\n")
        sums = []
        for name in ("encjson-0.9.1-linux-amd64.tar.gz", "encjson-0.9.1-darwin-arm64.tar.gz", "encjson-0.9.1-windows-amd64.zip"):
            data = name.encode()
            (assets / name).write_bytes(data)
            sums.append(hashlib.sha256(data).hexdigest() + "  " + name + "\n")
        (assets / "SHA256SUMS").write_text("".join(sums))
        self.state_file = self.root / "service.json"

    def publish(self, tag=None, release=False, draft=True):
        self.state_file.write_text(json.dumps({"tag": tag, "release": release, "draft": draft,
                                               "uploaded": False, "calls": []}))
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                   GH_TOKEN="fake-token", GH_REPO="test/repo", GH_FAKE_STATE=str(self.state_file))
        result = subprocess.run(["bash", str(PUBLISHER)], cwd=self.root, env=env,
                                text=True, capture_output=True)
        return result, json.loads(self.state_file.read_text())

    def test_first_release_creates_tag_before_draft_and_upload(self):
        result, state = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["tag"], "expected-commit")
        self.assertFalse(state["draft"])
        self.assertTrue(state["uploaded"])
        calls = state["calls"]
        create_ref = next(i for i, a in enumerate(calls) if "repos/test/repo/git/refs" in a)
        create_draft = next(i for i, a in enumerate(calls) if a[:2] == ["release", "create"])
        self.assertLess(create_ref, create_draft)

    def test_retry_of_untagged_draft_publishes_existing_release(self):
        result, state = self.publish(release=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["tag"], "expected-commit")
        self.assertFalse(state["draft"])
        self.assertFalse(any(a[:2] == ["release", "create"] for a in state["calls"]))

    def test_existing_tag_on_different_commit_blocks_upload(self):
        result, state = self.publish(tag="another-commit", release=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another commit", result.stderr)
        self.assertEqual(state["tag"], "another-commit")
        self.assertFalse(state["uploaded"])

    def test_retry_of_published_release_reuses_tag(self):
        result, state = self.publish(tag="expected-commit", release=True, draft=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state["uploaded"])
        self.assertFalse(any("repos/test/repo/git/refs" in a for a in state["calls"]))

    def test_corrupt_archive_blocks_api_calls(self):
        (self.root / "dist/release/encjson-0.9.1-linux-amd64.tar.gz").write_bytes(b"corrupted")
        result, state = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["calls"], [])


if __name__ == "__main__":
    unittest.main()
