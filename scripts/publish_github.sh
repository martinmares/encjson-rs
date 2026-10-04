#!/usr/bin/env bash
set -euo pipefail
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GH_REPO:?GH_REPO is required}"
# shellcheck disable=SC1091
source dist/release.env
(cd dist/release && sha256sum --check SHA256SUMS)
assets=(dist/release/encjson-"$RELEASE_VERSION"-*.tar.gz dist/release/encjson-"$RELEASE_VERSION"-*.zip dist/release/SHA256SUMS)
for asset in "${assets[@]}"; do test -s "$asset"; done

# Re-read the remote tag before publishing, even when checkout did not have it.
if gh release view "$RELEASE_TAG" --repo "$GH_REPO" >/dev/null 2>&1; then
  remote_commit="$(gh api "repos/$GH_REPO/commits/$RELEASE_TAG" --jq '.sha')"
  test "$remote_commit" = "$RELEASE_COMMIT" || { echo 'Release belongs to another commit; bump VERSION' >&2; exit 1; }
else
  if gh api "repos/$GH_REPO/git/ref/tags/$RELEASE_TAG" >/dev/null 2>&1; then
    remote_commit="$(gh api "repos/$GH_REPO/commits/$RELEASE_TAG" --jq '.sha')"
    test "$remote_commit" = "$RELEASE_COMMIT" || { echo 'Tag belongs to another commit; bump VERSION' >&2; exit 1; }
  fi
  gh release create "$RELEASE_TAG" --repo "$GH_REPO" --target "$RELEASE_COMMIT" \
    --title "encjson $RELEASE_TAG" --notes-file dist/release_notes.md --draft
fi
remote_commit="$(gh api "repos/$GH_REPO/commits/$RELEASE_TAG" --jq '.sha')"
test "$remote_commit" = "$RELEASE_COMMIT" || { echo 'Tag belongs to another commit; bump VERSION' >&2; exit 1; }
gh release upload "$RELEASE_TAG" --repo "$GH_REPO" "${assets[@]}" --clobber
prerelease=false
if [[ "$RELEASE_VERSION" == *-* ]]; then prerelease=true; fi
gh release edit "$RELEASE_TAG" --repo "$GH_REPO" --title "encjson $RELEASE_TAG" \
  --notes-file dist/release_notes.md --draft=false --prerelease="$prerelease"
