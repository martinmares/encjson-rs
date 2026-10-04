#!/usr/bin/env bash
set -euo pipefail
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GH_REPO:?GH_REPO is required}"
# shellcheck disable=SC1091
source dist/release.env
(cd dist/release && sha256sum --check SHA256SUMS)
assets=(dist/release/encjson-"$RELEASE_VERSION"-*.tar.gz dist/release/encjson-"$RELEASE_VERSION"-*.zip dist/release/SHA256SUMS)
for asset in "${assets[@]}"; do test -s "$asset"; done

# Draft releases may defer tag creation until publication. Create the Git ref
# explicitly so the commit check works before any release assets are uploaded.
if ! gh api "repos/$GH_REPO/git/ref/tags/$RELEASE_TAG" >/dev/null 2>&1; then
  gh api --method POST "repos/$GH_REPO/git/refs" \
    -f "ref=refs/tags/$RELEASE_TAG" -f "sha=$RELEASE_COMMIT" >/dev/null
fi
remote_commit="$(gh api "repos/$GH_REPO/commits/$RELEASE_TAG" --jq '.sha')"
test "$remote_commit" = "$RELEASE_COMMIT" || { echo 'Tag belongs to another commit; bump VERSION' >&2; exit 1; }

if ! gh release view "$RELEASE_TAG" --repo "$GH_REPO" >/dev/null 2>&1; then
  gh release create "$RELEASE_TAG" --repo "$GH_REPO" --verify-tag \
    --title "encjson $RELEASE_TAG" --notes-file dist/release_notes.md --draft
fi
gh release upload "$RELEASE_TAG" --repo "$GH_REPO" "${assets[@]}" --clobber
prerelease=false
if [[ "$RELEASE_VERSION" == *-* ]]; then prerelease=true; fi
gh release edit "$RELEASE_TAG" --repo "$GH_REPO" --title "encjson $RELEASE_TAG" \
  --notes-file dist/release_notes.md --draft=false --prerelease="$prerelease"
