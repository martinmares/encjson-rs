#!/usr/bin/env bash
set -euo pipefail
: "${CI_API_V4_URL:?}"
: "${CI_PROJECT_ID:?}"
: "${CI_JOB_TOKEN:?}"
# shellcheck disable=SC1091
source dist/release.env
(cd dist/release && sha256sum --check SHA256SUMS)
api="$CI_API_V4_URL/projects/$CI_PROJECT_ID"
package_url="$api/packages/generic/encjson/$RELEASE_VERSION"
tag_path="$(jq -nr --arg tag "$RELEASE_TAG" '$tag | @uri')"
response="$(mktemp)"
trap 'rm -f "$response"' EXIT

get_optional() {
  local status
  status="$(curl --silent --show-error --output "$response" --write-out '%{http_code}' \
    --header "JOB-TOKEN: $CI_JOB_TOKEN" "$1")"
  case "$status" in
    200) return 0 ;;
    404) return 1 ;;
    *) echo "GitLab API returned HTTP $status" >&2; exit 1 ;;
  esac
}

if get_optional "$api/repository/tags/$tag_path"; then
  test "$(jq -r '.commit.id' "$response")" = "$RELEASE_COMMIT" || { echo 'Tag belongs to another commit; bump VERSION' >&2; exit 1; }
fi
method=POST
endpoint="$api/releases"
if get_optional "$api/releases/$tag_path"; then
  test "$(jq -r '.commit.id' "$response")" = "$RELEASE_COMMIT" || { echo 'Release belongs to another commit; bump VERSION' >&2; exit 1; }
  method=PUT
  endpoint="$endpoint/$tag_path"
fi

# Upload separately to the persistent Package Registry, then publish release links.
links='[]'
for file in dist/release/encjson-"$RELEASE_VERSION"-*.tar.gz dist/release/encjson-"$RELEASE_VERSION"-*.zip dist/release/SHA256SUMS; do
  test -s "$file"
  name="${file##*/}"
  curl --silent --show-error --fail --request PUT --header "JOB-TOKEN: $CI_JOB_TOKEN" \
    --upload-file "$file" "$package_url/$name" >/dev/null
  links="$(jq -c --arg name "$name" --arg url "$package_url/$name" '. + [{name: $name, url: $url, link_type: "package"}]' <<< "$links")"
done

if [[ "$method" == POST ]]; then
  jq -n --arg name "encjson $RELEASE_TAG" --arg tag "$RELEASE_TAG" --arg ref "$RELEASE_COMMIT" \
    --rawfile notes dist/release_notes.md --argjson links "$links" \
    '{name: $name, tag_name: $tag, ref: $ref, description: $notes, assets: {links: $links}}' > dist/gitlab_release.json
else
  jq -n --arg name "encjson $RELEASE_TAG" --rawfile notes dist/release_notes.md \
    '{name: $name, description: $notes}' > dist/gitlab_release.json
fi
curl --silent --show-error --fail --request "$method" --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  --header 'Content-Type: application/json' --data-binary @dist/gitlab_release.json "$endpoint" >/dev/null

# Repair missing links on retries after a partially completed release.
if [[ "$method" == PUT ]]; then
  while IFS= read -r link; do
    name="$(jq -r '.name' <<< "$link")"
    get_optional "$api/releases/$tag_path/assets/links"
    id="$(jq -r --arg name "$name" '.[] | select(.name == $name) | .id' "$response")"
    link_method=POST
    link_endpoint="$api/releases/$tag_path/assets/links"
    if [[ -n "$id" ]]; then link_method=PUT; link_endpoint="$link_endpoint/$id"; fi
    curl --silent --show-error --fail --request "$link_method" --header "JOB-TOKEN: $CI_JOB_TOKEN" \
      --header 'Content-Type: application/json' --data "$link" "$link_endpoint" >/dev/null
  done < <(jq -c '.[]' <<< "$links")
fi
echo "Published encjson $RELEASE_TAG"
