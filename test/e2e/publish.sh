#!/bin/sh
# Publishes every tarball of a directory to a registry, bootstrapping a
# throwaway user first since npm refuses to publish without a token even
# when the server authorizes $all. Used twice: once to seed the fixture
# package into the registry sealift resolves against, and once to publish
# the archive sealift's export produced to the air-gapped registry.
set -eu

registry="${1:?usage: publish.sh <registry-url> <dir-of-tgz>}"
dir="${2:?usage: publish.sh <registry-url> <dir-of-tgz>}"

token=$(node -e '
fetch(process.argv[1] + "/-/user/org.couchdb.user:e2e", {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "e2e", password: "e2e" }),
})
  .then((r) => r.json())
  .then((body) => process.stdout.write(body.token || ""))
' "$registry")
npm config set "//$(echo "$registry" | sed -E 's#^https?://##')/:_authToken" "$token"

for tgz in "$dir"/*.tgz; do
  npm publish "$tgz" --registry "$registry"
done
