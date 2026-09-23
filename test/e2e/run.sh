#!/bin/sh
# Entrypoint of the "test" compose service: install pnpm, then hand off to
# run.mjs, which drives the whole end-to-end test through sealift's API.
# The documentation's examples run last, against the same sealift.
set -eu

# npm publish shells out to git even for a tarball path, and the plain
# node:22-bookworm-slim image the "test" service runs carries none. The
# documentation's examples call curl.
apt-get update >/dev/null && apt-get install -y --no-install-recommends git curl ca-certificates >/dev/null

npm install -g pnpm@10.34.5 >/dev/null

node run.mjs

node /repo/scripts/check-docs.mjs --run "$SEALIFT_URL" /repo/docs
