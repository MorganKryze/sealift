#!/bin/sh
# Entrypoint of the "test" compose service: install pnpm, then hand off to
# run.mjs, which drives the whole end-to-end test through sealift's API.
set -eu

# npm publish shells out to git even for a tarball path, and the plain
# node:22-bookworm-slim image the "test" service runs carries none.
apt-get update >/dev/null && apt-get install -y --no-install-recommends git >/dev/null

npm install -g pnpm@10.34.5 >/dev/null

node run.mjs
