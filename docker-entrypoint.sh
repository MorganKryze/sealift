#!/bin/sh
# HOME sits under the data volume so pnpm and Trivy, run as tools, and the
# server, run as app, write their caches to a directory both can reach.
# The volume can be empty on a first run, so this creates it every start
# instead of relying on the image layer, which a bind mount never sees.
set -e
mkdir -p "$HOME"
chmod 2775 "$HOME"
exec "$@"
