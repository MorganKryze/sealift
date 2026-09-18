#!/bin/sh
# Packs the local fixture package the end-to-end project depends on.
# Its package.json keeps publishConfig: sealift's own export strips it
# (spec section 5, step 3), so this script must not touch that field, or
# the test would prove nothing about sealift's stripping code.
set -eu

out="$(pwd)/fixture-out"
rm -rf "$out"
mkdir -p "$out"

npm pack "$(pwd)/fixtures/publishconfig-pkg" --pack-destination "$out" >/dev/null

echo "packed fixture:"
ls "$out"
