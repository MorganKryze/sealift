#!/bin/sh
# Publishes every tarball of a sealift archive to the lab's Nexus, the way
# the import does, and fails when any package fails. Run it from airgap-shell:
# `docker compose run --rm airgap-shell sh /scripts/publish-npm.sh /transfer/packages_npm.tar.gz`.
set -eu
archive=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
[ -f "$work/out/signature.key" ] || { echo "no out/signature.key in $archive"; exit 1; }

registry=http://nexus:8081/repository/npm/
auth=$(printf 'admin:%s' "${NEXUS_PASSWORD:-lab-admin-password}" | base64)
printf '//nexus:8081/repository/npm/:_auth=%s\n' "$auth" >"$work/.npmrc"

failed=0
for tarball in "$work"/out/*.tgz; do
	name=$(basename "$tarball")
	if npm publish "$tarball" --registry "$registry" --userconfig "$work/.npmrc" >/dev/null 2>"$work/err"; then
		echo "published  $name"
	elif grep -qE 'EPUBLISHCONFLICT|E409|cannot publish over' "$work/err"; then
		echo "present    $name"
	else
		echo "failed     $name: $(grep -m1 'npm error' "$work/err" || tail -1 "$work/err")"
		failed=$((failed + 1))
	fi
done
[ "$failed" -eq 0 ]
