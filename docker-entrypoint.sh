#!/bin/sh
# The import roles read no HOME and write only under /tmp or their own data
# volume, so they skip the setup below. They run from the copy of the binary
# that carries no capability, and also start under --cap-drop ALL. A bare
# `sealift` or its full path both select them.
case "${1:-}" in
sealift | /usr/local/bin/sealift)
	case "${2:-}" in
	import | import-server)
		role=$2
		shift 2
		exec /usr/local/bin/sealift-import "$role" "$@"
		;;
	esac
	;;
esac
# HOME sits under the data volume so pnpm and Trivy, run as tools, and the
# server, run as app, write their caches to a directory both can reach.
# The volume can be empty on a first run, so this creates it every start
# instead of relying on the image layer, which a bind mount never sees.
set -e
mkdir -p "$HOME"
chmod 2775 "$HOME"
exec "$@"
