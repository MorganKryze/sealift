#!/bin/sh
# Prepares a fresh lab once `docker compose up -d` has started it: the Nexus
# admin password and repositories, a MinIO bucket per user and the MinIO user
# of the import service.
set -eu
cd "$(dirname "$0")"
NEXUS=http://127.0.0.1:18441
NEXUS_PASSWORD=${NEXUS_PASSWORD:-lab-admin-password}

echo "waiting for Nexus, about two minutes on a first start"
until curl -sf "$NEXUS/service/rest/v1/status/writable" >/dev/null; do sleep 5; done

if docker compose exec -T nexus test -f /nexus-data/admin.password; then
	initial=$(docker compose exec -T nexus cat /nexus-data/admin.password)
	curl -sf -u "admin:$initial" -X PUT -H 'Content-Type: text/plain' \
		--data "$NEXUS_PASSWORD" "$NEXUS/service/rest/v1/security/users/admin/change-password"
fi
auth="admin:$NEXUS_PASSWORD"

# The community edition refuses writes until its EULA is accepted.
eula=$(curl -sf -u "$auth" "$NEXUS/service/rest/v1/system/eula" || true)
if [ -n "$eula" ] && ! printf '%s' "$eula" | grep -q '"accepted" *: *true'; then
	printf '%s' "$eula" | sed 's/"accepted" *: *false/"accepted": true/' |
		curl -sf -u "$auth" -X POST -H 'Content-Type: application/json' --data @- \
			"$NEXUS/service/rest/v1/system/eula"
fi

# Installs read anonymously, as on the air-gapped side; publishing needs the admin account.
curl -sf -u "$auth" -X PUT -H 'Content-Type: application/json' \
	--data '{"enabled":true,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' \
	"$NEXUS/service/rest/v1/security/anonymous" >/dev/null

for format in npm pypi; do
	if ! curl -sf -u "$auth" "$NEXUS/service/rest/v1/repositories/$format/hosted/$format" >/dev/null; then
		curl -sf -u "$auth" -X POST -H 'Content-Type: application/json' \
			--data "{\"name\":\"$format\",\"online\":true,\"storage\":{\"blobStoreName\":\"default\",\"strictContentTypeValidation\":true,\"writePolicy\":\"allow_once\"}}" \
			"$NEXUS/service/rest/v1/repositories/$format/hosted"
	fi
done
echo "Nexus ready: repositories npm and pypi"

# The import publishes as its own user, with the privileges to browse, read,
# add and edit in the npm repository and to upload components, and no others.
# Nexus refuses a component upload without the edit privilege. The role is
# written on every run, so an older lab picks up a changed list.
IMPORT_PASSWORD=$(cat import/nexus-password)
role='{"id":"sealift-import","name":"sealift-import","description":"Publishes imported npm packages","privileges":["nx-repository-view-npm-npm-read","nx-repository-view-npm-npm-browse","nx-repository-view-npm-npm-add","nx-repository-view-npm-npm-edit","nx-component-upload"],"roles":[]}'
if curl -sf -u "$auth" "$NEXUS/service/rest/v1/security/roles/sealift-import" >/dev/null; then
	curl -sf -u "$auth" -X PUT -H 'Content-Type: application/json' --data "$role" \
		"$NEXUS/service/rest/v1/security/roles/sealift-import" >/dev/null
else
	curl -sf -u "$auth" -X POST -H 'Content-Type: application/json' --data "$role" \
		"$NEXUS/service/rest/v1/security/roles" >/dev/null
fi
if ! curl -sf -u "$auth" "$NEXUS/service/rest/v1/security/users?userId=sealift-import" | grep -q '"userId" *: *"sealift-import"'; then
	curl -sf -u "$auth" -X POST -H 'Content-Type: application/json' \
		--data "{\"userId\":\"sealift-import\",\"firstName\":\"sealift\",\"lastName\":\"import\",\"emailAddress\":\"sealift-import@lab.invalid\",\"password\":\"$IMPORT_PASSWORD\",\"status\":\"active\",\"roles\":[\"sealift-import\"]}" \
		"$NEXUS/service/rest/v1/security/users" >/dev/null
fi
echo "Nexus ready: user sealift-import"

for user in alice bob; do
	docker compose run --rm -T mc mb --ignore-existing "lab/user-$user" >/dev/null 2>&1
	for kind in npm pip; do
		printf '' | docker compose run --rm -T mc pipe "lab/user-$user/packages/$kind/.keep" >/dev/null 2>&1
	done
done
echo "MinIO ready: buckets user-alice and user-bob"

# The import service reads and deletes under packages/npm/ in any user bucket
# and writes nothing. The policy and the user are rewritten on every run, so
# an older lab picks up a changed policy.
mc() { docker compose run --rm -T mc "$@"; }
mc admin policy create lab sealift-import /import/minio-policy.json >/dev/null
mc admin user add lab "$(cat import/minio-access-key)" "$(cat import/minio-secret-key)" >/dev/null
mc admin policy attach lab sealift-import --user "$(cat import/minio-access-key)" >/dev/null 2>&1 || true
echo "MinIO ready: user sealift-import"
