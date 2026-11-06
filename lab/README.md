# Lab

A local copy of both sides of the air gap, for development and proofs of concept. The connected side runs sealift with internet access. The air-gapped side runs Nexus, MinIO, Keycloak, oauth2-proxy and an nginx gateway on a Docker network with no route out. Every secret in `compose.yaml` is a fixed lab value, and every port binds to 127.0.0.1.

## Start

```sh
cd lab
just image                  # from the repository root: builds sealift:dev
docker compose up -d
./setup.sh
```

Every sealift service, connected and air-gapped, runs the published `ghcr.io/morgankryze/sealift:0.4.0`. `SEALIFT_IMAGE` picks another image, such as `sealift:dev` from `just image`.

`setup.sh` waits for Nexus (about two minutes on a first start), sets its admin password, accepts its EULA, creates the `npm` and `pypi` hosted repositories, creates the MinIO buckets `user-alice` and `user-bob` with `packages/npm/` and `packages/pip/`, and creates the MinIO user `sealift-import` with `import/minio-policy.json`. Run it again at any time: it skips what exists.

Nexus needs about 2 GB of memory. Give Docker at least 6 GB.

| Address | Service | Login |
| --- | --- | --- |
| http://localhost:18450 | sealift, connected side | none |
| http://localhost:18440 | the import service behind oauth2-proxy, air-gapped side | `alice` / `alice`, `bob` / `bob` |
| http://localhost:18441 | Nexus | `admin` / `lab-admin-password` |
| http://localhost:18442 | MinIO console | `lab-admin` / `lab-admin-password` |
| http://localhost:18443 | MinIO S3 API | same |
| http://localhost:18444 | Keycloak, realm `lab` | `admin` / `admin` |

The service at 18440 is `sealift import-server`, running without capabilities (`cap_drop: [ALL]`) on the air-gapped network with its own volume, `import-data`. It has no page yet: it answers `/api` with JSON. Sign in as a user and call it with the session cookie:

```sh
cookie=$(node scripts/session.mjs alice alice)
curl -H "Cookie: $cookie" http://localhost:18440/api/me
curl -H "Cookie: $cookie" http://localhost:18440/api/archives
```

oauth2-proxy runs with `--cookie-refresh=1m`, so the session outlives Keycloak's 5-minute access token. `scripts/forge.mjs` sends forged tokens straight to the service from `airgap-shell`, past the gateway: `other-key`, `none` and `expired` (the last waits about 6 minutes). Each answers 401 with the failed check named.

## Check the air gap

```sh
docker compose run --rm airgap-shell node /scripts/reach.mjs
docker compose run --rm connected-shell node -e "$(cat scripts/reach.mjs)"
```

The air-gapped shell must reach nexus, minio and keycloak, and neither registry.npmjs.org nor pypi.org. The connected shell must reach the two registries and none of the air-gapped services.

## Cross the gap

The protocol follows the real crossing. The `transfer/` folder plays the USB key and the kiosk: it is the only path between the two sides, and only a person moves files through it.

1. Connected side: in sealift at http://localhost:18450, set the signature key to `lab-signature-key` in the settings, install Trivy and its database, drop a `package.json`, analyse it and export. Save `packages_npm.tar.gz` and `manifest.json` into `lab/transfer/`.
2. Check the archive before it crosses: `shasum -a 256 transfer/packages_npm.tar.gz` must print the `archive.sha256` of `manifest.json`.
3. Air-gapped side: upload the archive and its manifest into the user's bucket, as users do through the MinIO browser:

   ```sh
   docker compose run --rm mc cp /transfer/packages_npm.tar.gz /transfer/manifest.json lab/user-alice/packages/npm/
   ```

4. Import. The service imports the archive from the user's folder; `sealift import` imports one from a local file. Both read `import/settings.yaml`, which points at Nexus as the `sealift-import` user that `setup.sh` creates with the privileges to read, browse, add and edit in the `npm` repository and to upload components, and no others. The signature key is `lab-signature-key`, the value step 1 sets in the settings.

   Through the service, start the import and follow it. The archive and `manifest.json` must sit together in the user's folder, as step 3 leaves them:

   ```sh
   curl -X POST -H "Cookie: $cookie" -H 'Content-Type: application/json' \
     -d '{"archive":"packages/npm/packages_npm.tar.gz"}' http://localhost:18440/api/imports
   curl -H "Cookie: $cookie" http://localhost:18440/api/imports/<id>
   ```

   The import is `queued`, then `running`, then `complete`, `incomplete`, `interrupted` or `refused`. Each package is `published`, `present` when Nexus already holds the same bytes, or `failed` with the reason. When it ends `complete`, the service removes the archive and its manifest from MinIO. A retry takes the body `{}`:

   ```sh
   curl -X POST -H "Cookie: $cookie" -H 'Content-Type: application/json' -d '{}' http://localhost:18440/api/imports/<id>/retry
   ```

   With the command line, run it from the sealift image on the air-gapped network:

   ```sh
   docker compose run --rm mc cp lab/user-alice/packages/npm/packages_npm.tar.gz /transfer/
   docker compose run --rm import sealift import -settings /import/settings.yaml -report /transfer/report.json /transfer/packages_npm.tar.gz
   ```

   The import checks the archive against `manifest.json` and the key before it uploads anything. The exit code is 0 when every package is published or present, and 1 otherwise. `transfer/report.json` holds the same result as JSON.

   To see a conflict, upload one of the archive's name and version with other bytes before the import. Repack it with one byte changed and upload it as admin:

   ```sh
   curl -u admin:lab-admin-password -F npm.asset=@planted.tgz "http://127.0.0.1:18441/service/rest/v1/components?repository=npm"
   ```

   Delete the component first when an import already published that name and version. The import then fails that package with both digests and publishes the others: through the service it ends `incomplete` and keeps the archive. It never overwrites. Delete the planted component in Nexus, or empty the repository with `docker compose down -v`, and retry: the retry uploads that one package, ends `complete` and removes the archive.

5. Install from Nexus on the air-gapped side, with the versions the export selected:

   ```sh
   docker compose run --rm airgap-shell sh -c 'cd /tmp && npm init -y >/dev/null && npm install --registry http://nexus:8081/repository/npm/ <name>@<version> ...'
   ```

   `airgap-shell` runs as linux x64, the platform sealift exports for. An arm64 shell would ask Nexus for platform packages the archive leaves out, such as `@esbuild/linux-arm64`.

A crossing passes when step 2 matches, step 4 reports no `failed`, and step 5 installs every selected version. With a planted conflict, step 4 fails that one package and step 5 installs the rest.

## Stop

```sh
docker compose down      # keeps the data
docker compose down -v   # deletes Nexus, MinIO, import and sealift data
```

## Not here yet

- The import web app: the service answers JSON, and the page that calls it does not exist.
- pip: the `pypi` repository and the `packages/pip/` folders exist, but no step publishes to them.
- Harbor, for container images.
