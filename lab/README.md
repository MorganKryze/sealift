# Lab

A local copy of both sides of the air gap, for development and proofs of concept. The connected side runs sealift with internet access. The air-gapped side runs Nexus, MinIO, Keycloak, oauth2-proxy and an nginx gateway on a Docker network with no route out. Every secret in `compose.yaml` is a fixed lab value, and every port binds to 127.0.0.1.

## Start

```sh
cd lab
docker compose up -d
./setup.sh
```

`setup.sh` waits for Nexus (about two minutes on a first start), sets its admin password, accepts its EULA, creates the `npm` and `pypi` hosted repositories, and creates the MinIO buckets `user-alice` and `user-bob` with `packages/npm/` and `packages/pip/`. Run it again at any time: it skips what exists.

Nexus needs about 2 GB of memory. Give Docker at least 6 GB.

| Address | Service | Login |
| --- | --- | --- |
| http://localhost:18450 | sealift, connected side | none |
| http://localhost:18440 | the app behind oauth2-proxy, air-gapped side | `alice` / `alice`, `bob` / `bob` |
| http://localhost:18441 | Nexus | `admin` / `lab-admin-password` |
| http://localhost:18442 | MinIO console | `lab-admin` / `lab-admin-password` |
| http://localhost:18443 | MinIO S3 API | same |
| http://localhost:18444 | Keycloak, realm `lab` | `admin` / `admin` |

Until the import web app exists, the app at 18440 is `traefik/whoami`: it echoes each request, so the page shows the `X-Access-Token` header and the user oauth2-proxy forwards, as the air-gapped gateway does.

`SEALIFT_IMAGE` picks another sealift image, such as `sealift:dev` from `just image`.

## Check the air gap

```sh
docker compose run --rm airgap-shell node /scripts/reach.mjs
docker compose run --rm connected-shell node -e "$(cat scripts/reach.mjs)"
```

The air-gapped shell must reach nexus, minio and keycloak, and neither registry.npmjs.org nor pypi.org. The connected shell must reach the two registries and none of the air-gapped services.

## Cross the gap

The protocol follows the real crossing. The `transfer/` folder plays the USB key and the kiosk: it is the only path between the two sides, and only a person moves files through it.

1. Connected side: in sealift at http://localhost:18450, set a signature key in the settings, install Trivy and its database, drop a `package.json`, analyse it and export. Save `packages_npm.tar.gz` and `manifest.json` into `lab/transfer/`.
2. Check the archive before it crosses: `shasum -a 256 transfer/packages_npm.tar.gz` must print the `archive.sha256` of `manifest.json`.
3. Air-gapped side: upload it into the user's bucket, as users do through the MinIO browser:

   ```sh
   docker compose run --rm mc cp /transfer/packages_npm.tar.gz lab/user-alice/packages/npm/
   ```

4. Import with `sealift import`, run from the sealift image on the air-gapped network. `import/settings.yaml` points it at Nexus as the `sealift-import` user, which `setup.sh` creates with the privileges to read, browse, add and edit in the `npm` repository and to upload components, and no others. The signature key is `lab-signature-key`, the value step 1 sets in the settings.

   ```sh
   docker compose run --rm mc cp lab/user-alice/packages/npm/packages_npm.tar.gz /transfer/
   docker compose run --rm import sealift import -settings /import/settings.yaml -report /transfer/report.json /transfer/packages_npm.tar.gz
   ```

   The import checks the archive against `manifest.json` and the key before it uploads anything. Each package prints `published`, `present` when Nexus already holds the same bytes, or `failed` with the reason. The exit code is 0 when every package is published or present, and 1 otherwise. `transfer/report.json` holds the same result as JSON.

   To see a conflict, upload one of the archive's name and version with other bytes before the import. Repack it with one byte changed and upload it as admin:

   ```sh
   curl -u admin:lab-admin-password -F npm.asset=@planted.tgz "http://127.0.0.1:18441/service/rest/v1/components?repository=npm"
   ```

   The import then fails that package with both digests, publishes the others, and exits 1. A second run reports the others as `present` and fails the same package again: the import never overwrites. Delete the component in Nexus, or empty the repository with `docker compose down -v`, to clear it.

5. Install from Nexus on the air-gapped side, with the versions the export selected:

   ```sh
   docker compose run --rm airgap-shell sh -c 'cd /tmp && npm init -y >/dev/null && npm install --registry http://nexus:8081/repository/npm/ <name>@<version> ...'
   ```

   `airgap-shell` runs as linux x64, the platform sealift exports for. An arm64 shell would ask Nexus for platform packages the archive leaves out, such as `@esbuild/linux-arm64`.

A crossing passes when step 2 matches, step 4 reports no `failed`, and step 5 installs every selected version. With a planted conflict, step 4 fails that one package and step 5 installs the rest.

## Stop

```sh
docker compose down      # keeps the data
docker compose down -v   # deletes Nexus, MinIO and sealift data
```

## Not here yet

- The import web app, which replaces `app` behind the gateway: the command exists, the page that runs it for a user does not.
- pip: the `pypi` repository and the `packages/pip/` folders exist, but no step publishes to them.
- Harbor, for container images.
