# Lab

A local copy of both sides of the air gap, for development and proofs of concept. The connected side runs sealift with internet access. The air-gapped side runs Nexus, MinIO, Keycloak, oauth2-proxy and an nginx gateway on a Docker network with no route out. Every secret in `compose.yaml` is a fixed lab value, and every port binds to 127.0.0.1.

## Start

```sh
cd lab
just image                  # from the repository root: builds sealift:dev
docker compose up -d sealift
node scripts/carry-key.mjs
docker compose up -d
./setup.sh
```

The import service exits with code 2 without `import/public-key.pem`, and a stopped `import-server` takes the gateway down with it, so the second line carries the connected sealift's public key before the rest of the stack starts. The key is generated per volume; [Cross the gap](#cross-the-gap) says when to carry it again.

Every sealift service, connected and air-gapped, runs the published `ghcr.io/morgankryze/sealift:0.8.0`. `SEALIFT_IMAGE` picks any other image, such as `sealift:dev` after `just image`.

`setup.sh` waits for Nexus (about two minutes on a first start), sets its admin password, accepts its EULA, creates the `npm` and `pypi` hosted repositories, creates the MinIO buckets `user-alice` and `user-bob` with `packages/npm/` and `packages/pip/`, and creates the MinIO user `sealift-import` with `import/minio-policy.json`. Run it again at any time: it creates what is missing, and rewrites the import's roles and users, passwords included, from the files under `import/`.

Nexus needs about 2 GB of memory. Give Docker at least 6 GB.

| Address | Service | Login |
| --- | --- | --- |
| http://localhost:18450 | sealift, connected side | none |
| http://localhost:18440 | the import service behind oauth2-proxy, air-gapped side | `alice` / `alice`, `bob` / `bob` |
| http://localhost:18441 | Nexus | `admin` / `lab-admin-password` |
| http://localhost:18442 | MinIO console | `lab-admin` / `lab-admin-password` |
| http://localhost:18443 | MinIO S3 API | same |
| http://localhost:18444 | Keycloak, realm `lab` | `admin` / `admin` |

The service at 18440 is `sealift import-server`, running without capabilities (`cap_drop: [ALL]`) on the air-gapped network with its own volume, `import-data`. It serves the import screens at `/` and answers `/api` with JSON. Open http://localhost:18440 and sign in as `alice` or `bob`; [Importing](../docs/importing.md) describes each screen. To call the API instead, sign in as a user and send the session cookie:

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

1. Connected side: wait until `curl -s http://localhost:18450/healthz` prints `{"status":"ok"}`, which a first start reaches once it has downloaded Trivy, its database, pnpm and uv. Then, in sealift at http://localhost:18450, drop a `package.json`, analyse it and export. Save `packages_npm.tar.gz`, `manifest.json` and `manifest.json.sig` into `lab/transfer/`. The key is generated per volume, so carry its public key to the import side once, before `import-server` starts (Start does it on a fresh lab): from `lab/`, run `node scripts/carry-key.mjs`. It writes `import/public-key.pem` (untracked) from the connected sealift's `GET /api/signing-key` and prints the public key sha256, which equals the one on sealift's Instance page and, once the service runs, on the import's Instance page. The import service and `sealift import` exit with code 2 without that file. Run the script again after a regenerate or a new volume, then restart `import-server`.
2. Check the archive before it crosses: `shasum -a 256 transfer/packages_npm.tar.gz` must print the `archive.sha256` of `manifest.json`.
3. Air-gapped side: upload the archive, its manifest and its signature into the user's bucket, as users do through the MinIO browser:

   ```sh
   docker compose run --rm mc cp /transfer/packages_npm.tar.gz /transfer/manifest.json /transfer/manifest.json.sig lab/user-alice/packages/npm/
   ```

4. Import. The service imports the archive from the user's folder; `sealift import` imports one from a local file. Both read `import/settings.yaml`, which points at Nexus as the `sealift-import` user for npm and the `sealift-import-pip` user for pip. `setup.sh` gives `sealift-import` the privileges to read, browse, add and edit in the `npm` and `pypi` repositories and to upload components, and `sealift-import-pip` browse, read and edit in `pypi` alone. `publicKeyFile` names `import/public-key.pem`, the file step 1 writes.

   Through the screens, press **Import** on the archive's row of the home, optionally paste its sha256 and press `Start the import`. The import page follows it through `Check`, `Publish` and `In Nexus`, and ends on Done, on the causes of its failed packages, or refused. **Cancel** stops it, and a cancel through the API is `POST /api/imports/<id>/cancel` with the body `{}`. Through the API, start the import and follow it. The archive, `manifest.json` and `manifest.json.sig` must sit together in the user's folder, as step 3 leaves them:

   ```sh
   curl -X POST -H "Cookie: $cookie" -H 'Content-Type: application/json' \
     -d '{"archive":"packages/npm/packages_npm.tar.gz"}' http://localhost:18440/api/imports
   curl -H "Cookie: $cookie" http://localhost:18440/api/imports/<id>
   ```

   The import is `queued`, then `running`, then `complete`, `incomplete`, `interrupted` or `refused`. Each package is `published`, `present` when Nexus already holds the same bytes, or `failed` with the reason. When it ends `complete`, the service removes the archive, its manifest and its signature from MinIO. A retry takes the body `{}`:

   ```sh
   curl -X POST -H "Cookie: $cookie" -H 'Content-Type: application/json' -d '{}' http://localhost:18440/api/imports/<id>/retry
   ```

   With the command line, run it from the sealift image on the air-gapped network:

   ```sh
   docker compose run --rm mc cp lab/user-alice/packages/npm/packages_npm.tar.gz /transfer/
   docker compose run --rm import sealift import -settings /import/settings.yaml -report /transfer/report.json /transfer/packages_npm.tar.gz
   ```

   The import checks the manifest's signature, then the archive against `manifest.json`, before it uploads anything. `manifest.json.sig` is read beside `manifest.json`. The exit code is 0 when every package is published or present, and 1 otherwise. `transfer/report.json` holds the same result as JSON.

   The lab run of the screens checked, in a browser driven by script through the gateway, signed in as `alice` and as `bob`:

   - Records kept in the `import-data` volume by 0.4.0 read with `Not recorded` and the general next action.
   - Home lists the lab archives, with a row that cannot be imported for a folder holding two archives and one for a folder without a manifest, and a started import's row links to it.
   - A start with a wrong expected sha256 ends `Refused` with both digests; starting again with the right one runs, and ends `Complete` with the archive removed and the three ETags shown.
   - A planted conflict ends `Incomplete`, names the package and Nexus's reason, and says what to change before a retry. After the version is deleted in Nexus, the retry completes.
   - `docker compose pause nexus` during an import, then `docker compose restart import-server`, shows `Interrupted`. After `docker compose unpause nexus`, the retry completes.
   - Deleting the `_oauth2_proxy` cookie and pressing `Refresh` shows `Your session has ended`.
   - `bob` sees none of `alice`'s archives or imports.

   On commit 744e44c, the lab showed the signature checks through `sealift import` and the service's API, not through the screens in a browser:

   - The trusted key's sha256 from `GET /api/me` on the import service equalled the one from `GET /api/signing-key` on sealift.
   - An export imported `complete` through the command and through the service, which removed the archive, the manifest and the signature.
   - A manifest changed by one byte was refused, exit 3, with `the signature does not match the manifest`.
   - After a regenerate, a new export was refused, exit 3, with `the manifest is signed by another key` and both sha256. The regenerate passed the Host check through `localhost:18450`.
   - A folder without `manifest.json.sig` listed its archive as not importable, and an export of the 0.4.0 image was refused as unsigned.

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

A crossing passes when the sha256 of the key matches on both sides, step 2 matches, step 4 reports no `failed`, and step 5 installs every selected version. With a planted conflict, step 4 fails that one package and step 5 installs the rest.

### Plant the three failures

The import page groups failed packages by cause. Three causes can be planted in one attempt, as a run on commit 109ff80 did. A scratch nginx in front of Nexus, on the lab's air-gapped network, plays the limit and the silence:

```nginx
server {
  listen 8081;
  client_max_body_size 400k;
  proxy_read_timeout 600s;
  proxy_send_timeout 600s;
  location ~ ^/repository/npm/(express|body-parser)/-/ { return 444; }
  location / { proxy_pass http://nexus:8081; }
}
```

Point `nexus.url` of a copy of `import/settings.yaml` at that nginx, and mount the copy over `/import/settings.yaml` with a compose override. Then:

| Cause | How to plant it |
| --- | --- |
| `No answer from Nexus` | `return 444` closes the connection with no answer on the tarball reads of the packages it names. `docker compose pause nexus` plants nothing: a paused Nexus still accepts connections, and the service waits up to 5 minutes for an answer. |
| `Too large for Nexus` | `client_max_body_size` below the largest package of the archive, such as 400k for the getting-started archive, whose `@babel/parser` tarball is 467.8 KB. |
| `Another file under the same version` | Upload a package of the archive with other bytes before the import, as step 4 shows. |

Clear each cause, then press its block's Retry: remove the `return 444` line and reload nginx, raise `client_max_body_size`, and delete the planted copies in Nexus. Each Retry uploads that cause's packages alone. To see a cancel's confirm, pause Nexus during a large import, such as one of 265 packages: the attempt waits while paused, which leaves time to press Cancel. Remove the scratch nginx and the override when done.

## Cross the gap with pip

A pip archive crosses the same way: `packages_pip.tar.gz`, `manifest.json` and `manifest.json.sig` go together into the user's `packages/pip/` folder, and the import publishes each wheel to the `pypi` repository that `nexus.pip.repository` names in `import/settings.yaml`. An image older than 0.7.0 has no pip import.

Export the pip archive from the connected side through the API, as [Python projects](../docs/python.md) shows, and carry its three files into `transfer/`. The import publishes as `sealift-import-pip`, which holds browse, read and edit on `pypi` and nothing else: `import/settings.yaml` names it under `nexus.pip`, with its password in `import/nexus-pip-password`.

To cross without the connected side, a test packs a lab archive from wheels you fetch yourself, signed with a key made for the run:

```sh
# from the repository root, with .whl files for linux x86_64 and CPython 3.11 in <dir>
SEALIFT_LAB_PIP_WHEELS=<dir> SEALIFT_LAB_PIP_OUT=$PWD/lab/transfer/pip-lab \
  go test -v -count=1 -run TestPackLabPipArchive ./internal/importtest/
```

`SEALIFT_LAB_PIP_OUT` takes an absolute path: `go test` runs in the package's directory. The test writes the three files and the run's `public-key.pem` there, and prints its sha256. The manifest's target is Python 3.11.2 on linux x86_64 with glibc 2.28. Copy `import/public-key.pem` aside, put `transfer/pip-lab/public-key.pem` in its place, and start the lab. To go back to the connected sealift's key afterwards, copy yours back or run `node scripts/carry-key.mjs`, then restart `import-server`.

Steps 3 to 5 of [Cross the gap](#cross-the-gap) then read:

3. Upload the three files into a folder of `packages/pip/`. A folder holds one archive:

   ```sh
   docker compose run --rm mc cp /transfer/pip-lab/packages_pip.tar.gz /transfer/pip-lab/manifest.json /transfer/pip-lab/manifest.json.sig lab/user-alice/packages/pip/lab-run/
   ```

   The archive list reads each manifest and marks an archive filed under the wrong folder as not importable: an npm archive under `packages/pip/` reads `its manifest is an npm archive's: keep the three files under packages/npm/`.

4. Import through the screens or the API, with the archive's key:

   ```sh
   curl -X POST -H "Cookie: $cookie" -H 'Content-Type: application/json' \
     -d '{"archive":"packages/pip/lab-run/packages_pip.tar.gz"}' http://localhost:18440/api/imports
   ```

   Or from a local file with the command line:

   ```sh
   SEALIFT_IMAGE=sealift:dev docker compose run --rm import sealift import -settings /import/settings.yaml -report /transfer/pip-lab/report.json /transfer/pip-lab/packages_pip.tar.gz
   ```

   Each wheel is `published`, `present` when Nexus serves the same file name with the same bytes, or `failed` with the reason. With settings that have no `nexus.pip` section, `sealift import` refuses a pip archive, exit 3, before it uploads anything.

   To see a conflict, add one entry to a copy of a wheel the archive holds, keep its file name, and upload it as admin. Delete the component first when an import already published it:

   ```sh
   zip six-1.16.0-py2.py3-none-any.whl planted.txt
   printf 'user = "admin:lab-admin-password"\n' | curl -K - -F pypi.asset=@six-1.16.0-py2.py3-none-any.whl "http://127.0.0.1:18441/service/rest/v1/components?repository=pypi"
   ```

   The import then fails that wheel, kind `conflict`, with both sha512, and the others go on. Delete the planted component and run it again: it publishes that one wheel. `GET /service/rest/v1/components?repository=pypi` as admin gives each component's id, and `DELETE /service/rest/v1/components/<id>` removes it.

5. Download each wheel from Nexus in `pip-shell`, which runs linux x86_64 with CPython 3.11, the platform of the manifest's target, and compare its sha256 with the one in `manifest.json`:

   ```sh
   docker compose run --rm pip-shell sh -c 'pip download --no-deps --only-binary :all: --trusted-host nexus \
     --index-url http://nexus:8081/repository/pypi/simple/ -d /tmp/w <name>==<version> ... && sha256sum /tmp/w/*'
   ```

   pip uses an index served over plain HTTP only for a trusted host, and the lab's Nexus has no TLS on the air-gapped network. `pip-shell` mounts `transfer/` and `scripts/` as `airgap-shell` does.

6. Install the project from Nexus alone in `pip-shell`. First check that the shell has no route out, then install into a fresh environment with wheels only:

   ```sh
   docker compose run --rm pip-shell sh -c 'python -c "import urllib.request; urllib.request.urlopen(\"https://pypi.org\", timeout=5)"; \
     python -m venv /tmp/v && /tmp/v/bin/pip install --no-cache-dir --only-binary :all: --trusted-host nexus \
       --index-url http://nexus:8081/repository/pypi/simple/ -r <requirements file> && /tmp/v/bin/pip check'
   ```

   The first command must fail to resolve `pypi.org`. The install then ends with exit 0 and `pip check` prints `No broken requirements found.`

On commit f5c6f46, the lab showed:

- the connected side resolved a project of two requirements files into 173 packages, each with one wheel, and exported them in one archive whose sha256 matched its manifest;
- the import service published the 173 wheels as `sealift-import-pip`, with browse, read and edit alone; settings naming a pip user Nexus did not know failed every wheel with 401 before any upload;
- the service's MinIO user listed and read `packages/npm/` and `packages/pip/`, and could not put an object, list a bucket's root or list the buckets;
- `pip-shell`, with no route to the internet, installed the whole set from Nexus at Python 3.11.2, and `pip check` found no broken requirement.

### Prove the pypi upload path

`sh scripts/pypi-proof.sh`, run from `lab/` after `setup.sh`, checks the calls the pip import makes on Nexus as `sealift-import`. It fetches four public wheels from files.pythonhosted.org with their sha256 checked. For three of them it reads the repository list, reads the project's simple page before the upload, uploads through the components API with the `pypi.asset` field, reads the page and the linked file back, posts the same file again, and downloads the wheel with pip in `pip-shell`. It then removes each privilege of the role in turn, uploads the fourth wheel, names the call that breaks and restores the role. Last, it deletes its components. It prints one Markdown table row per check and exits 1 when a check fails. Credentials reach `curl` on stdin.

On commit ee12d3d, the proof showed on Nexus 3.96.5:

- The upload answers 204. The simple page lists the file in the same second, with a relative link ending in `#sha256=` and the file's sha256, and the link gives the uploaded bytes.
- The same file posted again answers 409: a repository that allows one write never overwrites.
- Without `nx-repository-view-pypi-pypi-browse`, the repository list omits `pypi`. Without `nx-repository-view-pypi-pypi-read`, the page and the file answer 403. Without `nx-repository-view-pypi-pypi-edit`, the upload answers 400 `Not authorized for requested path`. Without `nx-repository-view-pypi-pypi-add` or without `nx-component-upload`, every call the import makes still passes. The role keeps both for this script; the crossing above published through `sealift-import-pip`, which holds neither.

### What the lab showed for pip

On commit fa8b14e, with the image built by `just image` and an archive of five public wheels (six 1.16.0, mypy_extensions 1.0.0, MarkupSafe 2.1.5 for cp311 manylinux x86_64, idna 3.6 and attrs 23.2.0), the lab showed:

- `sealift import` ended `complete`, exit 0, with the five wheels `published`. A second run gave five `present`.
- With a six wheel holding one extra entry uploaded as admin under the same file name, the run ended `incomplete`, exit 1: six `failed`, kind `conflict`, `nexus holds this file with other bytes` with the shipped and Nexus sha512, and the four others `present`. After that component was deleted, the next run published six alone.
- With `nexus.pip` removed from a copy of the settings, the run was refused, exit 3, with `the settings name no pip repository: set nexus.pip.repository`.
- Through the gateway as `alice`, the archive in `packages/pip/lab-run/` was listed importable. The import started through the API ended `complete` with five `published`, Python 3.11.2 and glibc 2.28 in its report, and the service removed the archive, the manifest and the signature from MinIO.
- An npm archive's three files under `packages/pip/` were listed not importable with `its manifest is an npm archive's: keep the three files under packages/npm/`.
- `bob` saw none of `alice`'s archives or imports, and `GET /api/imports/<id>` of `alice`'s import answered 404.
- In `pip-shell`, `pip download` of each of the five wheels from the `pypi` repository gave the sha256 of the file fetched from files.pythonhosted.org.

## Check a gateway that forwards another header

Some gateways pass the access token in a header other than `X-Access-Token`. The service reads the one header `token.header` names and no other. The lab's gateway sends the token in both `X-Access-Token` and `X-Auth-Request-Access-Token`, so the lab can run the service on the second.

Copy `import/` to a scratch directory, add the header to its `token` section, and keep the key files that `setup.sh` wrote next to it:

```yaml
token:
  keySetUrl: http://keycloak:8080/realms/lab/protocol/openid-connect/certs
  issuer: http://localhost:18444/realms/lab
  audience: oauth2-proxy
  header: X-Auth-Request-Access-Token
```

Write a compose override in the scratch directory that mounts the copy at `/import`:

```yaml
services:
  import-server:
    volumes:
      - import-data:/data
      - <scratch>/import:/import:ro
```

Start the service with it:

```sh
SEALIFT_IMAGE=sealift:dev docker compose -f compose.yaml -f <scratch>/override.yaml up -d import-server
```

Sign in with `node scripts/session.mjs alice alice` and call `http://localhost:18440/api/me` and `/api/archives` with the cookie. Both answer 200 for alice, also when the request carries `X-Auth-Request-Access-Token: forged` and `X-Access-Token: forged`: the gateway overwrites both headers with the token it checked.

Past the gateway, `forge.mjs` takes `HEADER` and a mode `absent` that sends no token:

```sh
docker compose -f compose.yaml -f <scratch>/override.yaml run --rm \
  -e HEADER=X-Auth-Request-Access-Token airgap-shell node /scripts/forge.mjs absent
```

The service answers 401 with `absent check failed`. A `none` token sent in `X-Access-Token` gets the same answer, which shows the service ignores the default header once the settings name another.

This ran on commit 4ca9743 with the image built by `just image`. Restore the lab with `SEALIFT_IMAGE=sealift:dev docker compose -f compose.yaml up -d import-server`, then check that `/healthz` answers 200.

## Stop

```sh
docker compose down      # keeps the data
docker compose down -v   # deletes Nexus, MinIO, import and sealift data
```

## Not here yet

Harbor, for container images.
