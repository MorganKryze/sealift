# Deployment

This page covers running sealift for a team: Compose, readiness, the policy file, a reverse proxy, the data volume, upgrades and backups. To deploy both sides from written steps, with a Helm chart for the import service on Kubernetes, read [the runbook](runbook.md), [Helm chart](helm.md) and [Request to the administrators](admin-request.md). [Getting started](getting-started.md) has the one-line `docker run` for a first try.

## The image

`ghcr.io/morgankryze/sealift` is published for `linux/amd64` and `linux/arm64`. Tags carry no `v`: `0.2.2`, and `latest` for the newest release. Pin a version in production and upgrade on purpose.

The image holds the sealift binary, the web interface and Node 22. The rest lands in the volume, downloaded at start with no action from anyone: the Trivy release the binary pins, its vulnerability database, and the pnpm and uv versions the default targets name. [Readiness](#readiness) says when the instance can take an analysis.

## Compose

```yaml
services:
  sealift:
    image: ghcr.io/morgankryze/sealift:0.7.0
    restart: unless-stopped
    ports:
      - 127.0.0.1:8080:8080
    volumes:
      - sealift-data:/data
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
      - KILL
    security_opt:
      - no-new-privileges=false
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
      interval: 30s
      start_period: 10m
      start_interval: 5s

volumes:
  sealift-data:
```

`deploy/connected/compose.yaml` holds the same service. This setup was checked with an analysis and an export. The root filesystem is read-only; sealift writes only to `/data` and `/tmp`.

sealift runs as user `app` (uid 10000) and starts pnpm and Trivy as a second user, `tools` (uid 10001), so neither they nor any package they handle can read `private/`, which holds the settings and the signing key. Switching users needs `SETUID` and `SETGID`, and stopping a cancelled job needs `KILL`. Every other capability can go.

`no-new-privileges` stops the switch to the `tools` user, and every analysis fails with `fork/exec ... operation not permitted`. A Docker daemon can set it for every container through `"no-new-privileges": true` in `daemon.json`, so the Compose file turns it off by name with `security_opt: [no-new-privileges=false]`. Leaving the option out is not enough on such a host. `docker inspect` shows `SecurityOpt: null` either way; `docker exec <container> grep NoNewPrivs /proc/1/status` shows what applies, and it must print `0`. sealift also logs an error at startup when it finds the flag set.

## Readiness

At start, sealift prepares five items, in this order: it checks the signing key, then installs the pinned Trivy and downloads its database, and installs pnpm and uv. The three installs take turns, one download at a time. Until every item is ready, `GET /healthz` answers 503 and names what is missing:

```
{"status":"preparing","missing":["trivy-db","pnpm"]}
```

Once all five are ready, it answers 200 with `{"status":"ok"}`. Meanwhile the interface and the API answer: the home shows Preparing this instance, with each item, its state and, for a failed one, its cause and the time of its next try. The home opens by itself once the instance is ready. The API refuses to create a session or start an analysis until Trivy and its database are in place. `GET /api/instance` gives each item's state and cause, as [the API reference](dev/api.md#instance) shows.

A failed item keeps its cause and tries again every minute, with no restart. A failed database refresh leaves the instance ready when an older database is on the volume: `GET /api/instance` then carries a `warning` with the cause and that database's date. Without a database, the instance stays not ready.

In the lab, at commit 8f5f3df, the connected Compose file on an empty volume answered 503 for about 15 seconds, then 200, and Docker marked the service `healthy` 20 seconds after the start, with no click. A volume that already holds the pinned Trivy and a database answered 200 within 10 seconds.

`/healthz` is a readiness check. Do not use it for liveness: an orchestrator that restarts on a failed liveness probe would restart an instance that is still downloading. `GET /livez` answers 200 with `{"status":"ok"}` whenever the server runs, whatever the preparation's state.

| Probe | Address |
| --- | --- |
| Readiness, or Docker's `healthcheck` | `/healthz` |
| Liveness | `/livez` |

The Compose healthcheck gives the first start 10 minutes (`start_period`), during which a failure does not count, and checks every 5 seconds until the first success (`start_interval`). `start_interval` needs Docker Engine 25 or later.

## The policy file

The policy file sets the default targets, the minimum release age, the parallelism and the brand. [Settings](settings.md) lists each key, its default and its range. `SEALIFT_POLICY` names the file; without it, the defaults apply, and an upgraded volume keeps the values it saved.

`deploy/connected/compose.policy.yaml` is an overlay, like the ephemeral one. It mounts `./policy/` read-only at `/etc/sealift/` and sets `SEALIFT_POLICY=/etc/sealift/policy.yaml`:

```sh
docker compose -f compose.yaml -f compose.policy.yaml up -d
```

`deploy/connected/policy/policy.yaml` is the example. Every key in it is commented out, so it changes nothing until you edit it. A key you uncomment replaces the value an upgraded instance saved. Keep the file and the logo outside `/data`, on a read-only mount, as the overlay does: the container then cannot change them.

sealift reads the file and the logo once, at start: restart the service after an edit. A bad value stops the start, and the log names the file, the key and the rule.

On Kubernetes, a ConfigMap mounted as a folder presents each file through a link, and sealift refuses a logo that is a link. Mount the logo with `subPath`, which gives a regular file. The policy file itself may be a link.

## Access

sealift has no login. Anyone who reaches port 8080 can run sessions, download archives and have any selection signed with the signing key. A request to regenerate the key also passes a Host check, described under [the key the import trusts](#the-key-the-import-trusts); no other route looks at the Host. No route installs a tool or changes the policy. Keep it bound to `127.0.0.1`, as above, and publish it through a reverse proxy that authenticates, or through an SSH tunnel:

<!-- illustrative -->
```sh
ssh -L 8080:127.0.0.1:8080 sealift-host
```

## Reverse proxy

The interface follows a running job through server-sent events on `/api/jobs/current/events`. The proxy must pass them through as they come, without buffering, and keep the connection open for the length of an analysis.

Caddy:

<!-- illustrative -->
```
sealift.example.internal {
	reverse_proxy 127.0.0.1:8080 {
		flush_interval -1
	}
}
```

Nginx:

<!-- illustrative -->
```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $http_host;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_read_timeout 1h;
}
```

A buffering proxy shows as progress that stalls, then jumps to the end.

## Outbound access

sealift needs HTTPS to these hosts, at start and for each analysis and export. A host the start cannot reach keeps the instance not ready, and `GET /api/instance` gives the cause.

| Host | At start | Later |
| --- | --- | --- |
| `api.github.com`, `github.com` and the download host it redirects to | The pinned Trivy release: one lookup of its tag, then its asset | Nothing |
| `mirror.gcr.io` | The Trivy vulnerability database | A refresh before each analysis |
| `registry.npmjs.org` | The default target's pnpm | Package metadata and tarballs, and the pnpm of a target that names another version |
| `pypi.org` and `files.pythonhosted.org` | The default pip target's uv | Index pages and wheels, and the uv of a target that names another version |

Once the pinned Trivy is on the volume, sealift asks GitHub nothing more, a restart included.

To resolve and download packages through an npm mirror, set both variables to its URL:

```yaml
    environment:
      SEALIFT_NPM_REGISTRY: https://npm-mirror.example.internal
      NPM_CONFIG_REGISTRY: https://npm-mirror.example.internal
```

`SEALIFT_NPM_REGISTRY` is where sealift reads package metadata and downloads pnpm; `NPM_CONFIG_REGISTRY` is where pnpm resolves and downloads. pnpm and every package are checked against the integrity this registry publishes, so it must be an `https` URL, or `http` on `localhost`, `127.0.0.1` or `::1`. The URL may carry credentials; sealift keeps them out of logs and errors.

A plain `http` mirror on another host needs `SEALIFT_ALLOW_HTTP_REGISTRY: "true"` as well. Without it, sealift refuses to start; with it, sealift starts and logs a warning that names the variable. Anyone on the network path to that mirror can then change pnpm or a package.

`SEALIFT_GITHUB_API` replaces `https://api.github.com` as the place sealift looks up the pinned Trivy release. Leave it unset unless you serve a mirror of that API. The value must be an `https` URL without credentials; `http` is accepted only on `localhost`, `127.0.0.1` and `::1`, and sealift refuses to start on any other value. The mirror supplies the address sealift downloads Trivy from. It can delay Trivy and cannot swap it: sealift installs the download only when its sha256 equals the one the binary pins.

`SEALIFT_GITHUB_TOKEN` is a GitHub token that sealift sends as `Authorization: Bearer` on its release lookup at the GitHub API, and nowhere else: pnpm and Trivy run without it. When `SEALIFT_GITHUB_API` is set, the token goes to that address, so a mirror receives it. It stays out of logs, errors, answers and the tools' environment. Set it when GitHub answers `403` because many users share your outbound address and use up the anonymous rate limit. A token with no scopes is enough. Unset keeps the lookups anonymous.

## The data volume

Everything sealift keeps lives under `/data`:

```
/data
  private/settings.json    the settings 0.7.0 and earlier saved, read and never written (app only)
  private/signing-key.pem  the private signing key, mode 0600 (app only)
  projects/<session>/
    project.json           the session: name, target, the manifest's sha256
    package.json           the manifest as dropped
    analyses/<id>/         each analysis: its result, its log, the resolved project
    exports/<id>/          each export: the archive, its manifest, the manifest's signature and four reports
  tools/trivy/<version>/   the pinned Trivy; tools/trivy/current points at it
  tools/pnpm/<version>/    pnpm, the default target's downloaded at start
  tools/uv/<version>/      uv, the default pip target's downloaded at start
  trivy-cache/db/          the vulnerability database, about 1.4 GB
  cache/                   downloaded tarballs and resolution caches
  home/                    the home directory of pnpm and Trivy
```

`cache/` can be deleted while sealift is stopped; the next export downloads again. Deleting `private/settings.json` drops the values 0.7.0 saved: the policy file and the defaults then apply. Once the pinned Trivy is active, the start removes every other version from `tools/trivy/`. Deleting `private/signing-key.pem` makes the next start generate a new key.

## Ephemeral mode

An ephemeral instance keeps nothing of a project once its archive has left. Start it with the overlay next to the Compose file:

```sh
docker compose -f compose.yaml -f compose.ephemeral.yaml up -d
```

The overlay sets two variables and mounts `/data/projects` and `/data/cache` in RAM:

| Variable | Value |
| --- | --- |
| `SEALIFT_EPHEMERAL` | `1` turns the mode on. Empty or `0` leaves it off. Any other value stops the server at start. |
| `SEALIFT_EPHEMERAL_IDLE` | Minutes without activity before a project is erased, 60 by default. It must be a positive whole number. |

In this mode:

- A project gets a random id, so no line of the container's log names it.
- **Erase this project now**, under the archive on the export screen, deletes the project: its `package.json`, analyses, logs, reports and archive. It also empties the shared caches that recorded what it fetched: pnpm's metadata and store, the tarball cache and the resolve directories. When another project's job is queued or running, that purge waits for the first minute the instance is idle. The browser tab forgets the version selection it kept, and API answers carry `Cache-Control: no-store`, so the browser's cache keeps none of them.
- Every minute, sealift deletes each project whose newest file is older than the idle delay and that has no job queued or running, then empties the caches once no project remains or a purge is waiting. Its log lines carry counts only.
- Trivy, its vulnerability database, the settings and the signing key stay.

The RAM mounts keep projects and caches off the disk, and a restart erases them as well. Two conditions hold that promise. The host must have no swap, or an encrypted one, since the kernel can write RAM pages to swap. And the volume must hold no `projects/` or `cache/` from an earlier run without the overlay: the mounts hide that data without erasing it, and the sweep never sees it. Use a fresh volume, or empty both folders before you start with the overlay. The mounts cost memory: a large analysis can need 2 to 3 GB, and the overlay caps each mount at 4 GB. Without the overlay, the mode still deletes the files, but the disk may keep their blocks until they are overwritten.

The mode does not overwrite files, and it leaves the browser's history and download folder alone.

The interface shows a line under the top bar on every screen while the mode is on.

## The key the import trusts

sealift generates its Ed25519 signing key on the first start of a volume and keeps it in `private/signing-key.pem`. The file is mode 0600 in a 0700 directory that the `tools` user cannot read. The API and the screens show the public key only.

The import side holds no key of its own. Carry the public key once, over a channel you trust that is not the kiosk the archives cross, and name the file in the import settings:

<!-- illustrative -->
```yaml
publicKeyFile: public-key.pem
```

Take the key from **Download public key** under Signing key on sealift's Instance page, or from `GET /api/signing-key`. The file holds one `PUBLIC KEY` PEM block, at most 4 KiB, with LF or CRLF line endings. `sealift import` and `sealift import-server` exit with code 2 and name `publicKeyFile` when it is absent or unreadable. A relative path resolves from the settings file's directory. Then compare the Public key sha256: sealift's Instance page shows it, and the import side's Instance page, under Trusted key, and every report show the one the import trusts. Carrying the key through the kiosk with the archive weakens the check, because whoever can forge the archive there can forge the key.

A lost volume means a new key. Stop sealift, restore `private/signing-key.pem` from a backup to keep the old one, give the file to the user the image runs as (`app`, uid 10000) with mode 0600 inside `private/` at mode 0700, and start again. A file left with the wrong owner or mode stops sealift with `cannot be read`; fix the owner or mode, and keep the file. Without a backup, sealift generates another key on the next start, and the import side refuses every archive until it receives the new public key, the archives exported before included. The key has no import: a key pair made elsewhere cannot be loaded.

A backup of the volume holds the private key. Keep it as you keep the volume.

A regenerate in Settings replaces the key, with the same consequence for the import side. The `POST /api/signing-key/regenerate` route refuses a request whose `Host` is not the server's own host (`localhost`, `127.0.0.1`, `::1` or the host of its listen address) with 403, so a page on another site cannot reach it by DNS rebinding. Behind a reverse proxy that passes a public name as `Host`, press **Regenerate key** through `localhost` or an SSH tunnel to `127.0.0.1:8080`. No other route holds the `Host` to that list.

## The import service

`sealift import-server` runs on the air-gapped side. It lets each signed-in user import the archives in their own MinIO folder into Nexus. It serves the contract of [`api/import.yaml`](../api/import.yaml), described in [API](dev/api.md#the-import-service), and runs behind a gateway that signs users in. The lab in `lab/` runs it that way, and the statements below were checked against that lab. On Kubernetes, [Helm chart](helm.md) installs it, and [the runbook](runbook.md) takes the image and the chart through Harbor and checks every link.

The image carries two copies of the binary. `sealift-import` holds no capability, and `docker-entrypoint.sh` starts `sealift import` and `sealift import-server` from it. Both start and run under `--cap-drop ALL` as user 10000, with an empty `CapPrm`, `CapEff` and `CapAmb`. An image cannot set `--cap-drop`: set it yourself, as the compose example below does. Without it, the container keeps Docker's default capability bounding set, which the setuid binaries of the base image can use. The collection role keeps its own copy, which holds `SETUID`, `SETGID` and `KILL`.

<!-- illustrative -->
```yaml
services:
  import-server:
    image: ghcr.io/morgankryze/sealift:<a release that carries the import>
    command: [sealift, import-server, -settings, /import/settings.yaml]
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - import-data:/data
      - ./import:/import:ro
```

`/data/imports` holds one record per import. The volume must outlive the container: a restart reads the records, and marks an import that was running as `interrupted`.

### Settings

The service reads the same YAML file as `sealift import`, `publicKeyFile` included, with two more sections. Each secret lives in its own file, resolved from the settings file's directory.

<!-- illustrative -->
```yaml
token:
  keySetUrl: http://keycloak:8080/realms/lab/protocol/openid-connect/certs
  issuer: http://localhost:18444/realms/lab
  audience: oauth2-proxy
minio:
  url: http://minio:9000
  region: us-east-1
  accessKeyFile: minio-access-key
  secretKeyFile: minio-secret-key
```

`token` is required. Its optional `header` names the one request header the service reads the access token from. It defaults to `X-Access-Token`, so a settings file without it reads as before. The service reads that header and no other: not `X-Access-Token` when another name is set, not `Authorization`, not a cookie. It refuses to start, naming `token.header`, when the value is empty, is not a valid header name, or is `Authorization`, `Cookie` or `Host`. Set it to the name your gateway sets on every request: ingress-nginx forwards oauth2-proxy's access token as `X-Auth-Request-Access-Token`, which is the chart's default. Without `minio`, the service starts and lists no archive. Both URLs follow the rules of `nexus.url`, and an `http` URL is logged as a warning at start and named in the `unencrypted` list of `GET /api/archives`.

### Keycloak

The service compares `issuer` and `audience` with the token's `iss` and `aud` claims, exactly. In the lab, Keycloak writes `iss` as the address the browser uses (`http://localhost:18444/realms/lab`, set by `KC_HOSTNAME`), while the service fetches the keys at `http://keycloak:8080`. The two differ, so `issuer` takes the first and `keySetUrl` the second. The realm's client `oauth2-proxy` carries an audience mapper that writes `oauth2-proxy` into the access token, and `audience` holds that value.

### MinIO

Give the service its own MinIO user. The lab's policy, `lab/import/minio-policy.json`, lets it list `packages/npm/` and `packages/pip/` and read and delete objects under both in any `user-*` bucket, and nothing else. With that user, at commit f5c6f46, `mc` listed and read both folders, and could not put an object, list the bucket's root or list the buckets. The policy covers every user's bucket: the service itself restricts a request to the bucket of the checked user.

MinIO refused a policy that gave `s3:GetBucketLocation` an `s3:prefix` condition: the condition belongs to `s3:ListBucket` alone.

### The gateway

The gateway signs users in and forwards the access token. In the lab, nginx asks oauth2-proxy about every request and copies the token from the answer into `X-Access-Token`, the header the settings name in `token.header`, `X-Access-Token` by default:

<!-- illustrative -->
```nginx
auth_request_set $token $upstream_http_x_auth_request_access_token;
proxy_set_header X-Access-Token $token;
proxy_set_header Host $http_host;
```

oauth2-proxy needs `--pass-access-token=true` and `--set-xauthrequest=true` for that header to exist. `Host` is passed as received because the service compares a request's `Origin` with it. The gateway sets the header from its own variable, so a value the client sends does not reach the service: a request through the gateway with a garbage `X-Access-Token` and an `X-Auth-Request-Preferred-Username` naming another user answered for the signed-in user. A token sent straight to the service, past the gateway, gets the same checks: a token signed by another key answered 401 `signature`, a token with `alg` none answered 401 `algorithm`, and a real realm token sent after its 5 minutes and the service's 60 seconds of leeway answered 401 `expiry`.

### The session

Keycloak's access token lives 5 minutes. oauth2-proxy renews it when `--cookie-refresh` has passed, and the lab sets `--cookie-refresh=1m`. With the session cookie of the first sign-in, `GET /api/me` still answered 200 six minutes later with no new sign-in, where the first token alone answered 401 `expiry`. The service checks the renewed token like any other.

The renewal needs two things from the gateway. oauth2-proxy answers the first request after the minute with a new session cookie of about 3.3 KiB next to the token headers. nginx's default header buffer is 4 KiB, and the lab's gateway answered 500 with `upstream sent too big header` until `proxy_buffer_size` was raised to 16k on `/oauth2/auth`. The gateway also has to hand the new cookie to the browser, with `auth_request_set` on `Set-Cookie` and `add_header Set-Cookie $auth_cookie always`; without the first, oauth2-proxy renews the session on every request, and without `always`, nginx drops the cookie from a 4xx or 5xx answer.

The recipe forwards one renewed cookie of at most 4 KiB: `$upstream_http_set_cookie` holds a single `Set-Cookie` header. A session that oauth2-proxy splits into several cookies past 4 KiB was not proven.

The screens add nothing to what the gateway must do, with two limits. The service answers its own pages and its `/api` with a `Content-Security-Policy` that allows scripts, styles, images, fonts and connections from the page's own origin only, `frame-ancestors 'none'`, `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`; through the lab gateway, `/` and `/api/imports` carried those headers unchanged. A gateway must not add framing or inline scripts, or a header that overrides these. A browser that finds its session ended gets a redirect to Keycloak from a script request, which it cannot follow across origins: the screen then says `Your session has ended` and offers `Sign in again`, which reloads the page and lets the gateway send the user to sign in.

An import that is running when its token expires still finishes: the token is checked when a request arrives, not while the import runs.

## Upgrading

Read the release notes, then pull the new tag and recreate the container on the same volume:

<!-- illustrative -->
```sh
docker pull ghcr.io/morgankryze/sealift:0.2.2
docker rm -f sealift
docker run -d --name sealift -p 127.0.0.1:8080:8080 -v sealift-data:/data ghcr.io/morgankryze/sealift:0.2.2
```

With Compose, change the tag and run `docker compose up -d`. Sessions, archives, settings and the signing key carry over. A job running during the upgrade is discarded: its session shows its previous state, and you start the job again.

### From 0.7.0

Take [a backup](#backing-up) first. Then:

1. Copy the new `compose.yaml` from the release, or add `start_period: 10m` and `start_interval: 5s` to your healthcheck, so the first start's downloads do not mark the service unhealthy.
2. Leave the policy file out for the first start. The instance keeps every value its settings held, and the log names no override.
3. Start the new release. It installs the pinned Trivy if the volume holds another version, then removes the others, and refreshes the database. `/healthz` answers 200 once it is done. No screen asks for a click.
4. To change a value, write the policy file and start with the overlay, as [The policy file](#the-policy-file) shows. The log then names each key the file overrides.

In the lab, at commit 8f5f3df, a copy of a 0.7.0 volume that held 6 projects, 7 analyses and 5 exports opened with every record and field unchanged. The public key's sha256 stayed the same, `private/settings.json` kept its sha256, and a re-export of a 0.7.0 analysis gave the same archive sha256 as 0.7.0's export.

The API routes that listed or installed tools and saved settings are gone. Each answers 410 Gone with Problem Details that name `GET /api/instance`. [The CHANGELOG](../CHANGELOG.md) names what replaces each.

### Rolling back

Stop the new release and start 0.7.0 on the same volume. 0.7.0 reads the records, the key and `private/settings.json` as it left them, and uses the pinned Trivy, which it finds active. Values set only in the policy file do not apply under 0.7.0. In the lab, at commit 8f5f3df, 0.7.0 opened the copy again after the upgrade, listed the same records, and answered healthy.

## Backing up

Stop sealift, then archive the volume:

<!-- illustrative -->
```sh
docker stop sealift
docker run --rm -v sealift-data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/sealift-data.tar.gz --exclude=./cache --exclude=./trivy-cache -C /data .
docker start sealift
```

The archive holds `private/signing-key.pem`. The two excluded folders are downloads: after a restore, the start downloads the database again. Restore by extracting the archive into an empty volume before the first start.
