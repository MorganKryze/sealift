# Deployment

This page covers running sealift for a team: Compose, a reverse proxy, the data volume, upgrades and backups. [Getting started](getting-started.md) has the one-line `docker run` for a first try.

## The image

`ghcr.io/morgankryze/sealift` is published for `linux/amd64` and `linux/arm64`. Tags carry no `v`: `0.2.2`, and `latest` for the newest release. Pin a version in production and upgrade on purpose.

The image holds the sealift binary, the web interface and Node 22. The rest lands in the volume: the setup screen downloads Trivy and its database, and the first analysis downloads pnpm 10.34.5 from the npm registry, checked against its published integrity.

## Compose

```yaml
services:
  sealift:
    image: ghcr.io/morgankryze/sealift:0.2.2
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
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
      interval: 30s

volumes:
  sealift-data:
```

This setup was checked with an analysis and an export. The root filesystem is read-only; sealift writes only to `/data` and `/tmp`.

sealift runs as user `app` (uid 10000) and starts pnpm and Trivy as a second user, `tools` (uid 10001), so neither they nor any package they handle can read `private/settings.json`. Switching users needs `SETUID` and `SETGID`, and stopping a cancelled job needs `KILL`. Every other capability can go.

Do not add `no-new-privileges`. It stops the switch to the `tools` user, and every analysis fails with `fork/exec /usr/local/bin/node: operation not permitted`.

## Access

sealift has no login. Anyone who reaches port 8080 can run sessions, download archives and change the signature key. Keep it bound to `127.0.0.1`, as above, and publish it through a reverse proxy that authenticates, or through an SSH tunnel:

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
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_read_timeout 1h;
}
```

A buffering proxy shows as progress that stalls, then jumps to the end.

## Outbound access

sealift needs HTTPS to:

| Host | For |
| --- | --- |
| `api.github.com`, `github.com` and the download host it redirects to | Trivy releases and their checksums |
| `mirror.gcr.io` | The Trivy vulnerability database |
| `registry.npmjs.org` | pnpm, package metadata and tarballs |

To resolve and download packages through an npm mirror, set both variables to its URL:

```yaml
    environment:
      SEALIFT_NPM_REGISTRY: https://npm-mirror.example.internal
      NPM_CONFIG_REGISTRY: https://npm-mirror.example.internal
```

`SEALIFT_NPM_REGISTRY` is where sealift reads package metadata; `NPM_CONFIG_REGISTRY` is where pnpm resolves and downloads. The first analysis still downloads pnpm itself from `registry.npmjs.org`, so keep that host open.

## The data volume

Everything sealift keeps lives under `/data`:

```
/data
  private/settings.json    settings, signature key included (app only)
  projects/<session>/
    project.json           the session: name, target, the manifest's sha256
    package.json           the manifest as dropped
    analyses/<id>/         each analysis: its result, its log, the resolved project
    exports/<id>/          each export: the archive and its five reports
  tools/trivy/<version>/   every Trivy installed; tools/trivy/current is the active one
  tools/pnpm/<version>/    pnpm, downloaded on the first analysis
  trivy-cache/db/          the vulnerability database, about 1.4 GB
  cache/                   downloaded tarballs and resolution caches
  home/                    the home directory of pnpm and Trivy
```

`cache/` can be deleted while sealift is stopped; the next export downloads again. Deleting `private/settings.json` resets the settings and removes the key.

## The import service

`sealift import-server` runs on the air-gapped side. It lets each signed-in user import the archives in their own MinIO folder into Nexus. It serves the contract of [`api/import.yaml`](../api/import.yaml), described in [API](dev/api.md#the-import-service), and runs behind a gateway that signs users in. The lab in `lab/` runs it that way, and the statements below were checked against that lab.

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

The service reads the same YAML file as `sealift import`, with two more sections. Each secret lives in its own file, resolved from the settings file's directory.

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

`token` is required. Without `minio`, the service starts and lists no archive. Both URLs follow the rules of `nexus.url`, and an `http` URL is logged as a warning at start and named in the `unencrypted` list of `GET /api/archives`.

### Keycloak

The service compares `issuer` and `audience` with the token's `iss` and `aud` claims, exactly. In the lab, Keycloak writes `iss` as the address the browser uses (`http://localhost:18444/realms/lab`, set by `KC_HOSTNAME`), while the service fetches the keys at `http://keycloak:8080`. The two differ, so `issuer` takes the first and `keySetUrl` the second. The realm's client `oauth2-proxy` carries an audience mapper that writes `oauth2-proxy` into the access token, and `audience` holds that value.

### MinIO

Give the service its own MinIO user. The lab's policy, `lab/import/minio-policy.json`, lets it list `packages/npm/` and read and delete objects under `packages/npm/` in any `user-*` bucket, and nothing else. With that user, `mc` could not put an object, and could not list or read `packages/pip/`, list the bucket's root or list the buckets. The policy covers every user's bucket: the service itself restricts a request to the bucket of the checked user.

MinIO refused a policy that gave `s3:GetBucketLocation` an `s3:prefix` condition: the condition belongs to `s3:ListBucket` alone.

### The gateway

The gateway signs users in and forwards the access token. In the lab, nginx asks oauth2-proxy about every request and copies the token from the answer into `X-Access-Token`, the one header the service reads:

<!-- illustrative -->
```nginx
auth_request_set $token $upstream_http_x_auth_request_access_token;
proxy_set_header X-Access-Token $token;
proxy_set_header Host $http_host;
```

oauth2-proxy needs `--pass-access-token=true` and `--set-xauthrequest=true` for that header to exist. `Host` is passed as received because the service compares a request's `Origin` with it. The gateway sets the header from its own variable, so a value the client sends does not reach the service: a request through the gateway with a garbage `X-Access-Token` and an `X-Auth-Request-Preferred-Username` naming another user answered for the signed-in user. A token sent straight to the service, past the gateway, gets the same checks: a token signed by another key answered 401 `signature`, a token with `alg` none answered 401 `algorithm`, and a real realm token sent after its 5 minutes and the service's 60 seconds of leeway answered 401 `expiry`.

### The session

Keycloak's access token lives 5 minutes. oauth2-proxy renews it when `--cookie-refresh` has passed, and the lab sets `--cookie-refresh=1m`. With the session cookie of the first sign-in, `GET /api/me` still answered 200 six minutes later with no new sign-in, where the first token alone answered 401 `expiry`. The service checks the renewed token like any other.

The renewal needs two things from the gateway. oauth2-proxy answers the first request after the minute with a new session cookie of about 3.3 KiB next to the token headers. nginx's default header buffer is 4 KiB, and the lab's gateway answered 500 with `upstream sent too big header` until `proxy_buffer_size` was raised to 16k on `/oauth2/auth`. The gateway also has to hand the new cookie to the browser, with `auth_request_set` on `Set-Cookie`; without it, oauth2-proxy renews the session on every request.

An import that is running when its token expires still finishes: the token is checked when a request arrives, not while the import runs.

## Upgrading

Read the release notes, then pull the new tag and recreate the container on the same volume:

<!-- illustrative -->
```sh
docker pull ghcr.io/morgankryze/sealift:0.2.2
docker rm -f sealift
docker run -d --name sealift -p 127.0.0.1:8080:8080 -v sealift-data:/data ghcr.io/morgankryze/sealift:0.2.2
```

With Compose, change the tag and run `docker compose up -d`. Sessions, archives and settings carry over. A job running during the upgrade is discarded: its session shows its previous state, and you start the job again.

## Backing up

Stop sealift, then archive the volume:

<!-- illustrative -->
```sh
docker stop sealift
docker run --rm -v sealift-data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/sealift-data.tar.gz --exclude=./cache --exclude=./trivy-cache -C /data .
docker start sealift
```

The two excluded folders are downloads: after a restore, the setup screen downloads the database again. Restore by extracting the archive into an empty volume before the first start.
