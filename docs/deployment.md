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
