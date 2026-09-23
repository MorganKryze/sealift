# Getting started

This page takes you from nothing to a first archive in about ten minutes. It uses a five-dependency project with known CVEs, so every screen has something to show.

## Requirements

- Docker on a machine with outbound HTTPS to GitHub (Trivy), `mirror.gcr.io` (its vulnerability database) and `registry.npmjs.org` (pnpm and packages). [Deployment](deployment.md#outbound-access) lists the hosts.
- About 2 GB of free disk for Trivy, its database and the package cache.

sealift runs on the connected side of your network. Only the archive it builds crosses to the air-gapped side.

## 1. Run it

```sh
docker run -d \
  --name sealift \
  -p 127.0.0.1:8080:8080 \
  -v sealift-data:/data \
  ghcr.io/morgankryze/sealift:latest
```

`127.0.0.1:8080` keeps the interface on this machine. The `sealift-data` volume holds every session, archive and setting, and survives an upgrade. [Deployment](deployment.md) covers Compose, a reverse proxy and backups.

Check that it answers:

<!-- run -->
<!-- expect: {"status":"ok"} -->
```sh
curl -s http://localhost:8080/healthz
```

```
{"status":"ok"}
```

## 2. Prepare sealift

Open <http://localhost:8080>. The first run opens on Prepare sealift.

![The setup screen, listing Trivy 0.74.0 at 43.3 MB, its vulnerability database at about 120 MB, and the signature key field, above one install button](assets/setup.png)

1. Press **Install Trivy (43.3 MB) and its database (about 120 MB, 1.4 GB once unpacked)**. Nothing downloads before this click. The sizes are those of the Trivy release shown; yours may differ.
2. Paste the signature key your Nexus import expects and press **Save key**. Ask the owner of the import project if you do not have it. To try sealift without one, any value works; replace it before you carry an archive.
3. Press **Continue** once both show as ready.

sealift checks Trivy against its published sha256. When the latest Trivy release is younger than 14 days, it offers the newest release past that age instead.

## 3. Drop a package.json

Save this as `package.json`:

```json
{
  "name": "sealift-demo",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "axios": "0.21.1",
    "express": "4.17.1",
    "lodash": "4.17.20"
  },
  "devDependencies": {
    "@babel/traverse": "7.22.5",
    "esbuild": "0.17.19"
  }
}
```

Drop it on the page, or press **Choose a file**. The preview counts the dependencies, checks that each one is pinned to an exact version, and names the target sealift resolves for.

![The drop preview for sealift-demo: 3 prod and 2 dev dependencies, pinning all exact, target linux/x64 with glibc and Node 22.17.1](assets/drop-preview.png)

Press **Analyse 5 dependencies**.

## 4. Wait for the analysis

sealift resolves the project, scans it, lists the newer versions of each dependency, then resolves and scans each candidate. For this project that is 254 candidates, about a minute and a half on a laptop. You can close the page; the session keeps running.

## 5. Review and export

The review opens on sealift's proposal: 45 CVEs today, including 1 critical, and none with the proposed versions. Open **express** to see why sealift proposes 5.1.0 and holds 4.22.3 back. [How sealift chooses](how-sealift-chooses.md) explains the rules.

Press **Confirm and build the archive**. sealift downloads the 100 packages the selection needs, checks each one's integrity, and ends on Archive ready.

![Archive ready: packages_npm.tar.gz, sealed, 100 packages, 6.7 MB, with its sha256, a download button, and five reports below](assets/export-done.png)

## 6. Take the files

Press **Download archive** for `packages_npm.tar.gz`, and **Download** next to each report you want to hand over. The same files stay on the volume under `/data/projects/<session>/exports/<export>/`:

```
packages_npm.tar.gz   the packages and signature.key
manifest.json         every package with its sha512
findings.csv          every CVE, one row each
report.cdx.json       CycloneDX SBOM
report.trivy.json     raw Trivy output
summary.md            before, after, remaining CVEs
```

[The air gap](air-gap.md) covers what to check before and after the kiosk, and what the import side receives.

## Next

- [Workflow](workflow.md): every screen, every button.
- [Settings](settings.md): the target platform, the key, the limits.
