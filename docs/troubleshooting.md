# Troubleshooting

This page lists the messages sealift shows, grouped by where they appear, with their cause and their fix. Search the page for the words on your screen.

When an analysis or an export stops, the cause shows under What went wrong. **Show the log** unfolds what pnpm and Trivy wrote, including their own error codes, which the message leaves out.

## Anywhere

### sealift is not reachable

On the home screen, the same problem reads Could not reach sealift.

The browser sent a request and got no answer. The container is stopped, restarting, or the reverse proxy in front of it is down.

Check the container with `docker ps` and its log with `docker logs sealift`, then try again.

### Progress stalls, then jumps to the end

A reverse proxy buffers the event stream. Turn buffering off for sealift: [Deployment](deployment.md#reverse-proxy) has the Caddy and Nginx settings.

## Setup and settings

### could not reach GitHub to look up Trivy releases

sealift asks `api.github.com` for the Trivy releases before it installs or updates Trivy. The machine has no route to GitHub, or a firewall blocks it. [Deployment](deployment.md#outbound-access) lists the hosts sealift needs.

### trivy release is too recent

**Update Trivy** found a latest release younger than the minimum release age. Keep the installed version, or press **Install anyway** to take the latest now.

### trivy asset checksum mismatch

The Trivy archive sealift downloaded does not match the sha256 in the release's checksum file. sealift keeps nothing from it. Retry; if the mismatch stays, something between you and GitHub alters the download.

### tools not ready

The API refuses to create a session or start an analysis while Trivy or its database is missing. The answer lists which one. The interface opens the setup screen instead: install what it shows, then continue.

### invalid limits

A limit is out of range. The message names it and the value:

```
invalid limits: download parallelism must be between 1 and 32, not 1000
```

[Settings](settings.md#limits) gives each range.

### Use an exact version, such as 22.17.1.

The Node version must be exact. `22`, `22.x` and `>=22` are refused.

## Drop

### sealift cannot analyse this file yet

The drop preview found entries sealift refuses. Each one shows with its reason:

| Reason | Fix |
| --- | --- |
| version must be exact, such as 1.2.3 | Replace the range or tag with the version the project uses today |
| only npm registry versions are supported | Replace the alias, Git URL or path with a registry version |
| not supported | Remove `overrides`, `resolutions`, `pnpm.overrides` or `pnpm.patchedDependencies` |
| lists no dependency to update | Drop a `package.json` with at least one dependency |

The API gives the same answer to a file sent directly:

<!-- run -->
<!-- expect: version must be exact, such as 1.2.3 -->
```sh
printf '{"name":"demo","dependencies":{"express":"^4.17.1"}}' > /tmp/range.json
curl -s -F manifest=@/tmp/range.json http://localhost:8080/api/projects
```

```json
{"detail":"the manifest has entries sealift cannot analyze","errors":[{"field":"dependencies","name":"express","reason":"version must be exact, such as 1.2.3","value":"^4.17.1"}],"status":400,"title":"invalid package.json","type":"about:blank"}
```

### That file is not valid JSON.

The dropped file does not parse. Check that you dropped the `package.json` itself, not a lockfile or another file.

### That file holds JSON, but not an object like a package.json.

The file parses, but holds an array, a string or a number at its top level.

## Analysis

The message under What went wrong starts with the step that failed, such as `resolve project:`.

### resolve project: pnpm install

pnpm could not install the project as dropped. The message carries pnpm's reason, and **Show the log** gives its full output. The common ones:

| In the message | Cause | Fix |
| --- | --- | --- |
| `ERR_PNPM_NO_MATCHING_VERSION` | A version that does not exist on the registry | Fix the version in the `package.json`, then drop it again |
| `ERR_PNPM_FETCH_404` | A package name that does not exist, or a private package | Fix the name; sealift reads the public registry, or the mirror set in [Deployment](deployment.md#outbound-access) |

![Analysis stopped at Resolve the project, with the message and the actions](assets/analysis-failed.png)

### fork/exec /usr/local/bin/node: operation not permitted

sealift could not start pnpm as its `tools` user. The container runs with `no-new-privileges`, or without the `SETUID` and `SETGID` capabilities. [Deployment](deployment.md#compose) has a setup that works.

### A running analysis disappeared after a restart

The server restarted while the analysis ran, for example during an upgrade, and discarded the unfinished job. The session shows its previous state. Start the analysis again.

### A dependency with CVEs shows under Nothing to do

No candidate it could propose has fewer CVEs: the ones that would are too recent, excluded by the Node version, deprecated or fail to resolve. Open the row: each candidate shows the signal that blocks it. [How sealift chooses](how-sealift-chooses.md#signals) explains each one.

## Export

### jobs: sign manifest.json

The export packed the archive but could not sign its manifest. The export fails at its Sign the manifest and write the reports step and offers no file to download. The message after the colon names the cause. Retry once; if it fails again, check the log of the container for the signing key's own message, described under [store: signing key cannot be read](#store-signing-key-cannot-be-read).

### Signed with a key replaced since

The done screen says an archive carries a key you regenerated after the export. The import refuses it once it trusts the new key. Press **Export another selection**, or run the same selection again, and carry the new files.

### Not signed: sealift 0.4.0 or earlier exported this archive

The archive was exported before signing existed. The import refuses it as unsigned. Export the selection again with this version.

### Could not read manifest.json.sig

The done screen could not read the signature file of an export. The file is missing or damaged in the volume. Export the selection again.

### jobs: the export selects no version and leaves out the current project, so it would pack nothing

The selection keeps every dependency at its current version, so the archive would be empty. Choose at least one new version in the review.

```json
{"detail":"jobs: the export selects no version and leaves out the current project, so it would pack nothing","status":400,"title":"queue export","type":"about:blank"}
```

### invalid export selection

The selection names a version the analysis did not resolve. This happens through the API, not through the review. The answer names each version:

```json
{"detail":"the selection names versions the analysis did not resolve","errors":[{"field":"selection","name":"express@9.9.9","reason":"not a version the analysis resolved"}],"status":400,"title":"invalid export selection","type":"about:blank"}
```

### jobs: downloaded tarball does not match its recorded integrity, possible tampering

A downloaded package does not match the sha512 the registry published. sealift stops and packs nothing. Retry once; if it fails again, a proxy or mirror between sealift and the registry serves altered files. Do not work around it.

### Stopped at Download and verify each package.

The export could not download a package. The message and the log name it. A registry or proxy that times out or limits connections is the usual cause: lower [download parallelism](settings.md#download-parallelism), then **Retry**.

## Start

### store: signing key cannot be read

sealift stops at start, naming the file, when `private/signing-key.pem` exists in the data volume and cannot be read, is not a PEM private key or is not an Ed25519 key. The messages read `store: signing key <path> cannot be read`, `store: signing key <path> is not a PEM private key` and `store: signing key <path> is not an Ed25519 key`. sealift never replaces the file by itself, because a silent new key would make the import side refuse every archive.

Restore the file from a backup of the volume. When there is none, remove `private/signing-key.pem` by hand and start again: sealift generates a new key, and you carry its public key to the import side before the next crossing. [Deployment](deployment.md#the-key-the-import-trusts) covers a lost volume.

## Import

These messages come from `sealift import` (exit code 3 for a refusal, 2 for a settings error) and from the import service, which shows a refusal as the cause on the import's page. Nothing was published in any of them. [Archive format](dev/archive-format.md#what-sealift-import-checks) describes the check order.

### the archive is unsigned

The full reason reads `the archive is unsigned: manifest.json.sig is missing beside the manifest. Export it again with sealift 0.6.0 or later and carry the archive, manifest.json and manifest.json.sig together`. Either the signature file did not cross with the archive, or sealift 0.4.0 or earlier exported the archive. Carry `manifest.json.sig` beside the manifest, or export again. With `-signature`, the name in the message is the file you passed. In the service, an archive without the signature in its folder is listed as Cannot be imported, with `no manifest.json.sig in its folder`.

### manifest.json.sig is not a signature this import reads

The reason ends with the first rule the file breaks: it is larger than 4096 bytes, it is not a JSON object, its algorithm is not ed25519, its `publicKeySha256` is not 64 lowercase hex digits, or its signature is not base64 of exactly 64 bytes. The file was cut, edited or replaced by another file in transit. Carry `manifest.json.sig` again from the connected side.

### the manifest is signed by another key

The full reason reads `the manifest is signed by another key, public key sha256 <named>; this import trusts <trusted>. If the connected side regenerated its key, carry its new public key here; otherwise export the archive again`. The two values are the sha256 of the key that signed and of the key the import trusts. Compare the first with the Public key sha256 in sealift's Settings on the connected side. When they are equal, the connected side regenerated its key: carry its new public key to the file `publicKeyFile` names, and start the import again. When they differ, this archive came from another sealift: do not import it.

### the signature does not match the manifest

The full reason reads `the signature does not match the manifest: manifest.json or manifest.json.sig changed after the export. Carry both again from the connected side`. The signature names the trusted key, and the check fails: a byte of the manifest or of the signature changed after the export. Do not edit either file. Carry both again, and check them with the sha256 you keep from the connected side.

### formatVersion is missing or not 2

The signature verified, but the manifest is not of the version this import reads. Export the selection again with a sealift of the same release as the import.

### publicKeyFile is required, or cannot be read

The import and the service start only with a trusted key. They exit with code 2 and one line naming the field when `publicKeyFile` is absent from the settings file (`publicKeyFile is required`), the file does not exist or cannot be read, is larger than 4096 bytes, or does not hold exactly one Ed25519 `PUBLIC KEY` PEM block (`publicKeyFile is not one Ed25519 PUBLIC KEY PEM block: ...`, ending with the problem). Download the key again from sealift's Settings, or take it from `GET /api/signing-key`, and save the whole block, `-----BEGIN PUBLIC KEY-----` to `-----END PUBLIC KEY-----`, in the file. LF and CRLF line endings both work.

### signatureKeyFile is an unknown field

A settings file written for 0.4 still holds `signatureKeyFile`. Remove the line and add `publicKeyFile`, as [The air gap](air-gap.md#the-import) shows.

## Reporting a problem

When none of this helps, open an issue with the sealift version (in `summary.md`, or the image tag), the target platform, the message on screen, and the log from **Show the log**. Remove any private package name first. The private signing key never appears in the log, and no one needs to send it.
