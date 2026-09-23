# The air gap

This page covers what crosses from the connected side to the air-gapped side: the archive, its reports, and the checks to run on each side of the kiosk. It is written for the operator who carries the files and for the team that imports them.

## What crosses

One export produces six files. Only the archive is needed for the import; the reports tell the import side what it receives.

| File | For |
| --- | --- |
| `packages_npm.tar.gz` | The packages and `signature.key`, for the Nexus import |
| `manifest.json` | Every package with its hashes, and the archive's own sha256 |
| `summary.md` | CVEs before and after, the updated dependencies, what remains |
| `findings.csv` | Every CVE, one row each, for a spreadsheet or a ticket |
| `report.cdx.json` | A CycloneDX SBOM of the selection |
| `report.trivy.json` | The raw Trivy output behind the counts |

## The archive

`packages_npm.tar.gz` holds one folder, `out/`, with one npm tarball per package and the key:

```
out/
out/accepts-2.0.0.tgz
out/asynckit-0.4.0.tgz
out/axios-0.33.0.tgz
...
out/signature.key
...
out/wrappy-1.0.2.tgz
```

The tarballs are the ones the npm registry serves, byte for byte, with one exception: a package whose `package.json` holds a `publishConfig` has it removed, since it would send a publish from the import side to another registry. `manifest.json` marks those packages.

The archive is reproducible. Entries are sorted by name, dated at the Unix epoch and owned by user 0, so the same selection built by the same sealift gives the same bytes and the same sha256.

## The signature key

`out/signature.key` holds the key saved in the settings, as plain text. The import project compares it with the value it expects, and refuses an archive that does not match.

The key is a shared value: anyone who knows it can build an archive the import accepts. It shows that the archive came from a sealift your team configured. It does not prove that the archive was not altered on the way; the sha256 below does that.

## Before the kiosk

The export screen shows the archive's sha256 with **Copy**. `manifest.json` carries the same value under `archive.sha256`. Check the file you downloaded against it:

<!-- illustrative -->
```sh
sha256sum packages_npm.tar.gz
```

```
7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7  packages_npm.tar.gz
```

On macOS, use `shasum -a 256`. Send the sha256 to the import side by a separate channel, such as the transfer request or a ticket.

## After the kiosk

Run the same command on the air-gapped side. A different sha256 means the file changed in transit: do not import it.

Each entry of `manifest.json`'s `packages` describes one tarball:

```json
{
  "name": "express",
  "version": "5.1.0",
  "file": "express-5.1.0.tgz",
  "originalIntegrity": "sha512-DT9ck5YIRU+8GYzzU5kT3eHGA5iL+1Zd0EutOmTE9Dtk+Tvuzd23VBU+ec7HPNSTxXYO55gPV/hq4pSBJDjFpA==",
  "shippedSha512": "0d3f5c939608454fbc198cf3539913dde1c603988bfb565dd04bad3a64c4f43b64f93beecdddb754153e79cec73cd493c5760ee7980f57f86ae294812438c5a4",
  "publishConfigStripped": false
}
```

`originalIntegrity` is the hash the npm registry published. `shippedSha512` is the hash of the file in `out/`. They match unless `publishConfigStripped` is `true`. An import tool can check every tarball against `shippedSha512` before it publishes anything. [Archive format](dev/archive-format.md) describes every field.

## The import

The import project, on the air-gapped side, reads the archive: it checks `signature.key`, then publishes each tarball of `out/` to the npm hosted repository in Nexus. sealift does not ship that project; its owner knows what it checks.

Once imported, projects install from Nexus as usual:

<!-- illustrative -->
```sh
pnpm install --registry https://nexus.example.internal/repository/npm-hosted/
```

## Versions that drift

sealift resolves the project on the day of the export and ships exactly what that resolution needs. On the air-gapped side, an install without a lockfile resolves again, against whatever Nexus holds. When earlier imports left other versions of the same packages there, pnpm may pick a different one than sealift scanned.

Commit the lockfile the first install produces on the air-gapped side, and install with `pnpm install --frozen-lockfile` from then on. A lockfile that asks for a version Nexus lacks then fails the install, instead of installing something nobody scanned.

## What sealift checks, and what it does not

sealift checks:

- every downloaded tarball against the sha512 the registry published;
- Trivy against the sha256 of its release;
- that no proposed version is younger than the minimum release age;
- that nothing is installed or downloaded without a click.

It does not:

- detect a malicious package that has no known CVE yet: Trivy knows only published vulnerabilities;
- sign the archive: `signature.key` is a shared value, and the sha256 is only as trustworthy as the channel that carries it.
