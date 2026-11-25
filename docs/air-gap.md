# The air gap

This page covers what crosses from the connected side to the air-gapped side: the archive, its reports, and the checks to run on each side of the kiosk. It is written for the operator who carries the files and for the team that imports them.

## What crosses

One export produces seven files. The import needs three of them, the archive, `manifest.json` and `manifest.json.sig`, side by side, and refuses an archive that lacks the manifest or the signature. The four reports tell the import side what it receives.

The archive holds the new versions and the packages they pull in, nothing else. A dependency kept at its current version is not packed, and neither is the rest of the current project: the import side must already hold those packages in Nexus, from earlier imports.

| File | For |
| --- | --- |
| `packages_npm.tar.gz` | The packages, for the Nexus import |
| `manifest.json` | Every package with its hashes, the archive's own sha256, and the review of an npm export |
| `manifest.json.sig` | The Ed25519 signature of `manifest.json`, and the key that made it |
| `summary.md` | CVEs before and after, the updated dependencies, what remains |
| `findings.csv` | Every CVE, one row each, for a spreadsheet or a ticket |
| `report.cdx.json` | A CycloneDX SBOM of the selection |
| `report.trivy.json` | The raw Trivy output behind the counts |

## The archive

`packages_npm.tar.gz` holds one folder, `out/`, with one npm tarball per package and nothing else:

```
out/
out/accepts-2.0.0.tgz
out/asynckit-0.4.0.tgz
out/axios-0.33.0.tgz
...
...
out/wrappy-1.0.2.tgz
```

The tarballs are the ones the npm registry serves, byte for byte, with one exception: a package whose `package.json` holds a `publishConfig` has it removed, since it would send a publish from the import side to another registry. `manifest.json` marks those packages.

The archive is reproducible. Entries are sorted by name, dated at the Unix epoch and owned by user 0, so the same selection built by the same sealift gives the same bytes and the same sha256.

## The signature and the trusted key

sealift signs `manifest.json` with an Ed25519 key it generated for its volume, and writes the signature to `manifest.json.sig`. The manifest names the archive's sha256 and size and the sha512 of every package, so one signature covers every byte the import publishes. The archive carries no key and no signature: it depends on the selection and the build alone, so the same selection gives the same sha256 whatever key signs it.

`manifest.json.sig` is a small JSON file: the algorithm (`ed25519`), the sha256 of the public key that signed (`publicKeySha256`) and the signature. [Archive format](dev/archive-format.md#manifestjsonsig) gives the fields.

The import side checks the signature with a public key you carry to it once. Do it before your first crossing:

1. On the connected side, open Instance, block Signing key. Press **Download public key** for `sealift-public-key.pem`, or copy it.
2. Carry the file to the import side over a channel you trust, not the kiosk the archives cross.
3. Name it in the import's settings, as `publicKeyFile` below shows.
4. Compare the Public key sha256 on both sides: sealift's Instance page shows one, the import side's Instance page shows the other under Trusted key, and every import report records the key it checked with. Equal values mean the import side holds the key you meant to carry.

The import trusts that one key and no other. It ignores any key an archive, a manifest or the signature file names, and uses the name only to word a refusal. A key carried with the archive would give nothing: whoever forges the archive forges the key.

What a valid signature shows: the manifest was made by the holder of the private key, which stays in the connected sealift's volume, and it has not changed since. What it does not show:

- Who pressed Export. Anyone who reaches sealift's port can have any selection signed.
- Freshness. An old archive with a valid signature stays importable until you regenerate the key.
- Anything about the four reports, which are not signed.

`sealift signing-key regenerate`, run in sealift's container or pod, or a lost volume, gives sealift a new key. The import side then refuses every new archive, and every archive exported before, until it holds the new public key. [Troubleshooting](troubleshooting.md#import) gives each refusal and its fix.

## The review in the manifest

The `manifest.json` of an npm export carries a `review`: what the selection decided, and the reasons given for it. The signature covers it with the rest of the manifest, so the import side reads the reasons as the connected side signed them. The review holds:

- the project's CVE counts by severity, before the selection and once it applies;
- each dependency the selection moves inside its line, with the counts of the CVEs the move fixes and leaves;
- each dependency kept on its line while a newer line exists, with its jump;
- each jump the selection takes, with its family and its reason;
- each CVE the project keeps, with the package Trivy found it in, the versions that fix it, and the reason when no version does;
- the number of other dependencies, left as they are.

The review names no person: the connected side has no login. Reasons and review leave the archive's bytes alone, so the same selection gives the same sha256 whatever the reasons say. A pip export writes no review yet.

An import that predates the review reads such an archive as before. The review adds a key and keeps `formatVersion` 2, and the import of sealift 0.7.0 ignores keys it does not know. A newer import reads the review by fixed rules. One it cannot read is kept out with the field at fault, and the import checks and publishes the packages as before: a review never refuses an archive. An archive from 0.7.0 or earlier has no review, and imports as before. Neither the import report nor the import screens show the review yet. [Archive format](dev/archive-format.md#the-review) gives every field and each reading rule.

Proven in the lab at commit 9557a5a: the `sealift import` of 0.7.0 checked and published an archive whose manifest carries a review with its reasons, and ended `import complete` with 0 failed. An analysis written by 0.7.0, exported again with the reasons it needed, gave the archive sha256 that 0.7.0 gave for the same selection.

## Before the kiosk

The export screen shows the archive's sha256 with **Copy**, and which key signed it. `manifest.json` carries the same value under `archive.sha256`. Carry the archive, `manifest.json` and `manifest.json.sig` together. Check the file you downloaded against the sha256:

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

`sealift import` runs on the air-gapped side. It checks the manifest's signature, then the archive against its manifest, then publishes each tarball of `out/` to the npm hosted repository in Nexus and reads each one back. It publishes nothing unless every check passes. [Archive format](dev/archive-format.md) lists the checks, the report and the exit codes.

<!-- illustrative -->
```sh
sealift import -settings /import/settings.yaml -sha256 <sha256 received separately> -report report.json packages_npm.tar.gz
```

The command reads `manifest.json` from the archive's directory, and `manifest.json.sig` beside the manifest; `-manifest <file>` and `-signature <file>` name others. `-sha256` is optional and compares the archive with the value you received by a separate channel. The exit code is 0 for a complete import, 1 when a package failed, 2 for a usage or settings error and 3 for a refused archive.

A pip archive imports with the same command: give `packages_pip.tar.gz`, with its `manifest.json` and `manifest.json.sig` beside it. The import reads which kind of archive it holds from the signed manifest and publishes the wheels to the pypi hosted repository that `nexus.pip` names (below). Without `nexus.pip`, or when Nexus does not list that repository as pypi hosted, the archive is refused with exit code 3 before it is read. When Nexus does not answer, or refuses the user, every wheel fails with kind `nexus` and the exit code is 1.

For each wheel, the import reads the zip directory, `METADATA` and `WHEEL` within fixed bounds, and never unpacks the wheel or runs anything from it. `METADATA` and the file name must name the project and version the manifest lists. A wheel that does not is `failed` with kind `mismatch`, and the others go on. The import then looks the file up in the repository's simple index. The same bytes there make the wheel `present`. Other bytes make it `failed` with kind `conflict`, and nothing is uploaded over them. Otherwise it uploads the wheel and reads it back, and the wheel is `published` only when Nexus serves the shipped sha512. A second run uploads only the wheels Nexus does not hold. [Archive format](dev/archive-format.md#importing-a-pip-archive) lists the bounds, the states and the report's pip fields.

The settings file is YAML. Each secret lives in its own file, and a relative path resolves from the settings file's directory:

<!-- illustrative -->
```yaml
nexus:
  url: https://nexus.example.internal
  repository: npm-hosted
  user: sealift-import
  passwordFile: nexus-password
  caFile: nexus-ca.pem          # optional, added to the system roots
  pip:                          # optional, for pip archives
    repository: pypi-hosted
    user: sealift-import-pip    # optional, with passwordFile
    passwordFile: nexus-pip-password
publicKeyFile: public-key.pem
```

`nexus.pip` names the pypi hosted repository that pip archives publish into. Without it, the import refuses a pip archive and imports npm archives as before. `user` and `passwordFile` go together: set both to publish pip archives as a second Nexus user, or leave both out to publish them as `nexus.user` with its password.

`publicKeyFile` holds the public key from sealift's Instance page on the connected side: one `PUBLIC KEY` PEM block of at most 4 KiB. The import and the service refuse to start without it, with exit code 2. The URL carries no user name, password or query, and no setting turns off certificate checks. An `http` URL works and the report marks it `unencrypted`.

Give the import its own Nexus user, with these privileges on the npm hosted repository and no others: `nx-repository-view-npm-<repository>-browse`, `-read`, `-add` and `-edit`, and `nx-component-upload`. Nexus refuses an upload without the edit privilege, so the user's rights do not stop an overwrite. The repository's deployment policy does: set it to **Disable redeploy** when the import alone writes to the repository. The import checks each version before it uploads and fails one that holds other bytes, and the policy makes Nexus refuse the overwrite itself. A repository that another tool also publishes to, such as Package Pusher's, keeps its policy: the import's read before the upload and its read-back after it are the guard there, and [the runbook](runbook.md#worst-cases-on-the-shared-repository) names the rule that closes the window between them.

Once imported, projects install from Nexus as usual:

<!-- illustrative -->
```sh
pnpm install --registry https://nexus.example.internal/repository/npm-hosted/
```

## The import through the service

Where `sealift import-server` runs, users import without a shell on the air-gapped side. Each user uploads the archive, `manifest.json` and `manifest.json.sig` into their own MinIO bucket, `user-<name>`, under `packages/npm/`, with the manifest and its signature next to the archive. The archive may sit in one folder below, such as `packages/npm/second/`. The service lists the archives of the signed-in user and no one else's: another user's bucket answered an empty list in the lab.

An import takes the archive through the same checks as `sealift import`, then publishes to Nexus with the service's own Nexus user. Imports run one at a time. The result for each package is stored as it ends:

| Outcome | Meaning | The archive in MinIO |
| --- | --- | --- |
| `complete` | Every package is published or already in Nexus | Removed, with its manifest and signature, after all three are checked unchanged |
| `incomplete` | At least one package failed, such as a version Nexus holds with other bytes | Kept |
| `interrupted` | The service stopped during the import | Kept |
| `refused` | A check failed before anything was published | Kept |

In the lab, an archive whose `bytes@3.1.2` already existed in Nexus with other bytes ended `incomplete` with 100 packages `present` and that one `failed`, and both objects stayed in MinIO. After the planted component was deleted in Nexus, a retry ended `complete`, uploaded that one package and removed the archive. Restarting the service during an import ended it `interrupted`, and a retry ended `complete`.

The screens of the service show all of this without `curl`: [Importing](importing.md) quotes each state word for word. Home lists the folder's archives and Import starts an import, Imports lists every import, and an import shows its stages, its report per package and its retry. Each failed package carries a kind: `conflict`, `nexus`, `source`, `interrupted`, `mismatch` or `local`. The page sorts them into those a retry clears as it is and those that need a change first. A record written by 0.4.0 has no kind and no check result, and the screen says `Not recorded` for both.

A retry reads every package from Nexus again and uploads only what Nexus no longer serves. It needs the archive to be in MinIO still and unchanged. Delete or replace nothing in the user's folder while an import is queued or running.

[Deployment](deployment.md#the-import-service) covers running the service.

## Versions that drift

sealift resolves each selected version on the day of the analysis, one dependency at a time, and the export ships what those resolutions need. On the air-gapped side, an install without a lockfile resolves again, against whatever Nexus holds. When earlier imports left other versions of the same packages there, pnpm may pick a different one than sealift scanned.

Commit the lockfile the first install produces on the air-gapped side, and install with `pnpm install --frozen-lockfile` from then on. A lockfile that asks for a version Nexus lacks then fails the install, instead of installing something nobody scanned.

## What sealift checks, and what it does not

sealift checks:

- every downloaded tarball against the sha512 the registry published;
- the manifest of each export with an Ed25519 signature, which the import checks against the public key you carried, and which covers the review and its reasons;
- that an export carries a reason for each jump out of a line and each CVE that no version fixes, unless the policy refuses them;
- Trivy against the sha256 of its release;
- that no proposed version of a direct dependency is younger than the minimum release age, and that neither are the packages it pulls in;
- that nothing downloads before you press Install, Analyse or Confirm and build the archive.

It does not:

- detect a malicious package that has no known CVE yet: Trivy knows only published vulnerabilities;
- sign the reports, or tell a fresh archive from an old one: the signature covers `manifest.json` and nothing else, and the sha256 is only as trustworthy as the channel that carries it.
