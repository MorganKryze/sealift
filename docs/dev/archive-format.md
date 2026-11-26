# Archive format

This page is the contract between sealift's export and the tool that imports it on the air-gapped side: the layout of `packages_npm.tar.gz` and `packages_pip.tar.gz`, the fields of `manifest.json`, and the reports. It describes `formatVersion` 2, the npm format, and `formatVersion` 3, the pip format. [The air gap](../air-gap.md) covers the npm files for operators.

## packages_npm.tar.gz

A gzip-compressed tar with one top-level directory, `out/`:

| Entry | Content |
| --- | --- |
| `out/` | Mode 0755 |
| `out/<file>.tgz` | One npm package tarball per package, mode 0644 |

`out/` holds the package tarballs and nothing else. The archive carries no key and no signature: both travel beside it (see below), so the archive depends on the selection and the build alone, whatever key signs the manifest.

`archive.WriteTarGz` writes the entries sorted by name, with the Unix epoch as every timestamp and 0 as owner and group. The same entries give the same bytes, so the same selection exported twice by the same build of sealift has the same sha256.

A tarball's file name comes from the package name and version, with a scope folded into the name: `@babel/code-frame` 7.29.7 ships as `babel-code-frame-7.29.7.tgz`. Two packages of one export can fold to one name, as `@a/b` and `a-b` at 1.0.0 do. Each scoped package among them then ships with a `~` in place of the slash, as `a~b-1.0.0.tgz`, and any unscoped one keeps its name. npm refuses `~` in a new package name, so the `~` form keeps the files apart. An older package name may hold `~`, so a file name can still be taken twice: the export then fails and names both packages. Without such a pair, every file keeps the folded name. Read the name and version from `manifest.json`, never from the file name.

## manifest.json

```json
{
  "formatVersion": 2,
  "toolVersion": "dev",
  "analysisId": "20260923T120255Z",
  "createdAt": "2026-09-23T12:04:24.410131126Z",
  "target": {
    "os": "linux",
    "cpu": "x64",
    "libc": "glibc",
    "node": "22.17.1",
    "pnpmVer": "10.34.5"
  },
  "archive": {
    "sha256": "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7",
    "size": 7031361
  },
  "packages": [
    {
      "name": "express",
      "version": "5.1.0",
      "file": "express-5.1.0.tgz",
      "originalIntegrity": "sha512-DT9ck5YIRU+8GYzzU5kT3eHGA5iL+1Zd0EutOmTE9Dtk+Tvuzd23VBU+ec7HPNSTxXYO55gPV/hq4pSBJDjFpA==",
      "shippedSha512": "0d3f5c939608454fbc198cf3539913dde1c603988bfb565dd04bad3a64c4f43b64f93beecdddb754153e79cec73cd493c5760ee7980f57f86ae294812438c5a4",
      "publishConfigStripped": false
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `formatVersion` | The version of this format, 2 today. Version 1 belongs to 0.4 and earlier, and an import refuses it |
| `toolVersion` | The sealift release that built the archive; `dev` for a build without a version, as in this example |
| `analysisId` | The analysis the selection came from |
| `createdAt` | When the export ran, RFC 3339, UTC |
| `target` | The platform and toolchain the packages were resolved for |
| `archive.sha256`, `archive.size` | Hex sha256 and byte size of `packages_npm.tar.gz` |
| `packages[].name`, `.version` | The package as the registry knows it |
| `packages[].file` | Its file name under `out/` |
| `packages[].originalIntegrity` | The integrity the registry published, in SRI form |
| `packages[].shippedSha512` | Hex sha512 of the file under `out/` |
| `packages[].publishConfigStripped` | `true` when sealift removed `publishConfig` from the tarball's `package.json`, and so rewrote it |

`manifest.json` travels next to the archive, not inside it: the archive's sha256 cannot be part of its own content.

## The review

A manifest may carry a `review` object: what the selection updates, keeps and takes out of its line, the CVEs the project keeps, and the reasons given for them. A dependency's line is the range npm's caret gives its current version: the same major from 1.0.0, the same minor below it, the same patch below 0.1.0. The signature covers the review with the rest of the manifest. The archive's bytes do not depend on it.

```json
{
  "cves": {
    "before": [1, 4, 6, 2, 0],
    "after": [0, 1, 3, 1, 0]
  },
  "updates": [
    {
      "name": "express",
      "from": "4.17.1",
      "to": "4.20.0",
      "fixed": [1, 2, 2, 0, 0],
      "left": [0, 0, 0, 1, 0]
    }
  ],
  "kept": [
    {
      "name": "debug",
      "version": "2.6.9",
      "jump": "4.4.3"
    }
  ],
  "jumps": [
    {
      "family": "react 19",
      "packages": [
        { "name": "react", "from": "18.3.1", "to": "19.2.0" },
        { "name": "react-dom", "from": "18.3.1", "to": "19.2.0" }
      ],
      "reason": "The app moved to React 19 in its last release, and its tests pass."
    }
  ],
  "left": [
    {
      "dependency": "html-minifier",
      "version": "4.0.0",
      "id": "CVE-2022-37620",
      "severity": "HIGH",
      "package": "html-minifier",
      "fixedIn": "",
      "reason": "No release fixes it. The build minifies our own templates only."
    },
    {
      "dependency": "express",
      "version": "4.20.0",
      "id": "CVE-2024-47764",
      "severity": "LOW",
      "package": "cookie",
      "fixedIn": "0.7.0"
    }
  ],
  "unchanged": 12
}
```

The counts in this example are made up. Each count vector holds the number of CVEs by severity: critical, high, medium, low and unknown, in that order.

| Field | Meaning |
| --- | --- |
| `cves.before` | The project's CVE counts before the selection |
| `cves.after` | The project's CVE counts once the selection applies, estimated as `summary.md` estimates them. Absent when the project scan could not be read |
| `updates[]` | A dependency the selection moves within its line: `name`, `from`, `to`, and the counts of the CVEs the move fixes (`fixed`) and leaves (`left`) |
| `kept[]` | A dependency kept on its line: `name`, `version`, and `jump`, the version outside the line it could take |
| `jumps[]` | A family, or a lone dependency, the selection takes out of its line: `family` (absent for a lone dependency), `packages[]` with `name`, `from` and `to`, and the `reason` given for the jump |
| `left[]` | A CVE the project keeps: the `dependency` and the `version` it keeps, the CVE `id`, its `severity`, the `package` Trivy found it in (empty when unknown), `fixedIn`, the versions Trivy names as fixing it (empty when none), and the `reason` given when no version fixes it |
| `unchanged` | The number of other dependencies, which the selection leaves as they are |

The review changes nothing the import must check, so it keeps `formatVersion` 2, as rule 6 of [What `sealift import` checks](#what-sealift-import-checks) allows. The import of sealift 0.7.0 ignores the key. Imports after 0.7.0 read it by these rules:

1. The review is read within the manifest's 16 MiB bound. Each list holds at most 100,000 entries, and `cves.before` is present.
2. Each `name`, `dependency` and `package` is a valid package name, and each version an exact version of at most 256 bytes, as rule 4 reads them. `id`, `fixedIn` and `family` are at most 256 bytes of printable characters, as rule 5 reads text. `severity` is one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` and `UNKNOWN`. Each count vector holds 5 counts of zero or more.
3. A reason holds 1 to 300 characters once trimmed, on one line, within 4,800 bytes. Letters, marks, numbers, punctuation, symbols, the plain space and the no-break spaces U+00A0, U+202F and U+3000 pass. A control character, a line or paragraph separator (U+2028, U+2029), a bidirectional override or any other format character breaks the rule. `archive.CheckReason` is that rule, the one a writer of the review applies too.
4. A review that breaks a rule is kept out with a problem that names the field and repeats no value, such as `review.left[1].severity is not one of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN`. The import still checks and publishes the packages as before: a review never refuses an archive.

`archive.CheckReview` reads a whole review through the import's own reader and returns the problem rule 4 would name. A writer that runs it before signing learns at the export that the import would keep the review out.

A manifest without `review`, as every archive from 0.7.0 or earlier, reads as a review not carried by this archive, and that is no problem. The import report does not show the review.

## manifest.json.sig

An export writes `manifest.json.sig` beside `manifest.json`. It holds an Ed25519 signature (RFC 8032, pure, no context and no prehash) over the exact bytes of `manifest.json` as written. Carry the archive, `manifest.json` and `manifest.json.sig` together.

```json
{
  "algorithm": "ed25519",
  "publicKeySha256": "6fefb059722cdef03cce92287e46148905131e1056bcf9a31e910ee0225f1c26",
  "signature": "<standard base64 of the 64 signature bytes>"
}
```

| Field | Meaning |
| --- | --- |
| `algorithm` | `ed25519` |
| `publicKeySha256` | Lowercase hex sha256 of the DER SubjectPublicKeyInfo of the key that signed |
| `signature` | Standard base64, with padding, of the 64-byte signature |

The file is indented JSON with a trailing newline, at most 4 KiB, and a reader ignores fields it does not know. An export signs with the key in use when it starts running, so a regenerate during the run changes nothing in it, and `publicKeySha256` names that key. The key signs manifests and nothing else. The manifest binds the archive's sha256 and size and each package's digests, so one signature covers every byte of the export. The reports are not signed.

The export step that writes `manifest.json` and its signature is named `reports` in the job's events. An export that cannot sign fails at that step and offers no file for download: a failed or cancelled export keeps only its `status.json`.

## What `sealift import` checks

`sealift import` reads the archive once and publishes nothing unless every check passes. The first problem found ends the run with its reason, except that a wrong size or sha256 is named before any other problem. The archive, the manifest and the signature are opened read-only.

The import trusts one key, the Ed25519 public key in the file named by `publicKeyFile` in its settings: one PKIX `PUBLIC KEY` PEM block, at most 4 KiB, LF or CRLF line endings, blank space around it allowed. The settings file has no `signatureKeyFile` any more.

The signature, checked before anything else is parsed:

1. The manifest is read once, within 16 MiB, and `manifest.json.sig` once, within 4 KiB. With `-signature`, the file is the one named; otherwise it is the manifest's path plus `.sig`.
2. The signature verifies over those exact manifest bytes with the trusted key. The verdict comes from the Ed25519 check alone: the `publicKeySha256` the file names only chooses the wording of the refusal.
3. Only then is the same manifest bytes parsed. A manifest edited after signing is refused by the signature, not by a manifest rule.

A refusal here opens with one of four phrases: `the archive is unsigned` (no signature file), `manifest.json.sig is not a signature this import reads` (unreadable, too large or malformed file), `the manifest is signed by another key` (the file names another key and the check fails), `the signature does not match the manifest` (the file names the trusted key and the check fails). A script matches these opening words and nothing after them. The refusal never quotes the file.

The manifest:

1. It is at most 16 MiB, and valid JSON with nothing after the document.
2. `formatVersion` is 2. Every field in the table above is present: a missing field refuses the manifest. `target.libc` must be present but may be empty, as older versions let a project save it empty. `packages` is not empty.
3. Each `file` is a plain file name of at most 255 bytes that starts with a letter, a digit or `_`, holds only letters, digits and `._~+-`, and ends in `.tgz`. No two packages share a `file` or a name and version.
4. Each `name` is a valid npm package name and each `version` an exact version of at most 256 bytes, as sealift's own checks read them. `shippedSha512` is 128 lowercase hex digits and `originalIntegrity` a usable integrity string of at most 4 KiB.
5. `toolVersion`, `analysisId`, `createdAt` and every `target` value are at most 256 bytes and hold only printable characters. A control character, a bidirectional override or any other format character refuses the manifest, so a report that prints these values cannot be made to write escape sequences. The refusal does not repeat the value.
6. Fields this version does not know are ignored. A change that alters what the import must check bumps `formatVersion`, so an older import refuses it.

The archive:

1. Its size and sha256 match `archive.size` and `archive.sha256`. With `-sha256`, it also matches the value received through a separate channel.
2. Entry names are exactly `out/` and `out/<file>`. An absolute path, a `..`, a `./out/` prefix, a path outside `out/`, a subdirectory, a directory other than `out/`, a link, a sparse file, anything but a regular file and a name that appears twice are refused.
3. The archive holds at most 10,000 entries and 10 GiB of unpacked content, counted from each entry's declared size before the entry is read, and no entry name passes 255 bytes. The inflated tar data is capped as well: the content bound, plus 4 KiB and the name bound for each entry, plus the 1 KiB end marker. Repeated extended or long-name headers before an entry count against that cap.
4. After the tar end marker, the archive holds at most 16 KiB of zero bytes. The gzip checksum is verified, and anything appended, a second entry or a second gzip member included, is refused without being inflated further.
5. Every file under `out/` is listed in `packages[].file`, and every listed file is present.
6. Each file's sha512 matches `shippedSha512`. When `publishConfigStripped` is `false`, it also matches `originalIntegrity`. When it is `true`, sealift rewrote the file, so `originalIntegrity` no longer describes it and is not compared.

Only then does the import publish each tarball to the npm hosted repository.

## The import report

`sealift import` prints a text report on stdout and, with `-report <file>`, writes the same account as JSON. The file is written once, at the end, with mode 0644. If that write fails, stderr says so and an exit code 0 becomes 1.

| Field | Meaning |
| --- | --- |
| `outcome` | `complete` when every package is `published` or `present`, `incomplete` when at least one failed, `refused` when a check failed and nothing was published |
| `reason` | Why the archive was refused; empty otherwise |
| `unencrypted` | `true` when the Nexus URL starts with `http:` |
| `importVersion` | The sealift release that ran the import |
| `archive.file`, `.sha256`, `.size` | The archive's file name, and the sha256 and size its manifest declares. A refusal for a wrong digest or size names the measured value in `reason` |
| `toolVersion`, `analysisId`, `target` | Copied from the manifest |
| `nexus.url`, `nexus.repository` | Where the import published to |
| `counts.published`, `.present`, `.failed` | Packages by state |
| `packages[].name`, `.version`, `.file` | The package, as the manifest lists it |
| `packages[].state` | `published`, `present` or `failed` |
| `packages[].reason` | Why a package failed; empty otherwise |
| `publicKeySha256` | The sha256 fingerprint of the trusted public key, as the settings name it. A report written by 0.4.0 or earlier has no such field |
| `archiveChecked` | `true` when the signature verified and the archive passed its checks against the manifest, `false` when the run was refused or stopped before they passed. A report written by 0.4.0 or earlier has no such field |
| `packages[].kind` | Set on a failed package only, one of the six kinds below. A report written by 0.4.0 or earlier has no `kind` on any package |
| `packages[].note` | Empty for a failed package. For a package whose manifest entry has `publishConfigStripped`, the note the publish step set, or `sealift removed publishConfig at export` when it set none |

A refused report lists no package, holds zero counts and has `archiveChecked` false.

Each failed package has one `kind`, set where the failure happens:

| Kind | Set when |
| --- | --- |
| `conflict` | Nexus holds this version with other bytes, found before any upload |
| `nexus` | Nexus refused the repository check, answered an upload or a read with an error, accepted an upload but does not serve the version, or served other bytes after the upload |
| `source` | The import service could not finish reading the archive from MinIO, so every package fails with that reason |
| `interrupted` | The run was stopped before the package ended, by an interrupt or by the service stopping |
| `mismatch` | The tarball is not a valid package, or names another name or version than the manifest entry |
| `local` | A file or the Nexus client on the import's own side failed: the checked tarball cannot be opened or read, it changed after the checks, the Nexus copy cannot be kept, or the client cannot be set up |

Before it looks at Nexus, the import reads each tarball: its `package.json` must name the manifest entry's name and version, hold no unsafe path and no second first-level `package.json`, stay under 100,000 entries, 10 GiB unpacked and 16 MiB for `package.json`, and no entry name or link target passes 4,096 bytes. A tarball that fails is `failed` with that reason and the others go on. Entry names in a reason are quoted, and text read from a tarball, the Nexus copy included, is cut to 300 characters with control characters removed.

A package is `present` when Nexus already serves the same bytes. For a package with `publishConfigStripped`, it is also `present` when Nexus serves other bytes with the same content, noted `same content, packed differently`. Same content means the same entry names, types, modes, link targets and file bytes, as written. Owners, times and entry order do not count. The `package.json` compares as decoded JSON once `publishConfig` is removed from both. A tarball that holds a name twice never matches, nor does one with data after its end-of-archive marker other than zero padding, which pnpm refuses. Any other difference is `failed`, naming both sha512 digests; a copy that cannot be read for the comparison is `failed` with the reason instead.

A package is `published` when the upload was read back and matched the shipped sha512, and `failed` otherwise. The report never holds the Nexus password, an `Authorization` header or any key.

The text form starts with `import <outcome>[ (unencrypted)]: <n> published, <n> present, <n> failed`. A warning line follows for an unencrypted connection, then `reason:` when there is one, the archive line, `import version: <importVersion>`, the manifest and Nexus lines, and one line per package: `<name>@<version> <state> <file>[: <reason>][ (<note>)]`.

| Exit code | Meaning |
| --- | --- |
| 0 | Complete |
| 1 | Incomplete: at least one package failed, or the JSON report could not be written |
| 2 | Usage or settings error: one line on stderr, no report. `-report` naming the archive, the manifest or the signature is one |
| 3 | Refused, an unsigned or wrongly signed archive included: nothing was published |

The archive and the manifest are opened read-only. The command writes the JSON report and one private temporary directory, which it removes on every exit.

## The reports

| File | Format | Content |
| --- | --- | --- |
| `summary.md` | Markdown | Analysis date, Trivy and database versions, target; CVE counts for the whole project before, for the project once the selection applies (estimated from the analysis' per-dependency scans), and for the packages in the archive; the updated dependencies; the remaining critical and high CVEs; the non-blocking signals on the selected versions; the archive's size, sha256 and package count |
| `findings.csv` | CSV with a header | One row per CVE and package: `dependency`, `current_version`, `selected_version`, `package`, `package_version`, `vulnerability_id`, `severity`, `status` (`fixed`, `remaining` or `introduced`), `fixed_version`, `title` |
| `report.cdx.json` | CycloneDX JSON | The SBOM of the exported packages, from Trivy |
| `report.trivy.json` | Trivy JSON, schema 2 | Trivy's scan of the exported packages |

The reports are for people and audit tools. The import does not need them.

## packages_pip.tar.gz

A pip export writes `packages_pip.tar.gz`, laid out as `packages_npm.tar.gz` is: a gzip-compressed tar with one top-level directory, `out/`.

| Entry | Content |
| --- | --- |
| `out/` | Mode 0755 |
| `out/<file>.whl` | One wheel per package, mode 0644 |

`out/` holds the wheels and nothing else, one per package. `archive.WriteTarGz` writes this archive too, so the entries are sorted, every timestamp is the Unix epoch and owner and group are 0. The same analysis exported twice by the same build of sealift has the same sha256.

A wheel keeps the file name the package index gave it, such as `MarkupSafe-3.0.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`. The manifest's `name` is the normalized project name, which the file name may spell another way. A file name is at most 251 bytes, so `out/<file>` stays within the 255-byte bound on an entry name.

## manifest.json of a pip export

```json
{
  "formatVersion": 3,
  "ecosystem": "pip",
  "toolVersion": "dev",
  "analysisId": "20261120T091500Z",
  "createdAt": "2026-11-20T09:17:42.518204331Z",
  "target": {
    "python": "3.11.2",
    "os": "linux",
    "cpu": "x86_64",
    "glibc": "2.28",
    "uvVer": "0.13.7"
  },
  "archive": {
    "sha256": "7412191e280551b2bb3071c767b661b39e9b6966528f0fb3afd9d167141043b7",
    "size": 1395712
  },
  "packages": [
    {
      "name": "jinja2",
      "version": "3.1.6",
      "file": "jinja2-3.1.6-py3-none-any.whl",
      "sha256": "dc4cadfd8d415504c2c06cd7f95028fcce2e45cd2297b52222fba1c0b0be8abb",
      "shippedSha512": "43e5e55037605ffd406599cb282af332714528dfd8cb7d3aa42e46c782fb4c7abab45a415ba60b3698e72fd2915750813cdf4a53b47e856db3d78a66712dabde"
    },
    {
      "name": "markupsafe",
      "version": "3.0.2",
      "file": "MarkupSafe-3.0.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
      "sha256": "7743268b07457bf5f423266c39c8de26a3bbea92091b6a7d715a5bdfeffecbc0",
      "shippedSha512": "2567b4efaa0966369b002906a9ed2f891befe023b797e90a664ddc12b1fb9cc54c9de7d96b7a4aebaa161927a7ff8e1d24ef18e08a998eb92a930f8a213e61ec"
    }
  ]
}
```

The digests in this example are made up and match no published wheel.

| Field | Meaning |
| --- | --- |
| `formatVersion` | 3, the pip format |
| `ecosystem` | `pip` |
| `toolVersion` | The sealift release that built the archive; `dev` for a build without a version, as in this example |
| `analysisId` | The analysis the wheels came from |
| `createdAt` | When the export ran, RFC 3339, UTC |
| `target.python`, `.os`, `.cpu`, `.glibc`, `.uvVer` | The interpreter, system and uv version the analysis chose the wheels for |
| `archive.sha256`, `archive.size` | Hex sha256 and byte size of `packages_pip.tar.gz` |
| `packages[].name` | The project name in its PEP 503 normalized form: lower case, each run of `-`, `_` and `.` turned into one `-` |
| `packages[].version` | The exact version |
| `packages[].file` | The wheel's file name under `out/` |
| `packages[].sha256` | The hex sha256 the package index published for the wheel |
| `packages[].shippedSha512` | Hex sha512 of the file under `out/`, the same bytes as `sha256` |

The pip manifest lists no source URL, no requirements file and no wheel tag: the import needs none of them. A pip manifest may carry a `review` read by the rules of [The review](#the-review), with pip's names and versions. A pip export writes none. `manifest.json.sig` signs a pip manifest as it signs an npm one, with the same key and the same Ed25519 scheme. The manifest is written as indented JSON and signed over those exact bytes.

## Telling the formats apart

Once the signature verifies, an import reads `formatVersion` and `ecosystem`, and nothing else, to choose the rules for the rest of the manifest:

| `formatVersion` | `ecosystem` | Read as |
| --- | --- | --- |
| 2 | absent or `npm` | npm, by the rules of [What `sealift import` checks](#what-sealift-import-checks) |
| 3 | `pip` | pip, by the rules of [What an import checks in a pip archive](#what-an-import-checks-in-a-pip-archive) |

Any other pair is refused with one of `formatVersion is missing`, `formatVersion 2 is an npm manifest, and its ecosystem is not npm`, `formatVersion 3 is a pip manifest, and its ecosystem is not pip` or `formatVersion is not 2 or 3, the versions this import reads`. The refusal does not repeat the value.

An npm manifest keeps `formatVersion` 2 and has no `ecosystem` key, so an npm export writes the bytes 0.6.2 wrote. The import of sealift 0.6.2 reads `formatVersion` 2 only, and refuses a pip manifest with `formatVersion is missing or not 2, the only version this import reads`.

## What an import checks in a pip archive

The signature comes first, with the same steps and the same four refusal phrases as for npm (see [What `sealift import` checks](#what-sealift-import-checks)). Then the import tells the formats apart as above.

The manifest:

1. It is at most 16 MiB, and valid JSON with nothing after the document.
2. `formatVersion` is 3 and `ecosystem` is `pip`. Every field in the table above is present and not empty: a missing field refuses the manifest. `packages` is not empty.
3. `toolVersion`, `analysisId`, `createdAt` and every `target` value are at most 256 bytes and hold only printable characters, as for npm. `createdAt` is an RFC 3339 time. The target is checked as text only.
4. Each `file` is a plain file name of at most 251 bytes that starts with a letter or a digit, holds only letters, digits and `._!+-`, and ends in `.whl`. It also reads as a wheel name: project name, version, an optional build tag, then the Python, ABI and platform tags. An sdist or any other file is refused.
5. Each `name` is a valid project name in its normalized form. Each `version` is an exact public version of at most 128 bytes, with no range, no wildcard and no local part.
6. Each `file` names its entry's package and version: the project name in the file, once normalized, is `name`, and its version equals `version` as PEP 440 compares them, so `3.1.6.0` matches `3.1.6`.
7. `sha256` is 64 lowercase hex digits and `shippedSha512` 128.
8. Each `name` appears once. A pip archive carries one wheel per package, so a second entry for a name, at the same version or another, refuses the manifest.
9. A refusal names the field at fault. It repeats a `file` or a `name` only after that value has passed its rule above, and no other manifest value.
10. Fields this version does not know are ignored.

The archive:

1. Rules 1 to 5 of the npm archive list apply as they are. They cover the size and sha256, the entry names, the bounds of 10,000 entries, 10 GiB unpacked and 255-byte names, and the cap on the inflated tar data. They also cover the zero padding after the end marker, and require every file under `out/` to be listed in `packages[].file` and every listed file to be present.
2. Each wheel's sha512 matches `shippedSha512`, and its sha256 matches `sha256`. The refusals read `<file> does not match its shipped sha512` and `<file> does not match its sha256`.
3. As for npm, a wrong size or sha256 of the archive is named before any other problem.

## Importing a pip archive

`sealift import` takes a pip archive as it takes an npm one: give it `packages_pip.tar.gz`, with `manifest.json` and `manifest.json.sig` beside it. Once the signature verifies, the manifest's `formatVersion` and `ecosystem` choose the rules, as [Telling the formats apart](#telling-the-formats-apart) shows. An npm archive goes on exactly as before, whether or not the settings name a pip repository.

A pip archive then goes through these steps, in this order:

1. The manifest is checked by the rules of [What an import checks in a pip archive](#what-an-import-checks-in-a-pip-archive).
2. The settings must name a pip repository. Without `nexus.pip`, the archive is refused with `the settings name no pip repository: set nexus.pip.repository`.
3. The import asks Nexus for its repository list, before it reads the archive. A repository Nexus does not list, or lists in another format or type, refuses the archive with `nexus repository "<name>" not found` or `nexus repository "<name>" is <format> <type>, not pypi hosted`. A Nexus that does not answer, or answers with an error such as 401 or 403, ends the import `incomplete`: every wheel fails with kind `nexus` and the reason `repository check failed: ` followed by the error, and the archive is not read.
4. The archive is checked against the manifest by the rules of the same section.
5. Each wheel is published in manifest order, one at a time.

For each wheel, the import first reads the wheel itself. It reads the zip directory, `METADATA` and `WHEEL` within bounds: 100,000 entries, 1,024 bytes for an entry name, 16 GiB declared unpacked, 1 MiB for `METADATA` and 64 KiB for `WHEEL`. It refuses an unsafe entry name and a wheel without exactly one `.dist-info` directory. It writes nothing out and runs nothing. `METADATA` and the file name must both name the manifest entry's project and version, compared by normalized name and by PEP 440 equality. A wheel that fails any of this ends `failed` with kind `mismatch`, and the next wheel goes on.

Then the import looks the file up in the repository's simple index, `/repository/<repository>/simple/<name>/`, and reads the file the page links to. It follows a link only below `/repository/<repository>/` on the configured host, and only to a file of the wheel's exact name. The sha512 of what Nexus serves decides the state:

| State | Set when |
| --- | --- |
| `present` | Nexus already serves the file with the shipped sha512. Nothing is uploaded |
| `published` | Nexus did not hold the file. The import uploaded it, read it back through the simple index, and Nexus served the shipped sha512 |
| `failed` | Any other end, with one kind below |

| Kind | Set when, for a wheel |
| --- | --- |
| `conflict` | Nexus serves a file of the same name with other bytes, found before any upload. The reason names both sha512 digests, and the wheel is not uploaded |
| `nexus` | The repository check failed, Nexus answered a read or the upload with an error, accepted the upload but does not list the file, or served other bytes after the upload |
| `source` | The import service could not finish reading the archive from MinIO |
| `interrupted` | The run was stopped before the wheel ended |
| `mismatch` | The wheel is not a valid wheel within the bounds above, or its `METADATA` or its file name names another project or version than the manifest entry |
| `local` | The checked wheel cannot be opened or read, it changed after the checks, or the Nexus client cannot be set up |

A second run on the same archive finds the published wheels `present` and uploads only the ones Nexus does not hold.

The report of a pip import has the fields of [The import report](#the-import-report), with three more. `ecosystem` is `pip`. `target.python` and `target.glibc` come from the manifest, and `target.libc`, `.node` and `.pnpmVer` are empty. `nexus.repository` is the pip repository. An npm report has no `ecosystem`, `target.python` or `target.glibc` key, so it keeps the shape 0.6.2 wrote.

The text form prints the manifest line with the Python target in place of Node and pnpm:

```text
manifest: sealift dev, analysis 20261120T091500Z, target linux x86_64, python 3.11.2, glibc 2.28
```

The other lines and the exit codes are the npm ones. A package line reads `six@1.16.0 published six-1.16.0-py2.py3-none-any.whl`. The report never holds the pip password.
