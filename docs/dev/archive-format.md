# Archive format

This page is the contract between sealift's export and the tool that imports it on the air-gapped side: the layout of `packages_npm.tar.gz`, the fields of `manifest.json`, and the reports. It describes `formatVersion` 1. [The air gap](../air-gap.md) covers the same files for operators.

## packages_npm.tar.gz

A gzip-compressed tar with one top-level directory, `out/`:

| Entry | Content |
| --- | --- |
| `out/` | Mode 0755 |
| `out/<file>.tgz` | One npm package tarball per package, mode 0644 |
| `out/signature.key` | The signature key from the settings, as plain text with no trailing newline, mode 0644 |

`archive.WriteTarGz` writes the entries sorted by name, with the Unix epoch as every timestamp and 0 as owner and group. The same entries give the same bytes, so the same selection exported twice by the same build of sealift has the same sha256.

A tarball's file name comes from the package name and version, with a scope folded into the name: `@babel/code-frame` 7.29.7 ships as `babel-code-frame-7.29.7.tgz`. Read the name and version from `manifest.json`, never from the file name.

## manifest.json

```json
{
  "formatVersion": 1,
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
| `formatVersion` | The version of this format, 1 today |
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

## What an import tool should check

1. The sha256 of `packages_npm.tar.gz` matches `archive.sha256`, and the value received through a separate channel.
2. `out/signature.key` holds the expected value.
3. Every entry under `out/` other than `signature.key` is listed in `packages[].file`, and every listed file is present.
4. Each file's sha512 matches `shippedSha512`. When `publishConfigStripped` is `false`, it also matches `originalIntegrity`.
5. Entry paths stay under `out/`: no `..`, no absolute path, no link.

Only then publish each tarball to the npm hosted repository.

## The reports

| File | Format | Content |
| --- | --- | --- |
| `summary.md` | Markdown | Analysis date, Trivy and database versions, target; CVE counts before and after; the updated dependencies; the remaining critical and high CVEs; the non-blocking signals on the selected versions; the archive's size, sha256 and package count |
| `findings.csv` | CSV with a header | One row per CVE and package: `dependency`, `current_version`, `selected_version`, `package`, `package_version`, `vulnerability_id`, `severity`, `status` (`fixed`, `remaining` or `introduced`), `fixed_version`, `title` |
| `report.cdx.json` | CycloneDX JSON | The SBOM of the exported packages, from Trivy |
| `report.trivy.json` | Trivy JSON, schema 2 | Trivy's scan of the exported packages |

The reports are for people and audit tools. The import does not need them.
