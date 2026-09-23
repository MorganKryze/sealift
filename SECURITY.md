# Security policy

## Supported versions

The latest release receives fixes. sealift stays on `0.y.z` for now, and a fix ships as a new patch or minor release, never as a change to an existing tag.

## Reporting a vulnerability

Use GitHub's private reporting: **Security**, then **Report a vulnerability**, on this repository. Do not open a public issue for something you believe others could exploit.

Include the version, what an attacker needs, and the steps that show the problem. You get an acknowledgement within a week. A confirmed problem gets a fix in a release, and the advisory is published once that release is out.

## What sealift guarantees

- Every package in an archive matches the sha512 integrity the npm registry published for it. A mismatch stops the export.
- Trivy matches the sha256 in its release's checksum file before sealift installs it.
- sealift proposes no package version younger than the minimum release age, 14 days by default, and installs a younger Trivy release only when you press **Install anyway**.
- sealift downloads and installs nothing until you press a button that says so.
- pnpm and Trivy run as a separate user that cannot read the settings file, which holds the signature key.
- The archive is reproducible: the same selection built by the same sealift gives the same sha256.

## What it does not

- `signature.key` is a shared value written in plain text into every archive. Anyone who knows it can build an archive the import accepts. It is not a cryptographic signature.
- A malicious package with no published CVE passes: Trivy knows only disclosed vulnerabilities. The minimum release age and the signals on each candidate reduce that risk; they do not remove it.
- sealift has no login. Anyone who reaches its port can run sessions, download archives and change the key. [Deployment](docs/deployment.md#access) shows how to keep it private.
- The sha256 of an archive is only as trustworthy as the channel that carries it to the import side.
