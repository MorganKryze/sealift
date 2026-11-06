# Security policy

## Supported versions

The latest release receives fixes. sealift stays on `0.y.z` for now, and a fix ships as a new patch or minor release, never as a change to an existing tag.

## Reporting a vulnerability

Use GitHub's private reporting: **Security**, then **Report a vulnerability**, on this repository. Do not open a public issue for something you believe others could exploit.

Include the version, what an attacker needs, and the steps that show the problem. You get an acknowledgement within a week. A confirmed problem gets a fix in a release, and the advisory is published once that release is out.

## What sealift guarantees

- Every package in an archive matches the sha512 integrity the npm registry published for it. A mismatch stops the export.
- Trivy matches the sha256 in its release's checksum file before sealift installs it.
- sealift proposes no version younger than the minimum release age, 14 days by default, and holds the packages under it to the same age, and installs a younger Trivy release only when you press **Install anyway**.
- sealift downloads nothing before you press Install, Analyse or Confirm and build the archive.
- In the published image, pnpm and Trivy run as a separate user that cannot read the settings file, which holds the signature key.
- The archive is reproducible: the same selection built by the same sealift gives the same sha256.
- `sealift import` publishes nothing until the archive passes every check: its sha256 and size match `manifest.json` (and the sha256 you pass with `-sha256`, when you give one), `signature.key` holds the configured key, every tarball matches its `shippedSha512`, and the listing has no extra, missing or oversized entry.
- The import never overwrites. A version Nexus already holds with other bytes fails with both digests, and the only exception is a copy that differs from the shipped one by the `publishConfig` that sealift removed.
- The import never turns TLS off, refuses redirects and warns when the Nexus URL is plain HTTP. Its credentials stay in memory: the password and the key are not written to the output, the report or an error.
- `sealift import-server` acts for a user only after the access token passes every check against the realm's keys: signature, algorithm, issuer, audience and expiry. A token signed by another key and a token with `alg` none each answered 401 in the lab. The user is the token's `preferred_username` claim alone; no forwarded header names one.
- The service reads and deletes only under `packages/npm/` in the bucket of the checked user, and never writes to MinIO. It removes an archive only after the import ended `complete` and both objects are unchanged.
- The import binary holds no Linux capability and is built to run under `--cap-drop ALL`. The image cannot set that flag: you set it in the compose file or on the `docker run` line, as [Deployment](docs/deployment.md#the-import-service) shows. Without it, the container keeps Docker's default capability bounding set, and the setuid binaries of the base image can use it.
- Tokens, the MinIO secret key, the Nexus password and the signature key stay out of logs, responses and stored records.

## What it does not

- `signature.key` is a shared value written in plain text into every archive. Anyone who knows it can build an archive the import accepts. It is not a cryptographic signature.
- The minimum release age relies on pnpm's `minimumReleaseAge`, which the default pnpm 10.34.5 honours. An older pnpm set through the API can ignore it for transitive packages.
- A malicious package with no published CVE passes: Trivy knows only disclosed vulnerabilities. The minimum release age and the signals on each candidate reduce that risk; they do not remove it.
- sealift has no login. Anyone who reaches its port can run sessions, download archives and change the key. [Deployment](docs/deployment.md#access) shows how to keep it private.
- The import checks `signature.key` and nothing more: it adds no signature of its own. A Nexus repository that allows redeploy can be overwritten by another tool between the check and the upload.
- The sha256 of an archive is only as trustworthy as the channel that carries it to the import side.
- A valid token acts as its user. Anyone who holds one, for as long as it is valid and the realm accepts it, can list that user's archives and start imports in their name.
- The service's MinIO key reads every user's folder: the MinIO policy covers every `user-*` bucket, and the service alone keeps a request to the checked user's bucket. A flaw in the service reaches every folder.
- The service trusts the gateway to forward the token it checked. It reads the token from one header and cannot tell a gateway from a client that reaches it directly; keep its port off any network users can reach but the gateway.
