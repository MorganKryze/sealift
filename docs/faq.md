# FAQ

Short answers to the questions that come up first. Each links to the page with the details.

## Can I drop a lockfile instead of a package.json?

No. sealift takes a `package.json` whose direct dependencies are pinned to exact versions, and resolves the rest itself with pnpm, for the target platform you set. A `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock` is not read. Workspaces and `overrides` are not supported either. [Workflow](workflow.md#drop) lists what the drop refuses.

## Does sealift update transitive dependencies?

Only through the direct ones. sealift proposes a new version for each direct dependency; the packages that version pulls in come with it. A CVE deep in the tree goes away when a direct dependency moves to a version whose tree no longer carries it. The CVE counts in the review include the whole tree of each candidate.

## Why is the proposal older than the latest release?

sealift proposes the oldest version among those with the fewest CVEs, and never one younger than 14 days. A recent release may show no CVE because nobody has looked at it yet. [How sealift chooses](how-sealift-chooses.md#why-the-oldest-version-that-fixes-the-most) has the reasoning and an example.

## Can I choose a version sealift did not propose?

Yes. Open the dependency in the review and pick any candidate without a blocking signal, or **Keep the current version**. **Show all 22 newer versions**, with the count for that dependency, lists every candidate.

## Does it handle Python, Docker images or other ecosystems?

Python, yes, through the API: a project of requirements files is resolved, scanned, exported and imported into a pypi repository in Nexus, with no screen yet. [Python projects](python.md) walks through it. Docker images and other ecosystems are not handled.

## What leaves the machine?

Requests to GitHub for Trivy, to `mirror.gcr.io` for its database, to the npm registry for package metadata and tarballs, and for Python projects to `pypi.org` and `files.pythonhosted.org` for uv, index pages and wheels. The `package.json` you drop stays on the machine: sealift sends package names and versions to the registry, as any install does, and nothing else. [Deployment](deployment.md#outbound-access) lists the hosts.

## Does it need internet on the air-gapped side?

No. The air-gapped side receives the archive and imports it into Nexus. sealift itself runs only on the connected side. [The air gap](air-gap.md) covers the import.

## Where does sealift keep its data?

In the `/data` volume: settings, sessions, archives, Trivy and its database, and the download cache. [Deployment](deployment.md#the-data-volume) describes the layout and how to back it up.

## How do I remove a session?

The interface has no delete button yet. The API removes a session with everything it holds:

<!-- illustrative -->
```sh
curl -X DELETE http://localhost:8080/api/projects/sealift-demo-321183
```

The session id is in the address bar, after `/sessions/`.

## How do I start over from scratch?

Remove the container and its volume, then run it again. Every session, archive and setting go with the volume, and so does the signing key: the next start generates a new one, which the import side must receive.

<!-- illustrative -->
```sh
docker rm -f sealift
docker volume rm sealift-data
```

## What does the signature prove?

That the `manifest.json` came from the holder of sealift's private key, which stays in that sealift's data volume. The manifest names the archive's sha256 and every package's sha512, so a valid signature covers every byte the import publishes. The import checks it with the public key you carried once to its settings, and refuses an archive signed by any other key. [The air gap](air-gap.md#the-signature-and-the-trusted-key) explains both sides.

It does not prove who pressed Export: anyone who reaches sealift's port can have a selection signed. It says nothing about freshness, so an old archive with a valid signature stays importable until you regenerate the key. It does not cover the reports. [Security policy](../SECURITY.md) lists these limits.

## What if I regenerate the key, or lose the volume?

The import side refuses every new archive until it holds the new public key, and it refuses the archives you exported before. Carry the new public key to the file `publicKeyFile` names, compare the Public key sha256 on both sides, then export again. [Deployment](deployment.md#the-key-the-import-trusts) covers a lost volume.

## Can two people use the same sealift?

Yes, through the same address. Jobs run one at a time, in order: a second analysis waits until the first ends. The theme is per browser; every other setting is shared.
