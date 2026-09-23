# FAQ

Short answers to the questions that come up first. Each links to the page with the details.

## Can I drop a lockfile instead of a package.json?

No. sealift takes a `package.json` whose direct dependencies are pinned to exact versions, and resolves the rest itself with pnpm, for the target platform you set. A `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock` is not read. Workspaces and `overrides` are not supported either. [Workflow](workflow.md#drop) lists what the drop refuses.

## Does sealift update transitive dependencies?

Only through the direct ones. sealift proposes a new version for each direct dependency; the packages that version pulls in come with it. A CVE deep in the tree goes away when a direct dependency moves to a version whose tree no longer carries it. The CVE counts in the review include the whole tree of each candidate.

## Why is the proposal older than the latest release?

sealift proposes the oldest version among those with the fewest CVEs, and never one younger than 14 days. A recent release may show no CVE because nobody has looked at it yet. [How sealift chooses](how-sealift-chooses.md#why-the-oldest-version-that-fixes-the-most) has the reasoning and an example.

## Can I choose a version sealift did not propose?

Yes. Open the dependency in the review and pick any candidate without a blocking signal, or **Keep the current version**. **Show all newer versions** lists every candidate.

## Does it handle Python, Docker images or other ecosystems?

Not yet. sealift handles npm packages only. The archive format and the review are built around npm.

## What leaves the machine?

Requests to GitHub for Trivy, to `mirror.gcr.io` for its database, and to the npm registry for package metadata and tarballs. The `package.json` you drop stays on the machine: sealift sends package names and versions to the registry, as any install does, and nothing else. [Deployment](deployment.md#outbound-access) lists the hosts.

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

Remove the container and its volume, then run it again. Every session, archive, setting and the key go with the volume.

<!-- illustrative -->
```sh
docker rm -f sealift
docker volume rm sealift-data
```

## Is signature.key a signature?

No. It is a shared value the import checks, written as plain text into the archive. It tells the import side the archive came from your sealift. The sha256, carried by a separate channel, is what shows the file did not change. [The air gap](air-gap.md#the-signature-key) explains both.

## Can two people use the same sealift?

Yes, through the same address. Jobs run one at a time, in order: a second analysis waits until the first ends. The theme is per browser; every other setting is shared.
