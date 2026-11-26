# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- sealift prepares itself at start, with no click: it installs the Trivy release its binary pins, downloads the vulnerability database, checks the signing key, and installs the pnpm and uv versions the default targets name. A failed step keeps its cause and tries again every minute. [Deployment](docs/deployment.md#readiness) describes it.
- A policy file, named by `SEALIFT_POLICY`, sets the npm and pip target defaults, the minimum release age, the resolve and download parallelism, and the brand: name, logo, accent, side labels, review word and contact. sealift refuses to start on an unknown key or a value out of range, and names the file, the key and the rule. [Settings](docs/settings.md) lists every key.
- `deploy/connected/compose.policy.yaml` mounts a policy folder read-only, and `deploy/connected/policy/policy.yaml` is an example with every key commented out.
- `GET /api/instance` reports readiness, item by item with each cause, the policy in effect, the brand and the tool versions. `GET /api/instance/logo` serves the policy's logo.
- `GET /livez` answers 200 while the server runs, for a liveness probe.
- The home shows Preparing this instance, with each item and its state, until the instance is ready, then opens by itself.
- Each dependency names its jump: the best version outside its current line, which sealift does not propose. [How sealift chooses](docs/how-sealift-chooses.md#the-jump) describes it.
- Families: dependencies whose jumps must move together, read from the jump's peer dependencies and from `@types` packages, such as `react 19` for react, react-dom and `@types/react`.
- An export that takes a version outside its line, or keeps a CVE that no version fixes, needs a reason for each family, lone jump or dependency. The review screen asks for them above **Confirm and build the archive**, which stays disabled until each is written, and the server refuses an export without them.
- The signed `manifest.json` of an npm export carries a `review`: CVE totals before and after, updates, kept dependencies, jumps with their reasons, and each CVE the project keeps with its fixing versions or its reason. The import of sealift 0.7.0 imports such an archive as before, and a review an import cannot read never refuses an archive. [The air gap](docs/air-gap.md#the-review-in-the-manifest) describes it.
- Each CVE in an analysis keeps the package Trivy found it in and the versions that fix it.
- Three review rules in the policy file: `review.proposeOtherMajors`, `review.majorJump` and `review.cveWithoutFix`. By default, proposals stay in their line and a jump or a CVE without fix needs a reason; `refuse` stops such an export whatever its reason. [Settings](docs/settings.md#review-rules) lists them.

### Changed

- `/healthz` is a readiness check: it answers 503 with the names of the missing items until every one is ready, then 200. Use `/livez` for liveness, or an orchestrator restarts an instance that is still downloading.
- `deploy/connected/compose.yaml` gives the first start 10 minutes before a failed healthcheck counts, and checks every 5 seconds until the first success. `start_interval` needs Docker Engine 25 or later.
- Settings that 0.7.0 saved in `private/settings.json` still apply, and a value the policy file sets wins over them. The start log names each key the file overrides. sealift reads that file and never writes it, so a new volume holds none, and 0.7.0 still reads it after a rollback.
- Once the pinned Trivy is active, the start removes every other Trivy version from the volume. An analysis is refused while another version is active.
- `sealift signing-key regenerate`, run in the container or pod as the image's user, replaces the signing key. It prints the new public key, its sha256 and the replaced key's sha256, and refuses a key file another user owns. The running server signs the next export with the new key, with no restart. [Deployment](docs/deployment.md#regenerate-the-key) describes it.
- `SEALIFT_NPM_REGISTRY` now also serves the download of pnpm.
- A new look, in light and dark: every colour reaches its contrast in both themes, states show as closed tinted rows, and figures read in bold.
- Both sides open in one frame: a sidebar of places, Home and Projects on the connected side, Home and Imports on the import side, with Instance at its foot, and a top bar with the breadcrumb and the side's name. [Workflow](docs/workflow.md#the-frame) describes it.
- The connected home opens on Start a crossing, with Update, then Needs you, for a review that waits or a crossing that failed, and In progress. A crossing is named after its project and its day. Past sessions and New session are gone.
- The import home greets the user and lists Needs you, In progress and Done today. The archive list becomes Choose an archive, reached from Import. [Importing](docs/importing.md#home) describes it.
- Projects lists every project with its latest crossing, by date or by name. A project's page lists its crossings, with To carry and Download all for the three files to carry, and Reports with Open.
- Instance replaces the Settings panel on both sides, read-only: readiness, the policy and the signing key's sha256 on the connected side, the trusted key with Compare on the import side. The connected page has no Regenerate key button: How to regenerate shows the command to run in the container. [Settings](docs/settings.md#the-instance-page) describes it.
- The connected side draws the brand: its name, logo, side label and accent, where the accent reaches 3:1 against the page. The import side keeps the defaults.
- Proposals stay in each dependency's current line by default, the range npm's caret gives its current version. express 4.17.1 no longer gets 5.1.0 proposed: it stays in major 4, and 5.1.0 is its jump.
- The `major-jump` signal follows the line below 1.0.0: 0.18.0 to 0.19.0 carries it, with the evidence `leaves 0.18.x`.
- A reason may hold the no-break spaces of French and CJK typography (U+00A0, U+202F, U+3000), on the review screen and in the signed review.
- A name listed twice, one entry in a family and one jumping alone, asks one reason for its jumps.
- Under `review.cveWithoutFix: refuse`, a pip export whose set holds a CVE with no fix is refused with 409. A pip export sent with reasons is refused with 400.
- With the project tree, the CVEs with no fix in the packages its lockfile holds, transitive ones included, go through the same check as a selection. A package no dependency's own scan names counts for each direct dependency whose tree in the lockfile holds it, and the review lists its CVE under that dependency. A package the lockfile places under no direct dependency refuses the export.
- An export request holds at most 10,000 reasons, 10,000 selected dependencies and 10,000 dependencies per reason, each name at most 214 bytes; a request past a bound gets a 400 that names it. A JSON request body over 16 MiB, or a project upload over 41 MiB, gets a 413, and a body that is neither JSON nor a multipart upload gets a 415.
- A CVE's fixing versions longer than 256 bytes are shortened at a version boundary in the signed review, instead of failing the export. The Trivy report in the archive keeps the full list.
- An analysis made by sealift 0.7.0 recorded no fixing versions, so an export from it counts each CVE as one without fix and asks a reason for it. A new analysis records them.

### Removed

Each removed route below answers 410 Gone, with Problem Details that name what replaces it.

- The setup screen and its install button: the start installs what it showed.
- The settings form: the policy file replaces it.
- `GET /api/tools`: `GET /api/instance` reports the same versions, with readiness.
- `POST /api/tools/trivy/update`: the start installs the pinned Trivy.
- `POST /api/tools/trivy/activate`: sealift runs the pinned Trivy only.
- `POST /api/tools/trivy/db/update`: the start refreshes the database, and so does each analysis.
- `POST /api/tools/uv/install`: the start installs the default pip target's uv, and an analysis installs another target's uv.
- `PUT /api/settings`: the policy file sets every value. `GET /api/settings` stays, read-only.
- `POST /api/signing-key/regenerate`: `sealift signing-key regenerate` replaces the key from the container or pod. `GET /api/signing-key` stays.

### Fixed

- A version whose `engines` held a value that is not a string, such as `"npm": 7`, lost its Node range too and could be proposed for a Node it does not support. Its Node range now counts.
- A version whose `engines.node` is not a string, such as `18` or `[">=18"]`, is flagged as a Node mismatch, as pnpm 10 and 11 match no Node against it. It used to read as a version with no Node range.
- An analysis with the project's own lockfile failed when that lockfile gave a package `engines` holding an object or a list, which pnpm 10 and 11 write. Such engines now read as a packument's do: a `node` value that is not a string counts as a Node mismatch.

- Cancelling an analysis still waiting in the queue keeps it in the session as Analysis cancelled, with Start it again. It used to vanish and leave No analysis yet with no action. For a pip project, the API keeps the cancelled record the same way.
- Cancelling an export still waiting in the queue keeps it as Export cancelled, with Start the export again. Before, the session dropped it without a word.
- An analysis or an export waiting for another job reads Waiting for another job, with no step in progress and no package counters, instead of looking like the running one.
- A second analysis or export of one project queued in the same second stays in the session's history and opens by its link. It used to vanish once it ended, and opening it answered an error.
- Analyses or exports of one project queued in the same second list in the order they were queued. With three or more, they used to list in a random order, so a session could show an older analysis as its latest.
- An analysis that fails before its first step, for example when sealift cannot write its log, shows the cause under What went wrong. It used to show Analysis stopped with nothing under it.
- On the home screen, a past session whose analysis or export waits in the queue reads Waiting for another job. It used to read Analysing or Exporting.
- A project whose target names another pnpm version than the default target resolves with that pnpm. It used to download that version, then resolve with the default target's pnpm.
- pnpm resolves through `SEALIFT_NPM_REGISTRY`. It used to resolve through the public registry unless `NPM_CONFIG_REGISTRY` named the mirror too. `NPM_CONFIG_REGISTRY` no longer reaches pnpm: remove it from your deployment.
- A request with a method an `/api` route does not serve, such as `DELETE /api/instance`, answers 405 with an `Allow` header naming the methods it serves. It used to answer 404. An unknown `/api` path answers 404 as Problem Details, in JSON like every other API error.
- A failure cause, an analysis warning and the evidence of a candidate that does not resolve, on screen and in the API, name a file in the data volume by its path inside the volume, such as `private/signing-key.pem`. Some of them used to carry the server's full path. This applies to analyses run after the upgrade: a finished analysis keeps the text it stored. The server log keeps the full error of a failure cause: it gets one warning per failed job, with the job's id and kind.

### Security

- Trivy is trusted by the sha256 built into sealift for each architecture, and no longer by the checksums file of the same release. sealift asks GitHub for the pinned release only, never for the latest one, and installs nothing when the download's sha256 differs. A mirror set in `SEALIFT_GITHUB_API` can delay Trivy and cannot swap it.
- No route installs a tool or forces a release younger than the minimum release age, so the cross-site and DNS-rebinding exposure of the install routes is gone with them. A project's target can still name another pnpm or uv, and both are held to the minimum release age.
- `SEALIFT_NPM_REGISTRY` must be `https`, or `http` on a loopback host, since pnpm's integrity comes from that registry. `SEALIFT_ALLOW_HTTP_REGISTRY=true` admits a plain `http` registry elsewhere, with a warning at start.
- The policy's logo must be a regular PNG or SVG file of at most 256 KiB, and is served with a `Content-Security-Policy` that blocks scripts and `X-Content-Type-Options: nosniff`. A contact address must be `https:` or `mailto:`, and brand text with a control character is refused.
- An analysis refuses an npm package document over 256 MiB and names the package, where it used to read a document of any size into memory. A request to the npm registry gives up after 5 minutes, so a registry that stops answering mid-response can no longer hold an analysis forever.
- A failed download or package lookup from a registry whose `SEALIFT_NPM_REGISTRY` URL carries a user and password no longer stores them in the job's cause or in an analysis warning, on screen and in the API. The server log no longer gets them either. This applies to analyses run after the upgrade: a finished analysis keeps the text it stored.

## [0.7.0] - 2026-11-23

### Added

- pip projects through the API: requirements files resolved together at the interpreter's exact version, scanned, one wheel recorded per package. No screen opens them yet. [API](docs/dev/api.md#pip-projects) describes them.
- `sealift import` publishes a pip archive to the pypi hosted repository that `nexus.pip` names. It checks each wheel's signed digests, its `METADATA` and its file name, uploads only the wheels Nexus lacks, and reads each upload back. Without `nexus.pip` in the settings, it refuses a pip archive before reading it. [Archive format](docs/dev/archive-format.md#importing-a-pip-archive) describes the checks and the report.
- The import service lists and imports archives from `packages/pip/` beside `packages/npm/`, and refuses an archive whose manifest belongs to the other folder. The MinIO service user needs list, read and delete on `packages/pip/` too; with the old policy, every list shows that `packages/pip/` could not be listed.
- The chart takes `nexus.pipRepository` and an optional `nexus.pipUser`. With `nexus.pipUser` set, the Secret also holds `nexus-pip-password`.
- The import screens show a pip archive's Python version and glibc.
- pip exports through the API: a signed archive of the analysis's wheels, with its manifest in format version 3 and the four reports. No screen exports them yet. [API](docs/dev/api.md#pip-exports) describes them.
- The runbook, the request to the administrators and a Python projects page cover pip: the pypi repository with three privileges, the MinIO policy for `packages/pip/`, and an install from Nexus. [Python projects](docs/python.md) walks through one.

### Changed

- The request to the administrators asks for three privileges on the pypi repository in place of five: browse, read and edit. A second Nexus user for pip, `nexus.pipUser`, keeps the npm role as it is.
- The image carries Debian's `python3`, which uv needs to resolve pip projects at the target's exact version. The image grows by about 73 MB.
- sealift refuses to start when `projects/` in its data directory is a symbolic link, with `store: <dir> must be a directory, not a link`. Mount the other disk at `projects/` itself instead of linking to it.

### Security

- Installing uv, or installing or updating Trivy, is refused with a 403 when the request comes from another site, carries no JSON body, or sends an `Origin` that differs from its `Host`. Behind a reverse proxy, pass the browser's host header through, as the nginx example under [Reverse proxy](docs/deployment.md#reverse-proxy) does, or these installs fail from the setup screen.
- In the published image, sealift opens the files pnpm, uv and Trivy leave only when they are regular files, and creates its own files there only where none exists. A compromised tool could otherwise have made sealift copy the private signing key into a folder the tool can read, overwrite a file through a link, or hold the job queue and the next start on a FIFO.

## [0.6.2] - 2026-11-19

### Added

- An ephemeral mode for the collection side. With `SEALIFT_EPHEMERAL=1`, a project and the caches it filled are erased from the export screen, or after `SEALIFT_EPHEMERAL_IDLE` minutes without activity (60 by default). Project ids no longer name the project, and `deploy/connected/compose.ephemeral.yaml` keeps projects and caches in RAM. [Deployment](docs/deployment.md#ephemeral-mode) describes it.

## [0.6.1] - 2026-11-19

### Fixed

- On a host whose Docker daemon sets `no-new-privileges` for every container, analyses and the Trivy database install failed with `operation not permitted`. `deploy/connected/compose.yaml` now turns the option off by name, and sealift logs an error at startup when it runs with the flag set.
- A failed request whose answer carried no readable detail, such as one a proxy rewrote, showed only "Request failed". The notice now gives the HTTP status and points to the container's log.
- `summary.md` printed the analysis' own picks as its After row, even when the export selected other versions. It now prints three rows: the whole project before, the project once the selection applies, and the packages in the archive. With the project tree included, the archive also holds the old versions, so its row can match Before.

### Security

- Activating a Trivy version refused nothing but an uninstalled one, so a request could point the active Trivy at another directory. A version must now be a release number.
- The image no longer carries the npm, npx, corepack and yarn that its Node base bundles. sealift never called them, and their dependencies held fixable high-severity CVEs. Each image build now fails on a fixable high or critical CVE.

## [0.6.0] - 2026-11-19

### Added

- A Helm chart for the import service, published beside the image at `oci://ghcr.io/morgankryze/charts/sealift` with each release. It runs one non-root pod, keeps `/data` on a claim that Helm and Argo CD leave in place, takes its credentials from one Secret you create, signs users in through ingress-nginx and admits only the ingress controller's namespace through a NetworkPolicy. It refuses to render while a value is missing or still a placeholder, and names the key. [Helm chart](docs/helm.md) describes it.
- `deploy/connected/compose.yaml` starts the collection role with the hardening of the deployment page, and `deploy/argocd/` holds an Argo CD repository Secret and an Application for the chart, neither with a credential.
- The chart carries `files/published.mjs`, which lists from an import's record every package that any attempt published, apart from the ones that may have landed, for an administrator's rollback in Nexus. [The runbook](docs/runbook.md) gives the commands, the checklist for a first install, and the worst cases on a shared Nexus repository.
- A request to the administrators that lists the MinIO, Nexus and Keycloak rights and the infrastructure the install needs: [Request to the administrators](docs/admin-request.md).
- The settings file's `token` section takes an optional `header`, the header that carries the access token behind a gateway. It defaults to `X-Access-Token`. `Authorization`, `Cookie` and `Host` are refused, and the service reads that one header only.
- sealift generates an Ed25519 signing key on first start and keeps it in its data volume. Settings shows the public key and its public key sha256, copies and downloads the public key, and regenerates the pair behind a confirmation. `GET /api/signing-key` and `POST /api/signing-key/regenerate` serve it; the private key never leaves the volume, and a regenerate from another site is refused.
- The import screens, served by `sealift import-server` behind the gateway: Archives lists the archives in your MinIO folder and starts an import, Imports lists the imports you started, and an import shows its stages, its report per package, how it ended and a retry card that says what each failure needs. [Importing](docs/importing.md) describes them.
- `sealift import-server` serves its own screens: Archives at `/`, Imports at `/imports` and an import at `/imports/<id>`, with the header and the Settings sheet. The files need no token, every other path outside `/api` and `/healthz` answers 404, and every answer carries a Content-Security-Policy and framing headers.
- The import screens show the trusted public key sha256 in Settings and on each import, and the signature's ETag beside the archive's and the manifest's.
- A failed package names its kind (`conflict`, `nexus`, `source`, `interrupted`, `mismatch` or `local`), and the report says whether the archive passed its checks (`archiveChecked`), in the import service and in `sealift import -report`. A report written by 0.4.0 has neither field.
- `SEALIFT_GITHUB_API` sets the GitHub API address the Trivy release lookup uses. Unset keeps `https://api.github.com`. sealift refuses to start on an address that is not `https` (or `http` on localhost) or that carries credentials.
- `SEALIFT_GITHUB_TOKEN` authenticates the Trivy release lookups against the GitHub API, which lifts the anonymous rate limit that answers `403` on a shared address. The token goes to the API address only.

### Changed

- `sealift import` and `sealift import-server` refuse an archive unless its manifest carries a valid Ed25519 signature by the key in `publicKeyFile`. `signatureKeyFile` is gone from the settings, `sealift import` takes `-signature`, and archives from 0.4 are refused as unsigned. The import report names the trusted key as `publicKeySha256`.
- Every export writes `manifest.json.sig`, an Ed25519 signature of `manifest.json`, and the archive no longer carries `signature.key`. The done screen says which key signed the export.
- A refused import no longer blocks a new import of the same archive, so a mistyped sha256 can be corrected by starting again. An import that is queued, running, incomplete or interrupted still does, whatever refused imports of that archive come after it.
- The import service lists an archive as importable only beside its `manifest.json` and `manifest.json.sig`, guards all three objects against a change in MinIO and removes all three after a complete import.
- `GET /api/me` on the import service also names the user's `bucket` and `folder`.

### Removed

- The signature key setting: the Settings section and the setup field are gone, and an export no longer needs a key typed in. A `settings.json` from 0.4 loses its `signatureKey` on the first start.

### Fixed

- An analysis that a restart interrupts now stays listed as interrupted instead of disappearing.

### Security

- pnpm and Trivy receive only an allowlist of the server's environment: `PATH`, `HOME`, `TMPDIR`, `TZ`, `LANG`, the locale, CA and proxy variables, and the `NPM_CONFIG_`, `PNPM_`, `NODE_` and `TRIVY_` prefixes.
- The analysis log no longer shows the user and password of a URL that pnpm prints.
- An analysis refuses a pnpm lockfile whose package names or versions are not safe to use in a path.
- An archive is no longer trusted for carrying a key of its own: the import side checks the manifest against the public key it was given, so a copy of the archive that someone altered on the way is refused.

## [0.4.0] - 2026-11-06

### Added

- The `sealift import` command, in the published image: it checks an archive against its manifest and signature key, then publishes its npm packages to a Nexus repository. It never overwrites a version Nexus holds with other bytes, and exits 1 when any package failed. `-report` writes the result as JSON.
- The `sealift import-server` command, a service that checks each request's token against the realm's signing keys and names the signed-in user at `GET /api/me` and lists the archives in the user's MinIO folder at `GET /api/archives`. It needs a `token` section in the settings file; a `minio` section turns the archive list on.
- `POST /api/imports` on the import service queues an import of an archive in the user's MinIO folder, and `GET /api/imports` and `GET /api/imports/{importId}` follow it. Imports run one at a time. Each package's state is stored as soon as it ends, and stopping the service ends the running import as `interrupted`. An archive that stops downloading partway ends `incomplete`, never `refused`.
- `POST /api/imports/{importId}/retry` adds an attempt to an import. A retry reads every package from Nexus again and uploads only what Nexus no longer serves. When an attempt ends `complete`, the service removes the archive and its manifest from MinIO after checking that both are unchanged; a failed removal keeps the archive and shows the reason, and `archiveRemoved` tells whether it went. An attempt that ends any other way removes nothing.

### Changed

- The import roles, `sealift import` and `sealift import-server`, run from a copy of the binary that holds no capability, built to run under `--cap-drop ALL`, which the operator sets in the compose file or on the `docker run` line. The collection role keeps its own.
- The export refuses a package whose tarball holds data after its end-of-archive marker, which pnpm refuses at install.

## [0.3.0] - 2026-11-05

### Added

- A user guide under `docs/`: getting started, each screen of a session, how sealift chooses a version, the settings, the air gap, deployment, troubleshooting and a FAQ.
- Developer documentation: a contributing guide, and pages on the architecture, the ranking, the API, the archive format and the web app.
- A security policy, a code of conduct, issue and pull request templates, and `llms.txt`.
- CI checks every link and anchor in the Markdown files, and runs the documentation's shell examples against the end-to-end stack.

### Changed

- The minimum release age also holds back every package a version pulls in, not only the direct dependency. A fix released inside the wait stays out of the proposal until the wait ends.
- A `package.json` with an invalid package name is refused on the drop screen.
- Deleting a project through the API while one of its jobs is queued or running answers 409 instead of failing partway with a 500.

### Fixed

- The review shows the analysis warnings: a dependency the analysis could not check no longer reads as clean.
- The review warns when the proposals together leave a peer dependency unmet, which pnpm only reports as a warning.
- The review says when your selection departs from the proposal the analysis checked as a whole.
- The export checks a cached tarball against its sha512 before shipping it, and downloads it again when it no longer matches.
- A package with several integrity hashes is checked against the strongest one, whatever their order.
- A failed resolve shows pnpm's own reason on screen instead of `pnpm install: exit status 1`.
- The logo link and the settings panel's close button reach a 32 px target, as do the Technical detail and Show the log disclosures.
- The text on an error screen meets the WCAG AA contrast ratio in the light theme.
- The "Archive ready" badge and the major-version chip meet the WCAG AA contrast ratio in the light theme, and the review counts a single CVE as one CVE.

## [0.2.2] - 2026-09-23

### Changed

- The settings panel offers the target as one platform choice (Linux x64 or arm64, glibc or musl), checks the Node version as you type, and shows pnpm as read-only.
- The signature key shows as saved, with Replace and a confirmed Clear.
- Each limit shows its unit, its range and what it changes; Save and Discard appear only when something changed, and errors show under their field.

### Fixed

- The API refuses a minimum release age outside 1 to 90 days, a resolve parallelism outside 1 to 16 and a download parallelism outside 1 to 32.

## [0.2.1] - 2026-09-22

### Added

- `GET /api/projects/{id}/manifest` returns the package.json a session was started from, and the Drop step shows it even when the analysis failed.

### Changed

- Settings open in a side panel over the current screen, and hold the light, dark or system theme.
- The drop zone on the home screen spans the page, with a Choose a file button and the pinning rules inside it.
- Setup shows each tool's version and download size, each download running, then each tool ready, and waits for Continue.
- The drop preview lists every problem the server would refuse, such as a range, an alias or an overrides field, and keeps Analyse disabled until the file is fixed.
- Resuming a session that produced an archive opens its export.
- The whole interface loads as one bundle, so a click never needs the server to fetch a screen.

### Fixed

- Retrying a cancelled or failed export packed an empty archive that claimed every CVE fixed. The retry now sends the same selection as the review, and the API refuses an export with nothing to pack.
- A request that cannot reach sealift says so, instead of doing nothing.
- A session analysed by v0.1.0 opens again. Its review crashed, because the API answered null where it promises a list of CVE ids.
- An analysis that v0.1.0 stopped says at which step, and points at its log, instead of showing an empty cause.
- A cancelled analysis or export reads as stopped by the user, not as a failure.
- The step bar keeps a failed or running step as such on every screen, and marks Review done only once an export exists.
- A screen that fails explains what happened and offers to try again, instead of "Something went wrong!". An unknown session says so at once.
- Update Trivy and Update database show that they are running, then report the version installed, the new database date, or that nothing needed updating. An unreachable GitHub is named as such.
- Settings refuse a Node or pnpm version that is not exact, and name the field.
- A manifest with no dependency is refused before it runs.
- A pick with more CVEs reads "Adds 5 CVEs" instead of "Fixes -5 CVEs".
- Export steps read in words, with a running state and a percentage.
- Focus returns to what opened the settings panel or the duplicate dialog, and candidate versions form a radio group.

## [0.2.0] - 2026-09-22

### Added

- A setup screen on first run. It lists Trivy, its vulnerability database and the signature key, with their download sizes, and installs nothing until you press Install. When the latest Trivy release is younger than the minimum release age, it offers the newest release past that age, or the latest if you choose to install it anyway.
- A step bar for each session: drop, analyse, review, export. You can open any finished step again.
- Duplicate detection: dropping a package.json that an earlier session already used offers to resume that session or start a new one.
- The cause of a failed step, on screen and after a reload, with the next actions and the full log.
- The CVE ids behind each count: on screen for the current version of a dependency, and in the API for each candidate as well.
- The time left while candidate versions resolve.
- The release age of each proposed version, and a note on why sealift prefers the oldest version that fixes the most CVEs.

### Changed

- The interface guides you through one session at a time. The review opens on sealift's proposal in three groups: to decide, proposed, and nothing to do. Each dependency shows its key candidates, with the full list one click away.
- The export screen shows its progress while it runs, with a cancel button, and ends on the archive with its sha256, one download for the archive, and the reports grouped below it.
- The API refuses to create a project or queue an analysis while Trivy, its database or the signature key is missing, and names what is missing.
- Past sessions list newest first.
- sealift waits 14 days before proposing or installing a new release, up from 7. An install that already saved its settings keeps its own value.

### Fixed

- A failed or cancelled export stays listed with its cause. It used to disappear within seconds.
- A settings update with a missing field answers 400 instead of 500.
- The release image reports its own version in `summary.md`. It said `dev`.
- A finished analysis or export now updates its screen at once. It could wait up to two seconds for the next refresh, because the final event sometimes arrived without the job's id.

## [0.1.0] - 2026-09-21

### Added

- Analysis of an npm project: resolve its lockfile, scan it with Trivy, and list the CVEs it carries.
- Ranking of the newer versions of each dependency, with the signals behind each rank (a fix for a CVE, a deprecation, a lost provenance, a major jump, among others) and the best candidate highlighted.
- Export that resolves the project against the chosen versions, downloads the packages, and packs them into a reproducible archive, carrying the signature key, alongside a CVE report and a version report.
- Web interface to create a project, queue an analysis, choose versions, queue an export, and download the result.
- Docker image with the web interface built in and Trivy and pnpm installed, ready to run on the connected side and produce archives an air-gapped registry can import.

[Unreleased]: https://github.com/MorganKryze/sealift/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/MorganKryze/sealift/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/MorganKryze/sealift/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/MorganKryze/sealift/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/MorganKryze/sealift/compare/v0.4.0...v0.6.0
[0.4.0]: https://github.com/MorganKryze/sealift/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/MorganKryze/sealift/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/MorganKryze/sealift/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/MorganKryze/sealift/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/MorganKryze/sealift/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MorganKryze/sealift/releases/tag/v0.1.0
