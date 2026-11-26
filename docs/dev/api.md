# API

This page lists every route of the HTTP API, what it is for, and how it fails, then describes the event stream. [`api/openapi.yaml`](../../api/openapi.yaml) is the contract; the Go server interface and the TypeScript types are generated from it with `just generate`.

Every route lives under `/api`, except `/healthz` and `/livez`. Request and response bodies are JSON unless stated.

## Errors

A failure answers with a problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)):

```json
{"detail":"not found","status":404,"title":"get project","type":"about:blank"}
```

`title` names the operation, `detail` the cause. A validation failure adds `errors`, one entry per problem with `field`, `reason`, and `name` and `value` when they apply. For a requirements file, `field` is the file name, `line` the line number and `value` the line; `line` is absent for a problem with the whole file. `type` is `about:blank`, except `tools-missing`, which adds `missing`.

| Status | When |
| --- | --- |
| 400 | An invalid body: a manifest or a requirements file sealift refuses, a selection it did not resolve, an empty export, an export whose reasons fall short, a target or limit out of range |
| 404 | An unknown project, analysis or export; a path under `/api` that no route serves (`/api` redirects to `/api/`, which answers 404) |
| 405 | A method the route does not serve; the `Allow` header lists the methods it serves |
| 409 | A tool the job needs is still being prepared or missing (`tools-missing`); the analysis is not done; the project has a job queued or running |
| 410 | A route a past release served; [Removed routes](#removed-routes) names what replaces it |
| 500 | Anything else; the server log has the cause |

## Health

`GET /healthz` is the readiness check. It answers 503 until every item the start prepares is ready, with the names of the others, and 200 after:

```json
{"status":"preparing","missing":["trivy-db","uv"]}
```

The body names the items only; their causes are in [`GET /api/instance`](#instance). `GET /livez` is the liveness check: 200 with `{"status":"ok"}` while the server runs, whatever the preparation's state. [Deployment](../deployment.md#readiness) says which probe uses which.

<!-- run -->
<!-- expect: {"status":"ok"} -->
```sh
curl -s http://localhost:8080/healthz
```

## Projects

A project is a session: one `package.json` and its history, or the requirements files of a pip project and theirs. `ecosystem` says which, `npm` or `pip`. An npm project carries `target`, a pip project `pipTarget`.

| Route | Purpose |
| --- | --- |
| `GET /api/projects` | List projects, each with its last analysis and export. `?manifestSha256=` keeps those created from that exact file, which is how the interface finds a duplicate. |
| `POST /api/projects` | Create a project from a `multipart/form-data` upload, field `manifest`, optional `name`, and queue its analysis. 201 with the project. 400 when the manifest is refused, 409 when the tools are not ready. With the field `ecosystem` set to `pip`, it creates a [pip project](#pip-projects). |
| `GET /api/projects/{projectId}` | The project, its target, its analyses and its exports. |
| `DELETE /api/projects/{projectId}` | Delete the project directory and everything in it. 204, or 409 while one of its jobs is queued or running. |
| `PUT /api/projects/{projectId}/target` | Change an npm project's target platform and toolchain. 400 for a pip project, whose target is set at creation. |
| `GET /api/projects/{projectId}/manifest` | The `package.json` the project was created from, byte for byte. |

<!-- run -->
<!-- expect: "id" -->
```sh
curl -s http://localhost:8080/api/projects
```

### pip projects

A pip project holds one or more requirements files, resolved together for one target. `POST /api/projects` creates one from these parts:

| Part | Content |
| --- | --- |
| `ecosystem` | `pip`. An absent field means `npm`, and any other value is refused. |
| `name` | Required. |
| `requirements` | One part per file, 1 to 32 files. The part's filename is the file name: a letter or digit, then letters, digits, `.`, `_` or `-`, 128 characters at most, with no two dots in a row and unique ignoring case. |
| `pipTarget` | Optional. The target as JSON, at most 4 KiB, unknown fields refused. Absent, the default applies: `{"python":"3.11.2","os":"linux","cpu":"x86_64","glibc":"2.28","uvVer":"0.13.7"}`. |

A target names Python as `3.<minor>.<patch>`, `os` `linux`, `cpu` `x86_64`, `glibc` from `2.17` to `2.40`, and the uv release that resolves it. A request holds at most 40 parts. A requirements file above 1 MiB is refused, never cut.

sealift reads every file before it stores anything. Each file pins exact versions with `==` and may include another file of the project with `-r` or `-c`. A pin may carry `--hash=sha256:` options. Any other option, a range, a URL or a local path is refused. A refusal answers 400 with one `errors` entry per refused line, the first 100 of them, and creates nothing. The same package pinned at two versions in two files is refused too, and the refusal names both files.

The project is created with its first analysis queued, as for npm.

## Analyses

| Route | Purpose |
| --- | --- |
| `POST /api/projects/{projectId}/analyses` | Queue a new analysis of the project. 202 with the queued analysis. 409 when the tools are not ready. |
| `GET /api/projects/{projectId}/analyses/{analysisId}` | The analysis: state, steps, failure, and once done its result, with each dependency, its vector, its candidates and `best`. |
| `DELETE /api/projects/{projectId}/analyses/{analysisId}` | Delete the analysis. |
| `GET /api/projects/{projectId}/analyses/{analysisId}/log` | The full log, as `text/plain`. |
| `POST /api/projects/{projectId}/analyses/{analysisId}/cancel` | Cancel the analysis, running or queued. |

A done npm analysis carries `result`. Beside each dependency's `current`, `vector`, `cves`, `candidates` and `best`, it holds what the review and the reasons need:

| Field | Content |
| --- | --- |
| `candidates[].leavesLine` | Whether the candidate leaves the line of the current version, the range npm's caret gives it. The server sets it when it reads the analysis, so every analysis has it. |
| `best` | The proposal, inside the line unless the policy sets `review.proposeOtherMajors`. Absent when no candidate improves on the current version. |
| `jump` | The first unblocked candidate outside the line, in the order a proposal is taken. Absent when there is none. |
| `family` | The name of the family the dependency's jump belongs to, such as `react 19`. Absent when the jump moves alone. |
| `cves[].package` | The package and version Trivy found the CVE in, as `name@version`. |
| `cves[].fixedIn` | The versions Trivy names as fixing it, as Trivy prints them, such as `4.19.2, 5.0.0`. Empty when none is known. |
| `families` | On `result`: each group of dependencies whose jumps must move together, with `name` and `members`, sorted by name. |
| `advisories` | On `result`: what each CVE id of a `cves` list does, by id. `title` is Trivy's title, at most 200 characters. `summary` is the first paragraph of Trivy's description, at most 500 characters, cut after its last whole sentence. `published` is the publication date, in RFC 3339, UTC. A field is absent when the report does not give it. |

The text of `advisories` comes from the Trivy report. sealift cleans it of control characters, URL credentials and data-directory paths, and stores it as plain text. A client shows it as text, never as HTML or Markdown.

An analysis written by sealift 0.7.0 has no `jump`, `family`, `families` or `advisories`, and its CVEs have no `package` or `fixedIn`: an export counts each of them as a CVE without fix. [How sealift chooses](../how-sealift-chooses.md#the-current-line) explains the line, the jump and families.

The states are `queued`, `running`, `done`, `failed`, `cancelled` and `interrupted`. A failed analysis carries `failure` with the step id and the message:

```json
{"message":"resolve project: pnpm install: ERR_PNPM_NO_MATCHING_VERSION No matching version found for left-pad@99.0.0: exit status 1","step":"resolve-project"}
```

An analysis that fails before its first step, for example when sealift cannot open its log, names the step `prepare`.

### pip analyses

A pip analysis runs these steps:

| Step | What it does |
| --- | --- |
| `validate` | Reads the project's files again and copies them into the analysis. |
| `prepare-tools` | Installs the target's uv from the package index, held to the minimum release age, and refreshes the Trivy database. |
| `check-pins` | Reads the index page of every requirement the target installs, and records each one with no wheel the target can install, or none its `--hash` options list, in `blocking`. `resolve` gives uv its line as a constraint, which keeps its version without requiring it, and it joins the set at that version, without a wheel. |
| `resolve` | Resolves every file together with uv, at the target's exact Python version and platform, with `--no-build`, and writes `project/requirements.lock`. The files' pins keep their versions; every other package is held to the minimum release age. |
| `choose-wheels` | Records, for every package of the set, the wheel the target's installer prefers, with the index's sha256 and upload time. A package with none stays in the set without a wheel and joins `blocking`. It reads index pages only and downloads no file. For a package no file pins, it chooses among the files uploaded before the minimum release age, as uv does. A wheel added later to an older release, or a file with no upload date, is never recorded. |
| `scan` | Scans the set and each version the previous crossing held for known CVEs, in one Trivy run. |

A done pip analysis carries `pipResult` in place of `result`, and `uvVersion` in place of `pnpmVersion`:

| Field | Content |
| --- | --- |
| `target` | The target the set was resolved for. |
| `files` | The requirements files the set comes from. |
| `packages` | Every package of the set, sorted by name: `name`, `version`, `files` (the files that pin it, empty for a package no file pins), `pinnedAt` (each `file` and `line` that pins it), `wheel` (`file`, `url`, `sha256`, `size`, and `uploadedAt` in UTC when the index gives one), `cves` (`id`, `severity`, `fixedVersions`, `title`), `yanked` (`reason`, empty when the index gives none) for a release the index has yanked, and `previous` (`version`, `cves` and `majorJump`) for a package the previous crossing held. `cves[].title` stays beside `advisories`. |
| `advisories` | The same table as an npm analysis's `advisories`, by CVE id, for every id a package's `cves` names. An analysis written by sealift 0.7.0 has none. |
| `blocking` | Each package with no wheel the target can install: `name`, `version`, `kind`, `detail` and `pinnedAt`. `kind` is `source-only`, `other-platforms`, `no-files` or `hash-mismatch`. For a package no file pins, the kind counts only the files uploaded before the minimum release age, and `detail` says so. |
| `previous` | The previous crossing: `projectId`, `projectName`, `exportId`, `analysisId` and `sealedAt`. It is the latest done export, created before the analysis started, of a pip project with the same name, trimmed and compared without case, this project included. |
| `removed` | Each package of the previous crossing that the set no longer holds: `name`, `version` and `cves`. |
| `warnings` | A pin uploaded within the minimum release age, a database that could not be refreshed, findings Trivy reported for packages outside the set, and a previous crossing that could not be read. |

A done pip analysis may carry a non-empty `blocking`: each package in it stays in `packages` without a `wheel`, and the export refuses the set. An analysis fails on a package with no wheel only when uv itself names it, at `resolve`, since uv then gives no set. A blocked pin that another package needs is one when no wheel of its version installs on the target: uv keeps that version and stops on it. A pip analysis that fails after finding a package with no wheel still carries `pipResult`: `blocking` lists every such package, and `packages` is empty. With no previous crossing, `previous` and `removed` are absent. An analysis written by sealift 0.7.0 has no `pinnedAt`, `yanked`, `uploadedAt`, `previous` or `removed`, and names a yanked release in `warnings`.

uv stops at the first package with no usable wheel, so such a package that no file pins shows alone. A second one behind it shows at the next analysis.

A done pip analysis is exported as a whole: see [pip exports](#pip-exports).

## Exports

| Route | Purpose |
| --- | --- |
| `POST /api/projects/{projectId}/analyses/{analysisId}/exports` | Queue an export. The body maps each dependency to the versions to include: `{"selection":{"express":["4.20.0"]}}`. `includeProject: true` also packs the current project's own packages; the interface leaves it false. `reasons` carries the reasons the selection needs, below. 400 for a version the analysis did not resolve, an export that packs nothing, or reasons that fall short; 409 when the analysis is not done, when `includeProject` is true and the analysis has no readable scan of the project's lockfile (`project.trivy.json`) or its lockfile is too large to walk, or when a tool the export needs is not ready (`tools-missing`). |
| `GET /api/projects/{projectId}/exports/{exportId}` | The export: state, steps, failure, and once done its files. |
| `DELETE /api/projects/{projectId}/exports/{exportId}` | Delete the export and its files. |
| `POST /api/projects/{projectId}/exports/{exportId}/cancel` | Cancel the export, running or queued. |
| `GET /api/projects/{projectId}/exports/{exportId}/files/{name}` | Download one file of a finished export: the archive, `manifest.json`, `manifest.json.sig` or a report. |

A dependency left out of the selection, or given an empty list, stays at its current version.

### Reasons

An npm export that takes a version outside its dependency's line, or whose archive holds a version with a CVE that no version fixes, sends a reason for each in `reasons`:

```json
{
  "selection": {"express": ["5.1.0"], "html-minifier": []},
  "reasons": [
    {"kind": "major-jump", "dependencies": ["express"], "text": "Our routes moved to express 5 in the last release."},
    {"kind": "cve-without-fix", "dependencies": ["html-minifier"], "text": "It minifies our own templates only, at build time."}
  ]
}
```

| Field | Content |
| --- | --- |
| `kind` | `major-jump` for a jump out of the line, `cve-without-fix` for CVEs that no version fixes |
| `dependencies` | The dependencies the reason covers, by name, at least one. A family needs one `major-jump` reason naming its members. A `cve-without-fix` reason covers every such CVE of the dependencies it names. |
| `text` | 1 to 300 characters once trimmed, on one line, with no control, line-separating, bidirectional or other format character; at most 1,200 characters before trimming. The manifest signs the trimmed text. |

The versions the archive holds count for CVEs: each selected version, and the current one when `includeProject` is true. A dependency the selection leaves out keeps its current version on the air-gapped side, so its CVEs without fix need a reason too, and the policy never refuses them. A CVE with no `fixedIn` counts as one without fix.

The server checks the reasons after the selection, whatever the client sends. A shortfall answers 400 with the title `invalid export reasons` and one problem per shortfall in `detail`, joined by `; `. A problem names dependencies, versions and CVE ids, and a reason by its position and kind, never by its text:

| Problem | When |
| --- | --- |
| `express 4.17.1 to 5.1.0 leaves major 4 and needs a reason` | A selected version leaves its line and no `major-jump` reason names its dependency. Below 1.0.0 it reads `leaves line 0.18`. |
| `html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and needs a reason` | A held version keeps a CVE without fix and no `cve-without-fix` reason names its dependency |
| `review.majorJump is refuse: react 18.3.1 to 19.2.0 cannot cross` | The policy refuses jumps, whatever the reasons |
| `review.cveWithoutFix is refuse: html-minifier 4.0.0 keeps CVE-2022-37620, which no version fixes, and cannot cross` | The policy refuses CVEs without fix in a version the archive holds |
| `reason 2 (major-jump) covers nothing the selection takes` | The reason names no dependency that needs one of its kind, or only ones an earlier reason covers |
| `reason 1 (cve-without-fix): the reason is empty` | The text breaks the reason rule; the problem names the rule, such as `is longer than 300 characters` |
| `reason 3 (major-jump) names a dependency the analysis does not hold` | A name the analysis does not list |
| `reason 2 (major-jump) names no dependency` | The reason's `dependencies` is empty |
| `reason 1 has an unknown kind` | `kind` is neither `major-jump` nor `cve-without-fix` |

<!-- illustrative -->
```json
{"detail":"express 4.17.1 to 5.1.0 leaves major 4 and needs a reason; reason 2 (major-jump) covers nothing the selection takes","status":400,"title":"invalid export reasons","type":"about:blank"}
```

A done export signs the reasons into the `review` of `manifest.json`. [Archive format](archive-format.md#the-review) describes it.

### pip exports

A pip export carries every package of the analysis, each with the wheel the analysis recorded. Its body is `{"selection":{}}`; a selection that names a package answers 400, since the set is the analysis's. 409 when the analysis is not done, lists no package, or holds a package with no recorded wheel. A refused request creates no export.

| Step | What it does |
| --- | --- |
| `package-list` | Checks the recorded set: every name, version, wheel file name, sha256 and size, within the bounds the import reads. |
| `download` | Downloads each wheel from the address the analysis recorded and checks it against the index's sha256. A wheel whose bytes differ fails the export at once, with no retry; a failed connection or a server error is tried up to three times. A wheel already in the cache is checked again and reused. |
| `archive` | Packs the wheels into `packages_pip.tar.gz`, hashing each again as it enters, then writes and signs `manifest.json`. The export never opens a wheel. |
| `reports` | Scans the exported set with Trivy and writes the four reports. |

A done pip export holds `packages_pip.tar.gz`, `manifest.json` (format version 3), `manifest.json.sig`, `report.trivy.json`, `report.cdx.json`, `findings.csv` and `summary.md`. [Archive format](archive-format.md#manifestjson-of-a-pip-export) describes the manifest. The same analysis exported twice gives the same archive sha256.

Downloaded wheels stay in the shared cache `cache/wheels/`, named by their sha256, so a second export of the same set downloads nothing. In ephemeral mode, erasing a project empties `cache/wheels/` with the other shared caches.

## Settings

| Route | Purpose |
| --- | --- |
| `GET /api/settings` | The npm target and the three limits in effect: the policy file's, else the values 0.7.0 saved, else the defaults. Read-only. |

[Settings](../settings.md#from-the-api) shows a real answer, and how each value is set.

## Instance

| Route | Purpose |
| --- | --- |
| `GET /api/instance` | How the instance was deployed and what it has prepared: `ready`, `preparing`, `warning`, `policy`, `brand`, `tools`, `ephemeral` and `idleMinutes`. |
| `GET /api/instance/logo` | The logo the policy file names, as read at start, with its type. 404 when the policy names none. |

`preparing` lists the five items in order: `trivy`, `trivy-db`, `signing-key`, `pnpm` and `uv`. Each has a `state`, `preparing`, `ready` or `failed`, and a `version`: the pinned Trivy, the database's date, the public key's sha256, or the pnpm or uv version. A failed item adds `reason`, cut at 300 characters, and `nextTry`. `ready` is true once all five are ready. `warning` holds a database refresh that failed while an older database stays in use. `policy` holds both targets and the three limits, and `brand` the name, the side labels, the review word, `logo` (whether the logo route serves one), and `accent` and `contact` when the policy sets them. `tools` gives the Trivy version, the database's date and the pnpm and uv versions on the volume.

<!-- run -->
<!-- expect: "ready":true -->
```sh
curl -s http://localhost:8080/api/instance
```

```json
{"brand":{"logo":false,"name":"sealift","offline":"Offline","online":"Online","reviewWord":"PR"},"ephemeral":false,"policy":{"downloadParallelism":16,"minReleaseAgeDays":14,"pipTarget":{"cpu":"x86_64","glibc":"2.28","os":"linux","python":"3.11.2","uvVer":"0.13.7"},"resolveParallelism":4,"target":{"cpu":"x64","libc":"glibc","node":"22.17.1","os":"linux","pnpmVer":"10.34.5"}},"preparing":[{"name":"trivy","state":"ready","version":"0.76.2"},{"name":"trivy-db","state":"ready","version":"2026-11-24T07:08:30Z"},{"name":"signing-key","state":"ready","version":"<64 lowercase hex digits>"},{"name":"pnpm","state":"ready","version":"10.34.5"},{"name":"uv","state":"ready","version":"0.13.7"}],"ready":true,"tools":{"pnpm":["10.34.5"],"trivy":"0.76.2","trivyDbDate":"2026-11-24T07:08:30.89Z","uv":["0.13.7"]}}
```

The logo route answers with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox` and `X-Content-Type-Options: nosniff`, so a script in an SVG logo does not run when its address is opened directly.

### Removed routes

The routes that listed or installed tools, saved settings and regenerated the signing key are gone. The deployment now prepares the tools, sets the policy and regenerates the key, so no request can. Each answers 410 Gone with Problem Details whose `detail` names what replaces it. Paths are under `/api`:

| Removed | Use instead |
| --- | --- |
| `GET /tools` | `GET /instance`: `tools`, `preparing` and `ready` |
| `POST /tools/trivy/update` | the pinned Trivy, installed at start |
| `POST /tools/trivy/activate` | nothing: sealift runs the pinned Trivy only |
| `POST /tools/trivy/db/update` | the refresh at start and before each analysis |
| `POST /tools/uv/install` | the default pip target's uv, installed at start; another uv installs during the analysis that needs it |
| `PUT /settings` | the policy file, read at start |
| `POST /signing-key/regenerate` | `sealift signing-key regenerate`, run in the container or pod; `GET /signing-key` reports the key |

## Signing key

sealift generates an Ed25519 key pair on first start and keeps the private key in the data volume, in `private/signing-key.pem` (mode 0600, in a 0700 directory). The API returns the public half only: no route, answer, log line or error carries the private key.

| Route | Purpose |
| --- | --- |
| `GET /api/signing-key` | The public key and its fingerprint: `{"publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...", "publicKeySha256": "<64 lowercase hex digits>"}`. `publicKeySha256` is the sha256 of the key's DER SubjectPublicKeyInfo encoding. |

No route changes the key. `sealift signing-key regenerate`, run in the container or pod, replaces it, and the server reads the file again when it changes. [Deployment](../deployment.md#regenerate-the-key) describes the command. The server stops at start, naming the file, when `signing-key.pem` exists and cannot be read, is not a regular file, is not a PEM private key or is not Ed25519: it never replaces a key file by itself. A key damaged while the server runs turns `GET /healthz` to 503 with `signing-key` among the items not ready, and every export fails before its first download with a failed `prepare` step that carries the cause, so the screen shows it.

## Package index

A pip analysis whose target names a uv the start did not prepare installs it at `prepare-tools`, under the minimum release age. uv and the pip analyses read one package index, `https://pypi.org/simple/`. `SEALIFT_PIP_INDEX` replaces it, for tests and development only. The value must be an `https` URL, or `http` on `localhost`, `127.0.0.1` or `::1`, with no credentials, query or fragment. sealift refuses to start on any other value and names the variable.

## The event stream

`GET /api/jobs/current/events` is a `text/event-stream` of the running job. It first replays every `step` event of the job and its most recent other events, up to 128, then streams the live ones, and ends after the `end` event. With no job running, the connection stays open and nothing arrives until one starts.

Each message names its kind in `event:` and repeats it in the JSON:

```
event: step
data: {"kind":"step","job":"analysis-2","storeId":"20260923T122834Z","data":{"name":"resolve-project","state":"done","durationMs":240}}

event: progress
data: {"kind":"progress","job":"analysis-2","storeId":"20260923T122834Z","data":{"step":"resolve-candidates","done":1,"total":5,"estimatedRemainingMs":1236}}

event: candidate
data: {"kind":"candidate","job":"analysis-2","storeId":"20260923T122834Z","data":{"dependency":"lodash","version":"4.17.21","vector":[0,1,2,0,0],"signals":[]}}

event: end
data: {"kind":"end","job":"analysis-2","storeId":"20260923T122834Z","data":{"state":"done"}}
```

| Kind | Data |
| --- | --- |
| `step` | A step's id, its state and, once over, its duration |
| `progress` | Progress inside a step: `done` of `total`, and an estimate of the time left when there is one |
| `candidate` | A ranked candidate: dependency, version, vector, signal names |
| `log` | A line for the log |
| `end` | The job's final state |

`storeId` is the analysis or export id used in the routes above; match on it. `job` is the queue's own id, which does not survive a restart. [Architecture](architecture.md#requests-and-jobs) explains why both exist.

## The import service

`sealift import-server` serves a second contract, [`api/import.yaml`](../../api/import.yaml), with its own generated package, `internal/importer/service`. It shares no route, handler or type with the API above: the collection server mounts none of it, and the import service mounts none of the collection's. Both contracts are generated by `just generate`.

The service answers `GET /healthz` without a token. Every route of the contract lives under `/api` and needs the access token in the header the settings name in `token.header`, `X-Access-Token` by default. No other header is read, `Authorization` included. Any other path answers 404.

| Route | Purpose |
| --- | --- |
| `GET /api/me` | The user the checked token stands for, whether the settings file has a `minio` section, the user's `bucket` and `folder`, and `publicKeySha256`, the sha256 of the public key every signature must verify with: `{"user":"alice","minioConfigured":true,"bucket":"user-alice","folder":"packages/npm/","publicKeySha256":"9f2c…"}`. The bucket and the folder are named whether or not the settings file has a `minio` section. |
| `GET /api/archives` | The archives in the user's MinIO folders, `packages/npm/` and `packages/pip/`. |
| `POST /api/imports` | Queue an import of one of those archives. |
| `GET /api/imports` | The user's imports, newest first. |
| `GET /api/imports/{importId}` | One import with its attempts. |
| `POST /api/imports/{importId}/retry` | Add an attempt to an import. |

The service checks each token against the keys of the realm named in the settings file before it acts for anyone. The user is the token's `preferred_username` claim and nothing else: a header such as `X-Auth-Request-Preferred-Username` is ignored. Failures use the problem body described under [Errors](#errors).

| Status | When |
| --- | --- |
| 401 | The token is absent or fails a check. `detail` names the check: `absent`, `malformed`, `algorithm`, `key`, `signature`, `issuer`, `audience`, `expiry` or `not before`. It never repeats the token. |
| 403 | The claim is absent, is not a string, or cannot name a folder: lower case letters, digits, dots and hyphens, 1 to 58 characters, no `..`. A `POST` that looks cross-site also answers 403 (see [Starting an import](#starting-an-import)). |
| 413 | A request body over 64 KiB. |
| 503 | The realm's keys cannot be had, or the service is stopping and takes no new work. |
| 500 | Anything else; the server log has the cause. |

Request headers get 10 seconds to arrive and are capped at 64 KiB.

### Listing archives

`GET /api/archives` lists the objects under `packages/npm/`, then under `packages/pip/`, in the bucket `user-<name>`, where `<name>` is the checked user. The request carries no bucket, prefix or user: a query parameter or header that names one is ignored. One MinIO call per folder reads at most 1,000 keys. The list reads no signature and no archive.

The answer holds `minioConfigured`, `bucket`, `folder`, `folders`, `bucketMissing`, `truncated`, `unencrypted` and `archives`. `folders` is `["packages/npm/","packages/pip/"]`. `folder` stays `packages/npm/` for clients written for sealift 0.6. Each archive has `key`, `ecosystem` (`npm` or `pip`, its folder's), `size`, `modified`, `importable` and, when it cannot be imported, a `reason`. An archive the user has already imported also has `latestImport`, the `id` and `outcome` of the newest import of that key made from the archive, manifest and signature now in MinIO. An import counts only when the ETags of all three match, so an upload that replaces the archive, its manifest or its signature under the same name shows no `latestImport` until it is imported.

An archive pairs with the `manifest.json` and the `manifest.json.sig` in its own folder, at the root of `packages/npm/` or `packages/pip/`, or one folder below it. Objects deeper than that are ignored, as is every file that is neither an archive, a `manifest.json` nor a `manifest.json.sig`. A folder pairs only its own objects: a signature under `packages/npm/` never completes a folder under `packages/pip/`.

For each archive that passes the rules below, the list reads its `manifest.json` with the listed ETag, within 16 MiB, and looks at `formatVersion` and `ecosystem` alone. A manifest of the other ecosystem marks the archive as not importable. The mark is a hint: a manifest that cannot be read or parsed leaves the archive importable, and the import checks the ecosystem again after the signature. The service keeps each manifest's ecosystem by its bucket, key and ETag, up to 4,096 manifests, and reads at most 50 manifests it has not read before in one list. Past 50, the remaining archives are marked at the next list.

| Reason | When |
| --- | --- |
| `its name cannot be imported` | The key is not under `packages/npm/` or `packages/pip/`, does not end in `.tar.gz`, has an empty, `.` or `..` segment (also once percent-decoded, and then under the same folder), holds a control character, is not UTF-8 or is over 1,024 bytes. |
| `the folder holds more than one archive` | Its folder holds two or more archives. Each one is listed with this reason. |
| `no manifest.json in its folder` | Its folder holds no `manifest.json`. |
| `no manifest.json.sig in its folder` | Its folder holds a `manifest.json` and no `manifest.json.sig`. |
| `its manifest is a pip archive's: keep the three files under packages/pip/` | The archive sits under `packages/npm/` and its manifest describes a pip archive. |
| `its manifest is an npm archive's: keep the three files under packages/npm/` | The archive sits under `packages/pip/` and its manifest describes an npm archive. |

| Case | Answer |
| --- | --- |
| No `minio` section in the settings file | 200, `minioConfigured` false, no archive. The service calls no MinIO. |
| MinIO has no bucket for the user | 200, `bucketMissing` true, no archive, and a `message` that names the bucket. |
| More than 1,000 objects under a folder | 200, `truncated` true, with the archives found in the first 1,000 of that folder. |
| MinIO refuses the list of one folder | 200 with the other folder's archives, and a `message` that names the folder and MinIO's reason: `MinIO could not list packages/pip/: ...`, control characters removed, cut to 300 characters. A MinIO policy that does not cover `packages/pip/` yet gives this answer. |
| MinIO is unreachable or refuses the list of both folders | 502. `detail` holds MinIO's reason with control characters removed, cut to 300 characters. |

`unencrypted` names each link that runs over plain `http`: `keySet`, `minio`, `nexus`.

### Starting an import

`POST /api/imports` takes `{"archive": "<key>", "expectedSha256": "<hex>"}`. `expectedSha256` is optional: 64 hex digits received through another channel, and a different archive is refused. A malformed value answers 400 and creates nothing.

The key must pass the same rule as the list. Any key that fails it, lies outside `packages/npm/` and `packages/pip/` or names an object that is not there answers 404, and a key that fails the rule causes no MinIO request. A key that names an archive the list marks as not importable answers 409 with the list's reason, except for the manifest's ecosystem: the start reads no manifest. The attempt checks the ecosystem after the signature and ends `refused` with `the manifest describes a pip archive, and this folder takes npm archives: move the three files to packages/pip/`, or `the manifest describes an npm archive, and this folder takes pip archives: move the three files to packages/npm/`. For a valid key the service lists the archive's folder, reads the description of the archive, its manifest and its signature, and records the key, the ETag and the size of each. The answer is 202 with the import as `GET /api/imports/{importId}` gives it.

The service reads every earlier import of the same objects, not only the newest, and answers 409 for the first one it finds that is queued, running, `incomplete` or `interrupted`. A `complete` import and a `refused` one do not block a new start. A refused latest attempt published nothing and removed nothing, so starting again, with a corrected `expectedSha256` or none, is the way out of a mistyped digest. An earlier attempt of the same import may have published packages: the new import finds them present. The refused import keeps its attempts and its outcome, and the list then holds both.

A `POST` is refused with 403, and nothing changes, when its `Origin` is not the request's own host (port included), when `Origin` is `null`, when `Sec-Fetch-Site` is `cross-site`, or when `Content-Type` is not `application/json`. A client that sends no `Origin` and sends JSON passes, as `curl` does. Behind a gateway, the gateway must pass the original host for an `Origin` from a browser to match.

| Status | When |
| --- | --- |
| 202 | The import is recorded and queued. |
| 400 | The body cannot be read, or `expectedSha256` is not 64 hex digits. |
| 404 | The key is not an archive in the user's folder. |
| 409 | The archive, its manifest and its signature, with the same ETag each, already have an import that is queued, running, `incomplete` or `interrupted`: `importId` names it. Also when the settings file has no `minio` section. |
| 502 | MinIO failed to list or describe the archive. |

### Following an import

Imports run one at a time across all users, the first started first. The queue owns an attempt's start and its end. The run writes only the state of each package, as soon as that package ends, so a reader of `GET /api/imports/{importId}` sees the packages move from `pending` to `published`, `present` or `failed` while the attempt is `running`. Another user's id, a missing id and a malformed id all answer 404 with the same body.

An import gives `id`, `createdAt`, the `archive`, `manifest` and `signature` objects (`key`, `etag`, `size`; `signature` is absent from an import recorded by sealift 0.4), `expectedSha256`, `outcome`, `archiveRemoved` and its `attempts`. `outcome` is the latest attempt's: `queued`, `running`, `complete`, `incomplete`, `refused` or `interrupted`. Each attempt has its `status` (`queued`, `running` or `ended`), its times, its `outcome` and the same `report` that `sealift import -report` writes. `archiveRemoved` is true once an attempt has removed the archive from MinIO (see [Removing the archive](#removing-the-archive)).

| Outcome | Meaning |
| --- | --- |
| `complete` | Every package was published or read back from Nexus with the shipped bytes. |
| `incomplete` | At least one package failed, or the service could not finish reading the archive from MinIO. A read that stops partway fails every package of the manifest with that reason and is never a refusal. |
| `refused` | A check failed, or the archive, its manifest or its signature changed in MinIO since the import was created (`the archive changed in MinIO; start a new import`, reading `the manifest` or `the signature` for `the archive` when that object moved). This attempt published nothing. |
| `interrupted` | The service stopped, or restarted, before the attempt ended. |

An attempt reads the manifest, the signature and the archive from MinIO once each, on condition that each still has the ETag recorded at the start. Its working files sit in a private directory below the import's own and are removed when the attempt ends, whatever the outcome. A read waits at most 60 seconds for the next bytes, and a list or a description at most 30 seconds. The token is checked when a request arrives and not again: an attempt that started goes on after the token's expiry.

Before it reads anything, each attempt, the first included, heads the archive, the manifest and the signature and compares their ETags with the ones recorded. A difference ends the attempt `refused` with the reason above and publishes nothing; an object that is gone or cannot be described ends it `incomplete` (`the signature is no longer in MinIO` for the signature). An import recorded by sealift 0.4 holds no signature, so its attempt heads two objects and then ends `refused` as unsigned.

A `report` is marked `unencrypted` when Nexus, MinIO or the key set is reached over plain `http`.

A report always carries `ecosystem`, `target.python` and `target.glibc`. `ecosystem` is the manifest's once the attempt has read it, and the archive's folder's before. A pip report fills `target.python` and `target.glibc`, leaves `libc`, `node` and `pnpmVer` empty, and names the pip repository under `nexus.repository`. An npm report sends `python` and `glibc` empty. A pip archive whose settings file has no `nexus.pip` section ends `refused` with `the settings name no pip repository: set nexus.pip.repository`, and nothing is read from the archive.

The report carries three fields that `sealift import -report` writes too, described in [The import report](archive-format.md#the-import-report). `publicKeySha256` is the sha256 of the public key the attempt checked the signature with. `archiveChecked` is `true` once the archive passed its checks and `false` before, or when the attempt ended without passing them. Each failed package has a `kind`: `conflict`, `nexus`, `source`, `interrupted`, `mismatch` or `local`. A client reads the kind to tell what to do next and reads `reason` for the words. An attempt that ended before it read the archive because an object changed in MinIO has `archiveChecked` false and no package. An import recorded by sealift 0.4.0 or earlier has none of them, and the service serves it as it is, without a `kind`, without `archiveChecked` and without `publicKeySha256`.

While an attempt runs, its report grows in two steps. Before the manifest is read, the packages are empty and `archiveChecked` is absent. Once the manifest is read, the report holds the manifest's `target`, the `archive` and `nexus` objects and every package as `pending`, with `archiveChecked` false and no `outcome`. When the archive passes its checks, `archiveChecked` turns `true`, and each package then moves to its final state. The `outcome` and the `reason` are written with the end.

### Retrying an import

`POST /api/imports/{importId}/retry` takes the body `{}` and adds a queued attempt numbered one past the latest. It is accepted whatever the last outcome was, a `complete` import whose archive was kept included, while no attempt is queued or running and the archive is still in MinIO. The earlier attempts and their reports stay as they are. The cross-site rules of [Starting an import](#starting-an-import) apply.

A retry carries nothing over. It reads the manifest, the signature and the archive again, repeats every check (the signature is verified again, with the key the service trusts at that moment), and reads every package from Nexus again, the ones an earlier attempt published or found included. It uploads only the packages that Nexus no longer serves with the shipped bytes, and it ends `complete` only when each package was read back in that attempt.

| Status | When |
| --- | --- |
| 202 | The attempt is queued. The answer is the import with its new attempt. |
| 404 | The id is malformed, missing or another user's. |
| 409 | An attempt is queued or running (`an attempt of this import is queued or running`), the archive is no longer in MinIO (`the archive is no longer in MinIO`), or the settings file has no `minio` section. `importId` names the import. |
| 502 | MinIO failed to describe the archive. |
| 503 | The service is stopping. The attempt is recorded as `interrupted`. |

An archive, manifest or signature replaced since the import was created is not a 409: the attempt runs and ends `refused`, so the change stays on record.

### Removing the archive

When an attempt ends `complete`, the service removes the archive, then its manifest, then its signature from the user's folder. It does so only if every package of that attempt was published or read back from Nexus, and only after it heads all three objects again and finds the ETags recorded at the start. An import recorded by sealift 0.4 has no signature to remove. The import and every report stay on the data volume.

The attempt's `removal` holds `removed` and a `reason`, and `archiveRemoved` on the import is true when any attempt removed the archive.

| Case | `removed` | `reason` |
| --- | --- | --- |
| All three objects went | true | empty |
| An object has another ETag, is gone, or could not be described | false | names the object and says nothing was removed |
| The archive could not be deleted | false | `could not remove the archive: ...`; the manifest and the signature are kept too |
| The archive went, the manifest could not be deleted | true | says the manifest stays in the folder |
| The archive and the manifest went, the signature could not be deleted | true | `the archive and the manifest were removed, but manifest.json.sig could not be and stays in the folder: ...` |

An `incomplete`, `refused` or `interrupted` attempt deletes nothing, and a failed removal leaves the import `complete`. A retry after a failed removal checks every package again before it tries to remove anything.

The service stores the `complete` end first and the removal after the delete. A client that reads between the two sees a `complete` attempt with no `removal`. If the service stops in that moment, the attempt stays `complete` with no `removal` and `archiveRemoved` false, whether or not the archive went; check MinIO before a retry.

The ETag check and the delete are two requests, so an object replaced in the few milliseconds between them is still deleted. The check closes the wider window of an upload that lands while the attempt runs.

Stopping the service cancels the running attempt, which ends `interrupted`, and starts none of the attempts still queued. The next start marks those `interrupted` as well and starts nothing by itself.
