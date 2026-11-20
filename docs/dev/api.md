# API

This page lists every route of the HTTP API, what it is for, and how it fails, then describes the event stream. [`api/openapi.yaml`](../../api/openapi.yaml) is the contract; the Go server interface and the TypeScript types are generated from it with `just generate`.

Every route lives under `/api`, except `/healthz`. Request and response bodies are JSON unless stated.

## Errors

A failure answers with a problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)):

```json
{"detail":"not found","status":404,"title":"get project","type":"about:blank"}
```

`title` names the operation, `detail` the cause. A validation failure adds `errors`, one entry per problem with `field`, `reason`, and `name` and `value` when they apply. `type` is `about:blank`, except `tools-missing`, which adds `missing`.

| Status | When |
| --- | --- |
| 400 | An invalid body: a manifest sealift refuses, a selection it did not resolve, an empty export, a target or limit out of range |
| 404 | An unknown project, analysis or export |
| 409 | Trivy or its database is missing (`tools-missing`); the analysis is not done; a Trivy release younger than the minimum release age |
| 502 | GitHub cannot be reached to list Trivy releases |
| 500 | Anything else; the server log has the cause |

## Health

`GET /healthz` answers while the server runs.

<!-- run -->
<!-- expect: {"status":"ok"} -->
```sh
curl -s http://localhost:8080/healthz
```

## Projects

A project is a session: one `package.json` and its history.

| Route | Purpose |
| --- | --- |
| `GET /api/projects` | List projects, each with its last analysis and export. `?manifestSha256=` keeps those created from that exact file, which is how the interface finds a duplicate. |
| `POST /api/projects` | Create a project from a `multipart/form-data` upload, field `manifest`, optional `name`, and queue its analysis. 201 with the project. 400 when the manifest is refused, 409 when the tools are not ready. |
| `GET /api/projects/{projectId}` | The project, its target, its analyses and its exports. |
| `DELETE /api/projects/{projectId}` | Delete the project directory and everything in it. 204, or 409 while one of its jobs is queued or running. |
| `PUT /api/projects/{projectId}/target` | Change the project's target platform and toolchain. |
| `GET /api/projects/{projectId}/manifest` | The `package.json` the project was created from, byte for byte. |

<!-- run -->
<!-- expect: "id" -->
```sh
curl -s http://localhost:8080/api/projects
```

## Analyses

| Route | Purpose |
| --- | --- |
| `POST /api/projects/{projectId}/analyses` | Queue a new analysis of the project. 202 with the queued analysis. 409 when the tools are not ready. |
| `GET /api/projects/{projectId}/analyses/{analysisId}` | The analysis: state, steps, failure, and once done its result, with each dependency, its vector, its candidates and `best`. |
| `DELETE /api/projects/{projectId}/analyses/{analysisId}` | Delete the analysis. |
| `GET /api/projects/{projectId}/analyses/{analysisId}/log` | The full log, as `text/plain`. |
| `POST /api/projects/{projectId}/analyses/{analysisId}/cancel` | Cancel the analysis, running or queued. |

The states are `queued`, `running`, `done`, `failed`, `cancelled` and `interrupted`. A failed analysis carries `failure` with the step id and the message:

```json
{"message":"resolve project: pnpm install: ERR_PNPM_NO_MATCHING_VERSION No matching version found for left-pad@99.0.0: exit status 1","step":"resolve-project"}
```

## Exports

| Route | Purpose |
| --- | --- |
| `POST /api/projects/{projectId}/analyses/{analysisId}/exports` | Queue an export. The body maps each dependency to the versions to include: `{"selection":{"express":["5.1.0"]}}`. `includeProject: true` also packs the current project's own packages; the interface leaves it false. 400 for a version the analysis did not resolve, or an export that packs nothing; 409 when the analysis is not done. |
| `GET /api/projects/{projectId}/exports/{exportId}` | The export: state, steps, failure, and once done its files. |
| `DELETE /api/projects/{projectId}/exports/{exportId}` | Delete the export and its files. |
| `POST /api/projects/{projectId}/exports/{exportId}/cancel` | Cancel the export, running or queued. |
| `GET /api/projects/{projectId}/exports/{exportId}/files/{name}` | Download one file of a finished export: the archive, `manifest.json`, `manifest.json.sig` or a report. |

A dependency left out of the selection, or given an empty list, stays at its current version.

## Settings

| Route | Purpose |
| --- | --- |
| `GET /api/settings` | Every setting: the target and the three limits. |
| `PUT /api/settings` | Replace every setting. A `signatureKey` in the body is ignored and never saved. 400 for a target or limit out of range. |

[Settings](../settings.md#from-the-api) shows both, with real answers.

## Signing key

sealift generates an Ed25519 key pair on first start and keeps the private key in the data volume, in `private/signing-key.pem` (mode 0600, in a 0700 directory). The API returns the public half only: no route, answer, log line or error carries the private key.

| Route | Purpose |
| --- | --- |
| `GET /api/signing-key` | The public key and its fingerprint: `{"publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...", "publicKeySha256": "<64 lowercase hex digits>"}`. `publicKeySha256` is the sha256 of the key's DER SubjectPublicKeyInfo encoding. |
| `POST /api/signing-key/regenerate` | Replace the key pair with a new one and answer with the new public key, in the same shape. The body is `{}` with `Content-Type: application/json`. |

A regenerate answers:

| Status | When |
| --- | --- |
| 200 | The new pair is on disk and in use. |
| 403 | The `Host` is not this server's own (the listen address's host, `localhost`, `127.0.0.1` or `::1`), the `Origin` is not one of those hosts, `Sec-Fetch-Site` is `cross-site`, or the body is not `application/json`. The key is unchanged. |
| 500 | The new key cannot be written. The problem's `detail` names the file; the old key stays on disk and in use. |

A request with no `Origin` and a JSON body passes the check, as curl must. The server stops at start, naming the file, when `signing-key.pem` exists and cannot be read, is not a PEM private key or is not Ed25519: it never replaces a key file by itself.

## Tools

| Route | Purpose |
| --- | --- |
| `GET /api/tools` | Installed and latest Trivy versions, the database date, pnpm versions, and `ready` with `missing`. |
| `POST /api/tools/trivy/update` | Install a Trivy release: the latest, or `version`. 409 when it is younger than the minimum release age, unless `force` is true. 502 when GitHub cannot be reached. |
| `POST /api/tools/trivy/activate` | Switch to another installed Trivy, body `{"version":"0.74.0"}`. |
| `POST /api/tools/trivy/db/update` | Download the vulnerability database now. |

<!-- run -->
<!-- expect: "trivyActive" -->
```sh
curl -s http://localhost:8080/api/tools
```

```json
{"latestSizeBytes":45424969,"missing":[],"pnpmInstalled":["10.34.5"],"ready":true,"trivyActive":"0.74.0","trivyDbDate":"2026-09-23T07:12:28.724391795Z","trivyInstalled":["0.74.0"],"trivyLatest":"0.74.0","trivyLatestAge":"960h59m15.099150044s"}
```

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

For each archive that passes the rules below, the list reads its `manifest.json` with the listed ETag, within 16 MiB, and looks at `formatVersion` and `ecosystem` alone. A manifest of the other ecosystem marks the archive as not importable. The mark is a hint: a manifest that cannot be read or parsed leaves the archive importable, and the import checks the ecosystem again after the signature. The service keeps each manifest's ecosystem by its ETag, up to 4,096 ETags, and reads at most 50 manifests it has not read before in one list. Past 50, the remaining archives are marked at the next list.

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
