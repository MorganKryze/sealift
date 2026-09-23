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
| 400 | An invalid body: a manifest sealift refuses, a selection it did not resolve, an empty export, a missing signature key, a target or limit out of range |
| 404 | An unknown project, analysis or export |
| 409 | Trivy, its database or the key is missing (`tools-missing`); the analysis is not done; a Trivy release younger than the minimum release age |
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
| `DELETE /api/projects/{projectId}` | Delete the project directory and everything in it. 204. |
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

The states are `queued`, `running`, `done`, `failed`, `cancelled`, and `interrupted` for a job a server restart stopped. A failed analysis carries `failure` with the step id and the message:

```json
{"message":"resolve project: pnpm install: exit status 1","step":"resolve-project"}
```

## Exports

| Route | Purpose |
| --- | --- |
| `POST /api/projects/{projectId}/analyses/{analysisId}/exports` | Queue an export. The body maps each dependency to the versions to include: `{"selection":{"express":["5.1.0"]}}`. 400 for a version the analysis did not resolve, an export that packs nothing, or a missing key; 409 when the analysis is not done. |
| `GET /api/projects/{projectId}/exports/{exportId}` | The export: state, steps, failure, and once done its files. |
| `DELETE /api/projects/{projectId}/exports/{exportId}` | Delete the export and its files. |
| `POST /api/projects/{projectId}/exports/{exportId}/cancel` | Cancel the export, running or queued. |
| `GET /api/projects/{projectId}/exports/{exportId}/files/{name}` | Download one file of a finished export: the archive or a report. |

A dependency left out of the selection, or given an empty list, stays at its current version.

## Settings

| Route | Purpose |
| --- | --- |
| `GET /api/settings` | Every setting; `signatureKey` reads `********` once set. |
| `PUT /api/settings` | Replace every setting. `"signatureKey": "********"` keeps the saved key, `""` clears it. 400 for a target or limit out of range. |

[Settings](../settings.md#from-the-api) shows both, with real answers.

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

`GET /api/jobs/current/events` is a `text/event-stream` of the running job. It first replays every event the job has emitted so far, then streams the live ones, and ends after the `end` event. With no job running, the connection stays open and nothing arrives until one starts.

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
