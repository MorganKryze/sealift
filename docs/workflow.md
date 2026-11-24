# Workflow

This page walks through each screen of a session, in order, with the label of every button. A session holds one `package.json`, its analysis, and the archives built from it.

The step bar at the top of a session shows Drop, Analyse, Review and Export. A finished step shows a check mark and opens again on a click. A running step shows a spinner, a failed one a cross.

## Preparing

While the instance prepares, the home shows Preparing sealift. sealift prepares each item on its own at start, and the screen has no button:

| Item | Where it comes from |
| --- | --- |
| Trivy and its version | `github.com/aquasecurity/trivy`, the release the binary pins, checked against the sha256 built into sealift |
| Vulnerability database | `mirror.gcr.io`, updated every six hours upstream; sealift refreshes it before each analysis |
| Signing key | sealift: an Ed25519 key it generated for this volume, shown with its public key sha256 |
| pnpm and its version | the npm registry, checked against the integrity it publishes. It resolves npm projects |
| uv and its version | the package index, checked against the sha256 it publishes. It resolves pip projects |

Each item reads Preparing, Ready or Failed. A failed item shows its cause and Next try at, with the time; sealift tries again every minute. The home opens once every item is ready, with no reload. [Deployment](deployment.md#readiness) explains readiness for whoever runs the instance.

## Home

The home screen is New session: a drop zone for a `package.json`, then Past sessions, newest first.

![New session, with the drop zone and one past session marked Archive ready](assets/home.png)

Drop a file on the zone, or press **Choose a file**. The zone repeats the rule sealift applies to every file: direct dependencies must be pinned to exact versions, such as `4.17.1`. It also names the current target.

Each past session shows its name, its target, its date and one status:

| Status | Meaning |
| --- | --- |
| Not analysed yet | The file was dropped; no analysis ran |
| Analysing | The analysis is running |
| Analysis failed | The analysis stopped on an error, or was cancelled |
| Awaiting export | The analysis finished; no archive yet |
| Exporting | An export is running |
| Export failed | The last export stopped on an error, or was cancelled |
| Archive ready | The last export produced an archive |

A click opens the session on its most useful step: the export for a session with an export, finished or not, the review for a finished analysis, the analysis otherwise.

## Drop

The preview reads the file before anything runs. It shows the project name, the count of prod and dev dependencies, the pinning check and the target.

![The drop preview with all five dependencies pinned](assets/drop-preview.png)

When the file breaks a rule, Pinning shows the number of problems and a list names each one. **Analyse** stays disabled until you fix the file and drop it again.

![A drop preview with three problems: overrides not supported, a caret range on express, an npm alias on lodash](assets/drop-problems.png)

sealift reads `dependencies`, `devDependencies` and `optionalDependencies`, and refuses:

- a range or a tag instead of an exact version: `^4.17.1`, `~4.17.1`, `latest` (version must be exact, such as 1.2.3);
- a version from anywhere but the npm registry: `npm:`, `git+`, `git:`, `github:`, `file:`, `link:`, `workspace:`, `http:` or `https:` (only npm registry versions are supported);
- the fields `overrides`, `resolutions`, `pnpm.overrides` and `pnpm.patchedDependencies` (not supported);
- a file with no dependency (lists no dependency to update).

Dropping a file that an earlier session already used, byte for byte, opens You already analysed this file. It says how that session ended. **Resume that session** opens it; **Start a new session** analyses the file again with fresh data.

**Analyse 5 dependencies** starts the analysis. **Choose another file** clears the preview.

## Analysis

The analysis runs nine steps. Each shows a check mark and its duration once done.

1. Check the manifest
2. Prepare pnpm and Trivy
3. Resolve the project
4. Scan for known CVEs
5. List newer versions
6. Resolve candidate versions
7. Scan candidate versions
8. Rank and propose
9. Check the combined install

Resolve candidate versions takes most of the time: sealift installs each newer version of each dependency against the whole project. A counter shows the candidates resolved so far and the time left. You can leave the page; the session keeps running on the server.

![The analysis at step 6, with 6 of 254 candidates resolved and about 2 minutes 45 seconds left](assets/analysis.png)

**Cancel** asks Cancel this analysis? before it stops. A cancelled analysis reads Analysis cancelled, with **Start it again**.

When a step fails, the screen reads Analysis stopped, with the cause under What went wrong and the actions that fit:

- **Retry** starts the analysis again from the beginning, with the same file.
- **Open settings** opens the settings panel, which shows the target and the limits in effect. The deployment's policy file sets them. A session keeps the target it started with; a new target applies to new sessions.
- **Choose another file** goes back to the drop screen.
- **Show the log** unfolds everything pnpm and Trivy wrote, with the error code the message above leaves out.

![Analysis stopped at Resolve the project on lodash 4.17.99](assets/analysis-failed.png)

[Troubleshooting](troubleshooting.md) lists each message and its fix.

## Review

The review opens on sealift's proposal. The summary compares the CVEs today with the CVEs left with the selection, by severity, and counts the dependencies that change.

A warnings block above the summary names what the analysis could not check, such as a dependency whose registry metadata failed. Such a dependency can look clean in the list, so read the block before you confirm. The analysis checked its proposal as a whole: once you change a pick, the bar above Confirm says your selection was not installed together.

![The review: 45 CVEs today, none with the selection, express opened on its candidates](assets/review.png)

Dependencies fall into three groups:

| Group | Holds |
| --- | --- |
| To decide | A proposal that may break: a major jump, a 0.x minor jump, or a signal worth a second look |
| Proposed | Jumps that fix CVEs |
| Nothing to do | No CVE, or no newer version helps |

A row names the dependency, the CVEs its proposal fixes, the kind of jump, the release age, and the change from the current version to the proposed one. A click opens it:

- Current lists the CVE ids of the current version.
- The key candidates follow, each with its CVE counts by severity, its release age and its signals. The proposed one reads proposed.
- A release younger than the minimum release age reads Held back as too recent for the minimum release age, and cannot be chosen.
- **Keep the current version** leaves the dependency as it is.
- **Show all 22 newer versions** lists every candidate; **Show fewer versions** folds them again.

[How sealift chooses](how-sealift-chooses.md) explains the proposal and each signal.

The bar at the bottom counts the changes and the CVEs left. **Confirm and build the archive** starts the export with the selection.

The review also comes in dark:

![The review in the dark theme](assets/review-dark.png)

## Export

The export runs five steps: List the packages to export, Download and verify each package, Strip publishConfig, Pack the archive, Sign the manifest and write the reports. While it runs, it counts the packages downloaded, those served from the cache, and the percentage done.

![Building the archive: 74 of 100 packages, none from cache, 74 percent](assets/export-running.png)

**Cancel** asks Cancel this export? before it stops. A cancelled export reads Export cancelled, with **Start the export again**. A failed one reads Export failed and names the step, with **Retry** and **Choose different versions**, which returns to the review.

A finished export reads Archive ready:

- the archive card shows Sealed, the package count, the size, and the sha256 with **Copy**;
- **Download archive** downloads `packages_npm.tar.gz`;
- under the sha256, one line says which key signed the archive: this sealift's current key, a key replaced since (export again), or none, for an archive exported by 0.4.0 or earlier;
- Reports lists six files, each with **Download**: `findings.csv`, `manifest.json`, `manifest.json.sig`, `report.cdx.json`, `report.trivy.json`, `summary.md`. The import needs `manifest.json` and `manifest.json.sig` beside the archive.

![Archive ready, with the archive card and the six files](assets/export-done.png)

**Export another selection** returns to the review to build a second archive from the same analysis. The earlier one stays below, under Earlier archive from this analysis. **Start a new session** returns home.

[The air gap](air-gap.md) covers what to do with these files.

## Settings

**Settings**, in the header, opens a side panel over the current screen. [Settings](settings.md) describes each one.
