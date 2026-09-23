# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/MorganKryze/sealift/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/MorganKryze/sealift/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/MorganKryze/sealift/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MorganKryze/sealift/releases/tag/v0.1.0
