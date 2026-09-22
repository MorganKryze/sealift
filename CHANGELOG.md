# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/MorganKryze/sealift/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/MorganKryze/sealift/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MorganKryze/sealift/releases/tag/v0.1.0
