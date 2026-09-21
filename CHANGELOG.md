# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-21

### Added

- Analysis of an npm project: resolve its lockfile, scan it with Trivy, and list the CVEs it carries.
- Ranking of the newer versions of each dependency, with the signals behind each rank (a fix for a CVE, a deprecation, a lost provenance, a major jump, among others) and the best candidate highlighted.
- Export that resolves the project against the chosen versions, downloads the packages, and packs them into a reproducible, signed archive alongside a CVE report and a version report.
- Web interface to create a project, queue an analysis, choose versions, queue an export, and download the result.
- Docker image with the web interface built in and Trivy and pnpm installed, ready to run against an air-gapped registry.

[Unreleased]: https://github.com/MorganKryze/sealift/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MorganKryze/sealift/releases/tag/v0.1.0
