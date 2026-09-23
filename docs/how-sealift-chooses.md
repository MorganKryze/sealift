# How sealift chooses

This page explains how sealift picks the version it proposes for each dependency, what each signal on a candidate means, and why the proposal can be older than the latest release.

## The short version

For each direct dependency, sealift proposes the version with the fewest CVEs, counted by severity. Among versions tied on CVEs, it takes the smallest jump from the current version, then the lowest version. A version that is too recent, does not run on your Node, does not resolve, or is deprecated is never proposed.

## Which versions are candidates

The candidates for a dependency are its stable releases newer than the current one, as the npm registry lists them. Pre-releases such as `5.0.0-beta.1` are left out.

sealift resolves each candidate in isolation with pnpm: the dependency at that version, plus the project's own version of each peer dependency it declares. It then scans what the resolution pulls in with Trivy. A candidate's CVEs are those of the version itself and of everything it installs.

Some candidates are resolved first, and shown first in the review. They are the key versions:

- for each version Trivy names as fixing a CVE, the lowest candidate at or above it;
- the latest patch in the current minor;
- the latest release in the current major;
- the latest release overall.

**Show all newer versions** in the review lists the others.

## Ranking by CVE count

sealift counts a candidate's distinct CVEs by severity: critical, high, medium, low, unknown. It compares two candidates one severity at a time, from the most serious:

| Candidate | Critical | High | Medium | Low | Rank |
| --- | --- | --- | --- | --- | --- |
| A | 0 | 3 | 0 | 0 | 2 |
| B | 0 | 2 | 9 | 9 | 1 |
| C | 1 | 0 | 0 | 0 | 3 |

B wins over A because it has fewer high CVEs, whatever its medium and low counts. C comes last because of its one critical.

When candidates tie, sealift takes the smallest jump: a patch in the same minor first, then a minor in the same major, then a new major. When they still tie, it takes the lowest version.

sealift proposes nothing when no candidate has fewer CVEs than the current version. The dependency then shows under Nothing to do.

## Why the oldest version that fixes the most

A release with no known CVE may have none because nobody has looked at it yet. An older release with the same count has had more time in use and more eyes on it. Taking the lowest version among equals also keeps the jump, and the risk of breaking the project, as small as it can be.

## Signals

A signal is a fact about a candidate worth a look. The review shows each one under the candidate, with its evidence.

The first four block a candidate: sealift never proposes it, and the review does not let you choose it.

| Signal | Meaning |
| --- | --- |
| `too-recent` | Published less than the minimum release age ago, 14 days by default, or with no publication date in the registry |
| `node-mismatch` | Its `engines.node` excludes the target's Node version |
| `does-not-resolve` | pnpm could not resolve it with the project's peer dependencies |
| `deprecated` | Its author deprecated it on the registry |

The other four inform:

| Signal | Meaning |
| --- | --- |
| `install-script-added` | It runs an install script; the current version does not |
| `provenance-lost` | The current version has a provenance attestation; this one has none |
| `publisher-changed` | A different npm account published it |
| `major-jump` | It leaves the current major version |

## The minimum release age

A new release gets 14 days before sealift proposes it. The wait gives the package's users and the registry time to find a bad or compromised publish, and to pull or deprecate it. The same wait applies to the Trivy release sealift installs.

[Settings](settings.md#minimum-release-age) changes the wait, from 1 to 90 days.

## The three groups

The review sorts dependencies by sealift's proposal:

| Group | When |
| --- | --- |
| To decide | The proposal is a major jump, a minor jump inside 0.x, or carries a signal other than `publisher-changed` |
| Proposed | The proposal is a patch or minor jump with no such signal |
| Nothing to do | sealift proposes nothing |

Inside 0.x, semantic versioning makes no promise between minor versions, so `0.21.1` to `0.33.0` may break as much as a major jump. `publisher-changed` alone does not move a row to To decide, since a new maintainer is common. The signal still shows on the candidate.

## A worked example

The demo project in [Getting started](getting-started.md) pins express 4.17.1, which carries 14 CVEs: 5 high, 3 medium, 6 low. The review shows its key versions and the proposal:

| Version | CVEs | Signals | Outcome |
| --- | --- | --- | --- |
| 4.17.3 | 4 high, 3 medium, 6 low | | Fewer CVEs, not the fewest |
| 4.19.2 | 4 high, 2 medium, 6 low | `publisher-changed` | Fewer CVEs, not the fewest |
| 4.20.0 | 2 high, 3 medium, 4 low | `publisher-changed` | Fewer CVEs, not the fewest |
| 4.22.3 | none | `too-recent`, `publisher-changed` | Blocked: released 9 days ago |
| 5.0.0 | 3 medium, 2 low | `publisher-changed`, `major-jump` | Fewer CVEs, not the fewest |
| 5.1.0 | none | `publisher-changed`, `major-jump` | Proposed |
| 5.2.1 | none | `publisher-changed`, `major-jump` | Same count and jump as 5.1.0, higher version |

4.22.3 would fix every CVE without leaving major version 4, but it is 9 days old. sealift proposes 5.1.0: no known CVE, and 18 months in use. A major jump, so express shows under To decide. Once 4.22.3 is 14 days old, a new analysis proposes it instead, and express moves to Proposed.

![express opened in the review, with 4.22.3 held back as too recent and 5.1.0 proposed](assets/review.png)

## After the choice

Step 9 of the analysis resolves the whole project with every proposed version at once. When they conflict, the analysis still finishes: the log holds pnpm's output, and the API's analysis result carries the warning. Each proposal stays selectable, and an export of a selection that does not install together stops on pnpm's error. Choose another version for one of the conflicting dependencies, or keep its current one.
