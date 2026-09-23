# Ranking

This page is for whoever changes how sealift picks a version: the types in `rank/`, where the analysis calls them, and the tests to extend. [How sealift chooses](../how-sealift-chooses.md) describes the same rules for users.

## Findings and vectors

`rank/findings.go` turns Trivy's output into something to compare.

- `ReadTrivyJSON` reads a `trivy --format json` report (schema version 2) into `[]Finding`.
- `NewIndex` groups findings by `name@version`. `Index.Set(keys)` returns the distinct vulnerabilities of a set of packages, keyed by id; when one id comes with several severities, the most serious wins.
- `VectorOf` counts a set by severity into a `Vector`, `[5]int` ordered critical, high, medium, low, unknown.
- `Vector.Compare` orders two vectors lexicographically: fewer critical first, then fewer high, and so on. One critical outweighs any number of high.

A candidate's vector counts every vulnerability in its isolated resolution: the package, its dependencies, and the project's own versions of the peers it declares.

## Signals

`rank.Signals(current, candidate Facts, p Policy) []Hit` returns every signal that applies, blocking ones first. `Facts` is what the registry and the resolution say about one version; `Policy` holds `Now`, `MinReleaseAge` and `TargetNode`.

| Signal | Blocking | Fires when |
| --- | --- | --- |
| `too-recent` | yes | `Now - Published < MinReleaseAge`, or `Published` is zero |
| `node-mismatch` | yes | `NodeCompatible` is false |
| `does-not-resolve` | yes | `Resolves` is false |
| `deprecated` | yes | `Deprecated` is not empty |
| `install-script-added` | no | the candidate has an install script and the current version does not |
| `provenance-lost` | no | the current version has provenance and the candidate does not |
| `publisher-changed` | no | both publishers are known and differ |
| `major-jump` | no | `JumpOf` gives `OtherMajor` |

`Signal.Blocking` is the one place that says which signals block. Each `Hit` carries its evidence as a sentence, which the review shows under the candidate.

## The choice

`rank.Best(current, currentVector, candidates) (Candidate, bool)`:

1. drops every candidate with a blocking signal;
2. sorts the rest by `Vector.Compare`, then by `JumpOf(current, version)` (`SameMinor`, `SameMajor`, `OtherMajor`), then by version, ascending;
3. returns the first, or `false` when its vector is not lower than the current one.

The ascending version order in step 2 is what makes sealift propose the oldest of the equally good versions.

## Key versions

`rank.KeyVersions(current, newer, fixed)` picks the candidates the analysis resolves first and the review shows first: for each fixed version Trivy reports, the lowest candidate at or above it; then the latest patch, the latest in the current major, and the latest overall. `newer` must be ascending, as `npm.NewerStable` returns it: stable releases above the current one, pre-releases left out.

## Where the analysis calls them

| Step | Code |
| --- | --- |
| 5, `list-candidates` | `analysis_candidates.go`: `npm.NewerStable`, then `rank.KeyVersions` with the fixed versions from the project's scan |
| 6, `resolve-candidates` | `analysis_candidates.go`: one isolated resolution per candidate, built by `buildProbeManifest`, key versions first |
| 7, `scan-candidates` | Trivy over every candidate lockfile, into one index |
| 8, `rank` | `analysis_rank.go`: `rankDependency` builds `Facts`, calls `rank.Signals` and `rank.Best`, and writes each candidate with its vector, CVE ids and signals |

When the current version's own resolution fails, `rankDependency` records a warning and skips ranking that dependency: a zero vector would read as "no CVE" and hide every candidate.

## The review groups

The three groups of the review are computed in the browser, in `web/src/lib/reviewGroups.ts`, from the analysis result. `groupOf` puts a dependency in:

- `nothing` when `best` is empty;
- `decide` when the best candidate carries any signal other than `publisher-changed`, or when `jumpKind` is `major` or `zero-minor`;
- `proposed` otherwise.

`jumpKind` treats a minor bump inside 0.x as `zero-minor`, since semantic versioning promises nothing there. The grouping follows sealift's proposal, not the user's pick, so a row does not move while someone changes its version.

## Tests to extend

| Change | Test |
| --- | --- |
| A new signal, or a change to one | `TestSignals` in `rank/candidates_test.go`, table-driven |
| The tie-break order | `TestBest` |
| Which versions count as key | `TestKeyVersions` |
| Vector order or severity parsing | `TestVectorCompare`, `TestParseSeverity` in `rank/findings_test.go` |
| How the analysis assembles candidates | `internal/jobs/analysis_rank_test.go` |
| The review groups | `web/src/lib/reviewGroups.test.ts` |

The review and `summary.md` print a signal's evidence as it comes; only `too-recent` has its own wording, in `web/src/components/session/review-screen.tsx`. A new signal needs a row in [How sealift chooses](../how-sealift-chooses.md#signals).
