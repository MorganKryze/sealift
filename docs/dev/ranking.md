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
| `major-jump` | no | `SameLine(current, candidate)` is false; the evidence names the line left, `leaves major version 4` or `leaves 0.18.x` |

`Signal.Blocking` is the one place that says which signals block. Each `Hit` carries its evidence as a sentence, which the review shows under the candidate.

## The line

`rank/line.go` says which versions stay in a dependency's line, the range npm's caret gives its current version.

- `SameLine(from, to)` is true when `to` falls inside `^from`: the same major from 1.0.0, the same minor below it, the same patch below 0.1.0. It is false when either string is not a version, when `to` is lower, and for a pre-release outside the tuple `from` pins.
- `LineOf(version)` names the line: `"4"`, `"0.18"`, `"0.0.3"`, or `""` for a string that is not a version.

## The choice

`rank.Best(current, currentVector, candidates) (Candidate, bool)`:

1. drops every candidate with a blocking signal;
2. sorts the rest by `Vector.Compare`, then by `JumpOf(current, version)` (`SameMinor`, `SameMajor`, `OtherMajor`), then by version, ascending;
3. returns the first, or `false` when its vector is not lower than the current one.

The ascending version order in step 2 is what makes sealift propose the oldest of the equally good versions.

`rank.Propose(current, currentVector, candidates, otherLines) (best, hasBest, jump, hasJump)` is what the analysis calls. It splits the candidates by `SameLine`, runs `Best` on those inside the line, or on every candidate when `otherLines` is true, and names the jump: the unblocked candidate outside the line that `Best`'s order puts first. The jump needs no lower vector than the current version. `otherLines` comes from the policy key `review.proposeOtherMajors`.

## Families

`rank.Families(jumpers []Jumper) []Family` groups the jumps that must move together. A `Jumper` is a dependency's name, its current version, its jump and the jump version's `peerDependencies`. B joins A when B's jump declares a peer range on A that excludes A's current version and admits A's jump, or when B is A's `@types` package (`@types/babel__core` for `@babel/core`). A range `semver` cannot parse makes no edge.

Each `Family` is a connected group of two or more. Its `Root` is the member the most others name, ties going to the first name, and its `Name` is the root and `LineOf` its jump: `react 19`. `Members` are sorted, and the families sorted by name.

## Key versions

`rank.KeyVersions(current, newer, fixed)` picks the candidates the analysis resolves first and the review shows first: for each fixed version Trivy reports, the lowest candidate at or above it; then the latest patch, the latest in the current major, and the latest overall. `newer` must be ascending, as `npm.NewerStable` returns it: stable releases above the current one, pre-releases left out.

## Where the analysis calls them

| Step | Code |
| --- | --- |
| 5, `list-candidates` | `analysis_candidates.go`: `npm.NewerStable`, then `rank.KeyVersions` with the fixed versions from the project's scan |
| 6, `resolve-candidates` | `analysis_candidates.go`: one isolated resolution per candidate, built by `buildProbeManifest`, key versions first |
| 7, `scan-candidates` | Trivy over every candidate lockfile, into one index |
| 8, `rank` | `analysis_rank.go`: `rankDependency` builds `Facts`, calls `rank.Signals` and `rank.Propose` with the policy's `review.proposeOtherMajors`, and writes each candidate with its vector, CVEs and signals, then `best` and `jump`. `cvesOf` keeps each CVE's `package` and `fixedIn`. Once every dependency is ranked, `setFamilies` reads each jump version's `peerDependencies` from the packument, calls `rank.Families`, and writes `families` and each member's `family` |

When the current version's own resolution fails, `rankDependency` records a warning and proposes nothing for that dependency: a zero vector would read as "no CVE" and hide every candidate. It still names the jump.

An analysis is never rewritten. The API marks `leavesLine` on every candidate when it reads one, from `rank.SameLine`, so an analysis written by sealift 0.7.0 gets the marks too. Such an analysis has no `jump`, `family` or `families`, and its CVEs carry no `package` or `fixedIn`.

## The review groups

The four groups of the review are computed in the browser, in `web/src/lib/reviewGroups.ts`, from the analysis result and the selection. `groupOf` puts a dependency in the first that matches:

- `reasons` when its selected version leaves its current line, when it belongs to a family whose jump the selection takes, or when the selected version keeps a CVE with no known fix;
- `updated` when the selected version differs from the current one;
- `kept` when the analysis recorded a jump the selection does not take;
- `unchanged` otherwise.

A publisher change is a fact on the row and never moves it. `jumpKind` treats a minor bump inside 0.x as `zero-minor`, since semantic versioning promises nothing there.

## Tests to extend

| Change | Test |
| --- | --- |
| A new signal, or a change to one | `TestSignals` in `rank/candidates_test.go`, table-driven |
| The tie-break order | `TestBest` |
| The line, the proposal inside it and the jump | `TestSameLine`, `TestLineOf`, `TestProposeKeepsTheLine`, `TestJumpIsTheFirstOutsideTheLine` |
| How jumps group into families | `rank/families_test.go`: `TestFamiliesFromPeers`, `TestFamiliesFromTypes`, `TestFamilyNamedAfterTheMemberOthersName` |
| What an export asks a reason for, and the review it signs | `internal/jobs/review_test.go`: `CheckReasons` and `ReviewOf` |
| Which versions count as key | `TestKeyVersions` |
| Vector order or severity parsing | `TestVectorCompare`, `TestParseSeverity` in `rank/findings_test.go` |
| How the analysis assembles candidates | `internal/jobs/analysis_rank_test.go` |
| The review groups | `web/src/lib/reviewGroups.test.ts` |

`summary.md` prints a signal's evidence as it comes. The review, in `web/src/components/session/review-screen.tsx`, gives `too-recent` its own sentence and prefixes the other evidence with a readable name from `humanizeSignal`. A new signal needs a row in [How sealift chooses](../how-sealift-chooses.md#signals).
