# Contributing

Bug reports and ideas are contributions too. The issue templates, [Bug report](https://github.com/MorganKryze/sealift/issues/new?template=bug_report.md) and [Feature idea](https://github.com/MorganKryze/sealift/issues/new?template=feature_idea.md), ask for what a maintainer needs to act on them. For a security problem, follow [SECURITY.md](SECURITY.md) instead.

## Requirements

- Go 1.27
- Node 22 and pnpm 12.3.4 for the web app (`corepack enable` picks the pinned pnpm)
- [just](https://just.systems) for the shortcuts
- [golangci-lint](https://golangci-lint.run) 2.13
- Docker, for the image and the end-to-end test
- Trivy on your `PATH`, for the integration tests only

## Layout

```
cmd/sealift/      wiring: flags, startup, the HTTP server
api/              openapi.yaml, the contract the server and the web client are generated from
internal/api/     HTTP handlers, problem responses, the event stream
internal/jobs/    the queue, the nine analysis steps, the export steps
internal/store/   the /data volume: settings, sessions, analyses, exports
internal/tools/   installing Trivy and pnpm, checking their hashes
internal/runner/  running pnpm and Trivy as the tools user
internal/report/  summary.md and findings.csv
npm/              package.json validation, the registry client, lockfiles, versions
rank/             CVE vectors, signals, the choice of the best candidate
archive/          the reproducible tar.gz writer
sbom/             CycloneDX output
web/              the React interface, embedded into the binary
test/e2e/         the end-to-end test against two local registries
docs/             user and developer documentation
```

[Architecture](docs/dev/architecture.md) explains how these fit together.

## Run it locally

Run the server on a scratch data directory, and the web app's dev server in front of it:

```sh
go run ./cmd/sealift -addr 127.0.0.1:8080 -data "$(mktemp -d)"
pnpm -C web install
pnpm -C web run dev
```

Open the address Vite prints. It proxies `/api` to `127.0.0.1:8080`; set `SEALIFT_API` to point it elsewhere. The first run shows the setup screen, which downloads Trivy and its database into the data directory.

Outside the image, sealift runs pnpm and Trivy as your own user: the switch to a separate `tools` user happens only when `SEALIFT_TOOLS_UID` and `SEALIFT_TOOLS_GID` are set, as the image does.

To run the real image instead:

```sh
just image
docker run --rm -p 127.0.0.1:8080:8080 -v sealift-dev:/data sealift:dev
```

## Checks

`just` lists every recipe. These are the ones CI runs:

| Recipe | Runs |
| --- | --- |
| `just check` | gofmt, go vet, golangci-lint, `go test -race ./...` |
| `just web-check` | typecheck, ESLint and Vitest on the web app |
| `just docs` | the link and anchor check on every Markdown file |
| `just integration` | the tests behind the `integration` tag, with real pnpm and Trivy; they skip when either is missing |
| `just e2e` | the end-to-end test, then the documentation's runnable examples |

`just hooks` links a pre-commit hook that runs `just check` before each commit.

The end-to-end test builds the image, starts it next to two Verdaccio registries, analyses and exports a fixture project, publishes the archive to the registry that has no uplink, and installs the project from it with pnpm. It then runs every shell block in `docs/` marked `<!-- run -->` against the same sealift.

## Changing the API

`api/openapi.yaml` is the contract. After changing it, run `just generate`: it regenerates the Go server interface in `internal/api/api.gen.go` and the TypeScript types in `web/src/api/schema.d.ts`. Commit the generated files with the change. [API](docs/dev/api.md) describes each route.

## Changing the interface

The web app has no Prettier config. Match the surrounding style by hand: no semicolons, double quotes, long lines. [Web](docs/dev/web.md) covers the routes, the step bar and how to check a screen in a real browser.

When a screen changes, re-read the pages that describe it, since they quote its labels word for word:

| Screen | Pages |
| --- | --- |
| Setup | `docs/getting-started.md`, `docs/workflow.md` |
| Home and drop | `docs/workflow.md`, `docs/troubleshooting.md` |
| Analysis | `docs/workflow.md`, `docs/troubleshooting.md` |
| Review | `docs/workflow.md`, `docs/how-sealift-chooses.md` |
| Export | `docs/workflow.md`, `docs/air-gap.md` |
| Settings | `docs/settings.md` |

Retake the screenshots in `docs/assets/` from a fresh volume, analysing the project in [Getting started](docs/getting-started.md), so the numbers on them match the text.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/): `type(scope): subject`, with the types `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci` and `chore`.
- The subject is imperative, lowercase, with no trailing period, 72 characters at most.
- The body explains why. The diff shows what.
- One logical change per commit, and each commit builds and passes the tests on its own.

A pull request body is plain paragraphs: what changed, why, and how you tested it.

## Writing

Documentation, error messages and code comments use short declarative sentences in the active voice. No emoji, no em dashes, no exclamation marks. A heading names what the section holds. A code comment gives a reason the code cannot show; it never restates the line below.

## Releases

Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and stay on `0.y.z` until the interface settles.

1. Move the `Unreleased` entries of `CHANGELOG.md` under the new version, with the date. Entries describe what a user notices.
2. Commit `chore(release): vX.Y.Z`.
3. Tag it: `git tag -a vX.Y.Z --cleanup=verbatim`, with the CHANGELOG section as the message. `--cleanup=verbatim` keeps its `###` headings.
4. Push `main` and the tag. The image workflow builds `linux/amd64` and `linux/arm64` and publishes `ghcr.io/morgankryze/sealift:X.Y.Z` and `:latest`. Image tags carry no `v`.
5. Create the GitHub release `vX.Y.Z` from the tag, with the CHANGELOG section as its body.
