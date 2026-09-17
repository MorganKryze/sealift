# sealift

sealift prepares npm dependency updates for air-gapped networks. It scans a project for known vulnerabilities, ranks the newer versions of each dependency, and packs the chosen versions into an archive an offline registry can import.

Status: early development. The Go library packages below exist; the web application does not yet.

| Package | Purpose |
| --- | --- |
| `npm` | package.json validation, pnpm lockfile parsing, platform filter, `engines` matching, registry client, tarball rewriting |
| `archive` | reproducible tar.gz archives |
| `sbom` | CycloneDX documents for npm packages |
| `rank` | vulnerability scores, candidate signals, best version choice |

## Install

```sh
go get github.com/MorganKryze/sealift/npm
```

Replace `npm` with `archive`, `sbom` or `rank` for the other packages.

## Development

Requires Go 1.27, [just](https://just.systems) and [golangci-lint](https://golangci-lint.run) 2.13.

```sh
just hooks   # link the pre-commit hook
just check   # formatting, vet, lint, race tests
just bench   # benchmarks
```

## License

GPL-3.0. See [LICENSE](LICENSE).
