# sealift documentation

sealift prepares npm dependency updates for air-gapped networks. Every page is one click from here.

## First steps

- [Getting started](getting-started.md): from nothing to a first archive in ten minutes.
- [Workflow](workflow.md): each screen of a session, and every button on it.

## Using sealift

- [How sealift chooses](how-sealift-chooses.md): the proposal, the signals, the minimum release age.
- [Settings](settings.md): the target platform, the signature key, the limits.
- [The air gap](air-gap.md): what crosses the kiosk, what to check, what the import side receives.

## Deploying

- [Deployment](deployment.md): Compose, reverse proxy, the data volume, upgrades and backups.

## Reference

- [Troubleshooting](troubleshooting.md): each message sealift shows, its cause and its fix.
- [FAQ](faq.md): lockfiles, other ecosystems, what leaves the machine, where data lives.

## Developing

- [Contributing](../CONTRIBUTING.md): the local stack, the checks, commits and releases.
- [Architecture](dev/architecture.md): the API, the job queue, the analysis and export steps, the data volume.
- [Ranking](dev/ranking.md): signals, the choice of a candidate, and the tests to extend.
- [API](dev/api.md): every route, its errors, and the event stream.
- [Archive format](dev/archive-format.md): the contract with the import tool.
- [Web](dev/web.md): routes, the step bar, following a job, checking a screen in a browser.
