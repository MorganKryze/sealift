# sealift documentation

sealift prepares npm dependency updates for air-gapped networks, and Python ones through its API. Every page is one click from here.

## First steps

- [Overview](overview.md): what sealift is, the two sides, one crossing end to end, the checks and the state on disk.
- [Getting started](getting-started.md): from nothing to a first archive in ten minutes.
- [Workflow](workflow.md): each screen of a session, and every button on it.

## Using sealift

- [How sealift chooses](how-sealift-chooses.md): the proposal, the signals, the minimum release age.
- [Settings](settings.md): the target platform, the signing key, the limits.
- [The air gap](air-gap.md): what crosses the kiosk, the signature and the trusted key, what to check, what the import side receives.
- [Importing](importing.md): the Archives, Imports and import screens of the import service, the trusted key and every state.
- [Python projects](python.md): a Python project through the API, from its requirements files to an install from Nexus.

## Deploying

- [Deployment](deployment.md): Compose, reverse proxy, the data volume, the key the import trusts, upgrades and backups.
- [Runbook](runbook.md): both sides from nothing to a first import, with every value to replace, Harbor, the sign-in values, a checklist and the worst cases on a shared Nexus repository.
- [Helm chart](helm.md): the chart of the import service, every value, the install notes and Argo CD.
- [Request to the administrators](admin-request.md): the accounts and the infrastructure the install needs, with the reason for each.

## Reference

- [Troubleshooting](troubleshooting.md): each message sealift shows, its cause and its fix.
- [FAQ](faq.md): lockfiles, other ecosystems, what leaves the machine, where data lives.

## Developing

- [Contributing](../CONTRIBUTING.md): the local stack, the checks, commits and releases.
- [Contributor guide](dev/contributing.md): the repository map, tests, CI, how a change is made, the design choices to keep, where to add things.
- [Architecture](dev/architecture.md): the API, the job queue, the analysis and export steps, the data volume.
- [Ranking](dev/ranking.md): signals, the choice of a candidate, and the tests to extend.
- [API](dev/api.md): every route, its errors, and the event stream.
- [Archive format](dev/archive-format.md): the contract with the import tool.
- [Web](dev/web.md): routes, the step bar, following a job, checking a screen in a browser.
