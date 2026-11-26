# Python projects

sealift carries Python packages across the air gap as it carries npm packages: it resolves a project's requirements files, scans the set for known CVEs, packs the wheels in a signed archive, and the import publishes them to a pypi hosted repository in Nexus. This page follows one Python project from its files to an install on the air-gapped side. On the connected side, Python projects run through the API for now: no screen creates or exports them yet. The import screens take Python archives as they take npm ones.

## What a project holds

A Python project holds one or more requirements files, resolved together for one target. Each file pins exact versions with `==`, and may include another file of the same project with `-r` or `-c`. A pin may carry `--hash=sha256:` options. sealift reads every file before it stores anything, and refuses:

- a range (`>=`, `~=`), a URL, a local path or any option other than `-r`, `-c` and `--hash`;
- the same package pinned at two versions in two files, naming both files;
- a file above 1 MiB, more than 32 files, or a file name it cannot store.

A refusal answers 400 with one entry per refused line and creates nothing. [The API](dev/api.md#pip-projects) gives every rule.

## The target

A project resolves for one target: a Python version, `linux`, `x86_64`, a glibc version, and the uv release that resolves. The default is Python 3.11.2 with glibc 2.28 and uv 0.13.7; the deployment's policy file can set another, under `targets.pip` ([Settings](settings.md#python-target)). Read the exact values on a machine of the air-gapped side:

<!-- illustrative -->
```sh
python3 -VV
ldd --version
```

The first line of each gives the Python version and the glibc version. sealift records one wheel per package for that target. A package with no wheel the target can install, such as one published as a source distribution only, is listed with the review, with the file and line that pin it, and the export of that set is refused.

## Analyse and export

The calls below go to a sealift that listens on `localhost:8080`. sealift installs the default pip target's uv at start, so create the project once `/healthz` answers 200: its first analysis starts at once. A target that names another uv version installs it during the analysis, under the same checks.

<!-- illustrative -->
```sh
curl -s -F ecosystem=pip -F name=my-service \
  -F requirements=@requirements.txt -F requirements=@requirements-test.txt \
  http://localhost:8080/api/projects
```

The answer gives the project's id. `GET /api/projects/<project-id>` lists its analyses. Follow the analysis until its state is `done`, then read `pipResult`: every package of the set with its wheel, its CVEs, and any package that blocks the export.

<!-- illustrative -->
```sh
curl -s http://localhost:8080/api/projects/<project-id>
curl -s http://localhost:8080/api/projects/<project-id>/analyses/<analysis-id>
```

Export the whole set. A Python export takes no selection:

<!-- illustrative -->
```sh
curl -s -X POST -H 'Content-Type: application/json' -d '{"selection":{}}' \
  http://localhost:8080/api/projects/<project-id>/analyses/<analysis-id>/exports
```

Follow the export until it is `done`, then download its files from `GET /api/projects/<project-id>/exports/<export-id>/files/<name>`. [The API](dev/api.md#pip-exports) describes each step and each answer.

## What crosses

Three files cross, as for npm: `packages_pip.tar.gz`, `manifest.json` and `manifest.json.sig`. Record the archive's sha256 on the connected side and send it by another channel. On the air-gapped side, the three files go to `packages/pip/<folder>/` in the user's MinIO bucket.

## Import

The import service lists `packages/pip/` beside `packages/npm/` and imports a Python archive the same way, into the repository that `nexus.pipRepository` names. [Importing](importing.md) covers the screens, and [the air gap](air-gap.md) the checks.

## Install on the air-gapped side

Install from the pypi repository's simple index, with wheels only:

<!-- illustrative -->
```sh
pip install --only-binary :all: \
  --index-url <nexus-url>/repository/<nexus-pypi-repository>/simple/ \
  -r requirements.txt -r requirements-test.txt
```

The lab ran this crossing at commit f5c6f46 with a project of two requirements files and 173 packages: the import published every wheel, and a Python 3.11.2 machine with no route to the internet installed the whole set from Nexus alone, with no broken requirement.

## Limits

- One wheel per package, for one target: `linux`, `x86_64` and glibc. No macOS, Windows or musl wheels.
- No source distribution: a package without a wheel for the target is listed with the review, and its export is refused.
- No collection screen yet: the API carries the connected side's steps.
