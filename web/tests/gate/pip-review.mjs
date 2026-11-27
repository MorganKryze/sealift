// A pip crossing's Analyse, Review and Check steps. The seeded volume holds no pip project, so
// GET /api/projects/ledger-service answers here in the contract's shape, its analysis' pipResult as
// pip-result.json holds it: the fields this branch records (pinnedAt, yanked, previous, uploadedAt,
// the previous crossing, removed, advisories) on new analyses, none of them on the one 0.7.0 wrote. A
// running analysis' event stream carries the events the pip analysis emits (a step event as each step
// ends, progress while check-pins and choose-wheels read index pages, uv's lines), and a stopped one's
// log is log.txt's lines.

const ID = "ledger-service"
const NAME = "ledger-service"
const LONG_NAME = "analytics-ingest-pipeline-airflow-worker"
const LONG_PACKAGE = "acme-ledger-reconciliation-opentelemetry-exporter-postgresql"
const AT = "20261125T091500Z"
const CREATED = "2026-11-25T09:15:00Z"
const TARGET = { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" }
const PREVIOUS = { projectId: ID, projectName: NAME, exportId: "20261120T102000Z", analysisId: "20261120T101500Z", sealedAt: "2026-11-20T10:20:00Z" }
const SHA = (i) => i.toString(16).padStart(64, "0")

const MANYLINUX = "cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64"
const wheel = (name, version, tag = "py3-none-any", i = 1) => ({
  file: `${name.replace(/-/g, "_")}-${version}-${tag}.whl`,
  url: `https://files.pythonhosted.org/packages/${SHA(i).slice(0, 2)}/${name}-${version}.whl`,
  sha256: SHA(i),
  size: 48_000 + i * 977,
  uploadedAt: "2025-03-31T14:00:00Z",
})
const finding = (id, severity, fixedVersions = [], title) => ({ id, severity, fixedVersions, ...(title ? { title } : {}) })
const at = (file, line) => [{ file, line }]
const same = (version, cves = []) => ({ version, cves, majorJump: false })
const jumped = (version, cves = []) => ({ version, cves, majorJump: true })
const pkg = (name, version, more = {}) => ({ name, version, files: ["requirements.txt"], wheel: wheel(name, version), cves: [], ...more })

// The mockup's crossing: django jumps, ecdsa keeps a CVE no version fixes, requests 2.32.0 is yanked,
// 12 pins changed, 4 packages added, 2 with a fix in a newer release, the rest unchanged.
const CHANGED = [
  ["Pillow", "10.2.0", "10.4.0", MANYLINUX, [finding("CVE-2024-28219", "HIGH", ["10.3.0"])]],
  ["Jinja2", "3.1.3", "3.1.5", undefined, [finding("CVE-2024-34064", "MEDIUM", ["3.1.4"]), finding("CVE-2024-56201", "MEDIUM", ["3.1.5"]), finding("CVE-2024-56326", "MEDIUM", ["3.1.5"])]],
  ["urllib3", "2.2.1", "2.2.3", undefined, [finding("CVE-2024-37891", "MEDIUM", ["2.2.2"])]],
  ["idna", "3.6", "3.10", undefined, [finding("CVE-2024-3651", "MEDIUM", ["3.7"])], []],
  ["certifi", "2023.11.17", "2024.8.30", undefined, [finding("CVE-2024-39689", "LOW", ["2024.7.4"])], []],
  ["cryptography", "42.0.5", "42.0.8", MANYLINUX, []],
  ["SQLAlchemy", "2.0.25", "2.0.36", MANYLINUX, []],
  ["pydantic", "2.6.1", "2.10.4", undefined, []],
  ["redis", "5.0.1", "5.2.1", undefined, []],
  ["boto3", "1.34.40", "1.35.90", undefined, [], ["constraints.txt"]],
  ["charset-normalizer", "3.3.2", "3.4.1", MANYLINUX, [], []],
  ["zope.interface", "6.1", "6.4.post2", MANYLINUX, []],
]
const ADDED = ["aiosignal", "frozenlist", "multidict", "yarl"]
const FIXABLE = [
  ["gunicorn", "22.0.0", [finding("CVE-2024-6827", "HIGH", ["23.0.0"])]],
  ["werkzeug", "3.0.3", [finding("CVE-2024-49766", "HIGH", ["3.0.6"])]],
]

function ledger({ noWheel = 0, written = false } = {}) {
  const packages = [
    pkg("django", "5.1.4", { pinnedAt: at("requirements.txt", 3), wheel: wheel("django", "5.1.4", "py3-none-any", 3), previous: jumped("4.2.16", [finding("CVE-2024-45230", "HIGH", ["4.2.17"]), finding("CVE-2024-45231", "MEDIUM", ["4.2.17"])]) }),
    pkg("numpy", "2.1.3", { pinnedAt: at("requirements.txt", 8), wheel: wheel("numpy", "2.1.3", MANYLINUX, 4), previous: jumped("1.26.4") }),
    pkg("ecdsa", "0.19.1", { pinnedAt: at("requirements.txt", 5), cves: [finding("CVE-2024-23342", "HIGH", [], "ecdsa: Minerva timing attack on P-256 in python-ecdsa")], previous: same("0.19.1", [finding("CVE-2024-23342", "HIGH")]) }),
    pkg("requests", "2.32.0", { pinnedAt: at("requirements.txt", 6), yanked: { reason: "Yanked due to conflicts with CVE-2024-35195 mitigation" }, previous: same("2.32.0") }),
    ...CHANGED.map(([name, from, to, tag, cves, files], i) =>
      pkg(name.toLowerCase(), to, { ...(files ? { files } : {}), ...(files?.length === 0 ? {} : { pinnedAt: at(files?.[0] ?? "requirements.txt", 10 + i) }), wheel: wheel(name.toLowerCase(), to, tag, 10 + i), previous: same(from, cves) }),
    ),
    ...ADDED.map((name, i) => pkg(name, "1.4.1", { files: [], wheel: wheel(name, "1.4.1", MANYLINUX, 30 + i) })),
    ...FIXABLE.map(([name, version, cves], i) => pkg(name, version, { pinnedAt: at("requirements.txt", 30 + i), cves, previous: same(version, cves) })),
    ...Array.from({ length: 126 }, (_, i) => pkg(`ledger-lib-${String(i).padStart(3, "0")}`, `1.${i % 9}.${i % 4}`, { files: i % 3 ? [] : ["requirements.txt"], previous: same(`1.${i % 9}.${i % 4}`) })),
  ]
  const blocked = [
    ["psycopg2", "2.9.10", "source-only", 4],
    ["pyodbc", "5.2.0", "other-platforms", 9],
    ["mysqlclient", "2.2.6", "no-files", 12],
  ].slice(0, noWheel)
  for (const [name, version, , line] of blocked) packages.push(pkg(name, version, { pinnedAt: at("requirements.txt", line), wheel: undefined, previous: same(version) }))
  packages.sort((a, b) => a.name.localeCompare(b.name))
  return {
    pipResult: {
      target: TARGET,
      files: ["requirements.txt", "constraints.txt"],
      packages,
      blocking: blocked.map(([name, version, kind, line]) => ({ name, version, kind, detail: { "source-only": "source distribution only", "other-platforms": "wheels for other platforms only", "no-files": "no files on the index" }[kind], pinnedAt: at("requirements.txt", line) })),
      warnings: [],
      previous: PREVIOUS,
      removed: [{ name: "py", version: "1.11.0", cves: [finding("CVE-2022-42969", "MEDIUM")] }],
      advisories: { "CVE-2024-23342": { title: "ecdsa: Minerva timing attack on P-256 in python-ecdsa", published: "2024-01-23T00:15:00Z" } },
    },
    reasons: written
      ? {
          "major-jump:django": "Moved to Django 5.1 in branch django-5, all tests green",
          "major-jump:numpy": "pandas 2.2 and our code run on NumPy 2 since PR #88",
          "cve-without-fix:ecdsa": "Only verifies signatures from our own HSM; never signs",
          "yanked:requests": "Our client tests run on 2.32.0; the move to 2.32.3 is #214",
        }
      : { "major-jump:numpy": "pandas 2.2 and our code run on NumPy 2 since PR #88" },
  }
}

// The worst case: 1,284 packages under a 40-character name, 15 major jumps (pandas-stubs among them),
// 15 CVEs with no fix in 6 packages (mlflow's 9), the 60-character name and the longest wheel name.
const MLFLOW = Array.from({ length: 9 }, (_, i) => finding(`CVE-2024-${37052 + i}`, i < 2 ? "CRITICAL" : i < 6 ? "HIGH" : "MEDIUM", [], `mlflow: deserialization of untrusted data in the ${["pyfunc", "pytorch", "sklearn", "tensorflow", "langchain", "recipes", "pmdarima", "lightgbm", "xgboost"][i]} flavor`))
function worst() {
  const jumps = [["pandas-stubs", "1.5.3.230321", "2.2.3.241126"], ["django", "4.2.16", "5.1.4"], ["numpy", "1.26.4", "2.1.3"], ["pandas", "1.5.3", "2.2.3"], ["sqlalchemy", "1.4.54", "2.0.36"], ["pydantic", "1.10.19", "2.10.4"], ["celery", "4.4.7", "5.4.0"], ["redis", "4.6.0", "5.2.1"], ["marshmallow", "3.23.2", "4.0.0"], ["flask", "2.3.3", "3.1.0"], ["werkzeug", "2.3.8", "3.1.3"], ["click", "7.1.2", "8.1.8"], ["protobuf", "4.25.5", "5.29.2"], ["grpcio", "1.68.1", "2.0.0"], ["apache-airflow", "2.10.4", "3.0.0"]]
  const noFix = [["mlflow", "2.19.0", MLFLOW], ["ecdsa", "0.19.1", [finding("CVE-2024-23342", "HIGH")]], ["py", "1.11.0", [finding("CVE-2022-42969", "MEDIUM")]], ["future", "1.0.0", [finding("CVE-2024-1001", "MEDIUM"), finding("CVE-2024-1002", "LOW")]], ["pyjwt", "2.10.1", [finding("CVE-2024-53861", "LOW")]], ["paramiko", "3.5.0", [finding("CVE-2023-48795", "MEDIUM")]]]
  const packages = [
    ...jumps.map(([name, from, to], i) => pkg(name, to, { pinnedAt: at("requirements.txt", 2 + i), wheel: wheel(name, to, i % 2 ? MANYLINUX : "py3-none-any", 100 + i), previous: jumped(from) })),
    ...noFix.map(([name, version, cves], i) => pkg(name, version, { pinnedAt: at("requirements.txt", 20 + i), cves, previous: same(version, cves) })),
    pkg(LONG_PACKAGE, "1.4.0", { pinnedAt: at("requirements.txt", 1), wheel: wheel(LONG_PACKAGE, "1.4.0", `${MANYLINUX}.musllinux_1_2_x86_64`, 99), previous: same("1.3.9") }),
    ...Array.from({ length: 1262 }, (_, i) => pkg(`ingest-lib-${String(i).padStart(4, "0")}`, `${1 + (i % 9)}.${i % 23}.${i % 7}`, { files: i % 4 ? [] : ["requirements-dev.txt"], previous: same(i % 5 ? `${1 + (i % 9)}.${i % 23}.${i % 7}` : `${1 + (i % 9)}.${i % 23}.0`) })),
  ].sort((a, b) => a.name.localeCompare(b.name))
  return { target: TARGET, files: ["requirements.txt", "requirements-dev.txt", "constraints.txt"], packages, blocking: [], warnings: [], previous: { ...PREVIOUS, projectName: LONG_NAME } }
}

// pip-result.json as 0.7.0 wrote it: no previous crossing, no yanked mark, no pin places; its yanked
// release is a warning sentence.
const LEGACY = {
  target: TARGET,
  files: ["requirements.txt"],
  packages: [
    { name: "jinja2", version: "3.1.4", files: [], wheel: { file: "jinja2-3.1.4-py3-none-any.whl", url: "https://files.pythonhosted.org/packages/jinja2-3.1.4.whl", sha256: SHA(7), size: 133_271 }, cves: [{ id: "CVE-2024-56201", severity: "MEDIUM", fixedVersions: ["3.1.5"], title: "jinja2: Jinja has a sandbox breakout through malicious filenames" }] },
    { name: "requests", version: "2.32.0", files: ["requirements.txt"], wheel: { file: "requests-2.32.0-py3-none-any.whl", url: "https://files.pythonhosted.org/packages/requests-2.32.0.whl", sha256: SHA(8), size: 63_589 }, cves: [] },
  ],
  blocking: [],
  warnings: ["requests==2.32.0 is yanked on the index: Yanked due to conflicts with CVE-2024-35195 mitigation"],
}

const analysis = (more) => ({ id: AT, projectId: ID, createdAt: CREATED, uvVersion: "0.13.7", trivyVersion: "0.76.2", trivyDbDate: "2026-11-25T06:12:00Z", ...more })
const answer = (page, project) => page.route((url) => url.pathname === `/api/projects/${ID}`, (route) => route.fulfill({ json: project }))
const projectWith = (analyses, name = NAME) => ({ id: ID, name, ecosystem: "pip", pipTarget: TARGET, analyses, exports: [] })
const stored = (page, reasons) =>
  page.addInitScript(([key, value]) => sessionStorage.setItem(key, JSON.stringify(value)), [`sealift:reasons:${AT}`, reasons])
const review = (made, name) => async (page) => {
  await answer(page, projectWith([analysis({ state: "done", pipResult: made.pipResult ?? made })], name))
  if (made.reasons) await stored(page, made.reasons)
}

// One frame per event, as internal/api writes them.
const frame = (kind, data) => `event: ${kind}\ndata: ${JSON.stringify({ kind, job: "analysis-9", storeId: AT, data })}\n\n`
const ORDER = ["validate", "prepare-tools", "check-pins", "resolve", "choose-wheels", "scan"]
const ended = (count) => ORDER.slice(0, count).map((name, i) => frame("step", { name, state: "done", durationMs: [90, 2400, 31_000, 8200, 12_500][i] }))
const RUNNING = [
  [],
  [frame("log", { line: "uv 0.13.7 ready" })],
  [frame("log", { line: "check-pins: 212 of 486 pins read" }), frame("progress", { step: "check-pins", done: 212, total: 486 })],
  [frame("progress", { step: "check-pins", done: 486, total: 486 }), frame("log", { line: "uv: Resolved 1,284 packages in 7.92s" })],
  [frame("progress", { step: "choose-wheels", done: 40, total: 120 })],
  [frame("progress", { step: "choose-wheels", done: 120, total: 120 }), frame("log", { line: "trivy: scanning 1,284 packages" })],
]
const running = (i) => async (page) => {
  await answer(page, projectWith([analysis({ state: "running" })]))
  await page.route((url) => url.pathname === "/api/jobs/current/events", (route) => route.fulfill({ status: 200, contentType: "text/event-stream", body: [...ended(i), ...RUNNING[i]].join("") }))
}
const failed = (failure, log, pipResult) => async (page) => {
  await answer(page, projectWith([analysis({ state: "failed", failure, ...(pipResult ? { pipResult } : {}) })]))
  await page.route((url) => url.pathname === `/api/projects/${ID}/analyses/${AT}/log`, (route) => route.fulfill({ status: 200, contentType: "text/plain", body: log }))
}
const PROBLEMS =
  "3 problems in the requirements files: requirements.txt line 3: Django>=4.2,<5: not pinned with ==; requirements.txt line 7: -e ./libs/shared-models: not on PyPI; requirements-dev.txt line 2: redis==5.1.1: conflicting pins for redis: requirements.txt:9 pins 5.2.0, requirements-dev.txt:2 pins 5.1.1"
const NO_WHEEL = "uv pip compile: exit status 1: Because psycopg2==2.9.10 has no usable wheels and you require psycopg2==2.9.10, we can conclude that your requirements are unsatisfiable; pinned by requirements.txt"
const INDEX = 'pip: Get "https://pypi.org/pypi/django/5.1.4/json": dial tcp: lookup pypi.org: no such host'

const PATH = `/crossings/${ID}`
const button = (name) => ({ role: "button", name })
const YANKED_TEXT = "The publisher withdrew this release from the index, most often for a bug. pip still installs it when a file pins this exact version, as here."
const WHEEL_TEXT = "A wheel is a package built ahead for one Python version and platform, which pip installs without running any of its code. A source distribution must be built during the install, so none crosses."
const CVE_TEXT = "A CVE is a publicly listed security flaw, named by an id such as CVE-2024-4068. Known CVEs counts the ones the scan found in these versions."

export const states = [
  ...["Reading the requirements files", "Preparing uv and the CVE database", "Checking a wheel for each pin", "Resolving the set", "Choosing a wheel per package", "Scanning for known CVEs"].map((title, i) => ({
    path: PATH,
    name: `analyse running, ${ORDER[i]}`,
    before: running(i),
    ready: title,
  })),
  { path: PATH, name: "analyse failed on the requirements", before: failed({ step: "validate", message: PROBLEMS }, "requirements.txt line 3: Django>=4.2,<5: not pinned with ==\n"), ready: "3 problems in the requirements files" },
  {
    path: PATH,
    name: "analyse failed on a package with no wheel",
    before: failed({ step: "resolve", message: NO_WHEEL }, `uv: ${NO_WHEEL}\n`, { ...LEGACY, packages: [], warnings: [], blocking: [{ name: "psycopg2", version: "2.9.10", kind: "source-only", detail: "source distribution only", pinnedAt: at("requirements.txt", 4) }] }),
    ready: "A package has no wheel for the target",
  },
  { path: PATH, name: "analyse failed on the index", before: failed({ step: "check-pins", message: INDEX }, "check-pins: no answer from pypi.org\n"), ready: "No answer from pypi.org" },
  { path: PATH, name: "analyse cancelled", before: (page) => answer(page, projectWith([analysis({ state: "cancelled" })])), ready: "Analysis cancelled" },
  { path: PATH, name: "review with a group open", before: review(ledger()), click: [button(/^12 pins changed/)], ready: "Opens once django, ecdsa and requests have a reason." },
  { path: PATH, name: "review with the CVE explanation open", before: review(ledger()), click: [button("What a CVE is")], ready: CVE_TEXT },
  { path: PATH, name: "review with the yanked explanation open", before: review(ledger()), click: [button("What a yanked release is")], ready: YANKED_TEXT },
  { path: PATH, name: "review with one package with no wheel", before: review(ledger({ noWheel: 1, written: true })), ready: "Opens once psycopg2 has a wheel for the target." },
  { path: PATH, name: "review with three packages with no wheel", before: review(ledger({ noWheel: 3 })), click: [button("What a wheel is")], ready: WHEEL_TEXT },
  { path: PATH, name: "review, the worst case", before: review(worst(), LONG_NAME), click: [button(/packages unchanged/)], ready: "21 things need you" },
  { path: PATH, name: "review, mlflow's CVEs open", before: review(worst(), LONG_NAME), click: [button("9 CVEs of mlflow")], ready: "CVE-2024-37060" },
  { path: PATH, name: "decide for a yanked release", before: review(ledger()), click: [button("Decide requests")], ready: "“Yanked due to conflicts with CVE-2024-35195 mitigation”" },
  { path: PATH, name: "decide for a CVE", before: review(ledger()), click: [button("Decide ecdsa")], ready: "ecdsa: Minerva timing attack on P-256 in python-ecdsa" },
  { path: PATH, name: "jump empty", before: review(ledger()), click: [button("Jump django")], ready: "Write a reason to record." },
  { path: PATH, name: "jump written", before: review(ledger({ written: true })), click: [button("Change django")], ready: "django-5.1.4-py3-none-any.whl" },
  { path: PATH, name: "a review 0.7.0 wrote", before: review(LEGACY), ready: "requests==2.32.0 is yanked on the index: Yanked due to conflicts with CVE-2024-35195 mitigation" },
  { path: `${PATH}?step=check`, name: "the crossing's Check", before: review(ledger()), ready: "2 requirements files" },
]
