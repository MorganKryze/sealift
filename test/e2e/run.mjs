// Drives the end-to-end test through sealift's own HTTP API (spec section
// 9): create a project, follow its analysis, queue an export, download the
// archive, publish it to an air-gapped Verdaccio, and install against it.
// This proves sealift's real analysis and export code, not a hand-built
// stand-in archive.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const SEALIFT_URL = required("SEALIFT_URL");
const REGISTRY_URL = required("REGISTRY_URL"); // uplinked Verdaccio sealift resolves against
const AIRGAP_URL = required("AIRGAP_URL"); // no-uplink Verdaccio for the final pnpm install
const api = `${SEALIFT_URL}/api`;

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} must be set`);
  return v;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function json(url, init) {
  const res = await fetch(url, init);
  const body = await res.json();
  if (!res.ok) {
    throw new Error(`${init?.method ?? "GET"} ${url} -> ${res.status}: ${JSON.stringify(body)}`);
  }
  return body;
}

async function waitForHealthz() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${SEALIFT_URL}/healthz`);
      if (res.ok) return;
    } catch {
      // sealift is still starting; retry.
    }
    await sleep(1000);
  }
  throw new Error("sealift never became healthy");
}

async function pollUntilDone(url) {
  for (;;) {
    const body = await json(url);
    if (body.state === "done") return body;
    if (["failed", "cancelled", "interrupted"].includes(body.state)) {
      throw new Error(`${url} ended in state ${body.state}: ${JSON.stringify(body)}`);
    }
    await sleep(2000);
  }
}

function publish(registryUrl, dir) {
  execFileSync("sh", ["publish.sh", registryUrl, dir], { stdio: "inherit" });
}

// tarballName mirrors spec section 2's npm pack naming: name-version.tgz,
// and scope-name-version.tgz for @scope/name.
function tarballName(name, version) {
  const flat = name.startsWith("@") ? name.slice(1).replace("/", "-") : name;
  return `${flat}-${version}.tgz`;
}

// resolvesFromRegistry asks a registry for one exact version, the way a
// real air-gapped install would, and returns whether it answered with
// that version rather than a 404.
function resolvesFromRegistry(registryUrl, name, version) {
  try {
    const out = execFileSync("npm", ["view", `${name}@${version}`, "version", "--registry", registryUrl], {
      encoding: "utf8",
    }).trim();
    return out === version;
  } catch {
    return false;
  }
}

async function main() {
  await waitForHealthz();
  console.log("sealift is healthy");

  // The fixture package sits only in the local registry: publish it before
  // sealift resolves anything, so its analysis finds it on the first try.
  execFileSync("sh", ["build-archive.sh"], { stdio: "inherit" });
  // path.resolve, not the bare relative name: npm-package-arg reads an
  // extensionless-looking relative path with a "/" as a hosted git
  // shorthand ("owner/repo"), not a local directory, and tries to shell
  // out to git and ssh over that "owner" instead of publishing the file.
  publish(REGISTRY_URL, path.resolve("fixture-out"));

  // Nothing installs Trivy on a fresh volume before the first analysis
  // needs it; the interface's force-update button (spec section 6) is the
  // real path to reach for one, so this drives that same route.
  const tools = await json(`${api}/tools/trivy/update`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ force: true }),
  });
  console.log("trivy installed:", tools.trivyActive);

  // An export refuses to start while signatureKey stays empty (spec
  // section 3), and PUT requires the full settings object.
  const settings = await json(`${api}/settings`);
  settings.signatureKey = "e2e-test-signature";
  await json(`${api}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(settings),
  });

  const form = new FormData();
  const manifest = readFileSync("project/package.json");
  form.append("manifest", new Blob([manifest], { type: "application/json" }), "package.json");
  const project = await json(`${api}/projects`, { method: "POST", body: form });
  const projectId = project.id;
  const analysisId = project.analyses[0].id;
  console.log("project created:", projectId, "analysis queued:", analysisId);

  const analysis = await pollUntilDone(`${api}/projects/${projectId}/analyses/${analysisId}`);
  console.log(
    "analysis done:",
    analysis.result.dependencies
      .map((d) => `${d.name}@${d.current} (${d.candidates.length} candidate(s))`)
      .join(", "),
  );

  // selection is a list of versions per dependency (api/openapi.yaml,
  // internal/jobs.ExportRequest): a dependency can ship more than one
  // version in the same archive, so a version that breaks the build on
  // the air-gapped side is not the only one already sitting in Nexus
  // (decisions.md, "rank candidates, let the user download any version").
  // includeProject ships the project's own resolved tree regardless of
  // what else gets selected, so the final pnpm install below always has
  // what project/package.json actually pins, whichever dependency the
  // multi-version proof below picks extra candidates from.
  const selection = {};
  let multiVersion = null;
  for (const d of analysis.result.dependencies) {
    if (!multiVersion && d.candidates.length >= 2) {
      multiVersion = { name: d.name, versions: [d.candidates[0].version, d.candidates[d.candidates.length - 1].version] };
      selection[d.name] = multiVersion.versions;
    }
  }
  if (multiVersion) {
    console.log(`selecting two versions of ${multiVersion.name}: ${multiVersion.versions.join(", ")}`);
  } else {
    console.log("no dependency offered two or more candidates; exporting only what includeProject carries");
  }

  const exportJob = await json(`${api}/projects/${projectId}/analyses/${analysisId}/exports`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ selection, includeProject: true }),
  });
  console.log("export queued:", exportJob.id);
  await pollUntilDone(`${api}/projects/${projectId}/exports/${exportJob.id}`);
  console.log("export done");

  const archiveRes = await fetch(
    `${api}/projects/${projectId}/exports/${exportJob.id}/files/packages_npm.tar.gz`,
  );
  if (!archiveRes.ok) throw new Error(`download archive: ${archiveRes.status}`);
  writeFileSync("packages_npm.tar.gz", Buffer.from(await archiveRes.arrayBuffer()));

  const work = mkdtempSync(path.join(tmpdir(), "sealift-e2e-"));
  execFileSync("tar", ["-xzf", "packages_npm.tar.gz", "-C", work]);

  const sigPath = path.join(work, "out", "signature.key");
  const sig = readFileSync(sigPath);
  if (sig.length === 0 || sig[sig.length - 1] === 0x0a) {
    throw new Error(`out/signature.key must hold the key with no trailing newline, got ${JSON.stringify(sig.toString())}`);
  }
  console.log(`out/signature.key OK: ${sig.length} bytes, no trailing newline`);

  if (multiVersion) {
    const files = readdirSync(path.join(work, "out"));
    for (const version of multiVersion.versions) {
      const want = tarballName(multiVersion.name, version);
      if (!files.includes(want)) {
        throw new Error(`packages_npm.tar.gz is missing ${want} (selected two versions of ${multiVersion.name}: ${multiVersion.versions.join(", ")}; archive has: ${files.join(", ")})`);
      }
    }
    console.log(`packages_npm.tar.gz holds both selected versions of ${multiVersion.name}: ${multiVersion.versions.map((v) => tarballName(multiVersion.name, v)).join(", ")}`);
  }

  publish(AIRGAP_URL, path.join(work, "out"));

  if (multiVersion) {
    for (const version of multiVersion.versions) {
      if (!resolvesFromRegistry(AIRGAP_URL, multiVersion.name, version)) {
        throw new Error(`${multiVersion.name}@${version} does not resolve from the air-gapped registry after publish`);
      }
    }
    console.log(`both selected versions of ${multiVersion.name} resolve from the air-gapped registry: ${multiVersion.versions.join(", ")}`);
  }

  execFileSync("pnpm", ["install", "--registry", AIRGAP_URL], { cwd: "project", stdio: "inherit" });
  console.log("pnpm install succeeded against the air-gapped registry, no uplink");

  const installed = JSON.parse(
    readFileSync("project/node_modules/sealift-e2e-publishconfig-pkg/package.json", "utf8"),
  );
  if (installed.publishConfig) {
    throw new Error("publishConfig was not stripped from the installed fixture package");
  }
  console.log("publishConfig confirmed stripped from the installed fixture package");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
