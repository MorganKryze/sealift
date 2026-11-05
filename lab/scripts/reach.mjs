// Prints what this side of the lab can reach. Run it from airgap-shell or
// connected-shell: `docker compose run --rm airgap-shell node /scripts/reach.mjs`.
const targets = [
  ["registry.npmjs.org", "https://registry.npmjs.org/"],
  ["pypi.org", "https://pypi.org/simple/"],
  ["nexus", "http://nexus:8081/service/rest/v1/status"],
  ["minio", "http://minio:9000/minio/health/live"],
  ["keycloak", "http://keycloak:8080/realms/lab"],
]
for (const [name, url] of targets) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) })
    console.log(`reachable    ${name} (${res.status})`)
  } catch (err) {
    console.log(`unreachable  ${name} (${err.cause?.code ?? err.name})`)
  }
}
