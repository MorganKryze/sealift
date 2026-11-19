// Sends forged and stale tokens straight to the import service, past the
// gateway, and prints the answer: run it from airgap-shell.
//
//   docker compose run --rm airgap-shell node /scripts/forge.mjs other-key
//   docker compose run --rm airgap-shell node /scripts/forge.mjs none
//   docker compose run --rm airgap-shell node /scripts/forge.mjs expired
//   docker compose run --rm -e HEADER=X-Auth-Request-Access-Token airgap-shell node /scripts/forge.mjs absent
//
// other-key  an RS256 token signed with a key the realm does not hold
// none       a token whose header says alg none
// expired    a real realm token, sent once its lifetime and the service's
//            60-second leeway have passed (about 6 minutes)
// absent     no token header at all
//
// HEADER names the header that carries the token. It defaults to
// X-Access-Token, the header the settings name unless `token.header` says
// otherwise.
//
// The tokens are never printed.
import { createSign, generateKeyPairSync } from "node:crypto"

const service = process.env.SERVICE ?? "http://import-server:8080"
const realm = process.env.REALM ?? "http://keycloak:8080/realms/lab"
const issuer = "http://localhost:18444/realms/lab"
const leewaySeconds = 60
const header = process.env.HEADER ?? "X-Access-Token"

const b64 = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url")

async function realmKid() {
  const keys = (await (await fetch(`${realm}/protocol/openid-connect/certs`)).json()).keys
  return keys.find((k) => k.alg === "RS256" && k.use === "sig").kid
}

function claims() {
  const now = Math.floor(Date.now() / 1000)
  return { iss: issuer, aud: "oauth2-proxy", sub: "forged", preferred_username: "alice", iat: now, exp: now + 300 }
}

async function otherKey() {
  const header = { alg: "RS256", typ: "JWT", kid: await realmKid() }
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const signing = `${b64(header)}.${b64(claims())}`
  const signature = createSign("RSA-SHA256").update(signing).sign(privateKey).toString("base64url")
  return `${signing}.${signature}`
}

async function none() {
  return `${b64({ alg: "none", typ: "JWT", kid: await realmKid() })}.${b64(claims())}.`
}

async function expired() {
  const res = await fetch(`${realm}/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "password",
      client_id: "oauth2-proxy",
      client_secret: "lab-client-secret",
      username: "alice",
      password: "alice",
    }),
  })
  const { access_token: token, expires_in: lifetime } = await res.json()
  const wait = lifetime + leewaySeconds + 5
  console.log(`token lifetime ${lifetime}s, waiting ${wait}s`)
  await new Promise((resolve) => setTimeout(resolve, wait * 1000))
  return token
}

const absent = async () => null

const modes = { "other-key": otherKey, none, expired, absent }
const mode = process.argv[2]
if (!modes[mode]) {
  console.error(`usage: node forge.mjs ${Object.keys(modes).join("|")}`)
  process.exit(2)
}
const token = await modes[mode]()
const res = await fetch(`${service}/api/me`, { headers: token === null ? {} : { [header]: token } })
const body = await res.json().catch(() => ({}))
console.log(`${mode}: ${res.status} ${body.title ?? ""} | ${body.detail ?? ""}`)
