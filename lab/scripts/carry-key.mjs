// Carries the connected sealift's public signing key to the import side:
// `node scripts/carry-key.mjs [url] [file]`. It writes the PEM and prints its
// public key sha256, the value both Settings screens show.
import { createHash, createPublicKey } from "node:crypto"
import { writeFileSync } from "node:fs"

const url = process.argv[2] ?? "http://localhost:18450/api/signing-key"
const file = process.argv[3] ?? "import/public-key.pem"

const res = await fetch(url)
if (!res.ok) {
  console.error(`${url} answered ${res.status}`)
  process.exit(1)
}
const { publicKeyPem } = await res.json()
if (typeof publicKeyPem !== "string") {
  console.error("the answer holds no publicKeyPem")
  process.exit(1)
}
const key = createPublicKey(publicKeyPem)
if (key.asymmetricKeyType !== "ed25519") {
  console.error("the key is not an Ed25519 public key")
  process.exit(1)
}
writeFileSync(file, publicKeyPem)
const der = key.export({ type: "spki", format: "der" })
console.log(createHash("sha256").update(der).digest("hex"))
