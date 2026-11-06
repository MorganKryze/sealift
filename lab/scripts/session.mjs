// Signs a lab user in through the gateway and prints the session cookie
// as a Cookie header value: `node scripts/session.mjs alice alice`.
// Run it from the host; it follows the redirects a browser would.
const [user, password] = process.argv.slice(2)
if (!user || !password) {
  console.error("usage: node scripts/session.mjs <user> <password>")
  process.exit(2)
}
const gateway = process.env.GATEWAY ?? "http://localhost:18440"
// Cookies are keyed by name only: the gateway and Keycloak share the host
// "localhost" and the lab sets no two cookies of one name.
const jar = new Map()

function keep(res) {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";")
    const at = pair.indexOf("=")
    const name = pair.slice(0, at).trim()
    const value = pair.slice(at + 1)
    if (value === "" || /max-age=0/i.test(line)) jar.delete(name)
    else jar.set(name, value)
  }
}

const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ")

async function hop(url, init = {}) {
  const res = await fetch(url, {
    ...init,
    redirect: "manual",
    headers: { ...init.headers, cookie: cookieHeader() },
  })
  keep(res)
  return { res, url: String(url) }
}

async function follow(start) {
  let { res, url } = start
  for (let i = 0; i < 12 && res.status >= 300 && res.status < 400; i++) {
    ;({ res, url } = await hop(new URL(res.headers.get("location"), url)))
  }
  return res
}

let res = await follow(await hop(gateway + "/"))
const page = await res.text()
const form = page.match(/<form[^>]*id="kc-form-login"[^>]*>/)?.[0]
const action = form?.match(/action="([^"]+)"/)?.[1]
if (!action) {
  console.error(`no login form after the redirects (last status ${res.status})`)
  process.exit(1)
}
res = await follow(
  await hop(action.replaceAll("&amp;", "&"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: user, password, credentialId: "" }),
  }),
)
const session = [...jar].filter(([k]) => k.startsWith("_oauth2_proxy") && !k.includes("csrf"))
if (session.length === 0) {
  console.error(`no session cookie after sign-in (last status ${res.status})`)
  process.exit(1)
}
console.log(session.map(([k, v]) => `${k}=${v}`).join("; "))
