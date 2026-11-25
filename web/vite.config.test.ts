// @vitest-environment node
import { mkdtempSync, rmSync } from "node:fs"
import { createServer as createHttpServer, request, type IncomingHttpHeaders, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { createServer } from "vite"
import { expect, test } from "vitest"

import { apiProxy } from "./vite.config"

const portOf = (server: Server) => (server.address() as AddressInfo).port

// The import service refuses a request whose Origin does not name the Host it
// receives, so the proxy in front of it must leave the Host as it came.
test("the api proxy passes on the browser's Host, which its Origin names", async () => {
  const seen: IncomingHttpHeaders[] = []
  const api = createHttpServer((req, res) => {
    seen.push(req.headers)
    res.end()
  })
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve))
  const root = mkdtempSync(join(tmpdir(), "sealift-proxy-"))
  const vite = await createServer({
    configFile: false,
    root,
    cacheDir: join(root, "cache"),
    logLevel: "silent",
    server: {
      host: "127.0.0.1",
      port: 0,
      watch: null,
      proxy: { "/api": { ...apiProxy["/api"], target: `http://127.0.0.1:${portOf(api)}` } },
    },
  })
  try {
    await vite.listen()
    const port = portOf(vite.httpServer as Server)
    const host = `localhost:${port}`
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = request(
        { host: "127.0.0.1", port, method: "POST", path: "/api/tools/uv/install", headers: { Host: host, Origin: `http://${host}`, "Content-Type": "application/json" } },
        (res) => {
          res.resume()
          res.on("end", () => resolve(res.statusCode))
        },
      )
      req.on("error", reject)
      req.end("{}")
    })

    expect(status).toBe(200)
    expect(seen).toHaveLength(1)
    expect(seen[0].origin).toBe(`http://${host}`)
    expect(seen[0].host).toBe(host)
  } finally {
    await vite.close()
    api.closeAllConnections()
    api.close()
    rmSync(root, { recursive: true, force: true })
  }
})
