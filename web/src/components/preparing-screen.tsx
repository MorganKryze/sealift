import { useQuery } from "@tanstack/react-query"
import { Check, Database, KeyRound, LoaderCircle, Package, ShieldCheck, TriangleAlert } from "lucide-react"
import { type ReactNode } from "react"

import { getInstance, type Instance } from "@/api/settings"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { formatDbDate } from "@/lib/format-tools"
import { cn } from "@/lib/utils"

type Item = Instance["preparing"][number]

const POLL_MS = 3000

/** Shows the preparing screen until the instance is ready, then its children; it asks again every 3 s until then. */
export function WhenReady({ children }: { children: ReactNode }) {
  const query = useQuery({
    queryKey: ["instance"],
    queryFn: getInstance,
    refetchInterval: (q) => (q.state.data?.ready ? false : POLL_MS),
  })

  if (query.data?.ready) return children
  if (query.data) return <PreparingScreen instance={query.data} />

  if (query.isError) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
        <p role="alert" className="text-sm text-severity-critical-fg">
          Could not reach sealift.
        </p>
        <Button onClick={() => void query.refetch()}>Retry</Button>
      </div>
    )
  }

  return (
    <div role="status" className="flex flex-1 items-center justify-center p-8 text-muted">
      Loading…
    </div>
  )
}

const ICONS: Record<Item["name"], ReactNode> = {
  trivy: <ShieldCheck className="size-5" />,
  "trivy-db": <Database className="size-5" />,
  "signing-key": <KeyRound className="size-5" />,
  pnpm: <Package className="size-5" />,
  uv: <Package className="size-5" />,
}

function title({ name, version }: Item) {
  switch (name) {
    case "trivy":
      return `Trivy ${version ?? ""}`.trim()
    case "trivy-db":
      return "Vulnerability database"
    case "signing-key":
      return "Signing key"
    default:
      return `${name} ${version ?? ""}`.trim()
  }
}

function description(item: Item) {
  switch (item.name) {
    case "trivy":
      return "Vulnerability scanner, checked against the sha256 built into sealift."
    case "trivy-db":
      return item.state === "ready" && item.version ? `Downloaded ${formatDbDate(item.version)}.` : "About 120 MB, refreshed before each analysis."
    case "signing-key":
      return "Signs the manifest of each archive. Carry its public key once to the import side."
    case "pnpm":
      return "Resolves npm projects."
    case "uv":
      return "Resolves pip projects."
  }
}

const STATE_WORDS: Record<Item["state"], string> = { ready: "Ready", preparing: "Preparing", failed: "Failed" }

/** What the start prepares, item by item. Nothing here installs: the server does it on its own and retries a failure. */
export function PreparingScreen({ instance }: { instance: Instance }) {
  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col gap-6 px-5 py-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-ink">Preparing sealift</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">
          sealift downloads what an analysis needs and checks each download. A failed step tries again on its own. The home opens once every item is
          ready.
        </p>
      </div>

      <ul className="grid gap-3">
        {instance.preparing.map((item) => (
          <li key={item.name}>
            <PreparingRow item={item} />
          </li>
        ))}
      </ul>
    </div>
  )
}

function PreparingRow({ item }: { item: Item }) {
  const name = title(item)
  const ready = item.state === "ready"
  const failed = item.state === "failed"
  return (
    <Card className="grid grid-cols-[40px_1fr_auto] items-start gap-3.5 p-4">
      <span
        className={cn(
          "grid size-10 flex-none place-items-center rounded-[10px] border",
          ready ? "border-transparent bg-accent/15 text-accent" : "border-line bg-card text-muted",
        )}
      >
        {ICONS[item.name]}
      </span>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-ink">{name}</h2>
        <p className="text-sm text-muted">{description(item)}</p>
        {item.name === "signing-key" && item.version ? (
          <code className="mt-2 block font-mono text-[13px] text-ink [overflow-wrap:anywhere]">{item.version}</code>
        ) : null}
        {failed ? (
          <div className="mt-2 flex flex-col gap-1 text-sm">
            {item.reason ? <p className="text-severity-critical-fg [overflow-wrap:anywhere]">{item.reason}</p> : null}
            {item.nextTry ? <p className="text-muted">Next try at {new Date(item.nextTry).toLocaleTimeString()}.</p> : null}
          </div>
        ) : null}
      </div>
      {/* One status per item, kept mounted across polls, so each change is announced once and politely. */}
      <p
        role="status"
        className={cn(
          "inline-flex items-center gap-1.5 pt-2.5 text-sm font-medium whitespace-nowrap",
          ready ? "text-severity-resolved-fg" : failed ? "text-severity-critical-fg" : "text-ink",
        )}
      >
        <span className="sr-only">{name}: </span>
        {ready ? (
          <Check className="size-3.5" strokeWidth={3} aria-hidden="true" />
        ) : failed ? (
          <TriangleAlert className="size-3.5" aria-hidden="true" />
        ) : (
          <LoaderCircle className="size-3.5 motion-safe:animate-spin" aria-hidden="true" />
        )}
        {STATE_WORDS[item.state]}
      </p>
    </Card>
  )
}
