import { useQuery } from "@tanstack/react-query"
import { CircleCheck, CircleX, LoaderCircle, RotateCw } from "lucide-react"
import { Fragment, type ReactNode, useEffect, useState } from "react"

import { getInstance, type Instance } from "@/api/settings"
import { Fingerprint } from "@/components/fingerprint/fingerprint"
import { BrandMark, BrandProvider, ContactCard, DEFAULT_BRAND, SideLabel, useBrand } from "@/components/frame/brand"
import { Button } from "@/components/ui/button"
import { formatDbDate } from "@/lib/format-tools"
import { cn } from "@/lib/utils"

type Item = Instance["preparing"][number]

const POLL_MS = 3000

/** The instance's answer, asked again every 3 s until it is ready. */
export function useInstance() {
  return useQuery({
    queryKey: ["instance"],
    queryFn: getInstance,
    refetchInterval: (q) => (q.state.data?.ready ? false : POLL_MS),
  })
}

/** Shows the preparing page until the instance is ready, then its children, under the deployment's brand. */
export function WhenReady({ children }: { children: ReactNode }) {
  const query = useInstance()

  // Set once a poll answered not ready, so the page that follows says
  // preparation ended; a reload on a ready instance says nothing.
  const [waited, setWaited] = useState(false)
  if (query.data && !query.data.ready && !waited) setWaited(true)
  const brand = query.data?.brand ?? DEFAULT_BRAND

  return (
    <BrandProvider brand={brand}>
      <WhenReadyContent query={query}>{children}</WhenReadyContent>
      {/* Kept mounted across the swap to the page, so a screen reader hears the end of preparation. */}
      <p role="status" className="sr-only">
        {query.data?.ready && waited ? `${brand.name} is ready.` : ""}
      </p>
    </BrandProvider>
  )
}

function WhenReadyContent({ query, children }: { query: ReturnType<typeof useInstance>; children: ReactNode }) {
  if (query.data?.ready) return children

  // A failed poll wins over cached data: the states and next-try times on screen may be stale.
  if (query.isError) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-3 p-8 text-center">
        <p role="alert" className="text-sm text-bad">
          Could not reach the server.
        </p>
        <Button onClick={() => void query.refetch()}>Retry</Button>
      </div>
    )
  }
  if (query.data) return <PreparingScreen instance={query.data} />

  return (
    <div role="status" className="flex min-h-screen items-center justify-center p-8 text-muted">
      Loading…
    </div>
  )
}

/** What the start prepares, item by item. Nothing here installs: the server does it on its own and retries a failure. */
export function PreparingScreen({ instance }: { instance: Instance }) {
  const brand = useBrand()
  const ready = instance.preparing.filter((i) => i.state === "ready").length
  const failed = instance.preparing.filter((i) => i.state === "failed").length
  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[720px] flex-col px-5 py-24">
      <div className="flex flex-wrap items-center gap-3">
        <span className="inline-flex min-w-0 items-center gap-2.5 font-semibold text-ink">
          <BrandMark size={28} />
          <span className="text-[15px] [overflow-wrap:anywhere]">{brand.name}</span>
        </span>
        <SideLabel side="online" />
      </div>
      <h1 className="mt-7 text-[28px] leading-tight font-bold tracking-[-0.015em] text-ink">Preparing this instance</h1>
      <p className="mt-1.5 text-muted">
        <span className="figure text-ink">{`${ready} of ${instance.preparing.length} ready`}</span>
        {" · "}
        {failed > 0 ? <span className="font-semibold text-bad">{`${failed} failed`}</span> : "opens by itself"}
      </p>
      <div className="mt-6 rounded-xl border border-rule bg-bg p-1.5">
        <ReadinessList items={instance.preparing} />
      </div>
      {failed > 0 ? <ContactCard /> : null}
    </div>
  )
}

const TITLES: Record<Item["name"], string> = {
  trivy: "Trivy",
  "trivy-db": "CVE database",
  "signing-key": "Signing key",
  pnpm: "pnpm",
  uv: "uv",
}

const STATE_WORDS: Record<Item["state"], string> = { ready: "Ready", preparing: "Preparing", failed: "Failed" }

const SHA256 = /^[0-9a-f]{64}$/

/** Each item the instance needs, with its state; a failed one with its cause and its next try. Reused by Instance. */
export function ReadinessList({ items, warning }: { items: Instance["preparing"]; warning?: string }) {
  return (
    <ul className="grid gap-1.5">
      {items.map((item) => {
        const warned = item.state === "ready" && item.name === "trivy-db" && warning
        return (
          <li
            key={item.name}
            className={cn(
              "grid grid-cols-[20px_minmax(0,1fr)] gap-x-3 px-3 py-3",
              item.state === "failed" && "tinted-bad",
              item.state === "preparing" && "tinted-info",
              warned && "tinted-warn",
            )}
          >
            <StateIcon state={item.state} />
            <div className="flex min-w-0 flex-col gap-2">
              {/* One status per item, kept mounted across polls, so each change is announced once and politely. */}
              <div role="status" className="flex min-w-0 flex-col gap-1">
                <div className="flex min-w-0 flex-wrap items-center justify-between gap-x-3 gap-y-1">
                  <h2 className="text-sm font-semibold text-ink">{TITLES[item.name]}</h2>
                  <ItemState item={item} />
                </div>
                {item.state === "failed" && item.reason ? <Cause text={item.reason} /> : null}
                {warned ? <p className="text-sm text-ink-2 [overflow-wrap:anywhere]">{warning}</p> : null}
              </div>
              {item.state === "failed" && item.nextTry ? <NextTry at={item.nextTry} /> : null}
              {item.name === "signing-key" && item.version && SHA256.test(item.version) ? <Fingerprint value={item.version} label="Signing key sha256" /> : null}
            </div>
          </li>
        )
      })}
    </ul>
  )
}

function StateIcon({ state }: { state: Item["state"] }) {
  if (state === "ready") return <CircleCheck aria-hidden="true" className="mt-0.5 size-4.5 text-ok" />
  if (state === "failed") return <CircleX aria-hidden="true" className="mt-0.5 size-4.5 text-bad" />
  return <LoaderCircle aria-hidden="true" className="mt-0.5 size-4.5 text-info motion-safe:animate-spin" />
}

function ItemState({ item }: { item: Item }) {
  if (item.state === "ready") {
    const figure = item.name === "trivy-db" ? (item.version ? formatDbDate(item.version) : null) : item.name === "signing-key" ? null : item.version
    return (
      <span className="inline-flex items-center gap-2 text-sm">
        {figure ? <span className="figure font-mono text-[12.5px] text-ink">{figure}</span> : null}
        <span className="sr-only">{STATE_WORDS.ready}</span>
      </span>
    )
  }
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center rounded-full border px-2.5 text-xs font-semibold",
        item.state === "failed" ? "border-bad bg-bad text-bg" : "border-info-line bg-bg text-info",
      )}
    >
      {STATE_WORDS[item.state]}
    </span>
  )
}

// A sha256 inside a cause shows as a fingerprint; the rest stays text.
function Cause({ text }: { text: string }) {
  const parts = text.split(/\b([0-9a-f]{64})\b/)
  return (
    <p className="text-sm text-ink-2 [overflow-wrap:anywhere]">
      {parts.map((part, index) =>
        index % 2 === 1 ? (
          <span key={index} className="mx-0.5 inline-flex max-w-full align-middle">
            <Fingerprint value={part} label="sha256" />
          </span>
        ) : (
          <Fragment key={index}>{part}</Fragment>
        ),
      )}
    </p>
  )
}

function useNow() {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])
  return now
}

function delay(ms: number) {
  const seconds = Math.ceil(ms / 1000)
  return seconds < 60 ? `${seconds} s` : `${Math.ceil(seconds / 60)} min`
}

// Outside the item's status: a countdown in a live region would speak every second.
function NextTry({ at }: { at: string }) {
  const left = new Date(at).getTime() - useNow()
  return (
    <span className="inline-flex min-h-7 w-fit items-center gap-1.5 rounded-full border border-bad-line bg-bg px-2.5 text-[13px] text-ink">
      <RotateCw aria-hidden="true" className="size-3.5 text-bad" />
      {left > 0 ? (
        <span>
          Next try in <span className="figure">{delay(left)}</span>
        </span>
      ) : (
        <span>Trying again now</span>
      )}
    </span>
  )
}
