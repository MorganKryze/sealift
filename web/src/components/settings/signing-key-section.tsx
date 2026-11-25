import { useQuery } from "@tanstack/react-query"
import { ChevronDown, CircleCheck, Download, RotateCcwKey } from "lucide-react"
import { useId, useState } from "react"

import { getSigningKey } from "@/api/settings"
import { CopyControl } from "@/components/copy-control"
import { Fingerprint } from "@/components/fingerprint/fingerprint"
import { cn } from "@/lib/utils"

const PEM_FILE = "sealift-public-key.pem"
const REGENERATE = "sealift signing-key regenerate"

/** Hands the browser the PEM as a file, built here from the answer: no route serves one. */
function downloadPem(pem: string) {
  const url = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }))
  const link = document.createElement("a")
  link.href = url
  link.download = PEM_FILE
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

/** The key every archive's manifest is signed with, read-only: the container regenerates it, never this page. */
export function SigningKeySection() {
  const keyQuery = useQuery({ queryKey: ["signing-key"], queryFn: getSigningKey })
  const [howOpen, setHowOpen] = useState(false)
  const howId = useId()
  const key = keyQuery.data

  return (
    <div className="grid grid-cols-[20px_minmax(0,1fr)] gap-x-3 px-3 py-3">
      <CircleCheck aria-hidden="true" className="mt-0.5 size-4.5 text-ok" />
      <div className="flex min-w-0 flex-col gap-1">
        <div className="flex min-w-0 items-start justify-between gap-3">
          <div className="flex flex-wrap items-baseline gap-x-1.5">
            <h2 className="text-sm font-semibold text-ink">Signing key</h2>
            <span className="font-mono text-[12.5px] text-ink-2">Ed25519</span>
          </div>
          {key ? (
            <button
              type="button"
              aria-label="Download public key"
              onClick={() => downloadPem(key.publicKeyPem)}
              className="-mt-1.5 -mr-1.5 grid size-8 flex-none place-items-center rounded-md text-ink-2 outline-none hover:bg-hover hover:text-ink focus-visible:ring-2 focus-visible:ring-ink"
            >
              <Download aria-hidden="true" className="size-4" />
            </button>
          ) : null}
        </div>
        {keyQuery.isPending ? (
          <p role="status" className="text-sm text-muted">
            Loading the signing key
          </p>
        ) : !key ? (
          <p role="alert" className="text-sm text-bad">
            Could not load the signing key: {keyQuery.error?.message}
          </p>
        ) : (
          <>
            <p className="text-[13px] text-muted">Public key sha256</p>
            <Fingerprint value={key.publicKeySha256} label="Public key sha256" />
            <div className="mt-2">
              <button
                type="button"
                aria-expanded={howOpen}
                aria-controls={howId}
                onClick={() => setHowOpen((open) => !open)}
                className={cn(
                  "-ml-1 inline-flex h-8 items-center gap-1.5 rounded-md px-1 text-[13px] text-ink-2 outline-none hover:text-ink focus-visible:ring-2 focus-visible:ring-ink",
                  howOpen && "font-semibold text-ink",
                )}
              >
                <RotateCcwKey aria-hidden="true" className="size-3.5" />
                How to regenerate
                <ChevronDown aria-hidden="true" className={cn("size-3.5 text-muted", howOpen && "rotate-180")} />
              </button>
              <div id={howId} className={cn(howOpen && "mt-1 ml-1.5 flex flex-col gap-1.5 border-l-2 border-rule py-1 pl-4")}>
                {howOpen ? (
                  <>
                    <p className="text-[13px] text-muted">In the container or pod</p>
                    <span className="inline-flex max-w-full min-w-0 flex-wrap items-start gap-1">
                      <code className="inline-flex min-h-8 items-center rounded-md bg-hover px-2.5 font-mono text-xs text-ink [overflow-wrap:anywhere]">{REGENERATE}</code>
                      <CopyControl text={REGENERATE} label="command" />
                    </span>
                  </>
                ) : null}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
