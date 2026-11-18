import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Download } from "lucide-react"
import { useEffect, useId, useRef, useState, type ReactNode } from "react"

import { ProblemError } from "@/api/client"
import { getSigningKey, regenerateSigningKey, type SigningKey } from "@/api/settings"
import { CopyControl } from "@/components/copy-control"
import { ProblemNotice } from "@/components/problem-notice"
import { Section } from "@/components/settings/settings-form"
import { Button } from "@/components/ui/button"

const PEM_FILE = "sealift-public-key.pem"

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

function KeyField({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  const labelId = useId()
  return (
    <div role="group" aria-labelledby={labelId} className="flex flex-col gap-1.5">
      <span id={labelId} className="text-sm font-medium text-ink">
        {label}
      </span>
      {children}
      {hint ? <p className="text-xs text-muted">{hint}</p> : null}
    </div>
  )
}

export function SigningKeySection() {
  const queryClient = useQueryClient()
  const keyQuery = useQuery({ queryKey: ["signing-key"], queryFn: getSigningKey })
  const [confirming, setConfirming] = useState(false)
  const [replaced, setReplaced] = useState(false)
  // Button takes no ref, so the two focus targets are found inside their wrappers.
  const dialogRef = useRef<HTMLDivElement>(null)
  const openerRef = useRef<HTMLDivElement>(null)

  const regenerate = useMutation({
    mutationFn: regenerateSigningKey,
    onSuccess: (next) => {
      queryClient.setQueryData(["signing-key"], next)
      setReplaced(true)
      close()
    },
    // The server may have swapped the key before the answer was lost: read it again.
    onError: async () => {
      const before = keyQuery.data?.publicKeySha256
      close()
      await queryClient.invalidateQueries({ queryKey: ["signing-key"] })
      const after = queryClient.getQueryData<SigningKey>(["signing-key"])?.publicKeySha256
      if (after && after !== before) setReplaced(true)
    },
  })

  useEffect(() => {
    if (confirming) dialogRef.current?.querySelector<HTMLElement>("[data-keep]")?.focus()
  }, [confirming])

  function close() {
    setConfirming(false)
    openerRef.current?.querySelector<HTMLElement>("button")?.focus()
  }

  function open() {
    regenerate.reset()
    setReplaced(false)
    setConfirming(true)
  }

  const key = keyQuery.data
  const failure = !replaced && regenerate.error instanceof ProblemError ? regenerate.error : null

  return (
    <Section
      title="Signing key"
      description="sealift signs the manifest of every archive with this key. The import side checks each signature with the public key below."
    >
      {keyQuery.isPending ? (
        <p role="status" className="text-sm text-muted">
          Loading the signing key…
        </p>
      ) : !key ? (
        <p role="alert" className="text-sm text-severity-critical-fg">
          Could not load the signing key: {keyQuery.error?.message}
        </p>
      ) : (
        <div className="flex flex-col gap-5">
          <KeyField label="Public key">
            <pre className="rounded-md border border-line bg-card p-3 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere]">{key.publicKeyPem}</pre>
            <div className="flex flex-wrap items-start gap-2">
              <CopyControl text={key.publicKeyPem} label="public key" />
              <Button type="button" variant="outline" className="h-8 gap-1.5 px-2.5 font-normal" onClick={() => downloadPem(key.publicKeyPem)}>
                <Download aria-hidden />
                <span aria-hidden>Download</span>
                <span className="sr-only">Download public key</span>
              </Button>
            </div>
          </KeyField>
          <KeyField label="Public key sha256" hint="Compare it by eye with the one the import side shows before your first crossing.">
            <code className="font-mono text-[13px] [overflow-wrap:anywhere]">{key.publicKeySha256}</code>
            <div>
              <CopyControl text={key.publicKeySha256} label="public key sha256" />
            </div>
          </KeyField>
          <p className="text-sm text-muted">The private key stays in this sealift&apos;s data volume. No screen or API shows it.</p>
        </div>
      )}

      {replaced ? (
        <p role="status" className="text-sm text-severity-resolved-fg">
          New key in use. Carry its public key to the import side before your next crossing.
        </p>
      ) : null}
      {failure ? <ProblemNotice status={failure.status} problem={failure.problem} /> : null}

      <div className="flex flex-col gap-3">
        <div ref={openerRef}>
          <Button type="button" variant="outline" size="sm" disabled={!key} onClick={open}>
            Regenerate key
          </Button>
        </div>
        {confirming ? (
          <div
            ref={dialogRef}
            role="alertdialog"
            aria-label="Regenerate the signing key"
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.stopPropagation()
                close()
              }
            }}
            className="rounded-lg border border-severity-critical/40 bg-severity-critical/5 p-3.5 text-sm"
          >
            <p className="font-medium text-ink">Regenerate the signing key?</p>
            <p className="mt-1 text-muted">
              The import side refuses every new archive until it holds the new public key. Archives you already exported stay signed with the current key,
              which the import refuses once it trusts the new one.
            </p>
            <div className="mt-3 flex gap-2">
              <Button type="button" size="sm" disabled={regenerate.isPending} onClick={() => regenerate.mutate()}>
                Regenerate
              </Button>
              <Button type="button" size="sm" variant="ghost" data-keep onClick={close}>
                Keep the current key
              </Button>
            </div>
          </div>
        ) : null}
      </div>
    </Section>
  )
}
