import { ChevronDown, GitCompareArrows, KeyRound, Lock } from "lucide-react"
import { type ReactNode, useId, useState } from "react"

import { Fingerprint, FingerprintCompare } from "@/components/fingerprint/fingerprint"
import { ThemeToggle } from "@/components/theme-toggle"
import { Button } from "@/components/ui/button"
import type { components } from "@/import/api/schema"
import { FOLDERS } from "@/import/lib/outcome"
import { cn } from "@/lib/utils"

type Me = components["schemas"]["Me"]

/** The import side's instance: the key every archive must be signed with, where the user's archives are read, the theme. */
export function OfflineInstancePage({ me }: { me: Me }) {
  const [comparing, setComparing] = useState(false)
  const compareId = useId()
  return (
    <div className="mx-auto flex w-full max-w-190 min-w-0 flex-col gap-10 pt-1">
      <h1 className="text-[28px] leading-tight font-bold tracking-tight">Instance</h1>

      <Section title="Trusted key" aside={<><Lock aria-hidden="true" className="size-3.5" />Set at deploy</>}>
        <div className="grid grid-cols-[32px_minmax(0,1fr)] items-start gap-x-3 border-y border-rule py-3">
          <span className="mt-px grid size-8 place-items-center rounded-lg border border-rule bg-hover text-ink-2">
            <KeyRound aria-hidden="true" className="size-4" />
          </span>
          <div className="flex min-w-0 flex-col gap-1">
            <p className="flex flex-wrap items-baseline gap-x-1.5">
              <span className="font-semibold">Signing key</span>
              <span className="font-mono text-[12.5px] text-ink-2">Ed25519</span>
            </p>
            <p className="text-[13px] text-muted">Public key sha256</p>
            <Fingerprint value={me.publicKeySha256} label="Public key sha256" />
            <div className="mt-2 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
              <p className="text-[13px] text-muted">An archive signed with any other key is refused.</p>
              <Button variant="outline" aria-expanded={comparing} aria-controls={compareId} onClick={() => setComparing((open) => !open)} className={cn(comparing && "border-ink-2 bg-hover")}>
                <GitCompareArrows aria-hidden="true" />
                Compare
                <ChevronDown aria-hidden="true" className={cn("text-muted", comparing && "rotate-180")} />
              </Button>
            </div>
            <div id={compareId} className={cn(comparing && "mt-3 border-t border-rule pt-3")}>
              <FingerprintCompare trusted={me.publicKeySha256} open={comparing} />
            </div>
          </div>
        </div>
      </Section>

      <Section title="Your folders">
        <dl>
          <Row term="Signed in as">{me.user}</Row>
          <Row term="Bucket">{me.bucket}</Row>
          <Row term="npm archives">{FOLDERS[0]}</Row>
          <Row term="pip archives">{FOLDERS[1]}</Row>
        </dl>
      </Section>

      <Section title="Appearance">
        <div className="grid grid-cols-[132px_minmax(0,1fr)] items-center gap-4 border-y border-rule py-2 text-sm max-sm:grid-cols-1 max-sm:gap-1.5">
          <span className="text-muted">Theme</span>
          <div className="flex flex-wrap items-center gap-x-3.5 gap-y-2.5">
            <ThemeToggle />
            <span className="text-[13px] text-muted">This browser only</span>
          </div>
        </div>
      </Section>
    </div>
  )
}

function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="min-w-0">
      <div className="mb-2 flex min-h-8 items-center gap-2.5">
        <h2 id={id} className="text-lg font-semibold tracking-tight">
          {title}
        </h2>
        {aside ? <span className="ml-auto inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap text-muted">{aside}</span> : null}
      </div>
      {children}
    </section>
  )
}

function Row({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="grid min-h-11 grid-cols-[132px_minmax(0,1fr)] items-start gap-4 border-t border-rule py-2.75 text-sm last:border-b max-sm:grid-cols-1 max-sm:gap-0.5">
      <dt className="text-muted">{term}</dt>
      <dd className="min-w-0 font-mono text-[12.5px] [overflow-wrap:anywhere]">{children}</dd>
    </div>
  )
}
