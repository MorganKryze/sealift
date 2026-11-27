import { Lock } from "lucide-react"
import { type ReactNode, useId } from "react"

import type { Instance } from "@/api/settings"
import { PLATFORMS } from "@/lib/platforms"

interface PolicySectionProps {
  policy: Instance["policy"]
  ephemeral: boolean
  /** The idle delay of ephemeral mode, in minutes. */
  idleMinutes?: number
}

const osName = (os: string) => (os === "linux" ? "Linux" : os)

function npmPlatform({ os, cpu, libc }: Instance["policy"]["target"]) {
  const listed = PLATFORMS.find((p) => p.os === os && p.cpu === cpu && p.libc === libc)
  return listed ? listed.label : [osName(os), cpu, libc].filter(Boolean).join(" ")
}

const rule = (value: Instance["policy"]["review"]["majorJump"]) => (value === "refuse" ? "Refused" : "Needs a reason")

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/** A figure the user reads for, in weight 600. */
const Figure = ({ children }: { children: ReactNode }) => <span className="figure">{children}</span>

/**
 * The defaults and limits the deployment sets, shown read-only: the policy file changes them, not
 * this page. The pnpm and uv versions sit with the readiness items, so the targets leave them out.
 */
export function PolicySection({ policy, ephemeral, idleMinutes }: PolicySectionProps) {
  const { target, pipTarget } = policy
  const rows: [string, ReactNode][] = [
    [
      "Release age",
      <>
        At least <Figure>{plural(policy.minReleaseAgeDays, "day", "days")}</Figure> old
      </>,
    ],
    [
      "npm target",
      <>
        Node <Figure>{target.node}</Figure>, {npmPlatform(target)}
      </>,
    ],
    [
      "pip target",
      <>
        Python <Figure>{pipTarget.python}</Figure>, {osName(pipTarget.os)} {pipTarget.cpu} · glibc <Figure>{pipTarget.glibc}</Figure>
      </>,
    ],
    [
      "Parallelism",
      <>
        <Figure>{policy.resolveParallelism}</Figure> {policy.resolveParallelism === 1 ? "resolve" : "resolves"}, <Figure>{policy.downloadParallelism}</Figure>{" "}
        {policy.downloadParallelism === 1 ? "download" : "downloads"}
      </>,
    ],
    ["Proposals", policy.review.proposeOtherMajors ? "Any version" : "Inside the current line"],
    ["Major jump", rule(policy.review.majorJump)],
    ["CVE without fix", rule(policy.review.cveWithoutFix)],
    ["Yanked release", rule(policy.review.yanked)],
    [
      "Projects",
      ephemeral ? (
        <>
          {idleMinutes !== undefined ? (
            <>
              Erased with their caches after <Figure>{plural(idleMinutes, "minute", "minutes")}</Figure> without activity
            </>
          ) : (
            "Erased with their caches once idle"
          )}
          <span className="block text-[13px] text-muted">Ephemeral mode</span>
        </>
      ) : (
        "Kept until someone deletes them"
      ),
    ],
  ]

  return (
    <Section
      title="Policy"
      aside={
        <>
          <Lock aria-hidden="true" className="size-3.5" />
          Set at deploy
        </>
      }
    >
      <Facts rows={rows} />
    </Section>
  )
}

/** A read-only description list, one term and its value per ruled row. */
export function Facts({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl>
      {rows.map(([term, value]) => (
        <div key={term} className="grid min-h-11 grid-cols-[120px_minmax(0,1fr)] items-start gap-4 border-t border-rule py-2.75 text-sm last:border-b max-sm:grid-cols-1 max-sm:gap-0.5">
          <dt className="text-muted">{term}</dt>
          <dd className="min-w-0 text-ink [overflow-wrap:anywhere]">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** A titled part of Instance, a landmark named by its title, with a note at the right of the title. */
export function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="min-w-0">
      <div className="mb-2 flex min-h-8 flex-wrap items-center gap-2.5">
        <h2 id={id} className="text-lg font-semibold tracking-tight text-ink">
          {title}
        </h2>
        {aside ? <span className="ml-auto inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap text-muted">{aside}</span> : null}
      </div>
      {children}
    </section>
  )
}
