import type { ReactNode } from "react"

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

const minutes = (n: number) => `${n} ${n === 1 ? "minute" : "minutes"}`

/** The defaults and limits the deployment sets, shown read-only: the policy file changes them, not this panel. */
export function PolicySection({ policy, ephemeral, idleMinutes }: PolicySectionProps) {
  const { target, pipTarget } = policy
  const rows: [string, string][] = [
    ["npm target", `${npmPlatform(target)}, Node ${target.node}, pnpm ${target.pnpmVer}`],
    ["pip target", `${osName(pipTarget.os)} ${pipTarget.cpu} · glibc ${pipTarget.glibc}, Python ${pipTarget.python}, uv ${pipTarget.uvVer}`],
    ["Minimum release age", `${policy.minReleaseAgeDays} ${policy.minReleaseAgeDays === 1 ? "day" : "days"}`],
    ["Resolve parallelism", `${policy.resolveParallelism} at once`],
    ["Download parallelism", `${policy.downloadParallelism} at once`],
    ["Proposals", policy.review.proposeOtherMajors ? "Any version" : "Inside the current line"],
    ["Major jump", rule(policy.review.majorJump)],
    ["CVE without fix", rule(policy.review.cveWithoutFix)],
    [
      "Mode",
      ephemeral && idleMinutes !== undefined
        ? `Ephemeral: a project is erased after ${minutes(idleMinutes)} without activity.`
        : ephemeral
          ? "Ephemeral: a project is erased once idle."
          : "Projects stay until someone deletes them.",
    ],
  ]

  return (
    <Section title="Policy" description="Set by your deployment.">
      <Facts rows={rows} />
    </Section>
  )
}

/** A read-only description list, one term and its value per row. */
export function Facts({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="grid grid-cols-[minmax(0,10rem)_1fr] gap-x-4 gap-y-2.5 text-sm">
      {rows.map(([term, value]) => (
        <div key={term} className="contents">
          <dt className="text-muted">{term}</dt>
          <dd className="min-w-0 text-ink [overflow-wrap:anywhere]">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Section({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold text-ink">{title}</h2>
        {description ? <p className="mt-0.5 text-sm text-muted">{description}</p> : null}
      </div>
      {children}
    </section>
  )
}
