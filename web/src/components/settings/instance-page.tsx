import { TriangleAlert } from "lucide-react"
import type { ReactNode } from "react"

import type { Instance } from "@/api/settings"
import { PAGE, usableAccent } from "@/components/frame/brand"
import { ReadinessList } from "@/components/preparing-screen"
import { Facts, PolicySection, Section } from "@/components/settings/policy-section"
import { SigningKeySection } from "@/components/settings/signing-key-section"
import { ThemeToggle } from "@/components/theme-toggle"

const THEMES = ["light", "dark"] as const
const themeName = { light: "Light", dark: "Dark" }

/** The online instance on one page, read-only: what makes it ready, the policy it runs under, its key and the theme. */
export function InstancePage({ instance }: { instance: Instance }) {
  const items = instance.preparing
  // The signing key's row comes from its own section, with its download and how to regenerate it.
  const keyAt = items.findIndex((item) => item.name === "signing-key")
  const before = keyAt < 0 ? items : items.slice(0, keyAt)
  const after = keyAt < 0 ? [] : items.slice(keyAt + 1)
  const warnings = instance.warning ? 1 : 0
  const ready = items.filter((item) => item.state === "ready").length - warnings
  const appearance: [string, ReactNode][] = [
    [
      "Theme",
      <div key="theme" className="flex flex-col items-start gap-2">
        <ThemeToggle />
        <span className="text-[13px] text-muted">This browser only</span>
      </div>,
    ],
  ]
  // usableAccent measures 0 for a value that is no #rrggbb colour, which the frame ignores too.
  const accent = instance.brand.accent
  if (accent && usableAccent(accent, PAGE.light).ratio > 0) appearance.push(["Accent", <AccentNote key="accent" accent={accent} />])

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 min-w-0 flex-col gap-8 px-5 py-10">
      <h1 className="text-[28px] leading-tight font-bold tracking-tight">Instance</h1>
      <div className="grid min-w-0 items-start gap-x-10 gap-y-10 lg:grid-cols-2">
        <Section
          title="Ready"
          aside={
            <>
              <span className="tinted-ok inline-flex h-6 items-center rounded-full px-2.5 text-xs font-semibold text-ok">{`${ready} ${ready === 1 ? "item" : "items"} ready`}</span>
              {warnings ? <span className="tinted-warn inline-flex h-6 items-center rounded-full px-2.5 text-xs font-semibold text-warn">1 warning</span> : null}
            </>
          }
        >
          <div className="grid gap-1.5 border-t border-rule pt-1.5">
            <ReadinessList items={before} warning={instance.warning} />
            {keyAt < 0 ? null : <SigningKeySection />}
            {after.length ? <ReadinessList items={after} warning={instance.warning} /> : null}
          </div>
        </Section>

        <div className="flex min-w-0 flex-col gap-10">
          <PolicySection policy={instance.policy} ephemeral={instance.ephemeral} idleMinutes={instance.idleMinutes} />
          <Section title="Appearance">
            <Facts rows={appearance} />
          </Section>
        </div>
      </div>
    </div>
  )
}

/** The deployment's accent with its ratio per theme; where it falls under 3:1 the frame draws the ink, and this says so. */
function AccentNote({ accent }: { accent: string }) {
  const measured = THEMES.map((theme) => ({ theme, ...usableAccent(accent, PAGE[theme]) }))
  const short = measured.filter((m) => m.color === null)
  return (
    <div className="flex flex-col items-start gap-1.5">
      <span className="inline-flex items-center gap-2">
        <span aria-hidden="true" className="size-3 rounded-full" style={{ backgroundColor: accent }} />
        <code className="font-mono text-[12.5px]">{accent}</code>
      </span>
      <span className="flex flex-wrap items-center gap-2">
        {measured.map(({ theme, color, ratio }) =>
          color ? (
            <span key={theme}>
              {themeName[theme]} <span className="figure">{`${ratio.toFixed(1)}:1`}</span>
            </span>
          ) : (
            <span key={theme} className="tinted-warn inline-flex min-h-6 items-center gap-1.5 rounded-full px-2.5 text-xs font-semibold text-warn">
              <TriangleAlert aria-hidden="true" className="size-3.5" />
              {`${themeName[theme]} ${ratio.toFixed(1)}:1, under 3:1`}
            </span>
          ),
        )}
      </span>
      {short.length ? (
        <span className="text-[13px] text-muted">{`${short.map((m) => themeName[m.theme]).join(" and ")} ${short.length === 1 ? "shows" : "show"} the ink in its place.`}</span>
      ) : null}
    </div>
  )
}
