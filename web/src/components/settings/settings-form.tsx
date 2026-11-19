import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Check } from "lucide-react"
import { useState, type ReactNode } from "react"

import { ProblemError } from "@/api/client"
import { updateSettings, type Settings } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"
import { PLATFORMS, platformIdOf, targetOf } from "@/lib/platforms"
import { cn } from "@/lib/utils"

interface SettingsFormProps {
  settings: Settings
}

interface FormState {
  platform: string
  node: string
  minReleaseAgeDays: string
  resolveParallelism: string
  downloadParallelism: string
}

type FieldKey = "platform" | "node" | "minReleaseAgeDays" | "resolveParallelism" | "downloadParallelism"

// Mirrors the store's own checks, so a mistake shows next to its field as it is typed.
const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const LIMITS = {
  minReleaseAgeDays: { min: 1, max: 90, message: "Between 1 and 90 days." },
  resolveParallelism: { min: 1, max: 16, message: "Between 1 and 16." },
  downloadParallelism: { min: 1, max: 32, message: "Between 1 and 32." },
} as const

// A saved target outside the list stays selectable, so opening the panel never changes it.
const CURRENT_TARGET = "current"

function toFormState(settings: Settings): FormState {
  return {
    platform: platformIdOf(settings.target) ?? CURRENT_TARGET,
    node: settings.target.node,
    minReleaseAgeDays: String(settings.minReleaseAgeDays),
    resolveParallelism: String(settings.resolveParallelism),
    downloadParallelism: String(settings.downloadParallelism),
  }
}

function fieldErrors(form: FormState): Partial<Record<FieldKey, string>> {
  const errors: Partial<Record<FieldKey, string>> = {}
  if (!EXACT_VERSION.test(form.node.trim())) {
    errors.node = "Use an exact version, such as 22.17.1."
  }
  for (const key of ["minReleaseAgeDays", "resolveParallelism", "downloadParallelism"] as const) {
    const value = Number(form[key])
    if (form[key].trim() === "" || !Number.isInteger(value) || value < LIMITS[key].min || value > LIMITS[key].max) {
      errors[key] = LIMITS[key].message
    }
  }
  return errors
}

/** Routes a server refusal to the field its message names; anything else stays a form-level notice. */
function serverFieldOf(detail: string | undefined): FieldKey | undefined {
  if (!detail) return undefined
  if (/\bnode\b/.test(detail)) return "node"
  if (/minimum release age/.test(detail)) return "minReleaseAgeDays"
  if (/resolve parallelism/.test(detail)) return "resolveParallelism"
  if (/download parallelism/.test(detail)) return "downloadParallelism"
  return undefined
}

export function SettingsForm({ settings }: SettingsFormProps) {
  const queryClient = useQueryClient()
  const [saved, setSaved] = useState(settings)
  const [form, setForm] = useState<FormState>(() => toFormState(settings))

  const saveMutation = useMutation({
    mutationFn: (next: Settings) => updateSettings(next),
    onSuccess: (result) => {
      setSaved(result)
      setForm(toFormState(result))
      queryClient.setQueryData(["settings"], result)
    },
  })

  const errors = fieldErrors(form)
  const initial = toFormState(saved)
  const dirty = (Object.keys(initial) as (keyof FormState)[]).some((key) => form[key].trim() !== initial[key].trim())
  const hasErrors = Object.keys(errors).length > 0

  const saveError = saveMutation.error instanceof ProblemError ? saveMutation.error : null
  const serverField = serverFieldOf(saveError?.problem?.detail)
  const errorFor = (key: FieldKey) => errors[key] ?? (serverField === key ? saveError?.problem?.detail : undefined)

  function update(key: keyof FormState, value: string) {
    saveMutation.reset()
    setForm((current) => ({ ...current, [key]: value }))
  }

  function payload(): Settings {
    const platform = targetOf(form.platform) ?? {
      os: saved.target.os,
      cpu: saved.target.cpu,
      libc: saved.target.libc,
    }
    return {
      target: {
        ...platform,
        node: form.node.trim(),
        pnpmVer: saved.target.pnpmVer,
      },
      minReleaseAgeDays: Number(form.minReleaseAgeDays),
      resolveParallelism: Number(form.resolveParallelism),
      downloadParallelism: Number(form.downloadParallelism),
    }
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    if (dirty && !hasErrors && !saveMutation.isPending) {
      saveMutation.mutate(payload())
    }
  }

  function discard() {
    saveMutation.reset()
    setForm(toFormState(saved))
  }

  const currentOption = form.platform === CURRENT_TARGET || initial.platform === CURRENT_TARGET

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-8" noValidate>
      <Section
        title="Target platform"
        description="The system the air-gapped projects run on. It decides which native packages the archive carries."
      >
        <Field id="platform" label="Platform" error={errorFor("platform")}>
          <select
            id="platform"
            value={form.platform}
            onChange={(event) => update("platform", event.target.value)}
            className={controlClass(false)}
          >
            {PLATFORMS.map((platform) => (
              <option key={platform.id} value={platform.id}>
                {platform.label} ({platform.hint})
              </option>
            ))}
            {currentOption ? (
              <option value={CURRENT_TARGET}>
                {saved.target.os} · {saved.target.cpu} · {saved.target.libc || "no libc"} (saved)
              </option>
            ) : null}
          </select>
        </Field>
        <Field
          id="node"
          label="Node version"
          hint="Candidates whose engines field excludes this version are held back."
          error={errorFor("node")}
        >
          <input
            id="node"
            inputMode="decimal"
            autoComplete="off"
            spellCheck={false}
            value={form.node}
            onChange={(event) => update("node", event.target.value)}
            className={cn(controlClass(!!errorFor("node")), "font-mono")}
          />
        </Field>
      </Section>

      <Section title="Limits" description="How cautious and how fast analyses and exports are.">
        <NumberField
          id="minReleaseAgeDays"
          label="Minimum release age"
          unit="days"
          hint="A release younger than this is never proposed, nor installed as Trivy. A bad or compromised publish has time to surface."
          value={form.minReleaseAgeDays}
          min={LIMITS.minReleaseAgeDays.min}
          max={LIMITS.minReleaseAgeDays.max}
          error={errorFor("minReleaseAgeDays")}
          onChange={(value) => update("minReleaseAgeDays", value)}
        />
        <div className="grid gap-5 sm:grid-cols-2">
          <NumberField
            id="resolveParallelism"
            label="Resolve parallelism"
            unit="at once"
            hint="Candidate versions resolved together. Higher is faster and uses more memory."
            value={form.resolveParallelism}
            min={LIMITS.resolveParallelism.min}
            max={LIMITS.resolveParallelism.max}
            error={errorFor("resolveParallelism")}
            onChange={(value) => update("resolveParallelism", value)}
          />
          <NumberField
            id="downloadParallelism"
            label="Download parallelism"
            unit="at once"
            hint="Packages downloaded together during an export."
            value={form.downloadParallelism}
            min={LIMITS.downloadParallelism.min}
            max={LIMITS.downloadParallelism.max}
            error={errorFor("downloadParallelism")}
            onChange={(value) => update("downloadParallelism", value)}
          />
        </div>
      </Section>

      {saveError && !serverField ? <ProblemNotice status={saveError.status} problem={saveError.problem} /> : null}

      {/* Only there when there is something to save or to confirm, so a clean panel carries no idle buttons. */}
      {dirty || saveMutation.isSuccess ? (
        <div className="sticky bottom-0 -mx-6 flex items-center gap-3 border-t border-line bg-background/95 px-6 py-3.5 backdrop-blur">
          <span className="flex-1 text-sm" role="status">
            {saveMutation.isSuccess && !dirty ? (
              <span className="inline-flex items-center gap-1.5 text-severity-resolved-fg">
                <Check className="size-4" strokeWidth={3} />
                Saved
              </span>
            ) : dirty ? (
              <span className="text-muted">Unsaved changes</span>
            ) : null}
          </span>
          <Button type="button" variant="ghost" disabled={!dirty || saveMutation.isPending} onClick={discard}>
            Discard changes
          </Button>
          <Button type="submit" disabled={!dirty || hasErrors || saveMutation.isPending}>
            {saveMutation.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      ) : null}
    </form>
  )
}

function controlClass(invalid: boolean) {
  return cn(
    "h-10 w-full rounded-md border bg-background px-3 text-sm text-ink outline-none transition-colors",
    "focus:border-accent focus:ring-3 focus:ring-accent/20",
    invalid ? "border-severity-critical" : "border-line",
  )
}

export function Section({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold text-ink">{title}</h2>
        <p className="mt-0.5 text-sm text-muted">{description}</p>
      </div>
      {children}
    </section>
  )
}

interface FieldProps {
  id: string
  label: string
  hint?: string
  error?: string
  children: ReactNode
}

function Field({ id, label, hint, error, children }: FieldProps) {
  return (
    <div data-field className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-ink">
        {label}
      </label>
      {children}
      {error ? (
        <p role="alert" className="text-xs text-severity-critical-fg">
          {error}
        </p>
      ) : hint ? (
        <p className="text-xs text-muted">{hint}</p>
      ) : null}
    </div>
  )
}

interface NumberFieldProps {
  id: string
  label: string
  unit: string
  hint: string
  value: string
  min: number
  max: number
  error?: string
  onChange: (value: string) => void
}

function NumberField({ id, label, unit, hint, value, min, max, error, onChange }: NumberFieldProps) {
  return (
    <Field id={id} label={label} hint={hint} error={error}>
      <div className="relative">
        <input
          id={id}
          type="number"
          inputMode="numeric"
          min={min}
          max={max}
          step={1}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className={cn(controlClass(!!error), "pr-16 font-mono tabular-nums")}
        />
        <span className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-xs text-muted">{unit}</span>
      </div>
    </Field>
  )
}
