import { useMutation } from "@tanstack/react-query"
import { useState } from "react"

import { ProblemError } from "@/api/client"
import { updateSettings, type Settings } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"

interface SettingsFormProps {
  settings: Settings
}

interface FormState {
  os: string
  cpu: string
  libc: string
  node: string
  pnpmVer: string
  signatureKey: string
  minReleaseAgeDays: string
  resolveParallelism: string
  downloadParallelism: string
}

function toFormState(settings: Settings): FormState {
  return {
    os: settings.target.os,
    cpu: settings.target.cpu,
    libc: settings.target.libc,
    node: settings.target.node,
    pnpmVer: settings.target.pnpmVer,
    signatureKey: "",
    minReleaseAgeDays: String(settings.minReleaseAgeDays),
    resolveParallelism: String(settings.resolveParallelism),
    downloadParallelism: String(settings.downloadParallelism),
  }
}

function validate(form: FormState): string[] {
  const errors: string[] = []
  if (Number(form.minReleaseAgeDays) < 1) {
    errors.push("Minimum release age must be at least 1 day.")
  }
  if (Number(form.resolveParallelism) < 1) {
    errors.push("Resolution parallelism must be at least 1.")
  }
  if (Number(form.downloadParallelism) < 1) {
    errors.push("Download parallelism must be at least 1.")
  }
  return errors
}

export function SettingsForm({ settings }: SettingsFormProps) {
  const [form, setForm] = useState<FormState>(() => toFormState(settings))
  const [storedKey, setStoredKey] = useState(settings.signatureKey)
  const [clientErrors, setClientErrors] = useState<string[]>([])

  const saveMutation = useMutation({
    mutationFn: (next: Settings) => updateSettings(next),
    onSuccess: (saved) => {
      setStoredKey(saved.signatureKey)
      setForm((current) => ({ ...current, signatureKey: "" }))
    },
  })

  const saveError = saveMutation.error instanceof ProblemError ? saveMutation.error : null

  function field(key: keyof FormState) {
    return {
      value: form[key],
      onChange: (event: React.ChangeEvent<HTMLInputElement>) =>
        setForm((current) => ({ ...current, [key]: event.target.value })),
    }
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const errors = validate(form)
    setClientErrors(errors)
    if (errors.length > 0) {
      return
    }

    saveMutation.mutate({
      target: { os: form.os, cpu: form.cpu, libc: form.libc, node: form.node, pnpmVer: form.pnpmVer },
      signatureKey: form.signatureKey.trim() === "" ? storedKey : form.signatureKey,
      minReleaseAgeDays: Number(form.minReleaseAgeDays),
      resolveParallelism: Number(form.resolveParallelism),
      downloadParallelism: Number(form.downloadParallelism),
    })
  }

  return (
    <form onSubmit={handleSubmit} className="flex max-w-xl flex-col gap-4">
      <h2 className="text-lg font-semibold text-ink">Default target</h2>
      <div className="grid grid-cols-2 gap-3">
        <Field label="OS" {...field("os")} />
        <Field label="CPU" {...field("cpu")} />
        <Field label="libc" {...field("libc")} />
        <Field label="Node" {...field("node")} />
        <Field label="pnpm" {...field("pnpmVer")} />
      </div>

      <h2 className="mt-2 text-lg font-semibold text-ink">Signing</h2>
      <label className="flex flex-col gap-1 text-sm text-ink">
        Signature key
        <input
          type="password"
          {...field("signatureKey")}
          placeholder="Unchanged"
          className="rounded-md border border-line bg-background px-3 py-2 text-sm"
        />
        <span className="text-xs text-muted">Current: {storedKey}. Leave blank to keep it.</span>
      </label>

      <h2 className="mt-2 text-lg font-semibold text-ink">Limits</h2>
      <div className="grid grid-cols-3 gap-3">
        <Field label="Min release age (days)" type="number" min={1} {...field("minReleaseAgeDays")} />
        <Field label="Resolution parallelism" type="number" min={1} {...field("resolveParallelism")} />
        <Field label="Download parallelism" type="number" min={1} {...field("downloadParallelism")} />
      </div>

      {clientErrors.length > 0 ? (
        <ul role="alert" className="list-disc pl-5 text-sm text-severity-critical">
          {clientErrors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      ) : null}

      {saveError ? <ProblemNotice status={saveError.status} problem={saveError.problem} /> : null}
      {saveMutation.isSuccess ? <p className="text-sm text-severity-resolved">Settings saved.</p> : null}

      <Button type="submit" disabled={saveMutation.isPending} className="self-start">
        Save settings
      </Button>
    </form>
  )
}

interface FieldProps {
  label: string
  type?: string
  min?: number
  value: string
  onChange: (event: React.ChangeEvent<HTMLInputElement>) => void
}

function Field({ label, type = "text", min, value, onChange }: FieldProps) {
  return (
    <label className="flex flex-col gap-1 text-sm text-ink">
      {label}
      <input
        type={type}
        min={min}
        value={value}
        onChange={onChange}
        className="rounded-md border border-line bg-background px-3 py-2 text-sm"
      />
    </label>
  )
}
