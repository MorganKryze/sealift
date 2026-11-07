import { CircleAlert, CircleCheck, CircleQuestionMark } from "lucide-react"

import { CopyControl } from "./copy-control"

interface ShaBlockProps {
  /** The sha256 the user gave when starting, or empty. */
  expected: string
  /** The sha256 the manifest names, or empty before the manifest is read. */
  manifest: string
  /** The attempt's record of the archive's checks; absent before they run and in a report that never recorded them. */
  checked: boolean | undefined
  /** The attempt's status: an absent mark means "not run yet" while it waits or runs, "not recorded" once it ended. */
  status: string
}

function Digest({ title, value, label }: { title: string; value: string; label: string }) {
  return (
    <div>
      <dt className="text-sm text-muted">{title}</dt>
      <dd className="mt-1 flex flex-wrap items-start gap-x-3 gap-y-2">
        <code className="min-w-0 font-mono text-[13px] [overflow-wrap:anywhere]">{value}</code>
        <CopyControl text={value} label={label} />
      </dd>
    </div>
  )
}

/**
 * Both digests in full and what the attempt recorded about the archive's checks. The word
 * "matched" appears only when the record says the checks passed: an outcome or a count proves nothing.
 */
export function ShaBlock({ expected, manifest, checked, status }: ShaBlockProps) {
  return (
    <div>
      <dl className="grid gap-4">
        {expected ? (
          <Digest title="Expected sha256" value={expected} label="expected sha256" />
        ) : (
          <div>
            <dt className="text-sm text-muted">Expected sha256</dt>
            <dd className="mt-1 text-sm">No expected sha256 was given.</dd>
          </div>
        )}
        {manifest ? (
          <Digest title="Manifest sha256" value={manifest} label="manifest sha256" />
        ) : (
          <div>
            <dt className="text-sm text-muted">Manifest sha256</dt>
            <dd className="mt-1 text-sm">Not read</dd>
          </div>
        )}
      </dl>
      <p className="mt-4 flex items-start gap-2 text-sm">
        {checked === true ? (
          <>
            <CircleCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-severity-resolved-fg" />
            <span>The archive matched: it passed its checks against the manifest and the signature key.</span>
          </>
        ) : checked === false ? (
          <>
            <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-severity-high" />
            <span>The archive has not passed its checks.</span>
          </>
        ) : (
          <>
            <CircleQuestionMark aria-hidden className="mt-0.5 size-4 shrink-0 text-muted" />
            <span>
              {status === "queued" || status === "running"
                ? "The archive's checks have not run yet."
                : "Not recorded: this attempt did not record the archive's checks."}
            </span>
          </>
        )}
      </p>
    </div>
  )
}
