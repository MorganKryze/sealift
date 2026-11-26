import { useQuery } from "@tanstack/react-query"
import { CircleX, Download, Eye, FileArchive, FileJson, FileSignature, FileText, KeyRound, List, LoaderCircle, RotateCw, ShieldCheck } from "lucide-react"
import { type ReactNode, useId, useState } from "react"

import { ApiError, send } from "@/api/client"
import type { Export, Project } from "@/api/projects"
import { getSigningKey } from "@/api/settings"
import { Fingerprint } from "@/components/fingerprint/fingerprint"
import { useBrand } from "@/components/frame/brand"
import { Button } from "@/components/ui/button"
import { readSeal, type SealFigures } from "@/lib/crossings"
import { formatBytes } from "@/lib/utils"

// The order a reader takes them in: the summary first, the raw scanner output last.
const REPORTS: Record<string, { note: string; icon: typeof FileText }> = {
  "summary.md": { note: "known CVEs before and after", icon: FileText },
  "findings.csv": { note: "every CVE, one row each", icon: FileText },
  "report.cdx.json": { note: "CycloneDX SBOM", icon: List },
  "report.trivy.json": { note: "raw Trivy output", icon: ShieldCheck },
}
const REPORT_ORDER = Object.keys(REPORTS)
const reportRank = (name: string) => (REPORT_ORDER.includes(name) ? REPORT_ORDER.indexOf(name) : REPORT_ORDER.length)

const COUNT = new Intl.NumberFormat("en-GB")

/** "1,284 packages · 96.5 MB", each figure only when manifest.json holds it; nothing when it holds neither. */
function archiveFigures(figures: SealFigures | undefined): ReactNode {
  if (!figures) return undefined
  const parts: ReactNode[] = []
  if (figures.packages !== undefined) {
    parts.push(
      <span key="packages">
        <span className="figure text-ink">{COUNT.format(figures.packages)}</span> {figures.packages === 1 ? "package" : "packages"}
      </span>,
    )
  }
  if (figures.size !== undefined) {
    parts.push(
      <span key="size" className="figure text-ink">
        {formatBytes(figures.size)}
      </span>,
    )
  }
  if (parts.length === 0) return undefined
  return <>{parts.flatMap((part, i) => (i === 0 ? [part] : [" · ", part]))}</>
}

const fileHref = (projectId: string, exportId: string, name: string) =>
  `/api/projects/${encodeURIComponent(projectId)}/exports/${encodeURIComponent(exportId)}/files/${encodeURIComponent(name)}`

function DownloadLink({ href, name, onClick }: { href: string; name: string; onClick?: () => void }) {
  return (
    <a
      href={href}
      download={name}
      onClick={onClick}
      aria-label={`Download ${name}`}
      className="grid size-8 flex-none place-items-center rounded-md text-ink-2 transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink"
    >
      <Download aria-hidden="true" className="size-4" />
    </a>
  )
}

function FileRow({ icon: Icon, name, note, children }: { icon: typeof FileText; name: string; note?: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex min-w-0 items-center gap-3">
      <Icon aria-hidden="true" className="size-4 flex-none text-muted" />
      <p className="min-w-0 flex-1 text-[13px] text-muted [overflow-wrap:anywhere]">
        <span className="font-mono text-ink">{name}</span>
        {note ? <> · {note}</> : null}
      </p>
      {children}
    </div>
  )
}

function SectionHead({ id, icon: Icon, title, count, children }: { id: string; icon: typeof Eye; title: string; count: number; children?: ReactNode }) {
  return (
    <div className="flex min-h-11 items-center justify-between gap-3 border-b border-rule bg-canvas px-4 py-1.5">
      <h4 id={id} className="flex items-center gap-2 text-[13px] font-semibold text-ink-2">
        <Icon aria-hidden="true" className="size-4" />
        <span>
          {title} · <span className="figure">{count}</span> {count === 1 ? "file" : "files"}
        </span>
      </h4>
      {children}
    </div>
  )
}

interface CrossingFilesProps {
  project: Project
  exported: Export
  /** Sealed's page makes Download all its primary; the project page keeps it a secondary. */
  downloadAllPrimary?: boolean
  /** Called when a download of a file to carry starts, never for a report. */
  onDownload?: () => void
}

/** A sealed export's files: To carry with Download all, each file and the archive's fingerprint, then the reports with Open first. */
export function CrossingFiles({ project, exported, downloadAllPrimary = false, onDownload }: CrossingFilesProps) {
  const brand = useBrand()
  const carryId = useId()
  const reportsId = useId()
  const [openFailure, setOpenFailure] = useState<string | null>(null)
  const seal = useQuery({ queryKey: ["seal", project.id, exported.id], queryFn: () => readSeal(project.id, exported.id), retry: false })
  const key = useQuery({ queryKey: ["signing-key"], queryFn: getSigningKey })

  const files = exported.files ?? []
  const archive = files.find((name) => name.endsWith(".tar.gz"))
  const carry = [archive, "manifest.json", "manifest.json.sig"].filter((name): name is string => name !== undefined && files.includes(name))
  const reports = files.filter((name) => !carry.includes(name)).sort((a, b) => reportRank(a) - reportRank(b) || a.localeCompare(b))
  const href = (name: string) => fileHref(project.id, exported.id, name)
  const replaced = seal.data && key.data && seal.data.keySha256 !== key.data.publicKeySha256 ? seal.data.keySha256 : undefined

  // One download per file: the server serves no bundle of the three.
  function downloadAll() {
    for (const name of carry) {
      const link = document.createElement("a")
      link.href = href(name)
      link.download = name
      link.click()
    }
    // Done opens on a download of a file to carry: with none, nothing went out.
    if (carry.length > 0) onDownload?.()
  }

  async function openReport(name: string) {
    setOpenFailure(null)
    try {
      const response = await send(href(name), undefined, (status, problem) => new ApiError(status, problem))
      const url = URL.createObjectURL(new Blob([await response.text()], { type: "text/plain;charset=utf-8" }))
      window.open(url, "_blank", "noopener")
      // The new tab has read the blob long before this.
      setTimeout(() => URL.revokeObjectURL(url), 60_000)
    } catch (error) {
      setOpenFailure(`Could not open ${name}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  return (
    <div className="border-t border-rule">
      {replaced ? (
        <div className="px-4 pt-3 pb-3">
          <div className="tinted-warn flex gap-3 p-4">
            <KeyRound aria-hidden="true" className="mt-0.5 size-4 flex-none text-warn" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-ink">Signed with a key this instance has replaced</p>
              <p className="mt-0.5 text-sm text-ink-2">{`${brand.offline} refuses this archive unless it still trusts that key.`}</p>
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <span className="text-[13px] text-muted">Key sha256</span>
                <Fingerprint value={replaced} label="Key sha256" />
              </div>
            </div>
          </div>
        </div>
      ) : null}
      <section aria-labelledby={carryId}>
        <SectionHead id={carryId} icon={Download} title="To carry" count={carry.length}>
          <Button type="button" variant={downloadAllPrimary ? "default" : "outline"} size={downloadAllPrimary ? "page" : "sm"} onClick={downloadAll}>
            <Download aria-hidden="true" />
            Download all
          </Button>
        </SectionHead>
        <ul>
          {carry.map((name) => (
            <li key={name} className="flex flex-col gap-2 border-b border-rule px-4 py-3">
              <FileRow
                icon={name === archive ? FileArchive : name === "manifest.json" ? FileJson : FileSignature}
                name={name}
                note={
                  name === archive
                    ? archiveFigures(seal.data?.figures)
                    : name === "manifest.json"
                      ? project.ecosystem === "pip"
                        ? "every wheel with its sha256"
                        : "every package with its sha512"
                      : "Ed25519 signature"
                }
              >
                <DownloadLink href={href(name)} name={name} onClick={onDownload} />
              </FileRow>
              {name === archive ? (
                <div className="pl-7">
                  {seal.isPending ? (
                    <div role="status" className="tinted-info flex w-fit items-center gap-2 px-3 py-1.5 text-[13px] text-info">
                      <LoaderCircle aria-hidden="true" className="size-4 motion-safe:animate-spin" />
                      Reading manifest.json
                    </div>
                  ) : seal.isError ? (
                    <div className="tinted-bad flex flex-wrap items-center gap-3 px-3 py-2">
                      <CircleX aria-hidden="true" className="size-4 flex-none text-bad" />
                      <p className="min-w-0 flex-1 text-[13px] text-ink [overflow-wrap:anywhere]">{`Could not read ${seal.error.message}`}</p>
                      <Button type="button" variant="outline" size="sm" onClick={() => void seal.refetch()}>
                        <RotateCw aria-hidden="true" />
                        Retry
                      </Button>
                    </div>
                  ) : (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[13px] text-muted">sha256</span>
                      <Fingerprint value={seal.data.archiveSha256} label={`sha256 of ${name}`} />
                    </div>
                  )}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      </section>
      {reports.length > 0 ? (
        <section aria-labelledby={reportsId}>
          <SectionHead id={reportsId} icon={Eye} title="Reports" count={reports.length} />
          <ul>
            {reports.map((name) => (
              <li key={name} className="border-b border-rule px-4 py-2.5 last:border-b-0">
                <FileRow icon={REPORTS[name]?.icon ?? FileText} name={name} note={REPORTS[name]?.note}>
                  <Button type="button" variant="outline" size="sm" aria-label={`Open ${name}`} onClick={() => void openReport(name)}>
                    <Eye aria-hidden="true" />
                    Open
                  </Button>
                  <DownloadLink href={href(name)} name={name} />
                </FileRow>
              </li>
            ))}
          </ul>
          {openFailure ? (
            <p role="alert" className="px-4 py-2.5 text-sm text-bad">
              {openFailure}
            </p>
          ) : null}
        </section>
      ) : null}
    </div>
  )
}
