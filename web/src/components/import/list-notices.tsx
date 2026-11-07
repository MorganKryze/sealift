import { TriangleAlert } from "lucide-react"

import type { ArchiveList } from "@/import/api/queries"

const LINKS: Record<string, string> = { keySet: "the key set", minio: "MinIO", nexus: "Nexus" }

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <p className="mb-3 flex gap-2.5 rounded-lg border border-line bg-card px-4 py-3 text-sm leading-6">
      <TriangleAlert aria-hidden className="mt-1 size-4 flex-none text-severity-high" />
      <span className="min-w-0 [overflow-wrap:anywhere]">{children}</span>
    </p>
  )
}

function joined(names: string[]) {
  if (names.length < 2) {
    return names.join("")
  }
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`
}

/** What the reader must know before trusting the rows: a cut list and links without encryption. */
export function ListNotices({ list }: { list: ArchiveList }) {
  const links = list.unencrypted.map((n) => LINKS[n] ?? n)
  return (
    <>
      {list.truncated ? (
        <Notice>
          This folder holds more than 1,000 objects. The list shows the first 1,000 in name order, so a newer archive may be missing. Moving finished archives out of {list.folder} makes room.
        </Notice>
      ) : null}
      {links.length > 0 ? (
        <Notice>
          The links to {joined(links)} run over plain http. Package contents and credentials cross the network unencrypted there.
        </Notice>
      ) : null}
    </>
  )
}
