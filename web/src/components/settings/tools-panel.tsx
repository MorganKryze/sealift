import type { Instance } from "@/api/settings"
import { Facts, Section } from "@/components/settings/policy-section"
import { formatDbDate } from "@/lib/format-tools"

/** The pinned Trivy and its database's date. The start installs and refreshes both, so nothing here acts. */
export function ToolsPanel({ tools }: { tools: Instance["tools"] }) {
  return (
    <Section title="Scanner" description="sealift refreshes the database before each analysis.">
      <Facts
        rows={[
          ["Trivy", tools.trivy],
          ["Vulnerability database", tools.trivyDbDate ? `Downloaded ${formatDbDate(tools.trivyDbDate)}` : "Not downloaded yet"],
        ]}
      />
    </Section>
  )
}
