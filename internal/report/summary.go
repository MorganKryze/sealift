package report

import (
	"fmt"
	"io"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/rank"
)

// DependencyChange is one updated dependency's row in summary.md.
type DependencyChange struct {
	Name            string
	CurrentVersion  string
	SelectedVersion string
	Before          rank.Vector
	After           rank.Vector
}

// SignalNote is a non-blocking signal on a selected version, shown so the
// reader sees what the export accepted even though it did not block the
// candidate.
type SignalNote struct {
	Dependency string
	Version    string
	Signal     rank.Signal
	Evidence   string
}

// Summary is the content of an export's summary.md.
type Summary struct {
	AnalysisDate      time.Time
	TrivyDBDate       time.Time
	TrivyVersion      string
	ToolVersion       string
	Target            store.Target
	Before            rank.Vector
	After             rank.Vector
	Dependencies      []DependencyChange
	RemainingCritical []rank.Finding
	RemainingHigh     []rank.Finding
	Signals           []SignalNote
	ArchiveSize       int64
	ArchiveSHA256     string
	PackageCount      int
}

// WriteSummary writes summary.md.
func WriteSummary(w io.Writer, s Summary) error {
	fmt.Fprintln(w, "# Export summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Analysis date: %s\n", s.AnalysisDate.Format(time.RFC3339))
	fmt.Fprintf(w, "- Trivy DB date: %s\n", s.TrivyDBDate.Format(time.DateOnly))
	fmt.Fprintf(w, "- Trivy version: %s\n", s.TrivyVersion)
	fmt.Fprintf(w, "- Tool version: %s\n", s.ToolVersion)
	fmt.Fprintf(w, "- Target: %s/%s %s, Node %s, pnpm %s\n", s.Target.OS, s.Target.CPU, s.Target.Libc, s.Target.Node, s.Target.PnpmVer)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## CVE counts")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| | Critical | High | Medium | Low | Unknown |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- |")
	fmt.Fprintf(w, "| Before | %d | %d | %d | %d | %d |\n", s.Before[0], s.Before[1], s.Before[2], s.Before[3], s.Before[4])
	fmt.Fprintf(w, "| After | %d | %d | %d | %d | %d |\n", s.After[0], s.After[1], s.After[2], s.After[3], s.After[4])
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Updated dependencies")
	fmt.Fprintln(w)
	if len(s.Dependencies) == 0 {
		fmt.Fprintln(w, "None.")
	} else {
		fmt.Fprintln(w, "| Dependency | Current | Selected | CVE change |")
		fmt.Fprintln(w, "| --- | --- | --- | --- |")
		for _, d := range s.Dependencies {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", d.Name, d.CurrentVersion, d.SelectedVersion, vectorDelta(d.Before, d.After))
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Remaining critical and high CVEs")
	fmt.Fprintln(w)
	writeFindingList(w, s.RemainingCritical, s.RemainingHigh)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Non-blocking signals on selected versions")
	fmt.Fprintln(w)
	if len(s.Signals) == 0 {
		fmt.Fprintln(w, "None.")
	} else {
		for _, sig := range s.Signals {
			fmt.Fprintf(w, "- %s %s: %s (%s)\n", sig.Dependency, sig.Version, sig.Signal, sig.Evidence)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Archive")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Size: %d bytes\n", s.ArchiveSize)
	fmt.Fprintf(w, "- SHA-256: %s\n", s.ArchiveSHA256)
	fmt.Fprintf(w, "- Packages: %d\n", s.PackageCount)
	return nil
}

// writeFindingList lists critical findings, then high ones, as "None." when
// both are empty.
func writeFindingList(w io.Writer, critical, high []rank.Finding) {
	if len(critical) == 0 && len(high) == 0 {
		fmt.Fprintln(w, "None.")
		return
	}
	for _, f := range critical {
		fmt.Fprintf(w, "- [critical] %s in %s@%s: %s\n", f.ID, f.Package, f.Version, f.Title)
	}
	for _, f := range high {
		fmt.Fprintf(w, "- [high] %s in %s@%s: %s\n", f.ID, f.Package, f.Version, f.Title)
	}
}

// vectorDelta describes how a vector changed, most serious severity first,
// as "no change" when nothing moved.
func vectorDelta(before, after rank.Vector) string {
	names := [5]string{"critical", "high", "medium", "low", "unknown"}
	s := ""
	for i := range before {
		if d := after[i] - before[i]; d != 0 {
			if s != "" {
				s += ", "
			}
			s += fmt.Sprintf("%+d %s", d, names[i])
		}
	}
	if s == "" {
		return "no change"
	}
	return s
}
