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
	After             *rank.Vector // nil when the analysis' combined check never ran
	Dependencies      []DependencyChange
	RemainingCritical []rank.Finding
	RemainingHigh     []rank.Finding
	Signals           []SignalNote
	ArchiveSize       int64
	ArchiveSHA256     string
	PackageCount      int
}

// errWriter wraps an io.Writer, remembering the first error any Write
// call returns and discarding every write after that. WriteSummary calls
// fmt.Fprintf and fmt.Fprintln unconditionally through it, one per line,
// and checks err only once at the end: a full disk or a closed pipe
// partway through must fail the whole write, not leave a summary.md that
// looks complete but stops mid-sentence.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// WriteSummary writes summary.md.
func WriteSummary(w io.Writer, s Summary) error {
	ew := &errWriter{w: w}
	fmt.Fprintln(ew, "# Export summary")
	fmt.Fprintln(ew)
	fmt.Fprintf(ew, "- Analysis date: %s\n", s.AnalysisDate.Format(time.RFC3339))
	fmt.Fprintf(ew, "- Trivy DB date: %s\n", s.TrivyDBDate.Format(time.DateOnly))
	fmt.Fprintf(ew, "- Trivy version: %s\n", s.TrivyVersion)
	fmt.Fprintf(ew, "- Tool version: %s\n", s.ToolVersion)
	fmt.Fprintf(ew, "- Target: %s/%s %s, Node %s, pnpm %s\n", s.Target.OS, s.Target.CPU, s.Target.Libc, s.Target.Node, s.Target.PnpmVer)
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## CVE counts")
	fmt.Fprintln(ew)
	fmt.Fprintln(ew, "| | Critical | High | Medium | Low | Unknown |")
	fmt.Fprintln(ew, "| --- | --- | --- | --- | --- | --- |")
	fmt.Fprintf(ew, "| Before | %d | %d | %d | %d | %d |\n", s.Before[0], s.Before[1], s.Before[2], s.Before[3], s.Before[4])
	if s.After != nil {
		fmt.Fprintf(ew, "| After | %d | %d | %d | %d | %d |\n", s.After[0], s.After[1], s.After[2], s.After[3], s.After[4])
	} else {
		fmt.Fprintln(ew, "| After | the combined check did not run | | | | |")
	}
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## Updated dependencies")
	fmt.Fprintln(ew)
	if len(s.Dependencies) == 0 {
		fmt.Fprintln(ew, "None.")
	} else {
		fmt.Fprintln(ew, "| Dependency | Current | Selected | CVE change |")
		fmt.Fprintln(ew, "| --- | --- | --- | --- |")
		for _, d := range s.Dependencies {
			fmt.Fprintf(ew, "| %s | %s | %s | %s |\n", d.Name, d.CurrentVersion, d.SelectedVersion, vectorDelta(d.Before, d.After))
		}
	}
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## Remaining critical and high CVEs")
	fmt.Fprintln(ew)
	writeFindingList(ew, s.RemainingCritical, s.RemainingHigh)
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## Non-blocking signals on selected versions")
	fmt.Fprintln(ew)
	if len(s.Signals) == 0 {
		fmt.Fprintln(ew, "None.")
	} else {
		for _, sig := range s.Signals {
			fmt.Fprintf(ew, "- %s %s: %s (%s)\n", sig.Dependency, sig.Version, sig.Signal, sig.Evidence)
		}
	}
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "## Archive")
	fmt.Fprintln(ew)
	fmt.Fprintf(ew, "- Size: %d bytes\n", s.ArchiveSize)
	fmt.Fprintf(ew, "- SHA-256: %s\n", s.ArchiveSHA256)
	fmt.Fprintf(ew, "- Packages: %d\n", s.PackageCount)
	return ew.err
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
