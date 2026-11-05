package jobs

import (
	"strings"
	"testing"
)

// pnpm 10.34.5's own output for react 17.0.2 kept with react-dom 18.3.1.
const peerOutput = " WARN  Issues with peer dependencies found\n.\n" +
	"\u251c\u2500\u252c react-dom 18.3.1\n\u2502 \u2514\u2500\u2500 \u2715 unmet peer react@^18.3.1: found 17.0.2\n" +
	"\u2514\u2500\u252c @testing-library/react 16.0.0\n  \u2514\u2500\u2500 \u2715 unmet peer react@^18.0.0: found 17.0.2\n\nDone in 1.8s using pnpm v10.34.5\n"

func TestPeerWarning(t *testing.T) {
	tests := []struct {
		name, project, combined, want string
	}{
		{"none", "Done\n", "Done\n", ""},
		{
			"brought by the proposals", "Done\n", peerOutput,
			"the best candidates together leave peer dependencies unmet: react-dom 18.3.1: unmet peer react@^18.3.1: found 17.0.2; @testing-library/react 16.0.0: unmet peer react@^18.0.0: found 17.0.2",
		},
		{"already in the project", peerOutput, peerOutput, ""},
		{
			"already in the project, versions moved",
			strings.ReplaceAll(strings.ReplaceAll(peerOutput, "found 17.0.2", "found 17.0.1"), "react-dom 18.3.1", "react-dom 18.2.0"),
			peerOutput, "",
		},
		{
			"summary line of a later pnpm", "Done\n", "[WARN] Issues with peer dependencies found. Run \"pnpm peers check\" to list them.\n",
			"the best candidates together leave peer dependencies unmet: pnpm reports peer dependency issues",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerWarning(tt.project, tt.combined); got != tt.want {
				t.Errorf("peerWarning() = %q, want %q", got, tt.want)
			}
		})
	}
}
