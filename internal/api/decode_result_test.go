package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/tools"
)

// An analysis written before CVE ids existed carries no "cves" field, and
// older ones may carry null arrays; the contract marks every one of these
// arrays required, and the review screen reads their length.
func TestDecodeAnalysisResultFillsArraysMissingFromOlderAnalyses(t *testing.T) {
	raw := json.RawMessage(`{
		"target": {"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},
		"before": [0,1,0,0,0],
		"dependencies": [{"name":"lodash","current":"4.17.20","best":"4.17.21","vector":[0,1,0,0,0],
			"candidates": [{"version":"4.17.21","vector":[0,0,0,0,0],"signals":null,"key":true,"resolved":true}]}],
		"warnings": null
	}`)

	result, ok := decodeAnalysisResult(raw)
	if !ok {
		t.Fatal("decodeAnalysisResult rejected an older analysis")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// after stays null on purpose: it means the combined check never ran.
	for _, field := range []string{`"cves":null`, `"signals":null`, `"warnings":null`, `"candidates":null`, `"dependencies":null`} {
		if strings.Contains(string(encoded), field) {
			t.Errorf("encoded result carries %s, want an empty array: %s", field, encoded)
		}
	}
}

func TestDecodeMarksCandidatesThatLeaveTheLine(t *testing.T) {
	raw := json.RawMessage(`{
		"target": {"os":"linux","cpu":"x64","libc":"glibc","node":"22.17.1","pnpmVer":"10.34.5"},
		"before": [0,0,0,0,0], "after": null, "warnings": [],
		"dependencies": [
			{"name":"foo","current":"0.18.0","vector":[0,0,0,0,0],"cves":[],"candidates":[
				{"version":"0.18.9","vector":[0,0,0,0,0],"cves":[],"signals":[],"key":true,"resolved":true},
				{"version":"0.19.0","vector":[0,0,0,0,0],"cves":[],"signals":[],"key":true,"resolved":true}]},
			{"name":"express","current":"4.17.1","vector":[0,0,0,0,0],"cves":[],"candidates":[
				{"version":"4.22.0","vector":[0,0,0,0,0],"cves":[],"signals":[],"key":true,"resolved":true},
				{"version":"5.0.0","vector":[0,0,0,0,0],"cves":[],"signals":[],"key":true,"resolved":true}]}
		]
	}`)

	result, ok := decodeAnalysisResult(raw)
	if !ok {
		t.Fatal("decodeAnalysisResult rejected the analysis")
	}
	want := map[string]bool{"foo 0.18.9": false, "foo 0.19.0": true, "express 4.22.0": false, "express 5.0.0": true}
	for _, d := range result.Dependencies {
		for _, c := range d.Candidates {
			key := d.Name + " " + c.Version
			if c.LeavesLine != want[key] {
				t.Errorf("%s leavesLine = %v, want %v", key, c.LeavesLine, want[key])
			}
		}
	}
}

// candidates070 is the candidates.json release 0.7.0 writes for express
// 4.17.1 with a clean 4.21.2 and 5.1.0: no jump, no family, and CVEs
// without the package or the fix Trivy reported.
const candidates070 = `{
  "target": {
    "os": "linux",
    "cpu": "x64",
    "libc": "glibc",
    "node": "22.17.1",
    "pnpmVer": "10.34.5"
  },
  "before": [
    0,
    0,
    1,
    1,
    0
  ],
  "after": null,
  "dependencies": [
    {
      "name": "express",
      "current": "4.17.1",
      "best": "4.21.2",
      "vector": [
        0,
        0,
        1,
        1,
        0
      ],
      "cves": [
        {
          "id": "CVE-2024-29041",
          "severity": "MEDIUM"
        },
        {
          "id": "CVE-2024-43796",
          "severity": "LOW"
        }
      ],
      "candidates": [
        {
          "version": "4.21.2",
          "vector": [
            0,
            0,
            0,
            0,
            0
          ],
          "cves": [],
          "signals": [],
          "key": true,
          "resolved": true,
          "published": "2024-12-05T23:31:13Z"
        },
        {
          "version": "5.1.0",
          "vector": [
            0,
            0,
            0,
            0,
            0
          ],
          "cves": [],
          "signals": [
            {
              "name": "major-jump",
              "evidence": "leaves major version 4",
              "blocking": false
            }
          ],
          "key": true,
          "resolved": true,
          "published": "2025-03-31T14:00:00Z"
        }
      ]
    }
  ],
  "warnings": []
}`

func TestDecodeA070ResultHasNoJumpOrFamily(t *testing.T) {
	result, ok := decodeAnalysisResult(json.RawMessage(candidates070))
	if !ok {
		t.Fatal("decodeAnalysisResult rejected a 0.7.0 analysis")
	}
	if result.Families != nil {
		t.Errorf("Families = %+v, want absent", *result.Families)
	}
	express := result.Dependencies[0]
	if express.Jump != nil || express.Family != nil {
		t.Errorf("Jump, Family = %v, %v, want both absent", express.Jump, express.Family)
	}
	for _, c := range express.Cves {
		if c.Package != nil || c.FixedIn != nil {
			t.Errorf("CVE %s carries package %v and fixedIn %v, want both absent: the fix is unknown", c.Id, c.Package, c.FixedIn)
		}
	}
	marks := map[string]bool{}
	for _, c := range express.Candidates {
		marks[c.Version] = c.LeavesLine
	}
	if marks["4.21.2"] || !marks["5.1.0"] {
		t.Errorf("leavesLine = %v, want 5.1.0 marked and 4.21.2 not", marks)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"families"`, `"jump"`, `"family"`, `"package"`, `"fixedIn"`} {
		if strings.Contains(string(encoded), key) {
			t.Errorf("the answer for a 0.7.0 analysis carries %s: %s", key, encoded)
		}
	}
}

func TestStatusForAnUnreachableReleaseSourceIsBadGateway(t *testing.T) {
	if got := statusFor(fmt.Errorf("wrapped: %w", tools.ErrReleaseSourceUnavailable)); got != http.StatusBadGateway {
		t.Fatalf("statusFor = %d, want %d", got, http.StatusBadGateway)
	}
}
