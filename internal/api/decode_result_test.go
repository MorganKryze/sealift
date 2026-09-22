package api

import (
	"encoding/json"
	"strings"
	"testing"
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
