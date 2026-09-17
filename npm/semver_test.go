package npm

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// testdata/engines-oracle.json holds every engines.node range of
// testdata/pnpm-lock.yaml, evaluated by the npm semver package 7.8.5.
func TestSatisfiesNodeAgreesWithNpm(t *testing.T) {
	data, err := os.ReadFile("testdata/engines-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Range  string `json:"range"`
		Node22 bool   `json:"node22_17_1"`
		Node18 bool   `json:"node18_12_0"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty oracle")
	}
	for _, c := range cases {
		for version, want := range map[string]bool{"22.17.1": c.Node22, "18.12.0": c.Node18} {
			got, err := SatisfiesNode(c.Range, version)
			if err != nil {
				t.Errorf("SatisfiesNode(%q, %s): %v", c.Range, version, err)
				continue
			}
			if got != want {
				t.Errorf("SatisfiesNode(%q, %s) = %v, npm says %v", c.Range, version, got, want)
			}
		}
	}
}

func TestSatisfiesNodeEdges(t *testing.T) {
	if ok, err := SatisfiesNode("", "22.17.1"); !ok || err != nil {
		t.Errorf("empty range = %v, %v; want true, nil", ok, err)
	}
	if _, err := SatisfiesNode(">=18", "22"); err == nil {
		t.Error("want an error for a partial node version")
	}
	if _, err := SatisfiesNode("not a range", "22.17.1"); err == nil {
		t.Error("want an error for an unreadable range")
	}
}

func TestNewerStable(t *testing.T) {
	got, err := NewerStable("4.21.2", []string{"4.17.1", "5.0.0-beta.1", "4.21.2", "5.1.0", "4.22.0", "not-a-version", "4.21.10"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"4.21.10", "4.22.0", "5.1.0"}; !slices.Equal(got, want) {
		t.Errorf("NewerStable = %v, want %v", got, want)
	}
	if _, err := NewerStable("latest", nil); err == nil {
		t.Error("want an error for a current version that is not a version")
	}
}
