package npm

import (
	"strings"
	"testing"
)

func TestIsExactVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"1.2.3", true},
		{"0.0.0", true},
		{"1.2.3-rc.1", true},
		{"1.2.3+build.5", true},
		{"^1.2.3", false},
		{"~1.2.3", false},
		{">=1.2.3", false},
		{"1.2", false},
		{"1.2.x", false},
		{"latest", false},
		{"01.2.3", false},
		{"", false},
	} {
		if got := IsExactVersion(tc.in); got != tc.want {
			t.Errorf("IsExactVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseManifestAndValidate(t *testing.T) {
	const pkg = `{
	  "name": "demo",
	  "dependencies": {"express": "4.21.2", "lodash": "^4.17.21", "left-pad": "npm:pad@1.0.0"},
	  "devDependencies": {"typescript": "5.7.3", "local": "file:../local"},
	  "optionalDependencies": {"fsevents": "2.3.3"},
	  "pnpm": {"overrides": {"qs": "6.13.0"}}
	}`
	m, err := ParseManifest(strings.NewReader(pkg))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "demo" {
		t.Errorf("Name = %q, want demo", m.Name)
	}

	var deps []string
	for _, d := range m.Dependencies {
		deps = append(deps, string(d.Kind)+" "+d.Name+" "+d.Version)
	}
	wantDeps := []string{
		"dependencies express 4.21.2",
		"dependencies left-pad npm:pad@1.0.0",
		"dependencies lodash ^4.17.21",
		"devDependencies local file:../local",
		"devDependencies typescript 5.7.3",
		"optionalDependencies fsevents 2.3.3",
	}
	if got, want := strings.Join(deps, "\n"), strings.Join(wantDeps, "\n"); got != want {
		t.Errorf("Dependencies:\n%s\nwant:\n%s", got, want)
	}

	var problems []string
	for _, p := range m.Validate() {
		problems = append(problems, p.Field+" | "+p.Name+" | "+p.Reason)
	}
	wantProblems := []string{
		"pnpm.overrides |  | not supported",
		"dependencies | left-pad | only npm registry versions are supported",
		"dependencies | lodash | version must be exact, such as 1.2.3",
		"devDependencies | local | only npm registry versions are supported",
	}
	if got, want := strings.Join(problems, "\n"), strings.Join(wantProblems, "\n"); got != want {
		t.Errorf("Validate:\n%s\nwant:\n%s", got, want)
	}
}

func TestParseManifestRejectsInvalidJSON(t *testing.T) {
	if _, err := ParseManifest(strings.NewReader("{")); err == nil {
		t.Fatal("ParseManifest accepted truncated JSON")
	}
}
