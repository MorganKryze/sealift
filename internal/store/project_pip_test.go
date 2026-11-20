package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// record062 is a project.json as 0.6.2 wrote it, byte for byte.
const record062 = `{
  "id": "left-pad-abc123",
  "name": "left-pad",
  "target": {
    "os": "linux",
    "cpu": "x64",
    "libc": "glibc",
    "node": "22.17.1",
    "pnpmVer": "10.34.5"
  },
  "createdAt": "2026-11-01T10:00:00Z",
  "manifestSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
`

func TestProjectStoredBeforePipReadsAsNPM(t *testing.T) {
	s := openTestStore(t)
	dir := filepath.Join(s.root, "projects", "left-pad-abc123")
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "project.json"), []byte(record062), 0o660); err != nil {
		t.Fatal(err)
	}

	p, err := s.Project("left-pad-abc123")
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if p.Ecosystem != NPM {
		t.Errorf("Ecosystem = %q, want %q", p.Ecosystem, NPM)
	}
	if p.Target.Node != "22.17.1" || p.Target.CPU != "x64" {
		t.Errorf("Target = %+v, want the stored npm target", p.Target)
	}
	if p.PipTarget != (PipTarget{}) {
		t.Errorf("PipTarget = %+v, want none", p.PipTarget)
	}
}

func TestNPMProjectRecordCarriesNoEcosystem(t *testing.T) {
	s := openTestStore(t)
	p, err := s.CreateProject("left-pad", []byte(`{"name":"left-pad"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Ecosystem != NPM {
		t.Errorf("Ecosystem = %q, want %q", p.Ecosystem, NPM)
	}
	data, err := os.ReadFile(filepath.Join(p.Dir, "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range keys {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"createdAt", "id", "manifestSha256", "name", "target"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("project.json keys = %v, want %v", got, want)
	}
}

func TestPipProjectRoundTrip(t *testing.T) {
	s := openTestStore(t)
	files := []RequirementsFile{
		{Name: "requirements.txt", Data: []byte("requests==2.32.3\n")},
		{Name: "requirements-dev.txt", Data: []byte("-r requirements.txt\npytest==8.3.3\n")},
		{Name: "constraints.txt", Data: []byte("urllib3==2.2.3\n")},
	}
	created, err := s.CreatePipProject("Data tools", files, DefaultPipTarget)
	if err != nil {
		t.Fatalf("CreatePipProject: %v", err)
	}
	if created.Ecosystem != Pip || created.PipTarget != DefaultPipTarget {
		t.Fatalf("created = %+v, want a pip project with the default target", created)
	}
	if created.Target != (Target{}) {
		t.Errorf("Target = %+v, want none for a pip project", created.Target)
	}
	if !strings.HasPrefix(created.ID, "data-tools-") {
		t.Errorf("ID = %q, want a slug of the name", created.ID)
	}

	read, err := s.Project(created.ID)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if read != created {
		t.Errorf("Project = %+v, want %+v", read, created)
	}
	got, err := s.ProjectRequirements(created.ID)
	if err != nil {
		t.Fatalf("ProjectRequirements: %v", err)
	}
	if !reflect.DeepEqual(got, files) {
		t.Errorf("ProjectRequirements = %+v, want the files in upload order", got)
	}

	data, err := os.ReadFile(filepath.Join(created.Dir, "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	if _, has := keys["target"]; has {
		t.Errorf("pip project.json holds an npm target: %s", data)
	}
	for _, k := range []string{"ecosystem", "pipTarget", "requirements"} {
		if _, has := keys[k]; !has {
			t.Errorf("pip project.json lacks %q: %s", k, data)
		}
	}

	listed, err := s.Projects()
	if err != nil || len(listed) != 1 || listed[0] != created {
		t.Errorf("Projects = %+v, %v, want the pip project", listed, err)
	}
}

func TestPipProjectRefusesUnsafeFileNames(t *testing.T) {
	cases := []struct {
		name  string
		files []RequirementsFile
	}{
		{"parent directory", []RequirementsFile{{Name: "../x.txt", Data: []byte("a==1\n")}}},
		{"separator", []RequirementsFile{{Name: "a/b.txt", Data: []byte("a==1\n")}}},
		{"hidden", []RequirementsFile{{Name: ".hidden", Data: []byte("a==1\n")}}},
		{"empty", []RequirementsFile{{Name: "", Data: []byte("a==1\n")}}},
		{"double dot", []RequirementsFile{{Name: "a..b", Data: []byte("a==1\n")}}},
		{"too long", []RequirementsFile{{Name: strings.Repeat("a", 129), Data: []byte("a==1\n")}}},
		{"case twin", []RequirementsFile{{Name: "r.txt", Data: []byte("a==1\n")}, {Name: "R.txt", Data: []byte("b==1\n")}}},
		{"no file", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := openTestStore(t)
			if _, err := s.CreatePipProject("proj", c.files, DefaultPipTarget); err == nil {
				t.Fatal("CreatePipProject accepted the files, want an error")
			}
			entries, err := os.ReadDir(filepath.Join(s.root, "projects"))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("projects/ holds %d entries after a refusal, want none", len(entries))
			}
		})
	}
}

func TestPipProjectRefusesInvalidTarget(t *testing.T) {
	s := openTestStore(t)
	bad := DefaultPipTarget
	bad.CPU = "aarch64"
	_, err := s.CreatePipProject("proj", []RequirementsFile{{Name: "r.txt", Data: []byte("a==1\n")}}, bad)
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("err = %v, want ErrInvalidTarget", err)
	}
}

func TestSetProjectTargetRefusesAPipProject(t *testing.T) {
	s := openTestStore(t)
	p, err := s.CreatePipProject("proj", []RequirementsFile{{Name: "r.txt", Data: []byte("a==1\n")}}, DefaultPipTarget)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetProjectTarget(p.ID, s.Settings().Target); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("err = %v, want ErrInvalidTarget", err)
	}
}

func TestValidatePipTarget(t *testing.T) {
	with := func(edit func(*PipTarget)) PipTarget {
		t := DefaultPipTarget
		edit(&t)
		return t
	}
	cases := []struct {
		name   string
		target PipTarget
		want   string // empty: accepted
	}{
		{"default", DefaultPipTarget, ""},
		{"glibc 2.17", with(func(t *PipTarget) { t.Glibc = "2.17" }), ""},
		{"glibc 2.40", with(func(t *PipTarget) { t.Glibc = "2.40" }), ""},
		{"python without patch", with(func(t *PipTarget) { t.Python = "3.11" }), "python"},
		{"python 2", with(func(t *PipTarget) { t.Python = "2.7.18" }), "python"},
		{"windows", with(func(t *PipTarget) { t.OS = "windows" }), "os"},
		{"aarch64", with(func(t *PipTarget) { t.CPU = "aarch64" }), "only x86_64 for now"},
		{"glibc 2.16", with(func(t *PipTarget) { t.Glibc = "2.16" }), "glibc"},
		{"glibc 2.41", with(func(t *PipTarget) { t.Glibc = "2.41" }), "glibc"},
		{"glibc 3.0", with(func(t *PipTarget) { t.Glibc = "3.0" }), "glibc"},
		{"uv without patch", with(func(t *PipTarget) { t.UvVer = "0.13" }), "uvVer"},
		{"empty", PipTarget{}, "python"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePipTarget(c.target)
			if c.want == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("err = %v, want ErrInvalidTarget", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %q, want it to contain %q", err, c.want)
			}
		})
	}
}
