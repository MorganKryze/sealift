// Package deploy tests the deployment examples under this directory.
package deploy

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func load(t *testing.T, path string, out any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestConnectedCompose(t *testing.T) {
	var c struct {
		Services map[string]struct {
			Image       string
			ReadOnly    bool `yaml:"read_only"`
			Tmpfs       []string
			CapDrop     []string `yaml:"cap_drop"`
			CapAdd      []string `yaml:"cap_add"`
			SecurityOpt []string `yaml:"security_opt"`
			Ports       []string
			Volumes     []string
			Healthcheck struct {
				Test []string
			}
		}
		Volumes map[string]struct {
			External bool
			Name     string
		}
	}
	load(t, "connected/compose.yaml", &c)
	if len(c.Services) != 1 {
		t.Fatalf("services = %d, want 1", len(c.Services))
	}
	for name, s := range c.Services {
		if !s.ReadOnly {
			t.Errorf("%s: read_only is not true", name)
		}
		if !slices.Contains(s.Tmpfs, "/tmp") {
			t.Errorf("%s: tmpfs = %v, want /tmp", name, s.Tmpfs)
		}
		if !slices.Equal(s.CapDrop, []string{"ALL"}) {
			t.Errorf("%s: cap_drop = %v, want [ALL]", name, s.CapDrop)
		}
		add := slices.Clone(s.CapAdd)
		slices.Sort(add)
		if !slices.Equal(add, []string{"KILL", "SETGID", "SETUID"}) {
			t.Errorf("%s: cap_add = %v, want SETUID SETGID KILL", name, s.CapAdd)
		}
		for _, o := range s.SecurityOpt {
			if strings.Contains(o, "no-new-privileges") {
				t.Errorf("%s: security_opt carries %q, which breaks the switch to the tools user", name, o)
			}
		}
		if len(s.Ports) == 0 {
			t.Errorf("%s: no port mapping", name)
		}
		for _, p := range s.Ports {
			if !strings.HasPrefix(p, "127.0.0.1:") {
				t.Errorf("%s: port %q is not bound to 127.0.0.1", name, p)
			}
		}
		var data string
		for _, v := range s.Volumes {
			if strings.HasSuffix(v, ":/data") {
				data = strings.TrimSuffix(v, ":/data")
			}
		}
		if data == "" {
			t.Errorf("%s: no volume mounted at /data", name)
		} else if v, ok := c.Volumes[data]; !ok {
			t.Errorf("%s: /data source %q is not a named volume", name, data)
		} else if !v.External || v.Name != "sealift-data" {
			t.Errorf("%s: volume %q = %+v, want external and named sealift-data, so a volume from a docker run install is kept", name, data, v)
		}
		if !strings.Contains(strings.Join(s.Healthcheck.Test, " "), "/healthz") {
			t.Errorf("%s: healthcheck = %v, want /healthz", name, s.Healthcheck.Test)
		}
	}
}

func TestArgoCDExamples(t *testing.T) {
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	load(t, "../charts/sealift/Chart.yaml", &chart)
	if chart.AppVersion == "" {
		t.Fatal("chart has no appVersion")
	}

	var repo struct {
		StringData map[string]string `yaml:"stringData"`
		Data       map[string]string `yaml:"data"`
	}
	load(t, "argocd/repository.yaml", &repo)
	url := repo.StringData["url"]
	if url == "" {
		t.Error("repository has no url")
	}
	if strings.Contains(url, "oci://") {
		t.Errorf("repository url %q carries oci://", url)
	}
	if repo.StringData["enableOCI"] != "true" {
		t.Errorf("enableOCI = %q, want \"true\"", repo.StringData["enableOCI"])
	}
	if repo.StringData["type"] != "helm" {
		t.Errorf("type = %q, want helm", repo.StringData["type"])
	}
	for _, m := range []map[string]string{repo.StringData, repo.Data} {
		for _, k := range []string{"password", "username", "token"} {
			if _, ok := m[k]; ok {
				t.Errorf("repository carries a %s key", k)
			}
		}
	}

	var app struct {
		Spec struct {
			Destination struct {
				Namespace string
			}
			Sources []struct {
				Chart          string
				TargetRevision string `yaml:"targetRevision"`
				Ref            string
				RepoURL        string `yaml:"repoURL"`
			}
			SyncPolicy struct {
				Automated   map[string]any `yaml:"automated"`
				SyncOptions []string       `yaml:"syncOptions"`
			} `yaml:"syncPolicy"`
		}
	}
	load(t, "argocd/application.yaml", &app)
	if len(app.Spec.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(app.Spec.Sources))
	}
	var hasRef, hasChart bool
	for _, s := range app.Spec.Sources {
		if s.Ref == "values" {
			hasRef = true
		}
		if s.Chart == "sealift" {
			hasChart = true
			if s.TargetRevision != chart.AppVersion {
				t.Errorf("targetRevision = %q, want appVersion %q", s.TargetRevision, chart.AppVersion)
			}
		}
	}
	if !hasRef || !hasChart {
		t.Errorf("sources: ref values = %v, chart sealift = %v", hasRef, hasChart)
	}
	if app.Spec.Destination.Namespace != "<namespace>" {
		t.Errorf("destination namespace = %q, want the <namespace> placeholder", app.Spec.Destination.Namespace)
	}
	if app.Spec.SyncPolicy.Automated != nil {
		t.Error("syncPolicy.automated is set")
	}
	if !slices.Contains(app.Spec.SyncPolicy.SyncOptions, "CreateNamespace=true") {
		t.Errorf("syncOptions = %v, want CreateNamespace=true", app.Spec.SyncPolicy.SyncOptions)
	}
}
