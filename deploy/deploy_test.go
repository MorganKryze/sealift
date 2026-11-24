// Package deploy tests the deployment examples under this directory.
package deploy

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/store"
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
		// A daemon.json can set no-new-privileges for every container, so
		// the service turns it off by name: leaving it out is not enough.
		if !slices.Equal(s.SecurityOpt, []string{"no-new-privileges=false"}) {
			t.Errorf("%s: security_opt = %v, want [no-new-privileges=false]", name, s.SecurityOpt)
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

// The ephemeral overlay turns the mode on and keeps the working data in
// RAM, owned by the app user and the data group so the tools user can write.
func TestConnectedEphemeralCompose(t *testing.T) {
	var c struct {
		Services map[string]struct {
			Environment map[string]string
			Tmpfs       []string
		}
	}
	load(t, "connected/compose.ephemeral.yaml", &c)
	s, ok := c.Services["sealift"]
	if !ok || len(c.Services) != 1 {
		t.Fatalf("services = %v, want sealift alone", c.Services)
	}
	if s.Environment["SEALIFT_EPHEMERAL"] != "1" {
		t.Errorf("SEALIFT_EPHEMERAL = %q, want 1", s.Environment["SEALIFT_EPHEMERAL"])
	}
	for _, dir := range []string{"/data/projects", "/data/cache"} {
		found := false
		for _, m := range s.Tmpfs {
			path, opts, _ := strings.Cut(m, ":")
			if path != dir {
				continue
			}
			found = true
			for _, want := range []string{"uid=10000", "gid=2000", "mode=0770", "size="} {
				if !strings.Contains(opts, want) {
					t.Errorf("tmpfs %s lacks %s: %q", dir, want, opts)
				}
			}
		}
		if !found {
			t.Errorf("no tmpfs on %s in %v", dir, s.Tmpfs)
		}
	}
	// compose merges tmpfs lists: a second /tmp would clash with the base file's.
	if slices.ContainsFunc(s.Tmpfs, func(m string) bool { return strings.HasPrefix(m, "/tmp") }) {
		t.Errorf("the overlay repeats /tmp, which compose.yaml already mounts")
	}
}

// A first start downloads Trivy, its database, pnpm and uv before /healthz
// answers 200, so the healthcheck must not count those minutes as failures.
func TestConnectedHealthcheckWaitsForThePreparation(t *testing.T) {
	var c struct {
		Services map[string]struct {
			Healthcheck struct {
				Interval      string
				StartPeriod   string `yaml:"start_period"`
				StartInterval string `yaml:"start_interval"`
			}
		}
	}
	load(t, "connected/compose.yaml", &c)
	h := c.Services["sealift"].Healthcheck
	duration := func(name, v string) time.Duration {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("%s = %q: %v", name, v, err)
		}
		return d
	}
	if d := duration("start_period", h.StartPeriod); d < 10*time.Minute {
		t.Errorf("start_period = %s, want at least 10m, the time a first start may take to download its tools", d)
	}
	start, interval := duration("start_interval", h.StartInterval), duration("interval", h.Interval)
	if start <= 0 || start >= interval {
		t.Errorf("start_interval = %s, want above zero and under interval %s, so the instance turns healthy soon after it is ready", start, interval)
	}
}

// The policy overlay mounts the policy folder read-only and names its file,
// on top of compose.yaml, as the ephemeral overlay does.
func TestPolicyOverlayMountsReadOnly(t *testing.T) {
	var c struct {
		Services map[string]struct {
			Environment map[string]string
			Volumes     []string
		}
	}
	load(t, "connected/compose.policy.yaml", &c)
	s, ok := c.Services["sealift"]
	if !ok || len(c.Services) != 1 {
		t.Fatalf("services = %v, want sealift alone", c.Services)
	}
	if !slices.Equal(s.Volumes, []string{"./policy:/etc/sealift:ro"}) {
		t.Errorf("volumes = %v, want [./policy:/etc/sealift:ro]", s.Volumes)
	}
	want := "/etc/sealift/policy.yaml"
	if s.Environment["SEALIFT_POLICY"] != want {
		t.Errorf("SEALIFT_POLICY = %q, want %q", s.Environment["SEALIFT_POLICY"], want)
	}
	if _, err := os.Stat("connected/policy/policy.yaml"); err != nil {
		t.Errorf("the mounted folder holds no policy.yaml: %v", err)
	}
}

// The example policy sets no key, so mounting it unchanged changes nothing:
// a new instance keeps the defaults and an upgraded one keeps the settings
// it saved.
func TestExamplePolicyLoads(t *testing.T) {
	p, err := policy.Load("connected/policy/policy.yaml", store.Settings{}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := policy.Policy{Settings: store.DefaultSettings, Pip: store.DefaultPipTarget, Brand: policy.DefaultBrand()}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("example policy = %+v, want the defaults %+v", p, want)
	}
}

func TestExamplePolicyKeepsSavedSettings(t *testing.T) {
	saved := store.Settings{
		Target:              store.Target{OS: "linux", CPU: "arm64", Libc: "musl", Node: "20.19.4", PnpmVer: "9.15.9"},
		MinReleaseAgeDays:   21,
		ResolveParallelism:  2,
		DownloadParallelism: 8,
	}
	p, err := policy.Load("connected/policy/policy.yaml", saved, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Settings != saved {
		t.Errorf("settings in effect = %+v, want the saved %+v", p.Settings, saved)
	}
	if len(p.Overrides) != 0 {
		t.Errorf("overrides = %v, want none", p.Overrides)
	}
}

// The lab mounts a policy whose brand differs from the default in every
// field, so each one shows on screen.
func TestLabPolicyChangesEveryBrandField(t *testing.T) {
	var c struct {
		Services map[string]struct {
			Environment map[string]string
			Volumes     []string
		}
	}
	load(t, "../lab/compose.yaml", &c)
	s := c.Services["sealift"]
	if !slices.Contains(s.Volumes, "./policy:/etc/sealift:ro") {
		t.Errorf("lab sealift volumes = %v, want ./policy:/etc/sealift:ro", s.Volumes)
	}
	if s.Environment["SEALIFT_POLICY"] != "/etc/sealift/policy.yaml" {
		t.Errorf("lab SEALIFT_POLICY = %q, want /etc/sealift/policy.yaml", s.Environment["SEALIFT_POLICY"])
	}
	p, err := policy.Load("../lab/policy/policy.yaml", store.Settings{}, false)
	if err != nil {
		t.Fatal(err)
	}
	b, d := p.Brand, policy.DefaultBrand()
	for _, f := range []struct {
		name     string
		got, def string
	}{
		{"name", b.Name, d.Name},
		{"accent", b.Accent, d.Accent},
		{"sides.online", b.Online, d.Online},
		{"sides.offline", b.Offline, d.Offline},
		{"reviewWord", b.ReviewWord, d.ReviewWord},
		{"logo type", b.LogoType, d.LogoType},
	} {
		if f.got == f.def {
			t.Errorf("lab brand %s = %q, the default", f.name, f.got)
		}
	}
	if b.Contact == nil {
		t.Error("lab brand has no contact, the default")
	}
}

// uncommentPolicy turns the example's commented keys into YAML and leaves
// its prose out: a commented key is a "#" line whose text starts with a key
// or a nested comment.
func uncommentPolicy(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key := regexp.MustCompile(`^\s*([A-Za-z]+:|#)`)
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		text, ok := strings.CutPrefix(line, "# ")
		if ok && key.MatchString(text) {
			out = append(out, text)
		}
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// keyPaths lists every mapping key of a YAML document, dotted from the root.
func keyPaths(n *yaml.Node, prefix string, out *[]string) {
	if n.Kind == yaml.DocumentNode {
		for _, c := range n.Content {
			keyPaths(c, prefix, out)
		}
		return
	}
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		p := prefix + n.Content[i].Value
		*out = append(*out, p)
		keyPaths(n.Content[i+1], p+".", out)
	}
}

// The example spells out every key the policy reads, and the values it
// shows are the defaults: uncommented, it loads to the defaults plus the
// three brand keys that have none.
func TestExamplePolicySpellsOutEveryDefault(t *testing.T) {
	text := uncommentPolicy(t, "connected/policy/policy.yaml")
	var doc yaml.Node
	if err := yaml.Unmarshal(text, &doc); err != nil {
		t.Fatalf("the uncommented example is not YAML: %v\n%s", err, text)
	}
	var got []string
	keyPaths(&doc, "", &got)
	want := []string{
		"targets", "targets.npm", "targets.npm.os", "targets.npm.cpu", "targets.npm.libc", "targets.npm.node", "targets.npm.pnpm",
		"targets.pip", "targets.pip.python", "targets.pip.os", "targets.pip.cpu", "targets.pip.glibc", "targets.pip.uv",
		"minReleaseAgeDays",
		"parallelism", "parallelism.resolve", "parallelism.download",
		"brand", "brand.name", "brand.sides", "brand.sides.online", "brand.sides.offline", "brand.reviewWord",
		"brand.logo", "brand.accent", "brand.contact", "brand.contact.label", "brand.contact.url",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("keys of the uncommented example = %v, want %v", got, want)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	logo := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>`)
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "logo.svg"), logo, 0o600); err != nil {
		t.Fatal(err)
	}
	// Load refuses an unknown key, so a key the example misspells fails here.
	p, err := policy.Load(path, store.Settings{}, false)
	if err != nil {
		t.Fatalf("the uncommented example does not load: %v", err)
	}
	wantBrand := policy.DefaultBrand()
	wantBrand.Logo, wantBrand.LogoType = p.Brand.Logo, p.Brand.LogoType
	wantBrand.Accent = "#0b6e99"
	wantBrand.Contact = &policy.Contact{Label: "Platform team", URL: "mailto:platform@example.com"}
	wantP := policy.Policy{Settings: store.DefaultSettings, Pip: store.DefaultPipTarget, Brand: wantBrand}
	if !reflect.DeepEqual(p, wantP) {
		t.Errorf("uncommented example = %+v, want the defaults %+v", p, wantP)
	}
	if p.Brand.LogoType != "image/svg+xml" {
		t.Errorf("logo type = %q, want image/svg+xml", p.Brand.LogoType)
	}
}
