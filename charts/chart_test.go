// Package charts tests the Helm chart by rendering it with the helm binary.
package charts

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importer"
)

const (
	chartDir   = "sealift"
	testValues = "testdata/values.yaml"
	testPEM    = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAfeijnGwLPX7OsM+Psi9HTKFkPKEFMZVWaXDua1BTEOA=\n-----END PUBLIC KEY-----\n"
	// testCA is a stand-in: nothing parses it.
	testCA = "-----BEGIN CERTIFICATE-----\nZXhhbXBsZQ==\n-----END CERTIFICATE-----\n"
)

// helm returns the path of the helm binary. It skips the test when helm is
// absent, and fails it when SEALIFT_CHART=1, which CI sets.
func helm(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("SEALIFT_CHART") == "1" {
			t.Fatal("helm is not installed and SEALIFT_CHART=1")
		}
		t.Skip("helm is not installed")
	}
	return path
}

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := exec.Command(helm(t), args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}

// render runs helm template on the chart with the test values and args after them.
func render(t *testing.T, args ...string) ([]map[string]any, error) {
	t.Helper()
	out, err := run(t, append([]string{"template", "rel", chartDir, "-f", testValues}, args...)...)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(strings.NewReader(out))
	var docs []map[string]any
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			return docs, nil
		} else if err != nil {
			return nil, err
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
}

func mustRender(t *testing.T, args ...string) []map[string]any {
	t.Helper()
	docs, err := render(t, args...)
	if err != nil {
		t.Fatalf("render %v: %v", args, err)
	}
	return docs
}

// kinds returns "Kind/name" for each document, in order.
func kinds(docs []map[string]any) []string {
	var out []string
	for _, d := range docs {
		out = append(out, fmt.Sprintf("%v/%v", d["kind"], at(d, "metadata", "name")))
	}
	return out
}

// at follows string keys and int indexes through decoded YAML; nil when a step is missing.
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

// find returns the document of a kind, and its name when several share the kind.
func find(t *testing.T, docs []map[string]any, kind, name string) map[string]any {
	t.Helper()
	for _, d := range docs {
		if d["kind"] == kind && (name == "" || at(d, "metadata", "name") == name) {
			return d
		}
	}
	t.Fatalf("no %s %s in %v", kind, name, kinds(docs))
	return nil
}

func deployment(t *testing.T, args ...string) map[string]any {
	t.Helper()
	return find(t, mustRender(t, args...), "Deployment", "")
}

func container(d map[string]any) map[string]any {
	c, _ := at(d, "spec", "template", "spec", "containers", 0).(map[string]any)
	return c
}

func volume(t *testing.T, d map[string]any, name string) map[string]any {
	t.Helper()
	vols, _ := at(d, "spec", "template", "spec", "volumes").([]any)
	for _, v := range vols {
		if at(v, "name") == name {
			return v.(map[string]any)
		}
	}
	return nil
}

func mount(d map[string]any, name string) map[string]any {
	mounts, _ := at(container(d), "volumeMounts").([]any)
	for _, m := range mounts {
		if at(m, "name") == name {
			return m.(map[string]any)
		}
	}
	return nil
}

// installNotes returns the NOTES text of a client-side dry-run install.
func installNotes(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run(t, append([]string{"install", "rel", chartDir, "--dry-run=client", "-f", testValues}, args...)...)
	if err != nil {
		t.Fatalf("install %v: %v", args, err)
	}
	_, notes, ok := strings.Cut(out, "NOTES:\n")
	if !ok {
		t.Fatalf("no NOTES in the install output of %v", args)
	}
	return notes
}

func writeValues(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestChartRunsOneImportService(t *testing.T) {
	docs := mustRender(t)
	d := find(t, docs, "Deployment", "")
	c := container(d)
	if got := at(d, "spec", "replicas"); got != 1 {
		t.Errorf("replicas = %v, want 1", got)
	}
	if got := at(d, "spec", "strategy", "type"); got != "Recreate" {
		t.Errorf("strategy = %v, want Recreate", got)
	}
	if n := len(at(d, "spec", "template", "spec", "containers").([]any)); n != 1 {
		t.Errorf("containers = %d, want 1", n)
	}
	if got := at(c, "image"); got != "ghcr.io/morgankryze/sealift:0.6.0" {
		t.Errorf("image = %v, want the image at appVersion", got)
	}
	wantArgs := []any{"sealift", "import-server", "-settings", "/etc/sealift/config/settings.yaml", "-addr", "0.0.0.0:8080", "-data", "/data"}
	if got := fmt.Sprint(at(c, "args")); got != fmt.Sprint(wantArgs) {
		t.Errorf("args = %v, want %v", got, wantArgs)
	}
	if got := at(d, "spec", "template", "spec", "automountServiceAccountToken"); got != false {
		t.Errorf("automountServiceAccountToken = %v, want false", got)
	}
	sc, _ := at(c, "securityContext").(map[string]any)
	for key, want := range map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true} {
		if sc[key] != want {
			t.Errorf("container securityContext.%s = %v, want %v", key, sc[key], want)
		}
	}
	if got := fmt.Sprint(at(sc, "capabilities", "drop")); got != "[ALL]" {
		t.Errorf("capabilities.drop = %v, want [ALL]", got)
	}
	if got := at(sc, "seccompProfile", "type"); got != "RuntimeDefault" {
		t.Errorf("container seccompProfile = %v, want RuntimeDefault", got)
	}
	psc := at(d, "spec", "template", "spec", "securityContext")
	if got := at(psc, "fsGroup"); got != 2000 {
		t.Errorf("fsGroup = %v, want 2000", got)
	}
	if got := at(psc, "runAsNonRoot"); got != true {
		t.Errorf("pod runAsNonRoot = %v, want true", got)
	}
	if got := at(d, "spec", "template", "spec", "nodeSelector", "kubernetes.io/arch"); got != "amd64" {
		t.Errorf("nodeSelector arch = %v, want amd64", got)
	}
	for _, probe := range []string{"livenessProbe", "readinessProbe"} {
		if got := at(c, probe, "httpGet", "path"); got != "/healthz" {
			t.Errorf("%s path = %v, want /healthz", probe, got)
		}
	}
	if m := mount(d, "tmp"); m == nil || m["mountPath"] != "/tmp" {
		t.Errorf("tmp mount = %v, want /tmp", m)
	}
	if v := volume(t, d, "tmp"); at(v, "emptyDir") == nil {
		t.Errorf("tmp volume = %v, want an emptyDir", v)
	}
	if at(c, "env") != nil {
		t.Errorf("env = %v, want none without a CA", at(c, "env"))
	}
	if sum, _ := at(d, "spec", "template", "metadata", "annotations", "checksum/settings").(string); sum == "" {
		t.Error("the pod carries no checksum/settings annotation")
	}
	if got := at(find(t, docs, "Service", ""), "spec", "ports", 0, "port"); got != 8080 {
		t.Errorf("service port = %v, want 8080", got)
	}
	if got := kinds(docs); len(got) != 6 {
		t.Errorf("rendered %v, want a Deployment, a Service, a NetworkPolicy, a PersistentVolumeClaim and two ConfigMaps", got)
	}

	t.Run("no value raises the replica count", func(t *testing.T) {
		d := deployment(t, "--set", "replicaCount=3", "--set", "replicas=3")
		if got := at(d, "spec", "replicas"); got != 1 {
			t.Errorf("replicas = %v, want 1", got)
		}
	})
	t.Run("the node selector can change", func(t *testing.T) {
		d := deployment(t, "--set", "nodeSelector.kubernetes\\.io/arch=arm64")
		if got := at(d, "spec", "template", "spec", "nodeSelector", "kubernetes.io/arch"); got != "arm64" {
			t.Errorf("nodeSelector arch = %v, want arm64", got)
		}
	})
	t.Run("a changed setting rolls the pod", func(t *testing.T) {
		before := at(d, "spec", "template", "metadata", "annotations", "checksum/settings")
		after := at(deployment(t, "--set", "nexus.repository=other"), "spec", "template", "metadata", "annotations", "checksum/settings")
		if before == after {
			t.Errorf("checksum/settings stayed %v after a settings change", before)
		}
	})
}

func TestChartImageDigestAndPullSecrets(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name      string
		args      []string
		wantImage string
	}{
		{"a tag", []string{"--set", "image.repository=harbor.example.internal/team/sealift", "--set", "image.tag=0.6.1"}, "harbor.example.internal/team/sealift:0.6.1"},
		{"a digest", []string{"--set", "image.digest=" + digest}, "ghcr.io/morgankryze/sealift:0.6.0@" + digest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := at(container(deployment(t, tt.args...)), "image"); got != tt.wantImage {
				t.Errorf("image = %v, want %v", got, tt.wantImage)
			}
		})
	}
	t.Run("pull secrets", func(t *testing.T) {
		d := deployment(t, "--set", "imagePullSecrets[0].name=harbor-pull", "--set", "image.pullPolicy=Always")
		if got := at(d, "spec", "template", "spec", "imagePullSecrets", 0, "name"); got != "harbor-pull" {
			t.Errorf("imagePullSecrets = %v, want harbor-pull", got)
		}
		if got := at(container(d), "imagePullPolicy"); got != "Always" {
			t.Errorf("imagePullPolicy = %v, want Always", got)
		}
	})
	t.Run("no pull secret by default", func(t *testing.T) {
		if got := at(deployment(t), "spec", "template", "spec", "imagePullSecrets"); got != nil {
			t.Errorf("imagePullSecrets = %v, want none", got)
		}
	})
}

func TestChartRefusesUnfilledValues(t *testing.T) {
	keys := map[string]string{
		"nexus.url":         "<nexus-url>",
		"nexus.repository":  "<nexus-repository>",
		"nexus.user":        "<nexus-user>",
		"keycloak.realmUrl": "<keycloak-realm-url>",
		"keycloak.clientId": "<keycloak-client-id>",
		"minio.url":         "<minio-url>",
		"secret.name":       "<secret-name>",
		"publicKey.pem":     "<public-key-pem>",
		"token.header":      "<token-header>",
	}
	for key, placeholder := range keys {
		t.Run(key+" empty", func(t *testing.T) {
			_, err := render(t, "--set", key+"=")
			if err == nil || !strings.Contains(err.Error(), key+" is required") {
				t.Errorf("err = %v, want %q", err, key+" is required")
			}
		})
		t.Run(key+" placeholder", func(t *testing.T) {
			_, err := render(t, "--set", key+"="+placeholder)
			want := key + " still holds its placeholder " + placeholder
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want %q", err, want)
			}
		})
	}
	t.Run("token.header null removes the default and is refused", func(t *testing.T) {
		_, err := render(t, "-f", writeValues(t, "token:\n  header: ~\n"))
		if err == nil || !strings.Contains(err.Error(), "token.header is required") {
			t.Errorf("err = %v, want token.header is required", err)
		}
	})
	t.Run("a valid header is written", func(t *testing.T) {
		docs := mustRender(t, "--set", "token.header=X-Other")
		if got := settingsOf(t, docs); !strings.Contains(got, "header: X-Other") {
			t.Errorf("settings = %q, want header X-Other", got)
		}
	})
	t.Run("a public key is not needed with an existing ConfigMap", func(t *testing.T) {
		mustRender(t, "--set", "publicKey.pem=", "--set", "publicKey.existingConfigMap=keys")
	})
}

func settingsOf(t *testing.T, docs []map[string]any) string {
	t.Helper()
	s, _ := at(find(t, docs, "ConfigMap", "rel-sealift-settings"), "data", "settings.yaml").(string)
	if s == "" {
		t.Fatal("the settings ConfigMap holds no settings.yaml")
	}
	return s
}

func TestChartSecretsComeFromOneSecret(t *testing.T) {
	docs := mustRender(t)
	for _, name := range kinds(docs) {
		if strings.HasPrefix(name, "Secret/") {
			t.Errorf("the chart renders %s, want no Secret", name)
		}
	}
	d := find(t, docs, "Deployment", "")
	v := volume(t, d, "secrets")
	if got := at(v, "secret", "secretName"); got != "sealift-import" {
		t.Errorf("secretName = %v, want sealift-import", got)
	}
	if got := at(v, "secret", "defaultMode"); got != 0o440 && got != 288 && got != 440 {
		t.Errorf("defaultMode = %v, want 0440", got)
	}
	items, _ := at(v, "secret", "items").([]any)
	var keys []string
	for _, it := range items {
		keys = append(keys, fmt.Sprint(at(it, "key")))
	}
	if got, want := strings.Join(keys, ","), "nexus-password,minio-access-key,minio-secret-key"; got != want {
		t.Errorf("secret keys = %s, want %s", got, want)
	}
	if m := mount(d, "secrets"); m == nil || m["readOnly"] != true || m["mountPath"] != "/etc/sealift/secrets" {
		t.Errorf("secrets mount = %v, want read-only at /etc/sealift/secrets", m)
	}
	settings := settingsOf(t, docs)
	for _, secret := range []string{"password", "accesskey", "secretkey"} {
		if strings.Contains(strings.ToLower(settings), secret+":") {
			t.Errorf("settings carry a %s value", secret)
		}
	}
	t.Run("a value cannot hold a credential", func(t *testing.T) {
		out, err := run(t, "template", "rel", chartDir, "-f", testValues, "--set", "nexus.password=stand-in")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "stand-in") {
			t.Error("a nexus.password value reaches the rendered output")
		}
	})
}

func TestChartPublicKey(t *testing.T) {
	t.Run("PEM in the values", func(t *testing.T) {
		docs := mustRender(t)
		cm := find(t, docs, "ConfigMap", "rel-sealift-public-key")
		if got := at(cm, "data", "public-key.pem"); got != testPEM {
			t.Errorf("public-key.pem = %q, want the test key", got)
		}
		d := find(t, docs, "Deployment", "")
		if got := at(volume(t, d, "public-key"), "configMap", "name"); got != "rel-sealift-public-key" {
			t.Errorf("public-key volume = %v, want rel-sealift-public-key", got)
		}
		if m := mount(d, "public-key"); m == nil || m["readOnly"] != true || m["mountPath"] != "/etc/sealift/public-key" {
			t.Errorf("public-key mount = %v, want read-only at /etc/sealift/public-key", m)
		}
	})
	t.Run("an existing ConfigMap", func(t *testing.T) {
		docs := mustRender(t, "--set", "publicKey.pem=", "--set", "publicKey.existingConfigMap=collection-key")
		for _, k := range kinds(docs) {
			if strings.Contains(k, "public-key") {
				t.Errorf("rendered %s, want no public key ConfigMap", k)
			}
		}
		d := find(t, docs, "Deployment", "")
		if got := at(volume(t, d, "public-key"), "configMap", "name"); got != "collection-key" {
			t.Errorf("public-key volume = %v, want collection-key", got)
		}
	})
}

func TestChartCA(t *testing.T) {
	t.Run("PEM in the values", func(t *testing.T) {
		docs := mustRender(t, "--set-file", "ca.pem="+writeValues(t, testCA))
		d := find(t, docs, "Deployment", "")
		env, _ := at(container(d), "env", 0).(map[string]any)
		if env["name"] != "SSL_CERT_FILE" || env["value"] != "/etc/sealift/ca/ca.pem" {
			t.Errorf("env = %v, want SSL_CERT_FILE=/etc/sealift/ca/ca.pem", env)
		}
		if m := mount(d, "ca"); m == nil || m["readOnly"] != true || m["mountPath"] != "/etc/sealift/ca" {
			t.Errorf("ca mount = %v, want read-only at /etc/sealift/ca", m)
		}
		cm := find(t, docs, "ConfigMap", "rel-sealift-ca")
		if got := at(cm, "data", "ca.pem"); got != testCA {
			t.Errorf("ca.pem = %v, want the given PEM", got)
		}
		if got := at(volume(t, d, "ca"), "configMap", "name"); got != "rel-sealift-ca" {
			t.Errorf("ca volume = %v, want rel-sealift-ca", got)
		}
	})
	t.Run("an existing ConfigMap", func(t *testing.T) {
		docs := mustRender(t, "--set", "ca.existingConfigMap=org-ca")
		d := find(t, docs, "Deployment", "")
		if got := at(volume(t, d, "ca"), "configMap", "name"); got != "org-ca" {
			t.Errorf("ca volume = %v, want org-ca", got)
		}
		if at(container(d), "env", 0, "name") != "SSL_CERT_FILE" {
			t.Error("SSL_CERT_FILE is not set with an existing CA ConfigMap")
		}
		for _, k := range kinds(docs) {
			if strings.HasSuffix(k, "-ca") {
				t.Errorf("rendered %s, want no CA ConfigMap", k)
			}
		}
	})
	t.Run("no value turns certificate checks off", func(t *testing.T) {
		out, err := os.ReadFile(filepath.Join(chartDir, "values.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, word := range []string{"insecure", "skipVerify", "skip_verify", "InsecureSkipVerify"} {
			if strings.Contains(strings.ToLower(string(out)), strings.ToLower(word)) {
				t.Errorf("values.yaml mentions %s", word)
			}
		}
	})
}

func TestChartStorage(t *testing.T) {
	t.Run("a created claim is kept", func(t *testing.T) {
		docs := mustRender(t)
		pvc := find(t, docs, "PersistentVolumeClaim", "")
		if got := at(pvc, "metadata", "annotations", "helm.sh/resource-policy"); got != "keep" {
			t.Errorf("resource-policy = %v, want keep", got)
		}
		if got := at(pvc, "metadata", "annotations", "argocd.argoproj.io/sync-options"); got != "Prune=false,Delete=false" {
			t.Errorf("sync-options = %v, want Prune=false,Delete=false", got)
		}
		if got := at(pvc, "spec", "resources", "requests", "storage"); got != "20Gi" {
			t.Errorf("size = %v, want 20Gi", got)
		}
		if got := at(pvc, "spec", "accessModes", 0); got != "ReadWriteOnce" {
			t.Errorf("accessMode = %v, want ReadWriteOnce", got)
		}
		if at(pvc, "spec", "storageClassName") != nil {
			t.Error("a storage class is set without a value")
		}
		d := find(t, docs, "Deployment", "")
		if got := at(volume(t, d, "data"), "persistentVolumeClaim", "claimName"); got != at(pvc, "metadata", "name") {
			t.Errorf("claimName = %v, want the created claim", got)
		}
		if m := mount(d, "data"); m == nil || m["mountPath"] != "/data" {
			t.Errorf("data mount = %v, want /data", m)
		}
	})
	t.Run("size, class and mode follow the values", func(t *testing.T) {
		pvc := find(t, mustRender(t, "--set", "persistence.size=50Gi", "--set", "persistence.storageClass=fast", "--set", "persistence.accessMode=ReadWriteOncePod"), "PersistentVolumeClaim", "")
		if at(pvc, "spec", "resources", "requests", "storage") != "50Gi" || at(pvc, "spec", "storageClassName") != "fast" || at(pvc, "spec", "accessModes", 0) != "ReadWriteOncePod" {
			t.Errorf("claim spec = %v, want 50Gi, fast, ReadWriteOncePod", pvc["spec"])
		}
	})
	t.Run("an existing claim", func(t *testing.T) {
		docs := mustRender(t, "--set", "persistence.existingClaim=import-data")
		for _, k := range kinds(docs) {
			if strings.HasPrefix(k, "PersistentVolumeClaim/") {
				t.Errorf("rendered %s, want no claim", k)
			}
		}
		if got := at(volume(t, find(t, docs, "Deployment", ""), "data"), "persistentVolumeClaim", "claimName"); got != "import-data" {
			t.Errorf("claimName = %v, want import-data", got)
		}
	})
	t.Run("persistence off", func(t *testing.T) {
		docs := mustRender(t, "--set", "persistence.enabled=false")
		for _, k := range kinds(docs) {
			if strings.HasPrefix(k, "PersistentVolumeClaim/") {
				t.Errorf("rendered %s, want no claim", k)
			}
		}
		if v := volume(t, find(t, docs, "Deployment", ""), "data"); at(v, "emptyDir") == nil {
			t.Errorf("data volume = %v, want an emptyDir", v)
		}
	})
	t.Run("the service writes as the data group", func(t *testing.T) {
		psc := at(deployment(t), "spec", "template", "spec", "securityContext")
		if at(psc, "fsGroup") != 2000 || at(psc, "runAsGroup") != 2000 || at(psc, "runAsUser") != 10000 {
			t.Errorf("pod securityContext = %v, want user 10000, group and fsGroup 2000", psc)
		}
	})
}

func TestChartNotes(t *testing.T) {
	notes := installNotes(t)
	for _, want := range []string{
		"kubectl -n default logs deploy/rel-sealift",
		"sealift-import",
		"nexus-password", "minio-access-key", "minio-secret-key",
		"Trusted key",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	pub, err := archive.ParsePublicKeyPEM([]byte(testPEM))
	if err != nil {
		t.Fatal(err)
	}
	if want := archive.PublicKeySHA256(pub); !strings.Contains(notes, want) {
		t.Errorf("notes lack the key's sha256 %s:\n%s", want, notes)
	}
	if strings.Contains(notes, "emptyDir") {
		t.Error("notes warn about an emptyDir while persistence is on")
	}
	t.Run("persistence off warns", func(t *testing.T) {
		notes := installNotes(t, "--set", "persistence.enabled=false")
		for _, want := range []string{"emptyDir", "lost when the pod is replaced"} {
			if !strings.Contains(notes, want) {
				t.Errorf("notes lack %q:\n%s", want, notes)
			}
		}
	})
	t.Run("an existing ConfigMap prints no sha256", func(t *testing.T) {
		notes := installNotes(t, "--set", "publicKey.pem=", "--set", "publicKey.existingConfigMap=collection-key")
		if strings.Contains(notes, "has the sha256") {
			t.Errorf("notes print a key sha256 for a key the chart does not hold:\n%s", notes)
		}
	})
	t.Run("a placeholder fails the install", func(t *testing.T) {
		_, err := run(t, "install", "rel", chartDir, "--dry-run=client", "-f", testValues, "--set", "nexus.url=<nexus-url>")
		if err == nil || !strings.Contains(err.Error(), "nexus.url still holds its placeholder <nexus-url>") {
			t.Errorf("err = %v, want the placeholder refusal", err)
		}
	})
}

// TestChartSettingsLoad loads the settings the chart renders through the
// import's own loader, in a directory laid out like the pod's /etc/sealift.
func TestChartSettingsLoad(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantIssuer string
		wantKeySet string
		wantAud    string
		wantHeader string
	}{
		{"derived from the realm", nil,
			"https://sso.example.internal/realms/example",
			"https://sso.example.internal/realms/example/protocol/openid-connect/certs",
			"sealift-import", "X-Auth-Request-Access-Token"},
		{"a trailing slash on the realm", []string{"--set", "keycloak.realmUrl=https://sso.example.internal/realms/example/"},
			"https://sso.example.internal/realms/example",
			"https://sso.example.internal/realms/example/protocol/openid-connect/certs",
			"sealift-import", "X-Auth-Request-Access-Token"},
		{"explicit issuer, audience and key set",
			[]string{"--set", "keycloak.issuer=https://public.example.internal/realms/example", "--set", "keycloak.audience=other", "--set", "keycloak.keySetUrl=http://keycloak.example.internal/certs"},
			"https://public.example.internal/realms/example",
			"http://keycloak.example.internal/certs",
			"other", "X-Auth-Request-Access-Token"},
		{"another header", []string{"--set", "token.header=x-other-token"},
			"https://sso.example.internal/realms/example",
			"https://sso.example.internal/realms/example/protocol/openid-connect/certs",
			"sealift-import", "X-Other-Token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			docs := mustRender(t, tt.args...)
			files := map[string]string{
				"config/settings.yaml":      settingsOf(t, docs),
				"secrets/nexus-password":    "stand-in-1\n",
				"secrets/minio-access-key":  "stand-in-2\n",
				"secrets/minio-secret-key":  "stand-in-3\n",
				"public-key/public-key.pem": testPEM,
			}
			for name, body := range files {
				p := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			s, err := importer.LoadSettings(filepath.Join(root, "config", "settings.yaml"))
			if err != nil {
				t.Fatalf("LoadSettings: %v", err)
			}
			if err := s.CheckService(); err != nil {
				t.Fatalf("CheckService: %v", err)
			}
			if got := s.NexusURL.String(); got != "https://nexus.example.internal" {
				t.Errorf("nexus url = %s", got)
			}
			if s.Repository != "npm-hosted" || s.User != "sealift-import" {
				t.Errorf("repository, user = %s, %s", s.Repository, s.User)
			}
			if s.Token.Issuer != tt.wantIssuer || s.Token.KeySetURL.String() != tt.wantKeySet || s.Token.Audience != tt.wantAud || s.Token.Header != tt.wantHeader {
				t.Errorf("token = %q %q %q %q, want %q %q %q %q", s.Token.Issuer, s.Token.KeySetURL, s.Token.Audience, s.Token.Header, tt.wantIssuer, tt.wantKeySet, tt.wantAud, tt.wantHeader)
			}
			if s.MinIO == nil || s.MinIO.URL.String() != "https://minio.example.internal" || s.MinIO.Region != "us-east-1" {
				t.Errorf("minio = %+v, want the test url and region", s.MinIO)
			}
			pub, _ := archive.ParsePublicKeyPEM([]byte(testPEM))
			if s.PublicKeySHA256 != archive.PublicKeySHA256(pub) {
				t.Error("the loaded key is not the test key")
			}
		})
	}
}

var ingressValues = []string{"--set", "ingress.enabled=true", "--set", "ingress.host=sealift.example.internal",
	"--set", "ingress.auth.url=https://auth.example.internal/oauth2/auth",
	"--set", "ingress.auth.signin=https://auth.example.internal/oauth2/start"}

func TestChartIngress(t *testing.T) {
	ing := find(t, mustRender(t, ingressValues...), "Ingress", "")
	for key, want := range map[string]string{
		"nginx.ingress.kubernetes.io/auth-url":              "https://auth.example.internal/oauth2/auth",
		"nginx.ingress.kubernetes.io/auth-signin":           "https://auth.example.internal/oauth2/start",
		"nginx.ingress.kubernetes.io/auth-response-headers": "X-Auth-Request-Access-Token",
	} {
		if got := at(ing, "metadata", "annotations", key); got != want {
			t.Errorf("annotation %s = %v, want %s", key, got, want)
		}
	}
	if got := at(ing, "spec", "rules", 0, "host"); got != "sealift.example.internal" {
		t.Errorf("host = %v", got)
	}
	if got := at(ing, "spec", "rules", 0, "http", "paths", 0, "backend", "service", "name"); got != "rel-sealift" {
		t.Errorf("backend = %v, want rel-sealift", got)
	}
	if got := at(ing, "spec", "tls", 0, "secretName"); got != "rel-sealift-tls" {
		t.Errorf("tls secret = %v, want rel-sealift-tls", got)
	}
	t.Run("a named TLS secret", func(t *testing.T) {
		ing := find(t, mustRender(t, append(ingressValues, "--set", "ingress.tls.secretName=sealift-tls", "--set", "ingress.className=nginx")...), "Ingress", "")
		if got := at(ing, "spec", "tls", 0, "secretName"); got != "sealift-tls" {
			t.Errorf("tls secret = %v, want sealift-tls", got)
		}
		if got := at(ing, "spec", "ingressClassName"); got != "nginx" {
			t.Errorf("class = %v, want nginx", got)
		}
	})
	t.Run("the token header reaches the annotation and the settings", func(t *testing.T) {
		docs := mustRender(t, append(ingressValues, "--set", "token.header=X-Forwarded-Access-Token")...)
		if got := at(find(t, docs, "Ingress", ""), "metadata", "annotations", "nginx.ingress.kubernetes.io/auth-response-headers"); got != "X-Forwarded-Access-Token" {
			t.Errorf("auth-response-headers = %v", got)
		}
		if got := settingsOf(t, docs); !strings.Contains(got, "header: X-Forwarded-Access-Token") {
			t.Errorf("settings = %q, want the same header", got)
		}
	})
	t.Run("user annotations cannot replace the sign-in ones", func(t *testing.T) {
		values := writeValues(t, "ingress:\n  annotations:\n    nginx.ingress.kubernetes.io/auth-url: \"\"\n    nginx.ingress.kubernetes.io/auth-signin: https://evil.example/start\n    nginx.ingress.kubernetes.io/auth-response-headers: X-Other\n    nginx.ingress.kubernetes.io/proxy-body-size: 8m\n")
		out, err := run(t, append([]string{"template", "rel", chartDir, "-f", testValues, "-f", values, "--show-only", "templates/ingress.yaml"}, ingressValues...)...)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"auth-url", "auth-signin", "auth-response-headers"} {
			if n := strings.Count(out, "nginx.ingress.kubernetes.io/"+key+":"); n != 1 {
				t.Errorf("%s appears %d times, want 1:\n%s", key, n, out)
			}
		}
		if !strings.Contains(out, "proxy-body-size") {
			t.Errorf("other user annotations were dropped:\n%s", out)
		}
	})
	t.Run("only sign-in annotations in the user map leave a valid Ingress", func(t *testing.T) {
		values := writeValues(t, "ingress:\n  annotations:\n    nginx.ingress.kubernetes.io/auth-url: x\n")
		docs, err := render(t, append([]string{"-f", values}, ingressValues...)...)
		if err != nil {
			t.Fatal(err)
		}
		if got := at(find(t, docs, "Ingress", ""), "metadata", "annotations", "nginx.ingress.kubernetes.io/auth-url"); got != "https://auth.example.internal/oauth2/auth" {
			t.Errorf("auth-url = %v", got)
		}
	})
	for _, key := range []string{"ingress.auth.url", "ingress.auth.signin", "ingress.host"} {
		t.Run(key+" empty is refused", func(t *testing.T) {
			_, err := render(t, append(ingressValues, "--set", key+"=")...)
			if err == nil || !strings.Contains(err.Error(), key+" is required") {
				t.Errorf("err = %v, want %q", err, key+" is required")
			}
		})
	}
	t.Run("ingress off renders none and the notes print the annotations", func(t *testing.T) {
		for _, k := range kinds(mustRender(t)) {
			if strings.HasPrefix(k, "Ingress/") {
				t.Errorf("rendered %s, want no Ingress", k)
			}
		}
		notes := installNotes(t)
		for _, want := range []string{"nginx.ingress.kubernetes.io/auth-url", "nginx.ingress.kubernetes.io/auth-signin", "nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Access-Token"} {
			if !strings.Contains(notes, want) {
				t.Errorf("notes lack %q:\n%s", want, notes)
			}
		}
	})
	t.Run("the notes print the address when on", func(t *testing.T) {
		if notes := installNotes(t, ingressValues...); !strings.Contains(notes, "https://sealift.example.internal/") {
			t.Errorf("notes lack the address:\n%s", notes)
		}
	})
}

func TestChartNetworkPolicy(t *testing.T) {
	var policies []map[string]any
	for _, d := range mustRender(t) {
		if d["kind"] == "NetworkPolicy" {
			policies = append(policies, d)
		}
	}
	if len(policies) != 1 {
		t.Fatalf("rendered %d NetworkPolicy documents, want 1", len(policies))
	}
	p := policies[0]
	if got := fmt.Sprint(at(p, "spec", "policyTypes")); got != "[Ingress]" {
		t.Errorf("policyTypes = %v, want [Ingress]", got)
	}
	rules, _ := at(p, "spec", "ingress").([]any)
	if len(rules) != 1 {
		t.Fatalf("ingress rules = %d, want 1", len(rules))
	}
	if peers, _ := at(rules[0], "from").([]any); len(peers) != 1 {
		t.Fatalf("peers = %v, want one", peers)
	}
	if got := at(rules[0], "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); got != "ingress-nginx" {
		t.Errorf("namespace = %v, want ingress-nginx", got)
	}
	if at(rules[0], "from", 0, "podSelector") != nil {
		t.Error("the peer selects pods without a value")
	}
	if ports, _ := at(rules[0], "ports").([]any); len(ports) != 1 || at(ports[0], "port") != "http" {
		t.Errorf("ports = %v, want http alone", at(rules[0], "ports"))
	}
	t.Run("pod labels narrow the peer", func(t *testing.T) {
		p := find(t, mustRender(t, "--set", "networkPolicy.ingressPodLabels.app\\.kubernetes\\.io/name=ingress-nginx", "--set", "networkPolicy.ingressNamespace=edge"), "NetworkPolicy", "")
		if got := at(p, "spec", "ingress", 0, "from", 0, "podSelector", "matchLabels", "app.kubernetes.io/name"); got != "ingress-nginx" {
			t.Errorf("pod selector = %v", got)
		}
		if got := at(p, "spec", "ingress", 0, "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); got != "edge" {
			t.Errorf("namespace = %v, want edge", got)
		}
	})
	t.Run("off renders none and the notes warn", func(t *testing.T) {
		for _, k := range kinds(mustRender(t, "--set", "networkPolicy.enabled=false")) {
			if strings.HasPrefix(k, "NetworkPolicy/") {
				t.Errorf("rendered %s, want none", k)
			}
		}
		if notes := installNotes(t, "--set", "networkPolicy.enabled=false"); !strings.Contains(notes, "Any pod of the cluster can reach the service") {
			t.Errorf("notes lack the warning:\n%s", notes)
		}
	})
	t.Run("the notes give the reach check when on", func(t *testing.T) {
		if notes := installNotes(t); !strings.Contains(notes, "kubectl run") || !strings.Contains(notes, "curl -m 5") {
			t.Errorf("notes lack the reach check:\n%s", notes)
		}
	})
}

func TestChartExampleValues(t *testing.T) {
	example := filepath.Join(chartDir, "values-example.yaml")
	_, err := run(t, "template", "rel", chartDir, "-f", example)
	if err == nil || !strings.Contains(err.Error(), "still holds its placeholder <") {
		t.Errorf("err = %v, want a placeholder refusal", err)
	}
	out, err := run(t, "template", "rel", chartDir, "-f", example, "-f", testValues, "-f", "testdata/example-filled.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"kind: Ingress", "kind: NetworkPolicy"} {
		if n := strings.Count(out, "\n"+kind+"\n"); n != 1 {
			t.Errorf("%s rendered %d times, want 1", kind, n)
		}
	}
}
