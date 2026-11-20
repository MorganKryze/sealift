package importer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/archive"
)

const (
	// testAccessKey and testMinIOSecret are the MinIO credentials the settings files hold.
	testAccessKey   = "test-access-id"
	testMinIOSecret = "test-minio-secret"
	// testPipPassword is the pypi repository's own password, distinct from the npm one.
	testPipPassword = "pip-only-secret"
	minioSection    = `minio:
  url: https://minio.example.internal:9000
  region: eu-west-1
  accessKeyFile: minio-access-key
  secretKeyFile: minio-secret-key
`
	tokenSection = `token:
  keySetUrl: https://idp.example.internal/realms/lab/protocol/openid-connect/certs
  issuer: https://idp.example.internal/realms/lab
  audience: sealift
`
	validSetting = `nexus:
  url: https://nexus.example.internal
  repository: npm-hosted
  user: sealift-import
  passwordFile: nexus-password
publicKeyFile: public-key.pem
`
)

// writeSettings writes a settings file with its two secret files and returns
// its path.
func writeSettings(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("nexus-password", testPassword+"\n")
	write("nexus-pip-password", testPipPassword+"\n")
	write("public-key.pem", archive.PublicKeyPEM(testPub))
	write("ca.pem", "pem")
	write("minio-access-key", testAccessKey+"\n")
	write("minio-secret-key", testMinIOSecret+"\n")
	write("settings.yaml", body)
	return filepath.Join(dir, "settings.yaml")
}

func publicKeyFile(content []byte) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "public-key.pem"), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func rsaPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestLoadSettingsPublicKey(t *testing.T) {
	pemText := archive.PublicKeyPEM(testPub)
	for name, content := range map[string]string{
		"crlf":                 strings.ReplaceAll(pemText, "\n", "\r\n"),
		"blank space around":   "\n\n  " + strings.TrimSuffix(pemText, "\n") + "  \n\n",
		"no final line ending": strings.TrimSuffix(pemText, "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			path := writeSettings(t, validSetting)
			publicKeyFile([]byte(content))(t, filepath.Dir(path))
			s, err := LoadSettings(path)
			if err != nil {
				t.Fatal(err)
			}
			if !s.PublicKey.Equal(testPub) || s.PublicKeySHA256 != testPubSHA {
				t.Errorf("trusted key sha256 %s, want %s", s.PublicKeySHA256, testPubSHA)
			}
		})
	}
}

func TestLoadSettings(t *testing.T) {
	t.Run("required values", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, validSetting))
		if err != nil {
			t.Fatal(err)
		}
		if s.NexusURL.String() != "https://nexus.example.internal" || s.Repository != "npm-hosted" || s.User != "sealift-import" {
			t.Errorf("got %+v", s)
		}
		if string(s.Password) != testPassword {
			t.Error("one trailing newline must come off each secret file")
		}
		if !s.PublicKey.Equal(testPub) || s.PublicKeySHA256 != testPubSHA {
			t.Errorf("trusted key sha256 %s, want %s", s.PublicKeySHA256, testPubSHA)
		}
		if s.CAFile != "" {
			t.Errorf("CAFile = %q", s.CAFile)
		}
	})
	t.Run("relative paths resolve from the settings file", func(t *testing.T) {
		path := writeSettings(t, validSetting+"  \n")
		body := strings.Replace(validSetting, "passwordFile: nexus-password\n", "passwordFile: nexus-password\n  caFile: ca.pem\n", 1)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadSettings(path)
		if err != nil {
			t.Fatal(err)
		}
		if s.CAFile != filepath.Join(filepath.Dir(path), "ca.pem") {
			t.Errorf("CAFile = %q", s.CAFile)
		}
	})
	t.Run("only one newline comes off", func(t *testing.T) {
		path := writeSettings(t, validSetting)
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "nexus-password"), []byte(testPassword+"\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadSettings(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(s.Password) != testPassword+"\n" {
			t.Errorf("password = %q", s.Password)
		}
	})
	t.Run("files lists every file the settings name", func(t *testing.T) {
		body := strings.Replace(validSetting, "passwordFile: nexus-password\n", "passwordFile: nexus-password\n  caFile: ca.pem\n", 1)
		body += strings.Replace(tokenSection, "  audience: sealift\n", "  audience: sealift\n  caFile: ca.pem\n", 1)
		body += strings.Replace(minioSection, "  secretKeyFile: minio-secret-key\n", "  secretKeyFile: minio-secret-key\n  caFile: ca.pem\n", 1)
		path := writeSettings(t, body)
		s, err := LoadSettings(path)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(path)
		want := []NamedFile{
			{"the settings file", path},
			{"nexus.passwordFile", filepath.Join(dir, "nexus-password")},
			{"publicKeyFile", filepath.Join(dir, "public-key.pem")},
			{"nexus.caFile", filepath.Join(dir, "ca.pem")},
			{"token.caFile", filepath.Join(dir, "ca.pem")},
			{"minio.accessKeyFile", filepath.Join(dir, "minio-access-key")},
			{"minio.secretKeyFile", filepath.Join(dir, "minio-secret-key")},
			{"minio.caFile", filepath.Join(dir, "ca.pem")},
		}
		if !slices.Equal(s.Files, want) {
			t.Errorf("Files = %v, want %v", s.Files, want)
		}
	})
	t.Run("http is accepted", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, strings.Replace(validSetting, "https://nexus.example.internal", "http://nexus.example.internal:8081/base", 1)))
		if err != nil || s.NexusURL.Scheme != "http" {
			t.Fatalf("got %v, %v", s.NexusURL, err)
		}
	})
}

func TestLoadSettingsRefuses(t *testing.T) {
	without := func(line string) string { return strings.Replace(validSetting, line, "", 1) }
	withURL := func(u string) string { return strings.Replace(validSetting, "https://nexus.example.internal", u, 1) }
	withoutLine := func(section, line string) string { return strings.Replace(section, line, "", 1) }
	withMinIOURL := func(u string) string {
		return strings.Replace(minioSection, "https://minio.example.internal:9000", u, 1)
	}
	withKeySet := func(u string) string {
		return strings.Replace(tokenSection, "https://idp.example.internal/realms/lab/protocol/openid-connect/certs", u, 1)
	}
	cases := []struct {
		name  string
		body  string
		after func(_ *testing.T, dir string)
		field string
		want  string
	}{
		{"url absent", without("  url: https://nexus.example.internal\n"), nil, "nexus.url", "required"},
		{"repository absent", without("  repository: npm-hosted\n"), nil, "nexus.repository", "required"},
		{"user absent", without("  user: sealift-import\n"), nil, "nexus.user", "required"},
		{"password file absent", without("  passwordFile: nexus-password\n"), nil, "nexus.passwordFile", "required"},
		{"key file absent", without("publicKeyFile: public-key.pem\n"), nil, "publicKeyFile", "required"},
		{"signatureKeyFile is an unknown field", validSetting + "signatureKeyFile: signature-key\n", nil, "signatureKeyFile", "unknown"},
		{"unknown field", validSetting + "extra: 1\n", nil, "extra", "unknown"},
		{"insecure field", strings.Replace(validSetting, "  user:", "  insecure: true\n  user:", 1), nil, "insecure", "unknown"},
		{"not yaml", "nexus: [", nil, "settings file", "not valid"},
		{"password file unreadable", validSetting, func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, "nexus-password")) }, "nexus.passwordFile", "cannot be read"},
		{"key file unreadable", validSetting, func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, "public-key.pem")) }, "publicKeyFile", "cannot be read"},
		{"password empty", validSetting, func(_ *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, "nexus-password"), []byte("\n"), 0o600)
		}, "nexus.passwordFile", "empty"},
		{"key file empty", validSetting, publicKeyFile(nil), "publicKeyFile", "holds no PEM block"},
		{"key file over 4 KiB", validSetting, publicKeyFile(make([]byte, archive.MaxPublicKeySize+1)), "publicKeyFile", "larger than 4096 bytes"},
		{"key file with two blocks", validSetting, publicKeyFile([]byte(archive.PublicKeyPEM(testPub) + archive.PublicKeyPEM(testPub))), "publicKeyFile", "more than one PEM block"},
		{"key file with text before", validSetting, publicKeyFile([]byte("my key\n" + archive.PublicKeyPEM(testPub))), "publicKeyFile", "text before the PEM block"},
		{"key file with a private key", validSetting, publicKeyFile(testPrivPEM), "publicKeyFile", "not a PUBLIC KEY block"},
		{"key file with an RSA key", validSetting, publicKeyFile(rsaPublicKeyPEM(t)), "publicKeyFile", "not an Ed25519 public key"},
		{"url with user", withURL("https://operator@nexus.example.internal"), nil, "nexus.url", "user name"},
		{"url with password", withURL("https://operator:hunter2@nexus.example.internal"), nil, "nexus.url", "user name"},
		{"url with query", withURL("https://nexus.example.internal/?a=b"), nil, "nexus.url", "query"},
		{"url with fragment", withURL("https://nexus.example.internal/#x"), nil, "nexus.url", "fragment"},
		{"url scheme", withURL("ftp://nexus.example.internal"), nil, "nexus.url", "http or https"},
		{"url without host", withURL("https:///path"), nil, "nexus.url", "host"},
		{"url not a url", withURL("https://nexus.example.internal:port"), nil, "nexus.url", "not a valid URL"},
		{"repository name", strings.Replace(validSetting, "npm-hosted", "npm/hosted", 1), nil, "nexus.repository", "letters"},
		{"token key set url absent", validSetting + strings.Replace(tokenSection, "  keySetUrl: https://idp.example.internal/realms/lab/protocol/openid-connect/certs\n", "", 1), nil, "token.keySetUrl", "required"},
		{"token issuer absent", validSetting + strings.Replace(tokenSection, "  issuer: https://idp.example.internal/realms/lab\n", "", 1), nil, "token.issuer", "required"},
		{"token audience absent", validSetting + strings.Replace(tokenSection, "  audience: sealift\n", "", 1), nil, "token.audience", "required"},
		{"token unknown field", validSetting + tokenSection + "  insecure: true\n", nil, "insecure", "unknown"},
		{"token key set url with user", validSetting + withKeySet("https://operator@idp.example.internal/certs"), nil, "token.keySetUrl", "user name"},
		{"token key set url with password", validSetting + withKeySet("https://operator:hunter2@idp.example.internal/certs"), nil, "token.keySetUrl", "user name"},
		{"token key set url with query", validSetting + withKeySet("https://idp.example.internal/certs?a=b"), nil, "token.keySetUrl", "query"},
		{"token key set url with fragment", validSetting + withKeySet("https://idp.example.internal/certs#x"), nil, "token.keySetUrl", "fragment"},
		{"token key set url scheme", validSetting + withKeySet("ftp://idp.example.internal/certs"), nil, "token.keySetUrl", "http or https"},
		{"token key set url without host", validSetting + withKeySet("https:///certs"), nil, "token.keySetUrl", "host"},
		{"token key set url not a url", validSetting + withKeySet("https://idp.example.internal:port/certs"), nil, "token.keySetUrl", "not a valid URL"},
		{"token ca file unreadable", validSetting + tokenSection + "  caFile: missing.pem\n", nil, "token.caFile", "cannot be read"},
		{"ca file unreadable", strings.Replace(validSetting, "passwordFile: nexus-password\n", "passwordFile: nexus-password\n  caFile: missing.pem\n", 1), nil, "nexus.caFile", "cannot be read"},
		{"minio url absent", validSetting + withoutLine(minioSection, "  url: https://minio.example.internal:9000\n"), nil, "minio.url", "required"},
		{"minio access key file absent", validSetting + withoutLine(minioSection, "  accessKeyFile: minio-access-key\n"), nil, "minio.accessKeyFile", "required"},
		{"minio secret key file absent", validSetting + withoutLine(minioSection, "  secretKeyFile: minio-secret-key\n"), nil, "minio.secretKeyFile", "required"},
		{"minio unknown field", validSetting + minioSection + "  insecure: true\n", nil, "insecure", "unknown"},
		{"minio url with user", validSetting + withMinIOURL("https://operator@minio.example.internal"), nil, "minio.url", "user name"},
		{"minio url with password", validSetting + withMinIOURL("https://operator:hunter2@minio.example.internal"), nil, "minio.url", "user name"},
		{"minio url with query", validSetting + withMinIOURL("https://minio.example.internal/?a=b"), nil, "minio.url", "query"},
		{"minio url with fragment", validSetting + withMinIOURL("https://minio.example.internal/#x"), nil, "minio.url", "fragment"},
		{"minio url scheme", validSetting + withMinIOURL("ftp://minio.example.internal"), nil, "minio.url", "http or https"},
		{"minio url without host", validSetting + withMinIOURL("https:///bucket"), nil, "minio.url", "host"},
		{"minio url not a url", validSetting + withMinIOURL("https://minio.example.internal:port"), nil, "minio.url", "not a valid URL"},
		{"minio access key file unreadable", validSetting + minioSection, func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, "minio-access-key")) }, "minio.accessKeyFile", "cannot be read"},
		{"minio secret key file unreadable", validSetting + minioSection, func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, "minio-secret-key")) }, "minio.secretKeyFile", "cannot be read"},
		{"minio access key file empty", validSetting + minioSection, func(_ *testing.T, dir string) { _ = os.WriteFile(filepath.Join(dir, "minio-access-key"), nil, 0o600) }, "minio.accessKeyFile", "empty"},
		{"minio secret key file empty", validSetting + minioSection, func(_ *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, "minio-secret-key"), []byte("\n"), 0o600)
		}, "minio.secretKeyFile", "empty"},
		{"minio ca file unreadable", validSetting + minioSection + "  caFile: missing.pem\n", nil, "minio.caFile", "cannot be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSettings(t, tc.body)
			if tc.after != nil {
				tc.after(t, filepath.Dir(path))
			}
			_, err := LoadSettings(path)
			var se *SettingsError
			if !errors.As(err, &se) {
				t.Fatalf("got %v, want a SettingsError", err)
			}
			if se.Field != tc.field || !strings.Contains(se.Reason, tc.want) {
				t.Errorf("got field %q reason %q, want %q containing %q", se.Field, se.Reason, tc.field, tc.want)
			}
			for _, leak := range []string{"hunter2", "operator", "nexus.example.internal", "idp.example.internal", "minio.example.internal", testPassword, "my key", privateKeyBody, testAccessKey, testMinIOSecret} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error %q repeats %q", err, leak)
				}
			}
		})
	}

	t.Run("settings file missing", func(t *testing.T) {
		_, err := LoadSettings(filepath.Join(t.TempDir(), "absent.yaml"))
		var se *SettingsError
		if !errors.As(err, &se) || se.Field != "settings file" || !strings.Contains(se.Reason, "cannot be read") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("settings file too large", func(t *testing.T) {
		_, err := LoadSettings(writeSettings(t, validSetting+"# "+strings.Repeat("x", maxSettingsBytes)+"\n"))
		var se *SettingsError
		if !errors.As(err, &se) || !strings.Contains(se.Reason, "larger than") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSecretIsRedacted(t *testing.T) {
	s := Secret("test-password")
	for _, got := range []string{
		s.String(), s.GoString(), fmt.Sprintf("%v %+v %#v %s %q %x %d", s, s, s, s, s, s, s),
		fmt.Sprintf("%v", Settings{Password: s, PublicKey: testPub}),
		fmt.Sprintf("%+v", &Settings{Password: s, PublicKey: testPub}),
		fmt.Sprintf("%#v", Settings{Password: s, PublicKey: testPub}),
	} {
		if strings.Contains(got, "test-password") || strings.Contains(got, "dGVzdC1w") {
			t.Errorf("printed a secret: %s", got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("no marker in %s", got)
		}
	}
	b, err := jsonOf(Settings{Password: s, PublicKey: testPub})
	if err != nil || strings.Contains(b, "test-password") || !strings.Contains(b, "[redacted]") {
		t.Errorf("json = %s, %v", b, err)
	}
}

func TestLoadSettingsServiceSections(t *testing.T) {
	t.Run("token section", func(t *testing.T) {
		path := writeSettings(t, validSetting+tokenSection+"  caFile: ca.pem\n")
		s, err := LoadSettings(path)
		if err != nil {
			t.Fatal(err)
		}
		if s.Token == nil {
			t.Fatal("Token = nil")
		}
		want := "https://idp.example.internal/realms/lab/protocol/openid-connect/certs"
		if s.Token.KeySetURL.String() != want || s.Token.Issuer != "https://idp.example.internal/realms/lab" || s.Token.Audience != "sealift" {
			t.Errorf("got %+v", s.Token)
		}
		if s.Token.CAFile != filepath.Join(filepath.Dir(path), "ca.pem") {
			t.Errorf("CAFile = %q", s.Token.CAFile)
		}
		if err := s.CheckService(); err != nil {
			t.Errorf("CheckService = %v", err)
		}
	})
	t.Run("http key set is accepted", func(t *testing.T) {
		body := validSetting + strings.Replace(tokenSection, "https://idp", "http://idp", 1)
		s, err := LoadSettings(writeSettings(t, body))
		if err != nil || s.Token.KeySetURL.Scheme != "http" {
			t.Fatalf("got %+v, %v", s.Token, err)
		}
	})
	t.Run("no token section", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, validSetting))
		if err != nil {
			t.Fatal(err)
		}
		if s.Token != nil {
			t.Errorf("Token = %+v, want nil", s.Token)
		}
		var se *SettingsError
		if err := s.CheckService(); !errors.As(err, &se) || se.Field != "token" || !strings.Contains(se.Reason, "required") {
			t.Fatalf("CheckService = %v, want a SettingsError naming token", err)
		}
	})
}

func TestLoadSettingsMinIOSection(t *testing.T) {
	t.Run("minio section", func(t *testing.T) {
		path := writeSettings(t, validSetting+minioSection+"  caFile: ca.pem\n")
		s, err := LoadSettings(path)
		if err != nil {
			t.Fatal(err)
		}
		m := s.MinIO
		if m == nil {
			t.Fatal("MinIO = nil")
		}
		if m.URL.String() != "https://minio.example.internal:9000" || m.Region != "eu-west-1" {
			t.Errorf("got %+v", m)
		}
		if string(m.AccessKey) != testAccessKey || string(m.SecretKey) != testMinIOSecret {
			t.Error("one trailing newline must come off each key file")
		}
		if m.CAFile != filepath.Join(filepath.Dir(path), "ca.pem") {
			t.Errorf("CAFile = %q", m.CAFile)
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", s, s, s), testMinIOSecret) {
			t.Error("the settings print the MinIO secret key")
		}
	})
	t.Run("region is optional", func(t *testing.T) {
		body := validSetting + strings.Replace(minioSection, "  region: eu-west-1\n", "", 1)
		s, err := LoadSettings(writeSettings(t, body))
		if err != nil || s.MinIO == nil || s.MinIO.Region != "" {
			t.Fatalf("got %+v, %v", s.MinIO, err)
		}
	})
	t.Run("no minio section", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, validSetting+tokenSection))
		if err != nil || s.MinIO != nil {
			t.Fatalf("got %+v, %v", s.MinIO, err)
		}
		if err := s.CheckService(); err != nil {
			t.Errorf("CheckService = %v: MinIO is optional", err)
		}
	})
}

func TestLoadSettingsTokenHeader(t *testing.T) {
	ok := []struct{ name, line, want string }{
		{"absent reads the default", "", "X-Access-Token"},
		{"kept in canonical form", "  header: x-auth-request-access-token\n", "X-Auth-Request-Access-Token"},
	}
	for _, tt := range ok {
		t.Run(tt.name, func(t *testing.T) {
			s, err := LoadSettings(writeSettings(t, validSetting+tokenSection+tt.line))
			if err != nil {
				t.Fatal(err)
			}
			if s.Token.Header != tt.want {
				t.Errorf("Header = %q, want %q", s.Token.Header, tt.want)
			}
		})
	}
	refused := []struct{ name, value, reason string }{
		{"empty", `""`, "is empty"},
		{"space", `"X Access Token"`, "is not a valid header name"},
		{"colon", `"X-Token:"`, "is not a valid header name"},
		{"Authorization", "Authorization", "cannot be Authorization, Cookie or Host"},
		{"cookie", "cookie", "cannot be Authorization, Cookie or Host"},
		{"HOST", "HOST", "cannot be Authorization, Cookie or Host"},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadSettings(writeSettings(t, validSetting+tokenSection+"  header: "+tt.value+"\n"))
			var se *SettingsError
			if !errors.As(err, &se) || se.Field != "token.header" || se.Reason != tt.reason {
				t.Fatalf("got %v, want token.header %s", err, tt.reason)
			}
		})
	}
}

// withPip returns the valid settings with a nexus.pip section holding lines,
// each indented under pip.
func withPip(lines string) string {
	return strings.Replace(validSetting, "  passwordFile: nexus-password\n", "  passwordFile: nexus-password\n  pip:\n"+lines, 1)
}

const (
	pipRepositoryOnly = "    repository: pypi-hosted\n"
	pipOwnUser        = pipRepositoryOnly + "    user: sealift-pip\n    passwordFile: nexus-pip-password\n"
)

func TestLoadSettingsPip(t *testing.T) {
	t.Run("no section leaves pip unset", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, validSetting))
		if err != nil {
			t.Fatal(err)
		}
		if s.Pip != nil {
			t.Errorf("Pip = %+v, want nil", s.Pip)
		}
		if s.Format != "" {
			t.Errorf("Format = %q, want empty for npm", s.Format)
		}
	})
	t.Run("repository only inherits the npm user and password", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, withPip(pipRepositoryOnly)))
		if err != nil {
			t.Fatal(err)
		}
		if s.Pip == nil {
			t.Fatal("Pip = nil")
		}
		if s.Pip.Repository != "pypi-hosted" || s.Pip.User != "sealift-import" || string(s.Pip.Password) != testPassword {
			t.Errorf("pip repository %q user %q, want pypi-hosted with the npm user and password", s.Pip.Repository, s.Pip.User)
		}
		for _, f := range s.Files {
			if f.Field == "nexus.pip.passwordFile" {
				t.Errorf("Files names %v without a pip password file", f)
			}
		}
	})
	t.Run("user and password file are read", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, withPip(pipOwnUser)))
		if err != nil {
			t.Fatal(err)
		}
		if s.Pip == nil {
			t.Fatal("Pip = nil")
		}
		if s.Pip.Repository != "pypi-hosted" || s.Pip.User != "sealift-pip" || string(s.Pip.Password) != testPipPassword {
			t.Errorf("pip repository %q user %q, want pypi-hosted, sealift-pip and the pip password", s.Pip.Repository, s.Pip.User)
		}
		if s.Repository != "npm-hosted" || s.User != "sealift-import" || string(s.Password) != testPassword {
			t.Errorf("npm repository %q user %q changed", s.Repository, s.User)
		}
	})
	t.Run("the pip password file is in Files", func(t *testing.T) {
		path := writeSettings(t, withPip(pipOwnUser))
		s, err := LoadSettings(path)
		if err != nil {
			t.Fatal(err)
		}
		want := NamedFile{"nexus.pip.passwordFile", filepath.Join(filepath.Dir(path), "nexus-pip-password")}
		if !slices.Contains(s.Files, want) {
			t.Errorf("Files = %v, want it to hold %v", s.Files, want)
		}
	})

	_, npmErr := LoadSettings(writeSettings(t, strings.Replace(validSetting, "npm-hosted", "npm/hosted", 1)))
	var npmRefusal *SettingsError
	if !errors.As(npmErr, &npmRefusal) {
		t.Fatalf("npm repository with a slash: got %v, want a SettingsError", npmErr)
	}
	refused := []struct {
		name   string
		body   string
		after  func(_ *testing.T, dir string)
		field  string
		reason string
	}{
		{"repository absent", withPip("    user: sealift-pip\n    passwordFile: nexus-pip-password\n"), nil, "nexus.pip.repository", "is required"},
		{"empty section", strings.Replace(validSetting, "  passwordFile: nexus-password\n", "  passwordFile: nexus-password\n  pip: {}\n", 1), nil, "nexus.pip.repository", "is required"},
		{"user without password file", withPip(pipRepositoryOnly + "    user: sealift-pip\n"), nil, "nexus.pip.passwordFile", "is required when nexus.pip.user is set"},
		{"password file without user", withPip(pipRepositoryOnly + "    passwordFile: nexus-pip-password\n"), nil, "nexus.pip.user", "is required when nexus.pip.passwordFile is set"},
		{"repository with a slash", withPip("    repository: pypi/hosted\n"), nil, "nexus.pip.repository", npmRefusal.Reason},
		{"unknown key", withPip(pipRepositoryOnly + "    insecure: true\n"), nil, "insecure", "is an unknown field"},
		{"empty password file", withPip(pipOwnUser), func(_ *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, "nexus-pip-password"), []byte("\n"), 0o600)
		}, "nexus.pip.passwordFile", "points to an empty file"},
		{"password file unreadable", withPip(pipOwnUser), func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, "nexus-pip-password")) }, "nexus.pip.passwordFile", "cannot be read: the file does not exist"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSettings(t, tc.body)
			if tc.after != nil {
				tc.after(t, filepath.Dir(path))
			}
			_, err := LoadSettings(path)
			var se *SettingsError
			if !errors.As(err, &se) {
				t.Fatalf("got %v, want a SettingsError", err)
			}
			if se.Field != tc.field || se.Reason != tc.reason {
				t.Errorf("got field %q reason %q, want %q %q", se.Field, se.Reason, tc.field, tc.reason)
			}
			for _, leak := range []string{testPassword, testPipPassword} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error %q repeats a password", err)
				}
			}
		})
	}
	if npmRefusal.Reason != "may hold only letters, digits, dots, hyphens and underscores" {
		t.Errorf("npm repository reason = %q", npmRefusal.Reason)
	}
}

func TestSettingsForPip(t *testing.T) {
	t.Run("its own user", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, withPip(pipOwnUser)))
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.ForPip()
		if err != nil {
			t.Fatal(err)
		}
		if p.Repository != "pypi-hosted" || p.User != "sealift-pip" || string(p.Password) != testPipPassword || p.Format != "pypi" {
			t.Errorf("ForPip repository %q user %q format %q, want pypi-hosted, sealift-pip, the pip password and pypi", p.Repository, p.User, p.Format)
		}
		if p.NexusURL.String() != s.NexusURL.String() || !p.PublicKey.Equal(s.PublicKey) {
			t.Error("ForPip changed the Nexus address or the trusted key")
		}
		if s.Repository != "npm-hosted" || s.User != "sealift-import" || string(s.Password) != testPassword || s.Format != "" {
			t.Errorf("receiver repository %q user %q format %q changed", s.Repository, s.User, s.Format)
		}
	})
	t.Run("the npm user", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, withPip(pipRepositoryOnly)))
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.ForPip()
		if err != nil {
			t.Fatal(err)
		}
		if p.Repository != "pypi-hosted" || p.User != "sealift-import" || string(p.Password) != testPassword || p.Format != "pypi" {
			t.Errorf("ForPip repository %q user %q format %q, want pypi-hosted with the npm user and password, and pypi", p.Repository, p.User, p.Format)
		}
	})
	t.Run("no section", func(t *testing.T) {
		s, err := LoadSettings(writeSettings(t, validSetting))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.ForPip()
		if !errors.Is(err, ErrNoPipRepository) {
			t.Fatalf("ForPip = %v, want ErrNoPipRepository", err)
		}
		if err.Error() != "the settings name no pip repository: set nexus.pip.repository" {
			t.Errorf("reason = %q", err)
		}
	})
}

func TestSettingsNeverPrintThePipPassword(t *testing.T) {
	s, err := LoadSettings(writeSettings(t, withPip(pipOwnUser)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.ForPip()
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(testPipPassword))
	for _, row := range []struct {
		name  string
		value any
	}{
		{"settings", s},
		{"settings pointer", &s},
		{"pip repository", *s.Pip},
		{"pip repository pointer", s.Pip},
		{"settings for pip", p},
		{"settings for pip pointer", &p},
	} {
		t.Run(row.name, func(t *testing.T) {
			b, err := jsonOf(row.value)
			if err != nil {
				t.Fatal(err)
			}
			for _, got := range []string{fmt.Sprintf("%v", row.value), fmt.Sprintf("%+v", row.value), fmt.Sprintf("%#v", row.value), b} {
				if strings.Contains(got, testPipPassword) || strings.Contains(got, encoded) {
					t.Errorf("printed the pip password: %s", got)
				}
			}
			if !strings.Contains(b, "[redacted]") {
				t.Errorf("json = %s, want the redaction marker", b)
			}
		})
	}
}
