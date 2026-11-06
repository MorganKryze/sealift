package importer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	// maxSettingsBytes is the largest settings file LoadSettings reads: 64 KiB.
	maxSettingsBytes = 64 << 10
	// maxSecretBytes is the largest password or key file LoadSettings reads: 64 KiB.
	maxSecretBytes = 64 << 10
	redacted       = "[redacted]"
)

var (
	repositoryName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	unknownField   = regexp.MustCompile(`field (\w+) not found`)
)

// Secret is a credential. It prints as "[redacted]" however it is formatted.
type Secret []byte

// String returns the redaction marker.
func (Secret) String() string { return redacted }

// GoString returns the redaction marker.
func (Secret) GoString() string { return redacted }

// MarshalJSON returns the redaction marker.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText returns the redaction marker.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Format prints the redaction marker under every verb.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// Settings are the values the import reads from its settings file.
type Settings struct {
	NexusURL     *url.URL
	Repository   string
	User         string
	Password     Secret
	CAFile       string
	SignatureKey Secret
}

// SettingsError names the field or file that is wrong, never a value.
type SettingsError struct {
	Field, Reason string
}

func (e *SettingsError) Error() string { return e.Field + " " + e.Reason }

func settingsErr(field, reason string) error { return &SettingsError{Field: field, Reason: reason} }

type rawSettings struct {
	Nexus struct {
		URL          string `yaml:"url"`
		Repository   string `yaml:"repository"`
		User         string `yaml:"user"`
		PasswordFile string `yaml:"passwordFile"`
		CAFile       string `yaml:"caFile"`
	} `yaml:"nexus"`
	SignatureKeyFile string `yaml:"signatureKeyFile"`
}

// LoadSettings reads a settings file. Relative paths in it resolve from the
// file's directory. Each secret file loses one trailing newline.
func LoadSettings(path string) (Settings, error) {
	data, err := readBounded(path, maxSettingsBytes)
	if err != nil {
		return Settings{}, readError("settings file", err)
	}
	var raw rawSettings
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		// The YAML error is not repeated: a parser may quote a value.
		if m := unknownField.FindStringSubmatch(err.Error()); m != nil {
			return Settings{}, settingsErr(m[1], "is an unknown field")
		}
		return Settings{}, settingsErr("settings file", "is not valid settings YAML")
	}
	for _, r := range []struct{ field, value string }{
		{"nexus.url", raw.Nexus.URL}, {"nexus.repository", raw.Nexus.Repository}, {"nexus.user", raw.Nexus.User},
		{"nexus.passwordFile", raw.Nexus.PasswordFile}, {"signatureKeyFile", raw.SignatureKeyFile},
	} {
		if r.value == "" {
			return Settings{}, settingsErr(r.field, "is required")
		}
	}
	u, err := parseNexusURL(raw.Nexus.URL)
	if err != nil {
		return Settings{}, err
	}
	if !repositoryName.MatchString(raw.Nexus.Repository) {
		return Settings{}, settingsErr("nexus.repository", "may hold only letters, digits, dots, hyphens and underscores")
	}
	dir := filepath.Dir(path)
	password, err := readSecret("nexus.passwordFile", resolve(dir, raw.Nexus.PasswordFile))
	if err != nil {
		return Settings{}, err
	}
	key, err := readSecret("signatureKeyFile", resolve(dir, raw.SignatureKeyFile))
	if err != nil {
		return Settings{}, err
	}
	s := Settings{NexusURL: u, Repository: raw.Nexus.Repository, User: raw.Nexus.User, Password: password, SignatureKey: key}
	if raw.Nexus.CAFile != "" {
		s.CAFile = resolve(dir, raw.Nexus.CAFile)
		f, err := os.Open(s.CAFile)
		if err != nil {
			return Settings{}, settingsErr("nexus.caFile", "cannot be read")
		}
		f.Close()
	}
	return s, nil
}

func parseNexusURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// The parser's error quotes the URL, which may carry a password.
		return nil, settingsErr("nexus.url", "is not a valid URL")
	}
	switch {
	case u.User != nil:
		return nil, settingsErr("nexus.url", "must not carry a user name or password")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, settingsErr("nexus.url", "must start with http or https")
	case u.Host == "":
		return nil, settingsErr("nexus.url", "must name a host")
	case u.RawQuery != "" || u.ForceQuery:
		return nil, settingsErr("nexus.url", "must not carry a query")
	case u.Fragment != "" || u.RawFragment != "" || strings.Contains(raw, "#"):
		return nil, settingsErr("nexus.url", "must not carry a fragment")
	}
	return u, nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

func readSecret(field, path string) (Secret, error) {
	data, err := readBounded(path, maxSecretBytes)
	if err != nil {
		return nil, readError(field, err)
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	if len(data) == 0 {
		return nil, settingsErr(field, "points to an empty file")
	}
	return Secret(data), nil
}

// readBounded reads a file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge{limit}
	}
	return data, nil
}

type errTooLarge struct{ limit int64 }

func (e errTooLarge) Error() string { return fmt.Sprintf("larger than %d bytes", e.limit) }

func readError(field string, err error) error {
	var big errTooLarge
	switch {
	case errors.As(err, &big):
		return settingsErr(field, "is "+big.Error())
	case errors.Is(err, fs.ErrNotExist):
		return settingsErr(field, "cannot be read: the file does not exist")
	default:
		return settingsErr(field, "cannot be read")
	}
}
