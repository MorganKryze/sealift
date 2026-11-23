// Package policy reads the file the deployment names in SEALIFT_POLICY: the
// default targets, the minimum release age, the parallelism and the brand.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"go.yaml.in/yaml/v3"

	"github.com/MorganKryze/sealift/internal/store"
)

// maxPolicyBytes bounds the policy file: 64 KiB, far above every key it holds.
const maxPolicyBytes = 64 << 10

// Policy is what applies to the instance once the file, the settings an
// older release stored and the defaults are merged, in that order.
type Policy struct {
	// Settings are the npm target, the minimum release age and the
	// parallelism in effect.
	Settings store.Settings
	// Pip is the target a pip project gets when its creator names none.
	Pip   store.PipTarget
	Brand Brand
	// Overrides names each key the file set over a different value the
	// stored settings held, for the start log.
	Overrides []string
}

type rawPolicy struct {
	Targets           rawTargets     `yaml:"targets"`
	MinReleaseAgeDays *int           `yaml:"minReleaseAgeDays"`
	Parallelism       rawParallelism `yaml:"parallelism"`
	Brand             rawBrand       `yaml:"brand"`
}

type rawTargets struct {
	Npm *rawNpmTarget `yaml:"npm"`
	Pip *rawPipTarget `yaml:"pip"`
}

type rawNpmTarget struct {
	OS   string `yaml:"os"`
	CPU  string `yaml:"cpu"`
	Libc string `yaml:"libc"`
	Node string `yaml:"node"`
	Pnpm string `yaml:"pnpm"`
}

type rawPipTarget struct {
	Python string `yaml:"python"`
	OS     string `yaml:"os"`
	CPU    string `yaml:"cpu"`
	Glibc  string `yaml:"glibc"`
	Uv     string `yaml:"uv"`
}

type rawParallelism struct {
	Resolve  *int `yaml:"resolve"`
	Download *int `yaml:"download"`
}

// keyPrefix maps each raw type to the path of its keys in the file, so an
// unknown key is named in full.
var keyPrefix = map[string]string{
	"policy.rawPolicy":      "",
	"policy.rawTargets":     "targets.",
	"policy.rawNpmTarget":   "targets.npm.",
	"policy.rawPipTarget":   "targets.pip.",
	"policy.rawParallelism": "parallelism.",
	"policy.rawBrand":       "brand.",
	"policy.rawSides":       "brand.sides.",
	"policy.rawContact":     "brand.contact.",
}

var (
	unknownKey = regexp.MustCompile(`line (\d+): field (\S+) not found in type (\S+)`)
	wrongType  = regexp.MustCompile(`line (\d+): cannot unmarshal`)
	yamlLine   = regexp.MustCompile(`line (\d+)`)
)

// Load reads the policy file at path, "" meaning none, over stored, what an
// older release's settings held when hasStored is true. Each value comes
// from the file, else from stored, else from the defaults. The error names
// the key and the rule it breaks, and never repeats a value of the file.
func Load(path string, stored store.Settings, hasStored bool) (Policy, error) {
	p := Policy{Settings: base(stored, hasStored), Pip: store.DefaultPipTarget, Brand: DefaultBrand()}
	if path == "" {
		return p, nil
	}
	data, err := readPolicyFile(path)
	if err != nil {
		return Policy{}, err
	}
	var raw rawPolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return Policy{}, yamlError(err)
	}
	// Decode reads the first document only: a second one would go unchecked
	// and unapplied.
	var rest yaml.Node
	if err := dec.Decode(&rest); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("holds more than one YAML document")
	}

	set := p.Settings
	if raw.Targets.Npm != nil {
		t, err := raw.Targets.Npm.target()
		if err != nil {
			return Policy{}, err
		}
		set.Target = t
	}
	for _, l := range []struct {
		key   string
		value *int
		max   int
		into  *int
	}{
		{"minReleaseAgeDays", raw.MinReleaseAgeDays, store.MaxMinReleaseAgeDays, &set.MinReleaseAgeDays},
		{"parallelism.resolve", raw.Parallelism.Resolve, store.MaxResolveParallelism, &set.ResolveParallelism},
		{"parallelism.download", raw.Parallelism.Download, store.MaxDownloadParallelism, &set.DownloadParallelism},
	} {
		if l.value == nil {
			continue
		}
		if *l.value < 1 || *l.value > l.max {
			return Policy{}, fmt.Errorf("%s must be between 1 and %d, not %d", l.key, l.max, *l.value)
		}
		*l.into = *l.value
	}
	if raw.Targets.Pip != nil {
		if p.Pip, err = raw.Targets.Pip.target(); err != nil {
			return Policy{}, err
		}
	}
	if p.Brand, err = raw.Brand.brand(filepath.Dir(path)); err != nil {
		return Policy{}, err
	}
	if hasStored {
		p.Overrides = overrides(p.Settings, set)
	}
	p.Settings = set
	return p, nil
}

// base is what applies before the file: each value the stored settings
// hold, else the default. A settings file from before a key existed holds
// its zero value.
func base(stored store.Settings, hasStored bool) store.Settings {
	set := store.DefaultSettings
	if !hasStored {
		return set
	}
	if stored.Target != (store.Target{}) {
		set.Target = stored.Target
	}
	for _, v := range []struct{ from, into *int }{
		{&stored.MinReleaseAgeDays, &set.MinReleaseAgeDays},
		{&stored.ResolveParallelism, &set.ResolveParallelism},
		{&stored.DownloadParallelism, &set.DownloadParallelism},
	} {
		if *v.from != 0 {
			*v.into = *v.from
		}
	}
	return set
}

// overrides names each key whose value the file changed from before.
func overrides(before, after store.Settings) []string {
	var keys []string
	if before.Target != after.Target {
		keys = append(keys, "targets.npm")
	}
	if before.MinReleaseAgeDays != after.MinReleaseAgeDays {
		keys = append(keys, "minReleaseAgeDays")
	}
	if before.ResolveParallelism != after.ResolveParallelism {
		keys = append(keys, "parallelism.resolve")
	}
	if before.DownloadParallelism != after.DownloadParallelism {
		keys = append(keys, "parallelism.download")
	}
	return keys
}

func (r rawNpmTarget) target() (store.Target, error) {
	if err := required("targets.npm", []string{"os", "cpu", "libc", "node", "pnpm"}, r.OS, r.CPU, r.Libc, r.Node, r.Pnpm); err != nil {
		return store.Target{}, err
	}
	t := store.Target{OS: r.OS, CPU: r.CPU, Libc: r.Libc, Node: r.Node, PnpmVer: r.Pnpm}
	if err := store.ValidateTarget(t); err != nil {
		return store.Target{}, invalidTarget("targets.npm", err)
	}
	return t, nil
}

func (r rawPipTarget) target() (store.PipTarget, error) {
	if err := required("targets.pip", []string{"python", "os", "cpu", "glibc", "uv"}, r.Python, r.OS, r.CPU, r.Glibc, r.Uv); err != nil {
		return store.PipTarget{}, err
	}
	t := store.PipTarget{Python: r.Python, OS: r.OS, CPU: r.CPU, Glibc: r.Glibc, UvVer: r.Uv}
	if err := store.ValidatePipTarget(t); err != nil {
		return store.PipTarget{}, invalidTarget("targets.pip", err)
	}
	return t, nil
}

// required refuses a target that leaves a field out: a target in the file
// replaces the whole default one, so a missing field has nothing to fall
// back on.
func required(key string, names []string, values ...string) error {
	for i, v := range values {
		if v == "" {
			return fmt.Errorf("%s.%s is required: a target sets all of %s", key, names[i], strings.Join(names, ", "))
		}
	}
	return nil
}

func invalidTarget(key string, err error) error {
	return fmt.Errorf("%s is not a valid target: %s", key, strings.TrimPrefix(err.Error(), store.ErrInvalidTarget.Error()+": "))
}

// readPolicyFile reads the regular file at path. A link is followed, as a
// mounted configuration file is often one; O_NONBLOCK keeps a FIFO from
// holding the open until the type check refuses it.
func readPolicyFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("the file does not exist")
	}
	if err != nil {
		return nil, fmt.Errorf("cannot be read: %w", errors.Unwrap(err))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot be read: %w", errors.Unwrap(err))
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot be read: %w", errors.Unwrap(err))
	}
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("is larger than %d bytes", maxPolicyBytes)
	}
	return data, nil
}

// yamlError names the line and, for an unknown key, the key. The parser's
// own text is not repeated, as it can quote a value.
func yamlError(err error) error {
	msg := err.Error()
	if m := unknownKey.FindStringSubmatch(msg); m != nil {
		return fmt.Errorf("%s%s is an unknown key (line %s)", keyPrefix[m[3]], m[2], m[1])
	}
	if m := wrongType.FindStringSubmatch(msg); m != nil {
		return fmt.Errorf("line %s holds a value of the wrong type", m[1])
	}
	if m := yamlLine.FindStringSubmatch(msg); m != nil {
		return fmt.Errorf("is not valid YAML (line %s)", m[1])
	}
	return errors.New("is not valid YAML")
}
