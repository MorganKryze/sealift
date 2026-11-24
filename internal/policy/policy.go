// Package policy reads the file the deployment names in SEALIFT_POLICY: the
// default targets, the minimum release age, the parallelism, the brand and
// the review rules.
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
	// Review says what a selection needs before it can cross.
	Review Review
	// Overrides names each key the file set over a different value the
	// stored settings held, for the start log.
	Overrides []string
	// Defaulted names each key the stored settings held empty or at zero
	// and the file does not set, so the default applies, for the start log.
	Defaulted []string
}

// Rule is what a selection that carries a major jump or a CVE without fix
// needs to cross.
type Rule string

const (
	// AskReason lets the selection cross with a reason written for it.
	AskReason Rule = "reason"
	// Refuse stops the selection whatever reason it holds.
	Refuse Rule = "refuse"
)

// Review holds the review rules of the policy file's review key.
type Review struct {
	// ProposeOtherMajors lets an analysis propose a version outside the
	// current major.
	ProposeOtherMajors bool
	MajorJump          Rule
	CVEWithoutFix      Rule
}

// DefaultReview proposes inside the current major only and asks a reason
// for a major jump and for a CVE without fix.
func DefaultReview() Review {
	return Review{MajorJump: AskReason, CVEWithoutFix: AskReason}
}

// StoredError reports a value the settings of an older release hold, which
// this release refuses and the policy file does not replace.
type StoredError struct {
	// Key is the key in the settings file, PolicyKey the key of the policy
	// file that replaces its value, and Rule the rule the value breaks.
	Key, PolicyKey, Rule string
}

func (e *StoredError) Error() string {
	return fmt.Sprintf("%s %s; set %s in the policy file to replace it", e.Key, e.Rule, e.PolicyKey)
}

type rawPolicy struct {
	Targets           rawTargets     `yaml:"targets"`
	MinReleaseAgeDays *int           `yaml:"minReleaseAgeDays"`
	Parallelism       rawParallelism `yaml:"parallelism"`
	Brand             rawBrand       `yaml:"brand"`
	Review            rawReview      `yaml:"review"`
}

type rawReview struct {
	ProposeOtherMajors *bool `yaml:"proposeOtherMajors"`
	// Nodes, since a *string reads an explicit null as a key left out.
	MajorJump     yaml.Node `yaml:"majorJump"`
	CVEWithoutFix yaml.Node `yaml:"cveWithoutFix"`
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
	"policy.rawReview":      "review.",
}

var (
	unknownKey = regexp.MustCompile(`line (\d+): field (\S+) not found in type (\S+)`)
	wrongType  = regexp.MustCompile(`line (\d+): cannot unmarshal`)
	yamlLine   = regexp.MustCompile(`line (\d+)`)
)

// Load reads the policy file at path, "" meaning none, over stored, what an
// older release's settings held when hasStored is true. Each value comes
// from the file, else from stored, else from the defaults. A stored value
// this release refuses stops the load with a *StoredError, unless the file
// replaces it. The error names the key and the rule it breaks. It repeats
// a number out of range, and never a text value of the file.
func Load(path string, stored store.Settings, hasStored bool) (Policy, error) {
	var raw rawPolicy
	if path != "" {
		var err error
		if raw, err = decodePolicy(path); err != nil {
			return Policy{}, err
		}
	}
	p := Policy{Settings: store.DefaultSettings, Pip: store.DefaultPipTarget}
	if err := p.merge(raw, stored, hasStored); err != nil {
		return Policy{}, err
	}
	var err error
	if raw.Targets.Pip != nil {
		if p.Pip, err = raw.Targets.Pip.target(); err != nil {
			return Policy{}, err
		}
	}
	if p.Review, err = raw.Review.review(); err != nil {
		return Policy{}, err
	}
	// Without a file, the brand holds no key and reads no logo.
	if p.Brand, err = raw.Brand.brand(filepath.Dir(path)); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// decodePolicy reads the policy file at path into its raw keys.
func decodePolicy(path string) (rawPolicy, error) {
	data, err := readPolicyFile(path)
	if err != nil {
		return rawPolicy{}, err
	}
	var raw rawPolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return rawPolicy{}, yamlError(err)
	}
	// Decode reads the first document only: a second one would go unchecked
	// and unapplied.
	var rest yaml.Node
	if err := dec.Decode(&rest); !errors.Is(err, io.EOF) {
		return rawPolicy{}, errors.New("holds more than one YAML document")
	}
	return raw, nil
}

// merge sets the npm target and the limits from raw, else from stored,
// else leaves the defaults, and records the keys the start log names.
func (p *Policy) merge(raw rawPolicy, stored store.Settings, hasStored bool) error {
	switch {
	case raw.Targets.Npm != nil:
		t, err := raw.Targets.Npm.target()
		if err != nil {
			return err
		}
		if hasStored && t != stored.Target {
			p.Overrides = append(p.Overrides, "targets.npm")
		}
		p.Settings.Target = t
	case !hasStored:
	case stored.Target == (store.Target{}):
		p.Defaulted = append(p.Defaulted, "targets.npm")
	default:
		if err := store.ValidateTarget(stored.Target); err != nil {
			return &StoredError{Key: "target", PolicyKey: "targets.npm", Rule: "is refused: " + targetProblems(err)}
		}
		p.Settings.Target = stored.Target
	}

	for _, l := range []struct {
		key, storedKey string
		value          *int
		stored, max    int
		into           *int
	}{
		{"minReleaseAgeDays", "minReleaseAgeDays", raw.MinReleaseAgeDays, stored.MinReleaseAgeDays, store.MaxMinReleaseAgeDays, &p.Settings.MinReleaseAgeDays},
		{"parallelism.resolve", "resolveParallelism", raw.Parallelism.Resolve, stored.ResolveParallelism, store.MaxResolveParallelism, &p.Settings.ResolveParallelism},
		{"parallelism.download", "downloadParallelism", raw.Parallelism.Download, stored.DownloadParallelism, store.MaxDownloadParallelism, &p.Settings.DownloadParallelism},
	} {
		switch {
		case l.value != nil:
			if *l.value < 1 || *l.value > l.max {
				return fmt.Errorf("%s %s", l.key, outOfRange(l.max, *l.value))
			}
			if hasStored && *l.value != l.stored {
				p.Overrides = append(p.Overrides, l.key)
			}
			*l.into = *l.value
		case !hasStored:
		// Every release wrote each key, and the first ones accepted a zero:
		// the default replaces it, and the start log says so.
		case l.stored == 0:
			p.Defaulted = append(p.Defaulted, l.key)
		case l.stored < 1 || l.stored > l.max:
			return &StoredError{Key: l.storedKey, PolicyKey: l.key, Rule: outOfRange(l.max, l.stored)}
		default:
			*l.into = l.stored
		}
	}
	return nil
}

func outOfRange(highest, value int) string {
	return fmt.Sprintf("must be between 1 and %d, not %d", highest, value)
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

// review applies each rule the file sets over the default review.
func (r rawReview) review() (Review, error) {
	out := DefaultReview()
	if r.ProposeOtherMajors != nil {
		out.ProposeOtherMajors = *r.ProposeOtherMajors
	}
	for _, f := range []struct {
		key   string
		value yaml.Node
		into  *Rule
	}{
		{"review.majorJump", r.MajorJump, &out.MajorJump},
		{"review.cveWithoutFix", r.CVEWithoutFix, &out.CVEWithoutFix},
	} {
		if f.value.Kind == 0 {
			continue
		}
		var value string
		if f.value.ShortTag() != "!!null" {
			if err := f.value.Decode(&value); err != nil {
				return Review{}, yamlError(err)
			}
		}
		switch rule := Rule(value); rule {
		case AskReason, Refuse:
			*f.into = rule
		default:
			return Review{}, fmt.Errorf("%s must be one of %s, %s", f.key, AskReason, Refuse)
		}
	}
	return out, nil
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
	return fmt.Errorf("%s is not a valid target: %s", key, targetProblems(err))
}

// targetProblems is what a target validation error says, without its
// sentinel's prefix.
func targetProblems(err error) string {
	return strings.TrimPrefix(err.Error(), store.ErrInvalidTarget.Error()+": ")
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
