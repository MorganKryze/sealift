package policy

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/internal/store"
)

// maxLogoBytes bounds the logo, which is held in memory and served as is.
const maxLogoBytes = 256 << 10

// Brand is the name and the marks the interface shows.
type Brand struct {
	Name, Accent, Online, Offline, ReviewWord string
	Logo                                      []byte
	// LogoType is "image/png" or "image/svg+xml", empty without a logo.
	LogoType string
	Contact  *Contact
}

// Contact is who the interface points a user to, with an https: or
// mailto: address.
type Contact struct{ Label, URL string }

// DefaultBrand is the brand without a policy: sealift's name and mark, the
// default accent, Online and Offline, PR, and no contact.
func DefaultBrand() Brand {
	return Brand{Name: "sealift", Online: "Online", Offline: "Offline", ReviewWord: "PR"}
}

type rawBrand struct {
	Name       *string     `yaml:"name"`
	Logo       *string     `yaml:"logo"`
	Accent     *string     `yaml:"accent"`
	Sides      rawSides    `yaml:"sides"`
	ReviewWord *string     `yaml:"reviewWord"`
	Contact    *rawContact `yaml:"contact"`
}

type rawSides struct {
	Online  *string `yaml:"online"`
	Offline *string `yaml:"offline"`
}

type rawContact struct {
	Label *string `yaml:"label"`
	URL   *string `yaml:"url"`
}

var (
	accentRE     = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	pngSignature = []byte("\x89PNG\r\n\x1a\n")
)

const maxContactURLBytes = 512

// brand checks every value the file set, over the defaults. dir is the
// policy file's folder, where a relative logo path starts.
func (r rawBrand) brand(dir string) (Brand, error) {
	b := DefaultBrand()
	for _, t := range []struct {
		key   string
		value *string
		max   int
		into  *string
	}{
		{"brand.name", r.Name, 40, &b.Name},
		{"brand.sides.online", r.Sides.Online, 20, &b.Online},
		{"brand.sides.offline", r.Sides.Offline, 20, &b.Offline},
		{"brand.reviewWord", r.ReviewWord, 12, &b.ReviewWord},
	} {
		if t.value == nil {
			continue
		}
		if err := checkText(t.key, *t.value, t.max); err != nil {
			return Brand{}, err
		}
		*t.into = *t.value
	}
	if r.Accent != nil {
		// Only the form is checked here; whether the colour reads well
		// is the interface's to judge.
		if !accentRE.MatchString(*r.Accent) {
			return Brand{}, errors.New("brand.accent must be a colour written #rrggbb")
		}
		b.Accent = *r.Accent
	}
	if r.Contact != nil {
		c, err := r.Contact.contact()
		if err != nil {
			return Brand{}, err
		}
		b.Contact = &c
	}
	if r.Logo != nil {
		var err error
		if b.Logo, b.LogoType, err = readLogo(dir, *r.Logo); err != nil {
			return Brand{}, err
		}
	}
	return b, nil
}

func (r rawContact) contact() (Contact, error) {
	if r.Label == nil {
		return Contact{}, errors.New("brand.contact.label is required with a contact")
	}
	if r.URL == nil {
		return Contact{}, errors.New("brand.contact.url is required with a contact")
	}
	if err := checkText("brand.contact.label", *r.Label, 60); err != nil {
		return Contact{}, err
	}
	raw := *r.URL
	if len(raw) > maxContactURLBytes {
		return Contact{}, fmt.Errorf("brand.contact.url is longer than %d bytes", maxContactURLBytes)
	}
	if err := checkCharacters("brand.contact.url", raw); err != nil {
		return Contact{}, err
	}
	if !contactAddress(raw) {
		return Contact{}, errors.New("brand.contact.url must be an https: or mailto: address")
	}
	return Contact{Label: *r.Label, URL: raw}, nil
}

// contactAddress accepts an https: address with a host and no credentials,
// or a mailto: address with a recipient. Any other scheme could run script
// or leave the user's browser for something they did not choose.
func contactAddress(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != "" && u.User == nil
	case "mailto":
		return u.Opaque != ""
	}
	return false
}

// checkText refuses an empty value, one past limit characters, or one that
// holds a character that would reorder or break the text around it.
func checkText(key, value string, limit int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is empty", key)
	}
	if utf8.RuneCountInString(value) > limit {
		return fmt.Errorf("%s is longer than %d characters", key, limit)
	}
	return checkCharacters(key, value)
}

// checkCharacters refuses control characters, format characters (the
// bidirectional overrides among them) and line or paragraph separators.
func checkCharacters(key, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", key)
	}
	for _, c := range value {
		if unicode.In(c, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%s holds a control character (U+%04X)", key, c)
		}
	}
	return nil
}

// readLogo reads the logo once, from a regular file: no link, no FIFO. Its
// type comes from its bytes, never from its name.
func readLogo(dir, name string) ([]byte, string, error) {
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, name)
	}
	data, err := store.ReadRegularFile(path, maxLogoBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", errors.New("brand.logo cannot be read: the file does not exist")
	}
	if err != nil {
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return nil, "", fmt.Errorf("brand.logo cannot be read: %w", err)
	}
	switch {
	case bytes.HasPrefix(data, pngSignature):
		return data, "image/png", nil
	case svgRoot(data):
		return data, "image/svg+xml", nil
	}
	return nil, "", errors.New("brand.logo must be a PNG or SVG file")
}

// svgRoot reports whether data is XML whose root element is svg. What comes
// before the root may only be the XML declaration, comments, a doctype and
// white space.
func svgRoot(data []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t.Name.Local == "svg"
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return false
			}
		case xml.ProcInst, xml.Comment, xml.Directive:
		default:
			return false
		}
	}
}
