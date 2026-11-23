package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/MorganKryze/sealift/internal/store"
)

var (
	pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)
	svgBytes = []byte("<?xml version=\"1.0\"?>\n<!-- mark -->\n<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1 1\"/>\n")
)

// policyWithLogo writes a policy that names logo, in a fresh directory,
// and lets plant put the logo's file there. It returns the policy's path.
func policyWithLogo(t *testing.T, logo string, plant func(dir string)) string {
	t.Helper()
	dir := t.TempDir()
	plant(dir)
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("brand:\n  logo: "+logo+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func logoRefused(t *testing.T, path string, want ...string) {
	t.Helper()
	_, err := Load(path, store.Settings{}, false)
	if err == nil {
		t.Fatal("Load accepted the logo")
	}
	for _, w := range append([]string{"brand.logo"}, want...) {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("Load = %q, want it to name %q", err, w)
		}
	}
}

func TestBrandDefaults(t *testing.T) {
	want := Brand{Name: "sealift", Online: "Online", Offline: "Offline", ReviewWord: "PR"}
	got := DefaultBrand()
	if got.Name != want.Name || got.Online != want.Online || got.Offline != want.Offline || got.ReviewWord != want.ReviewWord ||
		got.Accent != "" || got.Logo != nil || got.LogoType != "" || got.Contact != nil {
		t.Errorf("DefaultBrand() = %+v, want %+v", got, want)
	}

	p, err := Load(writePolicy(t, "minReleaseAgeDays: 14\n"), store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Brand.Name != "sealift" || p.Brand.ReviewWord != "PR" || p.Brand.Contact != nil {
		t.Errorf("a file without brand gave %+v, want the defaults", p.Brand)
	}

	set, err := Load(writePolicy(t, `
brand:
  name: Harbour
  accent: "#1a6b8f"
  sides: {online: Connected, offline: Air-gapped}
  reviewWord: MR
  contact: {label: Platform team, url: "mailto:platform@example.org"}
`), store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	b := set.Brand
	if b.Name != "Harbour" || b.Accent != "#1a6b8f" || b.Online != "Connected" || b.Offline != "Air-gapped" || b.ReviewWord != "MR" ||
		b.Contact == nil || *b.Contact != (Contact{Label: "Platform team", URL: "mailto:platform@example.org"}) {
		t.Errorf("Brand = %+v, want every value the file set", b)
	}
}

func TestLogoThroughALinkIsRefused(t *testing.T) {
	path := policyWithLogo(t, "logo.png", func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "real.png"), pngBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "real.png"), filepath.Join(dir, "logo.png")); err != nil {
			t.Fatal(err)
		}
	})
	logoRefused(t, path, "not a regular file")
}

func TestLogoFifoIsRefused(t *testing.T) {
	path := policyWithLogo(t, "logo.png", func(dir string) {
		if err := syscall.Mkfifo(filepath.Join(dir, "logo.png"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	logoRefused(t, path, "not a regular file")
}

func TestLogoOfAnotherTypeIsRefused(t *testing.T) {
	for name, data := range map[string][]byte{
		"gif":           []byte("GIF89a\x01\x00\x01\x00"),
		"html":          []byte("<html><svg/></html>"),
		"empty":         nil,
		"text then svg": []byte("hello <svg/>"),
	} {
		path := policyWithLogo(t, "logo", func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "logo"), data, 0o600); err != nil {
				t.Fatal(err)
			}
		})
		t.Run(name, func(t *testing.T) { logoRefused(t, path, "PNG or SVG") })
	}
}

func TestLogoOverTheLimitIsRefused(t *testing.T) {
	at := func(size int) string {
		return policyWithLogo(t, "logo.png", func(dir string) {
			data := append(bytes.Clone(pngBytes[:8]), make([]byte, size-8)...)
			if err := os.WriteFile(filepath.Join(dir, "logo.png"), data, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	logoRefused(t, at(256<<10+1), "larger than 262144 bytes")

	p, err := Load(at(256<<10), store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load of a 256 KiB logo: %v", err)
	}
	if len(p.Brand.Logo) != 256<<10 || p.Brand.LogoType != "image/png" {
		t.Errorf("logo of %d bytes typed %q, want 262144 bytes of image/png", len(p.Brand.Logo), p.Brand.LogoType)
	}
}

func TestLogoPathIsRelativeToThePolicyFile(t *testing.T) {
	path := policyWithLogo(t, "brand/mark.svg", func(dir string) {
		if err := os.Mkdir(filepath.Join(dir, "brand"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "brand", "mark.svg"), svgBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	t.Chdir(t.TempDir())
	p, err := Load(path, store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(p.Brand.Logo, svgBytes) || p.Brand.LogoType != "image/svg+xml" {
		t.Errorf("logo %q typed %q, want the SVG beside the policy file", p.Brand.Logo, p.Brand.LogoType)
	}

	missing := policyWithLogo(t, "mark.svg", func(string) {})
	logoRefused(t, missing, "does not exist")
}

func TestContactRefusesAJavascriptAddress(t *testing.T) {
	for _, url := range []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)",
		"data:text/html,hi",
		"http://ops.example.org",
		"https://user:secret@ops.example.org",
		"https:///no-host",
		"mailto:",
		"/relative",
	} {
		refused(t, "brand:\n  contact: {label: Ops, url: \""+url+"\"}\n", "brand.contact.url", "https: or mailto:")
	}
	refused(t, "brand:\n  contact: {label: Ops, url: \"https://ops.example.org/"+strings.Repeat("a", 512)+"\"}\n", "brand.contact.url", "512 bytes")
	refused(t, "brand:\n  contact: {label: Ops}\n", "brand.contact.url", "required")
	refused(t, "brand:\n  contact: {url: \"https://ops.example.org\"}\n", "brand.contact.label", "required")

	p, err := Load(writePolicy(t, "brand:\n  contact: {label: Ops, url: \"https://ops.example.org/help\"}\n"), store.Settings{}, false)
	if err != nil {
		t.Fatalf("Load of an https contact: %v", err)
	}
	if p.Brand.Contact == nil || p.Brand.Contact.URL != "https://ops.example.org/help" {
		t.Errorf("Contact = %+v, want the https address", p.Brand.Contact)
	}
}

func TestAccentMustBeSixHexDigits(t *testing.T) {
	for _, accent := range []string{"1a6b8f", "#1a6b8", "#1a6b8f0", "#1a6b8g", "red", "#fff"} {
		refused(t, "brand:\n  accent: \""+accent+"\"\n", "brand.accent", "#rrggbb")
	}
	p, err := Load(writePolicy(t, "brand:\n  accent: \"#1A6B8F\"\n"), store.Settings{}, false)
	if err != nil || p.Brand.Accent != "#1A6B8F" {
		t.Errorf("Load of #1A6B8F = %+v, %v, want it accepted", p.Brand, err)
	}
}

func TestBrandTextRefusesAControlCharacter(t *testing.T) {
	cases := []struct{ key, yaml string }{
		{"brand.name", "brand:\n  name: \"Harbour\\u202Eevil\"\n"},
		{"brand.name", "brand:\n  name: \"Harbour\\u0007\"\n"},
		{"brand.sides.online", "brand:\n  sides: {online: \"On\\nline\"}\n"},
		{"brand.sides.offline", "brand:\n  sides: {offline: \"Off\\u2066line\"}\n"},
		{"brand.reviewWord", "brand:\n  reviewWord: \"P\\u200FR\"\n"},
		{"brand.contact.label", "brand:\n  contact: {label: \"Ops\\u2028team\", url: \"https://ops.example.org\"}\n"},
		{"brand.contact.url", "brand:\n  contact: {label: Ops, url: \"https://ops.example.org/\\u202E\"}\n"},
	}
	for _, c := range cases {
		refused(t, c.yaml, c.key, "control character")
	}

	refused(t, "brand:\n  name: \"\"\n", "brand.name", "empty")
	refused(t, "brand:\n  name: \"   \"\n", "brand.name", "empty")
	refused(t, "brand:\n  name: "+strings.Repeat("a", 41)+"\n", "brand.name", "40 characters")
	refused(t, "brand:\n  sides: {online: "+strings.Repeat("a", 21)+"}\n", "brand.sides.online", "20 characters")
	refused(t, "brand:\n  reviewWord: "+strings.Repeat("a", 13)+"\n", "brand.reviewWord", "12 characters")
	refused(t, "brand:\n  contact: {label: "+strings.Repeat("a", 61)+", url: \"https://ops.example.org\"}\n", "brand.contact.label", "60 characters")

	p, err := Load(writePolicy(t, "brand:\n  name: "+strings.Repeat("é", 40)+"\n"), store.Settings{}, false)
	if err != nil || p.Brand.Name != strings.Repeat("é", 40) {
		t.Errorf("a name of 40 accented letters = %+v, %v, want it accepted", p.Brand, err)
	}
}
