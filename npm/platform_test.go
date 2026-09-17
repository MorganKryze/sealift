package npm

import "testing"

func TestPlatformAccepts(t *testing.T) {
	linux := Platform{OS: "linux", CPU: "x64", Libc: "glibc"}
	for _, tc := range []struct {
		name string
		pkg  LockPackage
		want bool
	}{
		{"no constraint", LockPackage{}, true},
		{"matching os and cpu", LockPackage{OS: []string{"linux"}, CPU: []string{"x64"}}, true},
		{"other os", LockPackage{OS: []string{"darwin"}}, false},
		{"other cpu", LockPackage{CPU: []string{"arm64"}}, false},
		{"musl only", LockPackage{OS: []string{"linux"}, Libc: []string{"musl"}}, false},
		{"glibc", LockPackage{OS: []string{"linux"}, Libc: []string{"glibc"}}, true},
		{"negated other os", LockPackage{OS: []string{"!win32"}}, true},
		{"negated target os", LockPackage{OS: []string{"!linux"}}, false},
		{"any", LockPackage{CPU: []string{"any"}}, true},
		{"mixed with negated target", LockPackage{OS: []string{"linux", "!linux"}}, false},
		{"mixed", LockPackage{OS: []string{"linux", "!win32"}}, true},
	} {
		if got := linux.Accepts(tc.pkg); got != tc.want {
			t.Errorf("%s: Accepts = %v, want %v", tc.name, got, tc.want)
		}
	}

	darwin := Platform{OS: "darwin", CPU: "arm64"}
	if !darwin.Accepts(LockPackage{OS: []string{"darwin"}, Libc: []string{"musl"}}) {
		t.Error("the libc list must not apply outside linux")
	}
}

func TestPlatformFilterFixture(t *testing.T) {
	kept := Platform{OS: "linux", CPU: "x64", Libc: "glibc"}.Filter(loadFixtureLockfile(t))
	keys := map[string]bool{}
	for _, p := range kept {
		keys[p.Key()] = true
	}
	for key, want := range map[string]bool{
		"@esbuild/linux-x64@0.25.0":       true,
		"@img/sharp-linux-x64@0.33.5":     true,
		"@esbuild/darwin-arm64@0.25.0":    false,
		"@img/sharp-linuxmusl-x64@0.33.5": false,
		"express@4.21.2":                  true,
	} {
		if keys[key] != want {
			t.Errorf("%s kept = %v, want %v", key, keys[key], want)
		}
	}
	if len(kept) != wantLinuxGlibcPackages {
		t.Errorf("kept %d packages, want %d", len(kept), wantLinuxGlibcPackages)
	}
}

// 840 packages minus the 73 built for another os, cpu or libc.
const wantLinuxGlibcPackages = 767
