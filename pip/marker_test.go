package pip

import "testing"

// Each decided row gives the answer uv gives for the same marker with
// --python-version 3.11.2 --python-platform x86_64-manylinux_2_28.
func TestMarkerHolds(t *testing.T) {
	cases := []struct {
		marker string
		python string // the target's Python when not 3.11.2
		want   bool
	}{
		{`python_full_version < "3.11.3"`, "", true},
		{`python_full_version < "3.11.3"`, "3.11.3", false},
		{`python_version < "3.8"`, "", false},
		{`python_version >= "3.8"`, "", true},
		{`python_version >= "3"`, "", true},
		{`python_version > "3.11"`, "", false},
		{`python_version != "3.11"`, "", false},
		{`python_version == "3.11.0"`, "", true},
		{`python_version == "03.11"`, "", true},
		{`python_version < "3.11.2"`, "", true},
		{`python_version == "3.11.2"`, "", false},
		{`python_full_version == "3.11"`, "", false},
		{`python_full_version > "3.11.1"`, "", true},
		{`python_version ~= "3.10"`, "", true},
		{`python_version ~= "3.11.0"`, "", true},
		{`python_full_version ~= "3.11.0"`, "", true},
		{`python_full_version ~= "3.10.0"`, "", false},
		{`"3.11" <= python_version`, "", true},
		{`"3.12" <= python_version`, "", false},
		{`"3.11.3" > python_full_version`, "", true},
		{`python_version in "3.10 3.11"`, "", true},
		{`python_version in "3.1"`, "", false},
		{`python_version not in "3.11"`, "", false},
		{`python_full_version in "3.11.2"`, "", true},
		{`implementation_version == "3.11.2"`, "", true},
		{`implementation_version >= "3.12"`, "", false},
		{`implementation_name == "cpython"`, "", true},
		{`platform_python_implementation == "CPython"`, "", true},
		{`platform_python_implementation == "PyPy"`, "", false},
		{`os_name == "posix"`, "", true},
		{`os_name == "nt"`, "", false},
		{`sys_platform == "linux"`, "", true},
		{`sys_platform == 'win32'`, "", false},
		{`sys_platform == "Linux"`, "", false},
		{`sys_platform != "darwin"`, "", true},
		{`platform_system == "Linux"`, "", true},
		{`platform_system == "Windows"`, "", false},
		{`platform_machine == "x86_64"`, "", true},
		{`platform_machine == "aarch64"`, "", false},
		{`platform_release == ""`, "", true},
		{`platform_version != ""`, "", false},
		{`"linux" in sys_platform`, "", true},
		{`"lin" in sys_platform`, "", true},
		{`sys_platform in "linux2 linux"`, "", true},
		{`sys_platform not in "darwin"`, "", true},
		{`"posix" == os_name`, "", true},
		{`extra == "dev"`, "", false},
		{`extra != "dev"`, "", true},
		{`os.name == "posix"`, "", true},
		{`sys.platform == "win32"`, "", false},
		{`platform.machine == "x86_64"`, "", true},
		{`python_implementation == "CPython"`, "", true},
		{`python_version<"3.12"and os_name=="posix"`, "", true},
		{`(python_version < "3.12")`, "", true},
		{`python_version == "3.11" and (os_name == "nt" or sys_platform == "linux")`, "", true},
		{`python_version == "3.11" or python_version == "2.7" and sys_platform == "win32"`, "", true},
		{`(python_version == "3.11" or python_version == "2.7") and sys_platform == "win32"`, "", false},
		{`python_version < "3.8" and platform_release >= "5"`, "", false},
		{`python_version >= "3.8" or platform_machine ~= "x86"`, "", true},
	}
	for _, c := range cases {
		p := host
		if c.python != "" {
			p.Python = c.python
		}
		got, err := MarkerHolds(c.marker, p)
		if err != nil || got != c.want {
			t.Errorf("MarkerHolds(%q) on %s = %v, %v; want %v", c.marker, p.Python, got, err, c.want)
		}
	}
}

// A marker MarkerHolds cannot decide the way uv does is an error, never a
// guess.
func TestMarkerHoldsRefusesWhatItCannotDecide(t *testing.T) {
	for _, marker := range []string{
		`platform_release >= "5"`,
		`sys_platform < "m"`,
		`platform_machine ~= "x86"`,
		`python_version === "3.11"`,
		`python_version > "3.11a1"`,
		`python_full_version <= "3.11.2.dev1"`,
		`python_version == "1!3.11"`,
		`python_version ~= "3"`,
		`python_version in "3.10 x"`,
		`python_version in "3.11.2 3.11"`,
		`"3.11" in python_version`,
		`extra in "dev"`,
		`unknown_name == "x"`,
		`"a" == "b"`,
		`os_name == sys_platform`,
		`python_version <`,
		`python_version "3.11"`,
		`(python_version < "3.8"`,
		`python_version < "3.8")`,
		`python_version == "3.11" and`,
		`python_version == "3.11" python_version == "3.12"`,
		`python_version == "3.11`,
		`and`,
		``,
		`python_version < "3.8" or platform_release >= "5"`,
	} {
		if got, err := MarkerHolds(marker, host); err == nil {
			t.Errorf("MarkerHolds(%q) = %v, want an error", marker, got)
		}
	}
}

func TestMarkerHoldsNeedsAFullLinuxTarget(t *testing.T) {
	for _, p := range []Platform{
		{Python: "3.11", OS: "linux", CPU: "x86_64"},
		{Python: "3.11.2", OS: "darwin", CPU: "x86_64"},
		{Python: "3.11.2", OS: "linux", CPU: ""},
	} {
		if _, err := MarkerHolds(`os_name == "posix"`, p); err == nil {
			t.Errorf("MarkerHolds on %+v succeeded, want an error", p)
		}
	}
}
