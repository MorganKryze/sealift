package rank

import "testing"

func TestSameLine(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{"4.17.20", "4.17.21", true},
		{"4.17.20", "4.22.0", true},
		{"4.17.20", "5.0.0", false},
		{"0.18.0", "0.18.9", true},
		{"0.18.0", "0.19.0", false},
		{"0.18.0", "1.0.0", false},
		{"0.0.3", "0.0.3", true},
		{"0.0.3", "0.0.4", false},
		{"4.17.20", "4.18.0-beta.1", false},
		{"4.17.20", "4.17.19", false},
		{"4.17.20", "latest", false},
		{"latest", "4.17.20", false},
	} {
		if got := SameLine(tc.from, tc.to); got != tc.want {
			t.Errorf("SameLine(%s, %s) = %t, want %t", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestLineOf(t *testing.T) {
	for _, tc := range []struct{ version, want string }{
		{"4.17.20", "4"},
		{"1.0.0", "1"},
		{"0.18.3", "0.18"},
		{"0.0.3", "0.0.3"},
		{"latest", ""},
		{"4.17", ""},
	} {
		if got := LineOf(tc.version); got != tc.want {
			t.Errorf("LineOf(%s) = %q, want %q", tc.version, got, tc.want)
		}
	}
}
