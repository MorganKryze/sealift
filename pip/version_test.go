package pip

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Django", "django"},
		{"Mypy_Extensions", "mypy-extensions"},
		{"zope.interface", "zope-interface"},
		{"a--b__c..d", "a-b-c-d"},
		{"A-._B", "a-b"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := Normalize(tt.in); got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestValidName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"requests", true},
		{"Mypy_Extensions", true},
		{"a", true},
		{"zope.interface", true},
		{"a1-b2", true},
		{"", false},
		{"-a", false},
		{"a-", false},
		{".a", false},
		{"a_", false},
		{"a b", false},
		{"a/b", false},
		{"a[x]", false},
		{"a;b", false},
	}
	for _, tt := range tests {
		if got := ValidName(tt.in); got != tt.want {
			t.Errorf("ValidName(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestIsExactVersion(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"1.0", true},
		{"1", true},
		{"2024.1.2", true},
		{"1.0rc1", true},
		{"1.0.0rc1", true},
		{"1.0.post1", true},
		{"1.0.dev3", true},
		{"1!2.0", true},
		{"1.0a1.post2.dev3", true},
		{"1.*", false},
		{"1.0+local", false},
		{"v1", false},
		{"", false},
		{" 1.0", false},
		{"1.0 ", false},
		{"1..0", false},
		{"1.0,<2", false},
		{"${VERSION}", false},
	}
	for _, tt := range tests {
		if got := IsExactVersion(tt.in); got != tt.want {
			t.Errorf("IsExactVersion(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSameVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"1.0", "1.0.0", true},
		{"1.0rc1", "1.0.0rc1", true},
		{"1.0RC1", "1.0c1", true},
		{"1.01", "1.1", true},
		{"1.0-1", "1.0.post1", true},
		{"1.0.post1", "1.0", false},
		{"1.0", "1.1", false},
		{"1.0rc1", "1.0", false},
		{"1!1.0", "1.0", false},
		{"1.0.dev1", "1.0", false},
		{"1.*", "1.0", false},
		{"", "", false},
		{"1.0+x", "1.0+x", false},
	}
	for _, tt := range tests {
		if got := SameVersion(tt.a, tt.b); got != tt.want {
			t.Errorf("SameVersion(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
