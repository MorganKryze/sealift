package main

import (
	"testing"
	"time"
)

func TestNoNewPrivs(t *testing.T) {
	cases := map[string]bool{
		"Name:\tsealift\nNoNewPrivs:\t1\nSeccomp:\t2\n": true,
		"Name:\tsealift\nNoNewPrivs:\t0\nSeccomp:\t2\n": false,
		"Name:\tsealift\n": false, // a kernel without the field
	}
	for status, want := range cases {
		if got := noNewPrivs(status); got != want {
			t.Errorf("noNewPrivs(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestEphemeralConfig(t *testing.T) {
	cases := []struct {
		on, idle string
		want     time.Duration
		ok       bool
	}{
		{"", "", 0, true},
		{"0", "", 0, true},
		{"1", "", time.Hour, true},
		{"1", "15", 15 * time.Minute, true},
		{"0", "15", 0, true},
		{"yes", "", 0, false},
		{"1", "0", 0, false},
		{"1", "-5", 0, false},
		{"1", "1h", 0, false},
	}
	for _, c := range cases {
		got, err := ephemeralConfig(c.on, c.idle)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ephemeralConfig(%q, %q) = %v, %v; want %v, ok %v", c.on, c.idle, got, err, c.want, c.ok)
		}
	}
}
