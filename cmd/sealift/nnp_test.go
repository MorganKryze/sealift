package main

import "testing"

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
