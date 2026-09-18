package jobs

import (
	"testing"
	"time"
)

// TestDBDateLabel checks the message stepPrepareTools' database warning
// shows: a formatted date when one is known, "an unknown date" otherwise.
func TestDBDateLabel(t *testing.T) {
	if got := dbDateLabel(time.Time{}); got != "an unknown date" {
		t.Errorf("dbDateLabel(zero) = %q, want %q", got, "an unknown date")
	}
	known := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if got := dbDateLabel(known); got != "2026-09-01" {
		t.Errorf("dbDateLabel(%v) = %q, want %q", known, got, "2026-09-01")
	}
}
