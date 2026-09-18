package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteProblem(t *testing.T) {
	p := NewProblem(http.StatusNotFound, "project not found", "no project has id \"acme\"")

	rec := httptest.NewRecorder()
	WriteProblem(rec, p)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/problem+json")
	}

	var got Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got.Status != http.StatusNotFound {
		t.Fatalf("body status = %d, want %d", got.Status, http.StatusNotFound)
	}
	if got.Title != "project not found" {
		t.Fatalf("body title = %q, want %q", got.Title, "project not found")
	}
	if got.Detail == nil || *got.Detail != "no project has id \"acme\"" {
		t.Fatalf("body detail = %v, want a pointer to the detail string", got.Detail)
	}
	if got.Type == nil || *got.Type != "about:blank" {
		t.Fatalf("body type = %v, want a pointer to \"about:blank\"", got.Type)
	}
}
