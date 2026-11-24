package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
)

func getInstance(t *testing.T, url string) Instance {
	t.Helper()
	resp, err := http.Get(url + "/api/instance")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/instance: %d", resp.StatusCode)
	}
	var in Instance
	if err := json.NewDecoder(resp.Body).Decode(&in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestInstance(t *testing.T) {
	srv, h := newTestServer(t)
	if in := getInstance(t, srv.URL); in.Ephemeral || in.IdleMinutes != nil {
		t.Errorf("default instance = %+v, want not ephemeral and no idle delay", in)
	}
	h.Ephemeral = 45 * time.Minute
	if in := getInstance(t, srv.URL); !in.Ephemeral || in.IdleMinutes == nil || *in.IdleMinutes != 45 {
		t.Errorf("ephemeral instance = %+v, want ephemeral with 45 minutes", in)
	}
}

func deleteProject(t *testing.T, url, id string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url+"/api/projects/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// In ephemeral mode, deleting the last project also empties the caches
// that recorded what it fetched; outside it, the caches stay.
func TestDeleteProjectPurgesCachesWhenEphemeral(t *testing.T) {
	for _, ephemeral := range []bool{false, true} {
		srv, h := newTestServer(t)
		if ephemeral {
			h.Ephemeral = time.Hour
		}
		cached := filepath.Join(h.Store.Root(), "cache", "tarballs", "x.tgz")
		if err := os.MkdirAll(filepath.Dir(cached), 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cached, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Created through the store: the API would also queue an analysis,
		// and a job in flight keeps the caches.
		p, err := h.Store.CreateProject("demo", []byte(`{"name":"demo"}`))
		if err != nil {
			t.Fatal(err)
		}
		if code := deleteProject(t, srv.URL, p.ID); code != http.StatusNoContent {
			t.Fatalf("ephemeral %v: DELETE = %d, want 204", ephemeral, code)
		}
		_, err = os.Stat(cached)
		if ephemeral && !os.IsNotExist(err) {
			t.Errorf("ephemeral: the tarball cache survived the delete")
		}
		if !ephemeral && err != nil {
			t.Errorf("not ephemeral: the tarball cache is gone: %v", err)
		}
	}
}

// A job of another project in flight keeps the caches through a delete: the
// purge waits for the sweep.
func TestDeleteProjectKeepsCachesWhileAnotherJobRuns(t *testing.T) {
	srv, h := newTestServer(t)
	h.Ephemeral = time.Hour
	cached := filepath.Join(h.Store.Root(), "cache", "tarballs", "x.tgz")
	if err := os.MkdirAll(filepath.Dir(cached), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := h.Store.CreateProject("other", []byte(`{"name":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(other.Dir, "analyses", "20261119T120000Z.tmp"), 0o770); err != nil {
		t.Fatal(err)
	}
	p, err := h.Store.CreateProject("demo", []byte(`{"name":"demo"}`))
	if err != nil {
		t.Fatal(err)
	}
	if code := deleteProject(t, srv.URL, p.ID); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", code)
	}
	if _, err := os.Stat(cached); err != nil {
		t.Errorf("the caches went while another project's job ran: %v", err)
	}
}

func TestEphemeralAnswersAreNotStored(t *testing.T) {
	_, h := newTestServer(t)
	for _, ephemeral := range []bool{false, true} {
		h.Ephemeral = 0
		if ephemeral {
			h.Ephemeral = time.Hour
		}
		// Routes reads the mode when it builds the handler.
		s := httptest.NewServer(Routes(h, testStatic()))
		resp, err := http.Get(s.URL + "/api/instance")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		s.Close()
		got := resp.Header.Get("Cache-Control")
		if ephemeral && got != "no-store" || !ephemeral && got == "no-store" {
			t.Errorf("ephemeral %v: Cache-Control = %q", ephemeral, got)
		}
	}
}

func TestInstanceListsEachPreparingItem(t *testing.T) {
	srv, h := newTestServer(t)
	next := time.Date(2026, 11, 24, 9, 31, 0, 0, time.UTC)
	h.Ready = fixedReadiness{Items: []tools.Item{
		{Name: "trivy", Version: "0.55.0", State: tools.ItemReady},
		{Name: "trivy-db", State: tools.ItemFailed, Reason: "vulnerability database download: connection reset by peer", NextTry: next},
		{Name: "signing-key", Version: "3f9a", State: tools.ItemReady},
		{Name: "pnpm", Version: "10.34.5", State: tools.ItemReady},
		{Name: "uv", Version: "0.13.7", State: tools.ItemPreparing},
	}}
	in := getInstance(t, srv.URL)
	if in.Ready {
		t.Error("ready = true while two items are not ready")
	}
	if in.Warning != nil {
		t.Errorf("warning = %q, want none", *in.Warning)
	}
	reason := "vulnerability database download: connection reset by peer"
	trivy, key, pnpm, uv := "0.55.0", "3f9a", "10.34.5", "0.13.7"
	want := []PreparingItem{
		{Name: PreparingItemNameTrivy, Version: &trivy, State: ItemReady},
		{Name: PreparingItemNameTrivyDb, State: ItemFailed, Reason: &reason, NextTry: &next},
		{Name: PreparingItemNameSigningKey, Version: &key, State: ItemReady},
		{Name: PreparingItemNamePnpm, Version: &pnpm, State: ItemReady},
		{Name: PreparingItemNameUv, Version: &uv, State: ItemPreparing},
	}
	if !reflect.DeepEqual(in.Preparing, want) {
		got, _ := json.Marshal(in.Preparing)
		t.Errorf("preparing = %s", got)
	}
}

func TestInstanceIsReadyWithTheRefreshWarning(t *testing.T) {
	srv, h := newTestServer(t)
	warning := "could not refresh the vulnerability database: timeout; using the database from 2026-11-20"
	h.Ready = fixedReadiness{Ready: true, Warning: warning, Items: []tools.Item{
		{Name: "trivy", Version: "0.55.0", State: tools.ItemReady},
	}}
	in := getInstance(t, srv.URL)
	if !in.Ready || in.Warning == nil || *in.Warning != warning {
		t.Errorf("ready = %v, warning = %v, want ready with %q", in.Ready, in.Warning, warning)
	}
}

func TestInstanceReportsTheBrand(t *testing.T) {
	srv, h := newTestServer(t)
	h.Policy.Brand = policy.Brand{
		Name: "Harbor", Accent: "#0b6e99", Online: "Outside", Offline: "Inside", ReviewWord: "MR",
		Logo: []byte("\x89PNG\r\n\x1a\n"), LogoType: "image/png",
		Contact: &policy.Contact{Label: "Platform team", URL: "mailto:platform@example.org"},
	}
	got := getInstance(t, srv.URL).Brand
	accent := "#0b6e99"
	want := Brand{
		Name: "Harbor", Accent: &accent, Online: "Outside", Offline: "Inside", ReviewWord: "MR", Logo: true,
		Contact: &Contact{Label: "Platform team", Url: "mailto:platform@example.org"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("brand = %+v, want %+v", got, want)
	}
}

func TestInstanceReportsTheBrandDefaults(t *testing.T) {
	srv, _ := newTestServer(t)
	got := getInstance(t, srv.URL).Brand
	want := Brand{Name: "sealift", Online: "Online", Offline: "Offline", ReviewWord: "PR"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("brand = %+v, want %+v", got, want)
	}
}

func TestInstanceReportsThePolicy(t *testing.T) {
	srv, h := newTestServer(t)
	npmTarget := store.Target{OS: "linux", CPU: "arm64", Libc: "musl", Node: "20.18.0", PnpmVer: "9.15.0"}
	pipTarget := store.PipTarget{Python: "3.12.4", OS: "linux", CPU: "x86_64", Glibc: "2.31", UvVer: "0.13.7"}
	h.Policy.Settings = store.Settings{Target: npmTarget, MinReleaseAgeDays: 30, ResolveParallelism: 2, DownloadParallelism: 5}
	h.Policy.Pip = pipTarget
	got := getInstance(t, srv.URL).Policy
	want := Policy{
		Target: targetToAPI(npmTarget), PipTarget: pipTargetToAPI(pipTarget),
		MinReleaseAgeDays: 30, ResolveParallelism: 2, DownloadParallelism: 5,
		Review: ReviewPolicy{ProposeOtherMajors: false, MajorJump: RuleReason, CveWithoutFix: RuleReason},
	}
	if got != want {
		t.Errorf("policy = %+v, want %+v", got, want)
	}
}

func TestInstanceReportsTheReviewPolicy(t *testing.T) {
	for _, c := range []struct {
		review policy.Review
		want   ReviewPolicy
	}{
		{policy.Review{ProposeOtherMajors: true, MajorJump: policy.Refuse, CVEWithoutFix: policy.AskReason}, ReviewPolicy{ProposeOtherMajors: true, MajorJump: RuleRefuse, CveWithoutFix: RuleReason}},
		{policy.Review{MajorJump: policy.AskReason, CVEWithoutFix: policy.Refuse}, ReviewPolicy{MajorJump: RuleReason, CveWithoutFix: RuleRefuse}},
	} {
		srv, h := newTestServer(t)
		h.Policy.Review = c.review
		if got := getInstance(t, srv.URL).Policy.Review; got != c.want {
			t.Errorf("review for %+v = %+v, want %+v", c.review, got, c.want)
		}
	}
}

func TestInstanceReportsToolVersions(t *testing.T) {
	srv, h := newTestServer(t)
	for _, dir := range []string{"tools/pnpm/10.34.5", "tools/pnpm/9.15.0", "tools/uv/0.13.7"} {
		if err := os.MkdirAll(filepath.Join(h.Store.Root(), dir), 0o770); err != nil {
			t.Fatal(err)
		}
	}
	got := getInstance(t, srv.URL).Tools
	date := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	want := InstanceTools{Trivy: tools.PinnedTrivy.Version, TrivyDbDate: &date, Pnpm: []string{"10.34.5", "9.15.0"}, Uv: []string{"0.13.7"}}
	if got.TrivyDbDate == nil || !got.TrivyDbDate.Equal(date) {
		t.Errorf("trivyDbDate = %v, want %v", got.TrivyDbDate, date)
	}
	got.TrivyDbDate = want.TrivyDbDate
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tools = %+v, want %+v", got, want)
	}
}

func TestInstanceReportsNoToolsOnAnEmptyVolume(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	h := NewHandlers(st, nil, tm)
	srv := httptest.NewServer(Routes(h, testStatic()))
	t.Cleanup(srv.Close)
	got := getInstance(t, srv.URL).Tools
	want := InstanceTools{Trivy: tools.PinnedTrivy.Version, Pnpm: []string{}, Uv: []string{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tools = %+v, want %+v", got, want)
	}
}

func getLogo(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url + "/api/instance/logo")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestInstanceLogoCarriesTheSandboxHeaders(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	png := []byte("\x89PNG\r\n\x1a\nrest")
	for _, logo := range []struct {
		data []byte
		kind string
	}{{svg, "image/svg+xml"}, {png, "image/png"}} {
		srv, h := newTestServer(t)
		h.Policy.Brand.Logo, h.Policy.Brand.LogoType = logo.data, logo.kind
		resp, body := getLogo(t, srv.URL)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", logo.kind, resp.StatusCode)
		}
		for name, want := range map[string]string{
			"Content-Type":            logo.kind,
			"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
			"X-Content-Type-Options":  "nosniff",
		} {
			if got := resp.Header.Get(name); got != want {
				t.Errorf("%s: %s = %q, want %q", logo.kind, name, got, want)
			}
		}
		if !bytes.Equal(body, logo.data) {
			t.Errorf("%s: body = %q, want the bytes read at start", logo.kind, body)
		}
	}
}

func TestInstanceLogoIs404WithoutALogo(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, body := getLogo(t, srv.URL)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", got)
	}
	var p Problem
	if err := json.Unmarshal(body, &p); err != nil || p.Status != http.StatusNotFound {
		t.Errorf("problem = %s (%v), want a 404 problem", body, err)
	}
}

func TestInstanceKeepsAnsweringWhenAToolFolderCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a folder whatever its mode")
	}
	srv, h := newTestServer(t)
	h.Ephemeral = 30 * time.Minute
	h.Ready = fixedReadiness{Items: []tools.Item{{Name: "uv", Version: "0.13.7", State: tools.ItemPreparing}}}
	for _, dir := range []string{"tools/pnpm/10.34.5", "tools/uv/0.13.7", "tools/trivy/0.55.0"} {
		if err := os.MkdirAll(filepath.Join(h.Store.Root(), dir), 0o770); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"tools/pnpm", "tools/trivy"} {
		locked := filepath.Join(h.Store.Root(), dir)
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o770) })
	}

	in := getInstance(t, srv.URL)
	if !in.Ephemeral || in.IdleMinutes == nil || *in.IdleMinutes != 30 {
		t.Errorf("ephemeral = %v, idleMinutes = %v, want true and 30", in.Ephemeral, in.IdleMinutes)
	}
	if len(in.Preparing) != 1 || in.Preparing[0].Name != PreparingItemNameUv {
		t.Errorf("preparing = %+v, want the uv item", in.Preparing)
	}
	want := InstanceTools{Trivy: tools.PinnedTrivy.Version, Pnpm: []string{}, Uv: []string{"0.13.7"}}
	got := in.Tools
	got.TrivyDbDate = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tools = %+v, want %+v", got, want)
	}
}
