package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// ItemState is where one item of the preparation stands.
type ItemState string

// States of an item.
const (
	ItemPreparing ItemState = "preparing"
	ItemReady     ItemState = "ready"
	ItemFailed    ItemState = "failed"
)

// Item is one thing an analysis needs, as the start prepares it.
type Item struct {
	Name string // "trivy", "trivy-db", "signing-key", "pnpm" or "uv"
	// Version is the pinned Trivy, the database's date, the public key's
	// sha256, or the pnpm or uv version.
	Version string
	State   ItemState
	Reason  string    // a failed item's cause
	NextTry time.Time // a failed item's next attempt
}

// Readiness is the state of every item, and whether all are ready.
type Readiness struct {
	Ready bool
	Items []Item
	// Warning reports a database refresh that failed while an older
	// database stays in use.
	Warning string
}

// DBUpdater downloads Trivy's vulnerability database; runner.Trivy is one.
type DBUpdater interface {
	UpdateDB(ctx context.Context) (string, error)
}

// causeLimit bounds a cause kept for the instance answer and the log.
const causeLimit = 300

// Preparer installs at start what an analysis needs: the pinned Trivy and
// its database, the default targets' pnpm and uv, and checks the signing
// key. A failed item keeps its cause and retries on its own.
type Preparer struct {
	// RetryEvery is the wait before a failed item's next attempt. Zero
	// means one minute. Set it before Run.
	RetryEvery time.Duration

	m         *Manager
	db        DBUpdater
	keySHA256 func() string
	pnpm, uv  string
	log       *slog.Logger

	mu      sync.Mutex
	items   []Item
	warning string
}

// NewPreparer returns a Preparer that installs through m, downloads the
// database through db, reads the public key's sha256 from keySHA256, and
// prepares the pnpm and uv versions given.
func NewPreparer(m *Manager, db DBUpdater, keySHA256 func() string, pnpm, uv string, log *slog.Logger) *Preparer {
	if log == nil {
		log = slog.Default()
	}
	return &Preparer{
		m: m, db: db, keySHA256: keySHA256, pnpm: pnpm, uv: uv, log: log,
		items: []Item{
			{Name: "trivy", Version: m.trivyPin().Version, State: ItemPreparing},
			{Name: "trivy-db", State: ItemPreparing},
			{Name: "signing-key", State: ItemPreparing},
			{Name: "pnpm", Version: pnpm, State: ItemPreparing},
			{Name: "uv", Version: uv, State: ItemPreparing},
		},
	}
}

// Run prepares every item: the key first, then Trivy and its database,
// pnpm and uv. The three start together, but each install holds
// Manager.mu for its whole download, so they take turns. It returns when
// ctx ends.
func (p *Preparer) Run(ctx context.Context) {
	if p.attempt(ctx, "signing-key", p.key) {
		var wg sync.WaitGroup
		wg.Go(func() {
			if p.attempt(ctx, "trivy", p.m.EnsureTrivy) {
				p.attempt(ctx, "trivy-db", p.database)
			}
		})
		wg.Go(func() {
			p.attempt(ctx, "pnpm", func(ctx context.Context) (string, error) {
				_, err := p.m.EnsurePnpm(ctx, p.pnpm)
				return p.pnpm, err
			})
		})
		wg.Go(func() {
			p.attempt(ctx, "uv", func(ctx context.Context) (string, error) {
				_, err := p.m.EnsureUv(ctx, p.uv)
				return p.uv, err
			})
		})
		wg.Wait()
	}
	<-ctx.Done()
}

// State returns a copy of every item. Safe for concurrent use.
func (p *Preparer) State() Readiness {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := Readiness{Ready: true, Items: append([]Item(nil), p.items...), Warning: p.warning}
	for _, it := range p.items {
		if it.State != ItemReady {
			r.Ready = false
		}
	}
	return r
}

// attempt runs step until it succeeds, waiting RetryEvery after each
// failure. It reports false when ctx ended first.
func (p *Preparer) attempt(ctx context.Context, name string, step func(context.Context) (string, error)) bool {
	every := p.RetryEvery
	if every <= 0 {
		every = time.Minute
	}
	for {
		version, err := step(ctx)
		if ctx.Err() != nil {
			return false
		}
		if err == nil {
			all := p.set(name, Item{Version: version, State: ItemReady})
			p.log.Info("prepared", "item", name, "version", version)
			if all {
				p.log.Info("instance ready")
			}
			return true
		}
		cause := p.clean(err.Error())
		next := time.Now().Add(every)
		p.set(name, Item{Version: p.version(name), State: ItemFailed, Reason: cause, NextTry: next})
		p.log.Warn("preparation failed, retrying", "item", name, "cause", cause, "next_try", next)
		timer := time.NewTimer(every)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

// set replaces the named item's state, and reports whether this change
// made every item ready.
func (p *Preparer) set(name string, it Item) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	all := true
	for i := range p.items {
		if p.items[i].Name == name {
			it.Name = name
			p.items[i] = it
		}
		all = all && p.items[i].State == ItemReady
	}
	return all && it.State == ItemReady
}

func (p *Preparer) version(name string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, it := range p.items {
		if it.Name == name {
			return it.Version
		}
	}
	return ""
}

func (p *Preparer) key(context.Context) (string, error) {
	if sum := p.keySHA256(); sum != "" {
		return sum, nil
	}
	return "", errors.New("no signing key on the data volume")
}

// database downloads the vulnerability database. A failed download leaves
// the instance ready only when an older database is on the volume.
func (p *Preparer) database(ctx context.Context) (string, error) {
	out, err := p.db.UpdateDB(ctx)
	date := p.m.trivyDBDate()
	if err != nil {
		cause := err.Error()
		if line := lastLine(out); line != "" {
			cause += ": " + line
		}
		if date.IsZero() || ctx.Err() != nil {
			return "", fmt.Errorf("vulnerability database download: %s", cause)
		}
		warning := p.clean(fmt.Sprintf("could not refresh the vulnerability database: %s; using the database from %s", cause, date.UTC().Format(time.DateOnly)))
		p.mu.Lock()
		p.warning = warning
		p.mu.Unlock()
		p.log.Warn("vulnerability database not refreshed", "cause", warning)
	} else if date.IsZero() {
		return "", errors.New("the vulnerability database download ended without a database on the data volume")
	}
	return date.UTC().Format(time.RFC3339), nil
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// clean makes a cause safe to show and log: control and format characters
// go, whitespace collapses, the GitHub token and the registry's credentials
// become "[redacted]", and the result is cut at causeLimit characters.
func (p *Preparer) clean(cause string) string {
	cause = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == utf8.RuneError:
			return -1
		}
		return r
	}, strings.ToValidUTF8(cause, ""))
	for _, secret := range p.secrets() {
		cause = strings.ReplaceAll(cause, secret, "[redacted]")
	}
	cause = strings.Join(strings.Fields(cause), " ")
	if utf8.RuneCountInString(cause) > causeLimit {
		cause = string([]rune(cause)[:causeLimit-3]) + "..."
	}
	return cause
}

// secrets lists the GitHub token and every form of the registry URL's
// credentials: the userinfo as written, as escaped and as decoded, whole and
// in parts, username included, since a token can stand alone as one. Longer
// values come first, so a value inside another never leaves part of it.
func (p *Preparer) secrets() []string {
	out := []string{p.m.GitHubToken}
	raw := p.m.NPMRegistry
	if i := strings.Index(raw, "//"); i >= 0 {
		raw = raw[i+2:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		info := raw[:i]
		user, pass, _ := strings.Cut(info, ":")
		out = append(out, info, user, pass)
	}
	if u, err := url.Parse(p.m.NPMRegistry); err == nil && u.User != nil {
		escaped := u.User.String()
		user, pass, _ := strings.Cut(escaped, ":")
		decoded, _ := u.User.Password()
		out = append(out, escaped, user, pass, u.User.Username(), decoded)
	}
	out = slices.DeleteFunc(out, func(s string) bool { return s == "" })
	slices.SortFunc(out, func(a, b string) int { return cmp.Or(len(b)-len(a), strings.Compare(a, b)) })
	return slices.Compact(out)
}
