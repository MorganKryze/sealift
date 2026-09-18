// Package store keeps sealift's data volume: settings, projects, analyses and
// exports.
package store

// Target is the system an export gets prepared for, plus the toolchain
// versions the resolution pins.
type Target struct {
	OS      string // "linux"
	CPU     string // "x64"
	Libc    string // "glibc" or "musl"
	Node    string // "22.17.1"
	PnpmVer string // "10.34.5"
}

// Settings holds every value the interface can change.
type Settings struct {
	Target              Target
	SignatureKey        string
	MinReleaseAgeDays   int
	ResolveParallelism  int
	DownloadParallelism int
}

// State is the state of an analysis, an export or a queued job.
type State string

// States of a job and of the directory it writes.
const (
	Queued      State = "queued"
	Running     State = "running"
	Done        State = "done"
	Failed      State = "failed"
	Cancelled   State = "cancelled"
	Interrupted State = "interrupted"
)
