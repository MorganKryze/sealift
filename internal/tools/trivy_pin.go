package tools

// TrivyPin names the one Trivy release sealift runs and the sha256 of its
// Linux tarball for each host architecture.
type TrivyPin struct {
	Version string            // release number, without the "v"
	SHA256  map[string]string // GOARCH to the sha256 of trivy_<Version>_Linux-64bit.tar.gz or _Linux-ARM64.tar.gz
}

// PinnedTrivy is the Trivy release built into sealift. The digests are the
// only trust for the binary: a release published or replaced later, or a
// mirror behind SEALIFT_GITHUB_API, cannot change what gets installed.
// Moving the pin takes a reviewed commit, which the integration test
// TestPinnedTrivyMatchesTheRelease checks against the real assets.
var PinnedTrivy = TrivyPin{
	Version: "0.76.2",
	SHA256: map[string]string{
		"amd64": "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
		"arm64": "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3",
	},
}
