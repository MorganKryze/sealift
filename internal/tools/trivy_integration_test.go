//go:build integration

package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestPinnedTrivyMatchesTheRelease downloads both pinned assets from the
// release on github.com and compares their sha256 with the pin, so a pin
// moved by hand cannot name bytes the release does not hold.
func TestPinnedTrivyMatchesTheRelease(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Minute}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			name, err := trivyAssetName(PinnedTrivy.Version, arch)
			if err != nil {
				t.Fatal(err)
			}
			url := fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/%s", PinnedTrivy.Version, name)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", url, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: %s", url, resp.Status)
			}
			h := sha256.New()
			if _, err := io.Copy(h, io.LimitReader(resp.Body, assetSizeLimit)); err != nil {
				t.Fatalf("read %s: %v", url, err)
			}
			if got, want := hex.EncodeToString(h.Sum(nil)), PinnedTrivy.SHA256[arch]; got != want {
				t.Errorf("%s: sha256 %s, pinned %s", name, got, want)
			}
		})
	}
}
