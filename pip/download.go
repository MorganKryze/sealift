package pip

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// MaxWheelBytes bounds the size of one wheel a download accepts: 4 GiB.
const MaxWheelBytes = 4 << 30

// ErrDigest reports a downloaded file whose bytes do not match the sha256
// the index recorded for it.
var ErrDigest = errors.New("pip: the file does not match its recorded sha256")

var (
	// retryDelays are the waits before the second and third attempts.
	retryDelays = []time.Duration{time.Second, 4 * time.Second}
	// stallTimeout cancels a download that receives no byte for this long,
	// headers included.
	stallTimeout = 60 * time.Second
)

var errStalled = errors.New("stalled")

// permanent marks a download error another attempt cannot fix.
type permanent struct{ err error }

func (p permanent) Error() string { return p.err.Error() }
func (p permanent) Unwrap() error { return p.err }

// DownloadFile fetches f.URL to path+".part", checks the size and sha256 the
// index recorded, renames it to path and returns the hex sha512. It reads no
// index page. Network errors and 5xx get three attempts; ErrNotFound,
// ErrDigest and a size mismatch get none. Errors name f.Filename, never f.URL.
func (c *Client) DownloadFile(ctx context.Context, f IndexFile, path string) (string, error) {
	if err := checkDownload(f); err != nil {
		return "", err
	}
	hc := http.Client{}
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	// A redirect is held to the rule the recorded URL passed.
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return permanent{fmt.Errorf("pip: %s: more than 10 redirects", f.Filename)}
		}
		if why := urlRefusal(req.URL); why != "" {
			return permanent{fmt.Errorf("pip: %s redirects to a url that %s", f.Filename, why)}
		}
		return nil
	}

	for attempt := 0; ; attempt++ {
		sum, err := downloadOnce(ctx, &hc, f, path)
		if err == nil {
			return sum, nil
		}
		var p permanent
		if errors.As(err, &p) || ctx.Err() != nil || attempt >= len(retryDelays) {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("pip: download %s: %w", f.Filename, ctx.Err())
		case <-time.After(retryDelays[attempt]):
		}
	}
}

// checkDownload refuses a file that is not a wheel, a size or sha256 the
// index did not record, and a URL a download may not fetch. The name is
// checked first, so the other refusals quote a name of a known class.
func checkDownload(f IndexFile) error {
	if _, err := ParseWheelName(f.Filename); err != nil {
		return err
	}
	if f.Size <= 0 {
		return fmt.Errorf("pip: %s has no recorded size", f.Filename)
	}
	if f.Size > MaxWheelBytes {
		return fmt.Errorf("pip: %s is recorded at %d bytes, above the %d-byte bound", f.Filename, f.Size, MaxWheelBytes)
	}
	if !sha256RE.MatchString(f.Sha256) {
		return fmt.Errorf("pip: %s has no valid sha256", f.Filename)
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return fmt.Errorf("pip: %s has an unreadable url", f.Filename)
	}
	if why := urlRefusal(u); why != "" {
		return fmt.Errorf("pip: %s has a url that %s", f.Filename, why)
	}
	return nil
}

// urlRefusal says why a download may not fetch u, or returns "" when it
// may: https, or http on a loopback host only, with no user info. The
// reason completes a sentence that names the file.
func urlRefusal(u *url.URL) string {
	if u.User != nil {
		return "holds credentials"
	}
	switch u.Scheme {
	case "https":
		return ""
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return ""
		}
	}
	return "is not https, or http on a loopback host"
}

// downloadOnce makes one attempt. A watchdog cancels the request when no
// byte arrives for stallTimeout. The .part file goes on any failure.
func downloadOnce(ctx context.Context, hc *http.Client, f IndexFile, path string) (sum string, err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	watchdog := time.AfterFunc(stallTimeout, func() { cancel(errStalled) })
	defer watchdog.Stop()

	fail := func(err error) (string, error) {
		if errors.Is(context.Cause(ctx), errStalled) {
			return "", fmt.Errorf("pip: the download of %s stalled: no byte arrived for %s", f.Filename, stallTimeout)
		}
		// A url.Error quotes the URL, which may carry a token.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return "", fmt.Errorf("pip: download %s: %w", f.Filename, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return "", permanent{fmt.Errorf("pip: %s has an unreadable url", f.Filename)}
	}
	resp, err := hc.Do(req)
	if err != nil {
		var p permanent
		if errors.As(err, &p) {
			return "", p
		}
		return fail(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", permanent{fmt.Errorf("%w: %s", ErrNotFound, f.Filename)}
	case resp.StatusCode >= 500:
		return "", fmt.Errorf("pip: download %s: the server answered status %d", f.Filename, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return "", permanent{fmt.Errorf("pip: download %s: the server answered status %d", f.Filename, resp.StatusCode)}
	}
	watchdog.Reset(stallTimeout)

	part := path + ".part"
	out, err := os.Create(part)
	if err != nil {
		return "", permanent{fmt.Errorf("pip: download %s: %w", f.Filename, err)}
	}
	defer func() {
		if err != nil {
			_ = os.Remove(part)
		}
	}()
	h256, h512 := sha256.New(), sha512.New()
	body := io.LimitReader(&watchedReader{r: resp.Body, watchdog: watchdog}, f.Size+1)
	n, copyErr := io.Copy(io.MultiWriter(out, h256, h512), body)
	if closeErr := out.Close(); copyErr == nil && closeErr != nil {
		return "", permanent{fmt.Errorf("pip: download %s: %w", f.Filename, closeErr)}
	}
	switch {
	case copyErr != nil:
		return fail(copyErr)
	case n > f.Size:
		return "", permanent{fmt.Errorf("pip: %s has at least %d bytes, the index recorded %d", f.Filename, n, f.Size)}
	case n < f.Size:
		return "", permanent{fmt.Errorf("pip: %s has %d bytes, the index recorded %d", f.Filename, n, f.Size)}
	case hex.EncodeToString(h256.Sum(nil)) != f.Sha256:
		return "", permanent{fmt.Errorf("%w: %s", ErrDigest, f.Filename)}
	}
	if err := os.Rename(part, path); err != nil {
		return "", permanent{fmt.Errorf("pip: download %s: %w", f.Filename, err)}
	}
	return hex.EncodeToString(h512.Sum(nil)), nil
}

// watchedReader pushes the watchdog back each time bytes arrive.
type watchedReader struct {
	r        io.Reader
	watchdog *time.Timer
}

func (w *watchedReader) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if n > 0 {
		w.watchdog.Reset(stallTimeout)
	}
	return n, err
}
