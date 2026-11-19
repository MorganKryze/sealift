package api

import (
	"context"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/MorganKryze/sealift/internal/store"
)

// regeneratePath is the one route refuseCrossSite guards.
const regeneratePath = "/api/signing-key/regenerate"

// GetSigningKey returns the public half of the signing key.
func (h *Handlers) GetSigningKey(_ context.Context, _ GetSigningKeyRequestObject) (GetSigningKeyResponseObject, error) {
	return GetSigningKey200JSONResponse(signingKeyToAPI(h.Store.SigningKey())), nil
}

// RegenerateSigningKey replaces the signing key. The cause of a write failure
// is the error's own text, which names the file and never the key.
func (h *Handlers) RegenerateSigningKey(_ context.Context, _ RegenerateSigningKeyRequestObject) (RegenerateSigningKeyResponseObject, error) {
	key, err := h.Store.RegenerateSigningKey()
	if err != nil {
		return RegenerateSigningKey500ApplicationProblemPlusJSONResponse(NewProblem(http.StatusInternalServerError, "regenerate the signing key", err.Error())), nil
	}
	return RegenerateSigningKey200JSONResponse(signingKeyToAPI(key)), nil
}

func signingKeyToAPI(key store.SigningKey) SigningKey {
	return SigningKey{PublicKeyPem: key.PublicPEM, PublicKeySha256: key.PublicKeySHA256}
}

// allowedHosts lists the host names that may send a regenerate: the listen
// address's own host and the loopback names. A page on another site reaches
// this server under a name of its own (DNS rebinding), which is not in it.
func allowedHosts(listenAddr string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h := hostName(listenAddr); h != "" {
		hosts = append(hosts, h)
	}
	return hosts
}

// hostName returns the lowercase host of a host:port, a bare host or a
// bracketed IPv6 literal, without its port.
func hostName(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func hostAllowed(host string, allowed []string) bool {
	for _, a := range allowed {
		if host == a {
			return true
		}
	}
	return false
}

// refuseCrossSite stops a regenerate that another site could have caused. It
// checks the Host first (a rebinding page sends its own Origin and Host, so
// the Origin alone would match), then the Origin, then Sec-Fetch-Site, then
// the body's media type. A client that sends no Origin and sends JSON passes,
// as curl must. The log line names the check and repeats no header value.
// Every other request goes through untouched.
func refuseCrossSite(next http.Handler, allowed []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != regeneratePath {
			next.ServeHTTP(w, r)
			return
		}
		refuse := func(check, why string) {
			slog.WarnContext(r.Context(), "signing key regenerate refused", "check", check)
			WriteProblem(w, NewProblem(http.StatusForbidden, "Request refused", why))
		}
		if !hostAllowed(hostName(r.Host), allowed) {
			refuse("host", "this request is not addressed to this server's own host")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !originAllowed(origin, allowed) {
			refuse("origin", "the Origin of this request is not this server's own host")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			refuse("fetch-site", "this request comes from another site")
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			refuse("content-type", "the body must be application/json")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originAllowed reports whether an Origin names an allowed host. "null" and
// anything that does not parse as http or https with a host do not.
func originAllowed(origin string, allowed []string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return hostAllowed(hostName(u.Host), allowed)
}
