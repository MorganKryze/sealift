package service

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/MorganKryze/sealift/internal/importer/token"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

// TokenHeader carries the access token the gateway forwards. No other header is read.
const TokenHeader = "X-Access-Token"

// MaxBodyBytes caps a request body at 64 KiB.
const MaxBodyBytes = 64 << 10

// userClaim names the claim that holds the user's name.
const userClaim = "preferred_username"

type userKey struct{}

// userFrom returns the user the middleware checked, or "" outside a checked request.
func userFrom(ctx context.Context) string {
	u, _ := ctx.Value(userKey{}).(string)
	return u
}

// limitBody refuses a body over MaxBodyBytes: at once when the request declares
// it, and while reading when it does not.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxBodyBytes {
			writeProblem(w, http.StatusRequestEntityTooLarge, "Request body too large",
				fmt.Sprintf("a request body may hold at most %d bytes", MaxBodyBytes))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// authenticate lets a request through only when its token passes Verify and
// its preferred_username can name a user folder. The user comes from the
// claim alone and is put in the request's context.
func (h *Handlers) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := h.verifier.Verify(r.Context(), r.Header.Get(TokenHeader))
		var rejected *token.Rejected
		var unavailable *token.Unavailable
		switch {
		case errors.As(err, &rejected):
			h.log.Info("refused a request", "check", rejected.Check)
			writeProblem(w, http.StatusUnauthorized, "Token rejected", rejected.Error())
			return
		case errors.As(err, &unavailable):
			h.log.Warn("the realm's keys are unavailable", "reason", unavailable.Reason)
			writeProblem(w, http.StatusServiceUnavailable, "Token cannot be checked", unavailable.Error())
			return
		case err != nil:
			// The error text is not logged: nothing guarantees a foreign error holds no token.
			h.log.Error("the token check failed unexpectedly")
			writeProblem(w, http.StatusInternalServerError, "Token check failed", "the token could not be checked")
			return
		}
		user, ok := claims.String(userClaim)
		if !ok || !imports.ValidUser(user) {
			h.log.Info("refused a request", "check", userClaim)
			writeProblem(w, http.StatusForbidden, "User refused",
				userClaim+" is absent or cannot name a user folder: lower case letters, digits, dots and hyphens, 1 to 58 characters")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
}

// refuseCrossSite stops a POST that another site could have caused: a foreign
// or null Origin, Sec-Fetch-Site cross-site, or a body that is not JSON. A
// client that sends no Origin and sends JSON passes, as curl must. It answers
// without repeating anything from the request.
func refuseCrossSite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		refuse := func(why string) {
			writeProblem(w, http.StatusForbidden, "Request refused", why)
		}
		if origin := r.Header.Get("Origin"); origin != "" && !sameHost(origin, r.Host) {
			refuse("the Origin of this request is not this service's own host")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			refuse("this request comes from another site")
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			refuse("the body must be application/json")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameHost reports whether an Origin names host, port included. "null" and
// anything that does not parse as scheme://host do not.
func sameHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.EqualFold(u.Host, host)
}
