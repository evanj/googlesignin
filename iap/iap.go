// Package iap provides HTTP middleware for Google Cloud's Identity-Aware Proxy.
// See https://cloud.google.com/iap/docs/concepts-overview
package iap

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/evanj/googlesignin/jwkkeys"
)

const jwtHeaderName = "x-goog-iap-jwt-assertion"
const jwkURL = "https://www.gstatic.com/iap/verify/public_key-jwk"

var issuer = []string{"https://cloud.google.com/iap"}

// From context.WithValue: To avoid allocating when assigning to an interface{}, context keys often
// have concrete type struct{}
type emailKey struct{}

type middleware struct {
	audience        string
	originalHandler http.Handler
	cachedKeys      jwkkeys.Set
	publicPaths     map[string]bool
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// allow public paths but without the email context
	// TODO: Unify the implementation with googlesignin?
	if m.publicPaths[r.URL.Path] {
		m.originalHandler.ServeHTTP(w, r)
		return
	}

	headerValue := r.Header.Get(jwtHeaderName)
	claims, err := jwkkeys.ValidateGoogleClaims(m.cachedKeys, headerValue, m.audience, issuer)
	if err != nil {
		log.Printf("ERROR: failed verifying JWT: %s", err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if claims.Email == "" {
		log.Println("ERROR: no email claim")
		http.Error(w, "forbidden", http.StatusForbidden)
	}

	ctxWithEmail := context.WithValue(r.Context(), emailKey{}, claims.Email)
	rWithCtx := r.WithContext(ctxWithEmail)
	m.originalHandler.ServeHTTP(w, rWithCtx)
}

func newMiddleware(audience string, handler http.Handler) *middleware {
	if audience == "" {
		// TODO: Return an error instead?
		panic("audience must not be empty: all requests will be forbidden")
	}
	return &middleware{audience, handler, jwkkeys.New(jwkURL), nil}
}

// Required ensures requests are authenticated with Google's Identity-Aware Proxy. It returns a
// handler that returns an HTTP 403 Forbidden error to any request that does not have a valid
// header, or if any error occurs while trying to validate the signed header. This function is
// sufficient for most services, but you need to use RequiredWithExceptions for Kubernetes.
//
// The audience must not be empty or Required will panic. For possible values for audience, see:
// https://cloud.google.com/iap/docs/signed-headers-howto#verify_the_jwt_payload
func Required(audience string, handler http.Handler) http.Handler {
	return newMiddleware(audience, handler)
}

// Email returns the email address of the user logged in via IAP, or panics. The request must have
// been served by the HTTP middleware returned by Required.
func Email(r *http.Request) string {
	return r.Context().Value(emailKey{}).(string)
}

// RequiredWithExceptions ensures requests are authenticated with Google's Identity-Aware Proxy,
// except for some paths which are public. The paths passed as exceptions will be public and not
// require authentication. Unlike the http package's mux, these paths are matched exactly.
//
// Most applications should use Required, but when using IAP with Kubernetes, you will need to
// make your service's health check public by passing the appropriate path as an exception
// (e.g. "/health").
func RequiredWithExceptions(audience string, handler http.Handler, exceptions []string) http.Handler {
	m := newMiddleware(audience, handler)

	m.publicPaths = make(map[string]bool)
	for _, exception := range exceptions {
		// TODO: return errors don't panic? Add tests
		if exception == "" || exception[0] != '/' {
			panic(fmt.Sprintf("exceptions must start with /: %#v", exception))
		}
		if m.publicPaths[exception] {
			panic(fmt.Sprintf("exceptions must be unique: %#v", exception))
		}
		m.publicPaths[exception] = true
	}
	return m
}
