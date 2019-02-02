// Package iap provides HTTP middleware for Google Cloud's Identity-Aware Proxy.
// See https://cloud.google.com/iap/docs/concepts-overview
package iap

import (
	"context"
	"log"
	"net/http"

	"github.com/evanj/googlesignin/jwkkeys"
)

const jwtHeaderName = "x-goog-iap-jwt-assertion"
const jwkURL = "https://www.gstatic.com/iap/verify/public_key-jwk"
const Issuer = "https://cloud.google.com/iap"

type contextKey int

const emailKey = contextKey(1)

type middleware struct {
	audience        string
	originalHandler http.Handler
	cachedKeys      jwkkeys.Set
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headerValue := r.Header.Get(jwtHeaderName)
	claims, err := jwkkeys.ValidateGoogleClaims(m.cachedKeys, headerValue, m.audience, Issuer)
	if err != nil {
		log.Printf("ERROR: failed verifying JWT: %s", err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if claims.Email == "" {
		log.Println("ERROR: no email claim")
		http.Error(w, "forbidden", http.StatusForbidden)
	}

	ctxWithEmail := context.WithValue(r.Context(), emailKey, claims.Email)
	rWithCtx := r.WithContext(ctxWithEmail)
	m.originalHandler.ServeHTTP(w, rWithCtx)
}

// Required returns an http.Handler which ensures requests came from Google's Identity-Aware Proxy.
// The handler will return an HTTP 403 Forbidden error to any request that does not have a valid
// header, or if any error occurs while trying to validate the signed header.
//
// To see the possible values for audience, see:
// https://cloud.google.com/iap/docs/signed-headers-howto#verify_the_jwt_payload
func Required(audience string, handler http.Handler) http.Handler {
	h := &middleware{audience, handler, jwkkeys.New(jwkURL)}
	return h
}

// Email returns the email address of the user logged in via IAP, or panics. The request must have
// been served by the HTTP middleware returned by Required.
func Email(r *http.Request) string {
	return r.Context().Value(emailKey).(string)
}
