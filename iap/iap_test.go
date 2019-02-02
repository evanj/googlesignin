package iap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evanj/googlesignin/signintest"
)

func TestNoHeader(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {}
	const audience = "some_audience"
	authenticatedHandler := Required(audience, http.HandlerFunc(handler))
	authenticatedHandler.(*middleware).cachedKeys = signintest.InsecureKeys()

	// No header: fails
	recorder := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusForbidden {
		t.Error("expected Forbidden:", recorder.Code)
	}

	// TODO: Add fake header: it should work
	const email = "u@example.com"
	validToken := signintest.InsecureToken(audience, issuer, email, "")
	r.Header.Set(jwtHeaderName, validToken)

	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusOK {
		t.Error("expected OK:", recorder.Code)
	}
}
