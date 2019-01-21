package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evanj/googlesignin/signintest"
)

// A demonstration of how to test handlers using googlesignin.
func TestAuthenticatedRequest(t *testing.T) {
	s := newServer(signintest.ClientID)
	testAuth := signintest.InsecureTestAuthenticator(s.authenticator)

	r := httptest.NewRequest(http.MethodGet, "/page1", nil)
	testAuth.InsecureMakeAuthenticated(r, "user@example.com")
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Error("expected OK:", w.Code)
	}
	body, _ := ioutil.ReadAll(w.Result().Body)
	if !bytes.Contains(body, []byte("user@example.com")) {
		t.Error("Body does not contain user's email:", string(body))
	}
}
