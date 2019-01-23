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
	clientAuth := signintest.InsecureTestAuthenticator(s.authenticator)

	r := httptest.NewRequest(http.MethodGet, "/page1", nil)
	clientAuth.InsecureMakeAuthenticated(r, "user@example.com")
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

func TestTokenInfo(t *testing.T) {
	// Configure a fake tokeninfo server
	accessTokenParam := ""
	const tokenInfoResponse = "token_info_response"
	tokenInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessTokenParam = r.URL.Query().Get("access_token")
		w.Write([]byte(tokenInfoResponse))
	}))
	defer tokenInfoServer.Close()
	s := newServer(signintest.ClientID)
	clientAuth := signintest.InsecureTestAuthenticator(s.authenticator)
	s.tokenInfoURL = tokenInfoServer.URL

	// request the page
	r := httptest.NewRequest(http.MethodGet, "/tokeninfo", nil)
	clientAuth.InsecureMakeAuthenticated(r, "user@example.com")
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Error("expected OK:", w.Code)
	}
	body, _ := ioutil.ReadAll(w.Result().Body)
	if !bytes.Contains(body, []byte(tokenInfoResponse)) {
		t.Error("Body does not contain tokeninfo response:", string(body))
	}
	if accessTokenParam != "fake_access_token" {
		t.Error("incorrect access token param:", accessTokenParam)
	}
}
