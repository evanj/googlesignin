// Tests of the public googlesignin API to avoid import cycles with signintest.
package googlesignin_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evanj/googlesignin"
	"github.com/evanj/googlesignin/signintest"
)

const insecureTestDomain = "example.com"
const testEmail = "user@" + insecureTestDomain

type fixture struct {
	a           *googlesignin.Authenticator
	requestAuth *signintest.RequestAuthenticator
}

func newFixture() *fixture {
	f := &fixture{
		googlesignin.New(signintest.ClientID),
		nil,
	}
	f.a.HostedDomain = insecureTestDomain
	f.requestAuth = signintest.InsecureTestAuthenticator(f.a)
	return f
}

func TestGetEmail(t *testing.T) {
	f := newFixture()
	r := httptest.NewRequest(http.MethodGet, "/hello", nil)
	email, err := f.a.GetEmail(r)
	if !(email == "" && strings.Contains(err.Error(), "no ID token cookie")) {
		t.Error("GetEmail without cookie expected no ID token", email, err)
	}

	// Set a token: hack the key cache to avoid using google's keys
	r = f.requestAuth.InsecureMakeAuthenticated(r, testEmail)
	email, err = f.a.GetEmail(r)
	if !(email == "user@example.com" && err == nil) {
		t.Error("expected success", email, err)
	}
}

func TestAuthenticatedHandler(t *testing.T) {
	f := newFixture()

	var calledRequest *http.Request
	handler := func(w http.ResponseWriter, r *http.Request) {
		calledRequest = r
	}

	authenticatedHandler := f.a.RequireSignIn(http.HandlerFunc(handler))

	// request failed: not permitted
	recorder := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/hello?param=1", nil)
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusForbidden {
		t.Error("expected Forbidden:", recorder.Code)
	}
	if calledRequest != nil {
		t.Error("handler should not have been called:", calledRequest)
	}

	// enable redirects: GET should now be redirected; POST should fail
	f.a.RedirectIfNotSignedIn = true
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	location := recorder.Header().Get("Location")
	if calledRequest != nil || !(recorder.Code == http.StatusSeeOther && location == "/__start_signin") {
		t.Error("expected redirect:", recorder.Code, location)
	}
	postR := httptest.NewRequest(http.MethodPost, "/hello", nil)
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, postR)
	if calledRequest != nil || recorder.Code != http.StatusForbidden {
		t.Error("expected forbidden:", recorder.Code)
	}

	// make hello public: should be permitted
	f.a.MakePublic("/hello")
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if calledRequest == nil || recorder.Code != http.StatusOK {
		t.Error("expected succesful request:", recorder.Code)
	}
	calledRequest = nil

	// the sign in path must be public
	r.URL.Scheme = "https"
	r.URL.Path = "/__start_signin"
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if calledRequest != nil || recorder.Code != http.StatusOK {
		t.Error("expected succesful request for sign in:", recorder.Code)
	}
	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Error("body read failed:", err.Error())
	}
	if !bytes.Contains(body, []byte("https://accounts.google.com/gsi/client")) {
		t.Error("sign in page should load JS library", string(body))
	}

	r.URL.Path = "/other"
	r = f.requestAuth.InsecureMakeAuthenticated(r, "user@example.com")
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if calledRequest == nil || recorder.Code != http.StatusOK {
		t.Error("expected succesful request:", recorder.Code)
	}
	email := f.a.MustGetEmail(calledRequest)
	if email != testEmail {
		t.Errorf("MustGetEmail expected %#v got %#v", testEmail, email)
	}
}

func TestHTTPSSignIn(t *testing.T) {
	f := newFixture()
	handler := func(w http.ResponseWriter, r *http.Request) {}
	authenticatedHandler := f.a.RequireSignIn(http.HandlerFunc(handler))

	// HTTPS request: works
	recorder := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/__start_signin", nil)
	r.URL.Scheme = "https"
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusOK {
		t.Error("expected OK:", recorder.Code)
	}

	// HTTP request: fails
	recorder = httptest.NewRecorder()
	r.URL.Scheme = "http"
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusInternalServerError {
		t.Error("expected InternalServerError:", recorder.Code)
	}

	// HTTP with X-Forwarded-Proto: success
	recorder = httptest.NewRecorder()
	r.URL.Scheme = "http"
	r.Header.Set("X-Forwarded-Proto", "https")
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusOK {
		t.Error("expected OK:", recorder.Code)
	}
	r.Header.Del("X-Forwarded-Proto")

	// HTTP request with insecure set: works
	f.a.PermitInsecureCookies()
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusOK {
		t.Error("expected OK:", recorder.Code)
	}
}
