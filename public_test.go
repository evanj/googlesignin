// Tests of the public googlesignin API to avoid import cycles with signintest.
package googlesignin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/evanj/googlesignin"
	"github.com/evanj/googlesignin/signintest"

	"testing"
)

const insecureTestDomain = "example.com"
const testEmail = "user@" + insecureTestDomain

type fixture struct {
	a           *googlesignin.Authenticator
	requestAuth *signintest.RequestAuthenticator
}

func newFixture() *fixture {
	f := &fixture{
		googlesignin.New(signintest.ClientID, signintest.ClientSecret, "/loggedin"),
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

	// sanity check the json tags
	extraClaims := &googlesignin.ExtraClaims{"domain", "email"}
	output, err := json.Marshal(extraClaims)
	if string(output) != `{"hd":"domain","email":"email"}` {
		t.Error(string(output))
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
	if calledRequest != nil || !(recorder.Code == http.StatusSeeOther && location == "/__start_signin#/hello?param=1") {
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
	r.URL.Path = "/__start_signin"
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if calledRequest != nil || recorder.Code != http.StatusOK {
		t.Error("expected succesful request for sign in:", recorder.Code)
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
