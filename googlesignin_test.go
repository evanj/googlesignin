package googlesignin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"testing"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const insecureTestClientID = "clientid"
const insecureTestClientSecret = "clientsecret"
const insecureTestDomain = "example.com"
const testEmail = "user@" + insecureTestDomain

// generated with gopkg.in/square/go-jose.v2/jwk-keygen
const insecurePubKey = `{"use":"sig","kty":"EC","crv":"P-256","alg":"ES256","x":"-YdsjSFTEqKWQn7ZjThmkhuDDSasgh3ACWmgFKlo_7w","y":"LejdIY1pMKjXRlf3lStziDpQGPOynW49uF_Jlymcaxg"}`
const insecurePrivateKey = `{"use":"sig","kty":"EC","crv":"P-256","alg":"ES256","x":"-YdsjSFTEqKWQn7ZjThmkhuDDSasgh3ACWmgFKlo_7w","y":"LejdIY1pMKjXRlf3lStziDpQGPOynW49uF_Jlymcaxg","d":"xK_dS2q20mgRrYFVlwcJHOlNWmVxneJyzWFO-CGZ0BE"}`

type fixture struct {
	a          *Authenticator
	validToken string
}

func newFixture() *fixture {
	privateKey := loadJSONWebKey(insecurePrivateKey)
	publicKey := loadJSONWebKey(insecurePubKey)
	publicKey.KeyID = "xxxid"
	privateKey.KeyID = publicKey.KeyID

	f := &fixture{
		New(insecureTestClientID, insecureTestClientSecret, "/loggedin"),
		makeSignedToken(privateKey),
	}
	f.a.HostedDomain = insecureTestDomain

	// hack the cache to load the public key without an HTTP Request
	f.a.googleKeySet.keys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*publicKey}}
	f.a.googleKeySet.expires = time.Now().Add(time.Hour)
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
	privateKey := loadJSONWebKey(insecurePrivateKey)
	publicKey := loadJSONWebKey(insecurePubKey)
	publicKey.KeyID = "xxxid"
	privateKey.KeyID = publicKey.KeyID

	r.Header.Set("Cookie", cookieName+"="+f.validToken)
	email, err = f.a.GetEmail(r)
	if !(email == "user@example.com" && err == nil) {
		t.Error("expected success", email, err)
	}

	// sanity check the json tags
	extraClaims := &googleExtraClaims{"domain", "email"}
	output, err := json.Marshal(extraClaims)
	if string(output) != `{"hd":"domain","email":"email"}` {
		t.Error(string(output))
	}
}

func TestParseMaxAge(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", minCacheSeconds},
		{"max-age=123", 123},
		{"public, max-age = 12345, must-revalidate, no-transform", 12345},
		{"max-age=12345,public", 12345},
		{" MAX-AGE = 12345 ", 12345},
		{" MAX-age = 12345 technically invalid", 12345},

		{"invalid max-age=123", minCacheSeconds},
		{"invalid max-age=123", minCacheSeconds},
		{"max-age=123.567", minCacheSeconds},
		{"max-age=1", minCacheSeconds},
		{"max-age=abc", minCacheSeconds},
	}

	for i, test := range tests {
		output := parseMaxAge(test.input)
		if output != test.expected {
			t.Errorf("%d: parseMaxAge(%#v)=%#v; expected %#v", i, test.input, output, test.expected)
		}
	}
}

func TestCachedKeys(t *testing.T) {
	responseBody := "{}"
	handledRequest := false
	keyHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=12345, must-revalidate, no-transform")
		w.Write([]byte(responseBody))
		handledRequest = true
	}
	server := httptest.NewServer(http.HandlerFunc(keyHandler))
	defer server.Close()

	// Get an empty set of keys
	cachedKeys := &cachedKeySet{server.URL, nil, time.Time{}}
	keys, err := cachedKeys.Get()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 0 {
		t.Error(keys)
	}
	expiresDuration := cachedKeys.expires.Sub(time.Now())
	if expiresDuration < 12340*time.Second {
		t.Errorf("incorrect expires duration: %v ; expires %v", expiresDuration, cachedKeys.expires)
	}
	if !handledRequest {
		t.Error("must have handled the request")
	}

	handledRequest = false
	_, err = cachedKeys.Get()
	if err != nil {
		t.Fatal(err)
	}
	if handledRequest {
		t.Error("response should have been cached")
	}

	// force expiry
	cachedKeys.expires = time.Now().Add(-time.Second)
	_, err = cachedKeys.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !handledRequest {
		t.Error("response should have been refreshed")
	}
}

func TestMakePublic(t *testing.T) {
	a := New("clientid", "clientsecret", "/loggedin")
	a.MakePublic("/")
	a.MakePublic("/public")
	a.MakePublic("/publicdir/")

	publicPaths := []string{
		"/",
		"/public",
		"/publicdir/",
	}
	notPublicPaths := []string{
		"/x",
		"/publicx",
		"/public/",
		"/publicdir",
		"/publicdirx",
		"/publicdir/x",
	}
	for i, publicPath := range publicPaths {
		if !a.isPublic(publicPath) {
			t.Errorf("%d: isPublic(%#v) should be true", i, publicPath)
		}
	}
	for i, notPublicPath := range notPublicPaths {
		if a.isPublic(notPublicPath) {
			t.Errorf("%d: isPublic(%#v) should be false", i, notPublicPath)
		}
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
	r := httptest.NewRequest(http.MethodGet, "/hello", nil)
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusForbidden {
		t.Error("expected Forbidden:", recorder.Code)
	}
	if calledRequest != nil {
		t.Error("handler should not have been called:", calledRequest)
	}

	// enable redirects: should now be redirected
	f.a.RedirectIfNotSignedIn = true
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	location := recorder.Header().Get("Location")
	if calledRequest != nil || !(recorder.Code == http.StatusSeeOther && location == defaultSignInPath) {
		t.Error("expected redirect:", recorder.Code, location)
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
	r.URL.Path = defaultSignInPath
	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if calledRequest != nil || recorder.Code != http.StatusOK {
		t.Error("expected succesful request for sign in:", recorder.Code)
	}

	r.URL.Path = "/other"
	r.AddCookie(&http.Cookie{Name: cookieName, Value: f.validToken})
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

func loadJSONWebKey(json string) *jose.JSONWebKey {
	jwk := &jose.JSONWebKey{}
	err := jwk.UnmarshalJSON([]byte(json))
	if err != nil {
		panic(err)
	}
	if !jwk.Valid() {
		panic("invalid key")
	}
	return jwk
}

func makeSignedToken(jwk *jose.JSONWebKey) string {
	// from https://godoc.org/gopkg.in/square/go-jose.v2/jwt#Signed
	// this library embeds kid if signing with a private key
	signingKey := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk}
	sig, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	claims := jwt.Claims{
		Subject:   "subject",
		Issuer:    googleIssuer,
		NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Audience:  jwt.Audience{insecureTestClientID},
	}
	extraClaims := googleExtraClaims{
		Email:        testEmail,
		HostedDomain: insecureTestDomain,
	}

	raw, err := jwt.Signed(sig).Claims(claims).Claims(extraClaims).CompactSerialize()
	if err != nil {
		panic(err)
	}
	fmt.Println(raw)
	return raw
}
