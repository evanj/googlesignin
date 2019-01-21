// Tests of private package internals
package googlesignin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
	keys, err := cachedKeys.getKeySet()
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
	_, err = cachedKeys.getKeySet()
	if err != nil {
		t.Fatal(err)
	}
	if handledRequest {
		t.Error("response should have been cached")
	}

	// force expiry
	cachedKeys.expires = time.Now().Add(-time.Second)
	_, err = cachedKeys.getKeySet()
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

func TestClaimsJSON(t *testing.T) {
	// sanity check the json tags so we don't forget them
	extraClaims := &ExtraClaims{"domain", "email"}
	output, err := json.Marshal(extraClaims)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != `{"hd":"domain","email":"email"}` {
		t.Error(string(output))
	}
}
