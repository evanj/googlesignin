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
	validToken := signintest.InsecureToken(audience, issuer[0], email, "")
	r.Header.Set(jwtHeaderName, validToken)

	recorder = httptest.NewRecorder()
	authenticatedHandler.ServeHTTP(recorder, r)
	if recorder.Code != http.StatusOK {
		t.Error("expected OK:", recorder.Code)
	}
}

func TestBadAudience(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {}

	// call Required with empty string and catch the panic
	var recoveredPanic interface{}
	func() {
		defer func() {
			recoveredPanic = recover()
		}()
		Required("", http.HandlerFunc(handler))
	}()

	if _, isString := recoveredPanic.(string); !isString {
		t.Error("Required with empty audience should have paniced")
	}
}

func TestRequiredWithExceptions(t *testing.T) {
	handlerCalled := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}
	authenticatedHandler := RequiredWithExceptions(
		"audience", http.HandlerFunc(handler), []string{"/health", "/xyz/"})

	permittedPaths := []string{"/health", "/xyz/"}
	for i, path := range permittedPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		resp := httptest.NewRecorder()
		handlerCalled = false
		authenticatedHandler.ServeHTTP(resp, req)

		if resp.Code != http.StatusOK {
			t.Errorf("%d: path=%s should have status OK was %d", i, path, resp.Code)
		}
		if !handlerCalled {
			t.Errorf("%d: handler should have been called", i)
		}
	}

	forbiddenPaths := []string{"/", "/health/", "/health/x", "/healthy", "/healt", "/xyz", "/xyz/x"}
	for i, path := range forbiddenPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		resp := httptest.NewRecorder()
		handlerCalled = false
		authenticatedHandler.ServeHTTP(resp, req)

		if resp.Code != http.StatusForbidden {
			t.Errorf("%d: path=%s should have status Forbidden was %d", i, path, resp.Code)
		}
		if handlerCalled {
			t.Errorf("%d: handler should NOT have been called", i)
		}
	}

}
