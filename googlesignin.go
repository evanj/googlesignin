package googlesignin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/appengine"
	"google.golang.org/appengine/urlfetch"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const idTokenCookieName = "__id"
const accessTokenCookieName = "__access"
const minCacheSeconds = 60
const defaultSignInPath = "/__start_signin"
const defaultScopes = "openid email"
const defaultSecureCookie = "secure;"

// https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token
const googleJWKURL = "https://www.googleapis.com/oauth2/v3/certs"

// Issuer is the value of the issuer field (iss) in Google's OpenID tokens.
const Issuer = "accounts.google.com"

var maxAgePattern = regexp.MustCompile(`(?:,|^)\s*(?i:max-age)\s*=\s*([^\s,]+)`)

// ErrKeyNotFound is the error returned by KeySet.Get when the key ID is not found.
var ErrKeyNotFound = errors.New("key not found")

type contextKey int

const authenticatorKey = contextKey(1)

// Fetches and parses keys from sourceURL, caching them for as long as permitted.
type cachedKeySet struct {
	sourceURL string
	keys      *jose.JSONWebKeySet
	expires   time.Time
}

// Parses the max-age out of a Cache-Control header. Returns minCache if it cannot parse it, or
// if the value is blow the minimum.
// TODO: Use a real header parser that obeys all the various rules? E.g.
// https://github.com/pquerna/cachecontrol
//
// See the specifications:
// Cache-Control: https://tools.ietf.org/html/rfc7234#section-5.2
// ABNF syntax: https://tools.ietf.org/html/rfc7234#appendix-C
func parseMaxAge(cacheControl string) int {
	// parse with a regexp; quoted strings could confuse this but it seems unlikely
	matches := maxAgePattern.FindStringSubmatch(cacheControl)
	if len(matches) == 0 {
		return minCacheSeconds
	}
	if len(matches) != 2 {
		panic("logic bug: must have exactly 1 capturing group")
	}

	parsedSeconds, err := strconv.Atoi(matches[1])
	if err != nil {
		return minCacheSeconds
	}
	if parsedSeconds < minCacheSeconds {
		return minCacheSeconds
	}
	return parsedSeconds
}

func (c *cachedKeySet) Get(keyID string) (*jose.JSONWebKey, error) {
	set, err := c.getKeySet()
	if err != nil {
		return nil, err
	}

	keys := set.Key(keyID)
	if len(keys) > 0 {
		return &keys[0], nil
	}
	return nil, ErrKeyNotFound
}

// TODO: Remove! This isn't even guaranteed to work due to a race, but its good enough for now.
var legacyAppEngineHackClient = http.DefaultClient
var hackForLegacyAppEngine = func(r *http.Request) {}

// EnableLegacyAppEngineHack makes this barely work with go1.9. It replaces a module-level client
// with the App Engine urlfetch client. This has a horrible race condition and should not be used
// for critical applications. It only exists to make it easier to port an application to Go 1.11.
// TODO: Remove this.
func EnableLegacyAppEngineHack() {
	hackForLegacyAppEngine = func(r *http.Request) {
		ctx := appengine.NewContext(r)
		legacyAppEngineHackClient = urlfetch.Client(ctx)
	}
}

func (c *cachedKeySet) getKeySet() (*jose.JSONWebKeySet, error) {
	if c.keys != nil && time.Now().Before(c.expires) {
		return c.keys, nil
	}

	resp, err := legacyAppEngineHackClient.Get(c.sourceURL)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(resp.Body)
	keys := &jose.JSONWebKeySet{}
	err = decoder.Decode(keys)
	err2 := resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if err2 != nil {
		return nil, err2
	}

	cacheSeconds := parseMaxAge(resp.Header.Get("Cache-Control"))
	if cacheSeconds == minCacheSeconds {
		log.Printf("warning: caching for minimum time: Cache-Control: %#v",
			resp.Header.Get("Cache-Control"))
	}
	c.expires = time.Now().Add(time.Duration(cacheSeconds) * time.Second)
	c.keys = keys
	return c.keys, nil
}

// KeySet retrieves keys in JWK format to validate tokens.
type KeySet interface {
	// Get returns the key matching keyID, or an error indicating what happened. Must return
	// ErrKeyNotFound if the key does not exist.
	Get(keyID string) (*jose.JSONWebKey, error)
}

// Authenticator is an HTTP server middleware for requiring Google Sign-In.
type Authenticator struct {
	// Space-separated OAuth scopes to be appended. By default we request "openid email". See:
	// https://developers.google.com/identity/protocols/googlescopes
	ExtraScopes string
	// If set, the Google accounts must belong to this domain. See:
	// https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
	HostedDomain string
	// The path to the page used to start and complete Google Sign In. Defaults to /__start_signin.
	SignInPath string
	// If true, users will be redirected to log in if they are not. Otherwise they get a failed
	// response.
	RedirectIfNotSignedIn bool

	// Gets keys to validate tokens. Should not be changed except in tests.
	CachedKeys KeySet

	clientID           string
	signedInPath       string
	publicPaths        map[string]bool
	secureCookieOption string
}

// New creates an Authenticator, configured with the provided OAuth configuration. The
// middleware will serve the page to start the sign in publicly at signInPath. Once successful,
// it will redirect back to signedInPath.
func New(clientID string, signedInPath string) *Authenticator {
	return &Authenticator{
		defaultScopes, "", defaultSignInPath, false,
		&cachedKeySet{googleJWKURL, nil, time.Time{}},
		clientID, signedInPath,
		make(map[string]bool), defaultSecureCookie,
	}
}

// InsecureCookies configures the Authenticator to send cookies over HTTP connections. This should
// only be used for localhost testing. In other cases, you should only send the cookie over HTTPS
// since it contains sensitive user data.
func (a *Authenticator) InsecureCookies() {
	a.secureCookieOption = ""
}

// Renders the Google sign-in page, which will eventually set the ID token cookie and redirect
// the user to LoggedInPath.
func (a *Authenticator) startSignInPage(w http.ResponseWriter, r *http.Request) {
	data := &signInValues{a.clientID, a.signedInPath, idTokenCookieName, accessTokenCookieName,
		defaultScopes + " " + a.ExtraScopes, a.HostedDomain, a.secureCookieOption}
	buf := &bytes.Buffer{}
	err := signInTemplate.Execute(buf, data)
	if err != nil {
		log.Printf("rendering sign in page failed: %s", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	buf.WriteTo(w)
}

// ExtraClaims stores the JSON for Google Sign-In's extra claims that are not included in the
// basic OpenID claims.
type ExtraClaims struct {
	// https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
	HostedDomain string `json:"hd,omitempty"`
	Email        string `json:"email,omitempty"`
}

func findKey(keys KeySet, token *jwt.JSONWebToken) (*jose.JSONWebKey, error) {
	for _, header := range token.Headers {
		key, err := keys.Get(header.KeyID)
		if err == ErrKeyNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, ErrKeyNotFound
}

// GetEmail returns the email for a request. The error reports details that should not be returned
// to the client. However, it will not leak truly private data (e.g. the token).
func (a *Authenticator) GetEmail(r *http.Request) (string, error) {
	// Parse the ID token from the cookie
	cookie, err := r.Cookie(idTokenCookieName)
	if err == http.ErrNoCookie {
		return "", fmt.Errorf("no ID token cookie found")
	}
	if err != nil {
		return "", err
	}
	token, err := jwt.ParseSigned(cookie.Value)
	if err != nil {
		return "", err
	}

	// validate the token and get the claims
	key, err := findKey(a.CachedKeys, token)
	if err != nil {
		return "", err
	}
	standardClaims := &jwt.Claims{}
	extraClaims := &ExtraClaims{}
	err = token.Claims(key, standardClaims, extraClaims)
	if err != nil {
		return "", err
	}
	fmt.Println(standardClaims, extraClaims)
	err = standardClaims.Validate(jwt.Expected{
		Audience: jwt.Audience{a.clientID},
		Issuer:   Issuer,
		Time:     time.Now(),
	})
	if err != nil {
		return "", err
	}

	log.Println("claims", standardClaims, extraClaims)
	if a.HostedDomain != "" && a.HostedDomain != extraClaims.HostedDomain {
		return "", fmt.Errorf("hosted domain does not match %s != %s",
			a.HostedDomain, extraClaims.HostedDomain)
	}
	if extraClaims.Email == "" {
		return "", fmt.Errorf("invalid email: %s", extraClaims.Email)
	}

	return extraClaims.Email, nil
}

// GetAccessToken returns the access token for a request. The error reports details that should not
// be returned to the client. However, it will not leak truly private data (e.g. the token).
func (a *Authenticator) GetAccessToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(accessTokenCookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// MustGetEmail returns the authenticated user's email address, or panics if the user is not signed
// in. The request must have been served by RequiresSignIn.
func (a *Authenticator) MustGetEmail(r *http.Request) string {
	// Verify that this request passed through our middleware. This prevents errors where we
	// might try to use this in a code path that was not properly authenticated.
	if r.Context().Value(authenticatorKey) != authenticatorKey {
		panic("request was not handled by Authenticator.RequireSignIn.")
	}

	email, err := a.GetEmail(r)
	if err != nil {
		panic(err)
	}
	return email
}

// RequireSignIn wraps an existing http.Handler to require a user to be signed in. It will fail
// the request, or will redirect the user to sign in.
func (a *Authenticator) RequireSignIn(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.isPublic(r.URL.Path) {
			// public request: pass through
			handler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == a.SignInPath {
			// serve the sign in page
			a.startSignInPage(w, r)
			return
		}

		// requires authentication
		hackForLegacyAppEngine(r)
		_, err := a.GetEmail(r)
		if err != nil {
			log.Printf("%s: not authenticated: %s", r.URL.String(), err.Error())
			if r.Method == http.MethodGet && a.RedirectIfNotSignedIn {
				redirectPath := a.SignInPath + "#" + r.URL.Path
				if r.URL.RawQuery != "" {
					redirectPath += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, redirectPath, http.StatusSeeOther)
			} else {
				http.Error(w, "forbidden", http.StatusForbidden)
			}
			return
		}

		// correctly authenticated! Mark the request to prevent bugs
		ctxAuthenticated := context.WithValue(r.Context(), authenticatorKey, authenticatorKey)
		rWithContext := r.WithContext(ctxAuthenticated)
		handler.ServeHTTP(w, rWithContext)
	})
}

// InsecureMakeAuthenticated makes a new *http.Request that authenticated. It copies r and
// sets idToken and accessToken in the correct cookies, and marks the request as valid for
// MustGetEmail. This should only be called by tests.
func InsecureMakeAuthenticated(r *http.Request, idToken string, accessToken string) *http.Request {
	ctxAuthenticated := context.WithValue(r.Context(), authenticatorKey, authenticatorKey)
	rWithContext := r.WithContext(ctxAuthenticated)
	rWithContext.AddCookie(&http.Cookie{Name: idTokenCookieName, Value: idToken})
	rWithContext.AddCookie(&http.Cookie{Name: accessTokenCookieName, Value: accessToken})
	return rWithContext
}

// MakePublic makes path accessible without signing in. This does path matching, unlike ServeMux,
// so "/" only permits the root page, and "/dir/" only permits the exact path "/dir/". It is
// currently not possible to permit subdirectories or any kind of pattern.
func (a *Authenticator) MakePublic(path string) {
	a.publicPaths[path] = true
}

func (a *Authenticator) isPublic(path string) bool {
	return a.publicPaths[path]
}

type signInValues struct {
	ClientID              string
	LoggedInRedirect      string
	IDTokenCookieName     string
	AccessTokenCookieName string
	Scopes                string
	HostedDomain          string
	SecureCookieOption    string
}

var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html><html><head>
<title>Google Sign-In Redirecting ...</title>
<script src="https://apis.google.com/js/platform.js?onload=init" async defer></script>
<script>
function init() {
	gapi.load('auth2', function() {
		const sessionStorageKey = "__after_redirect";

		// Returns the path we should redirect BACK to, if we are authenticated, or the empty string.
		function getRedirect() {
			const hash = window.location.hash;
			if (hash[0] === "/") {
				return hash;
			}

			const sessionRedirect = sessionStorage.getItem(sessionStorageKey);
			if (sessionRedirect !== null && sessionRedirect[0] === "/") {
				sessionStorage.removeItem(sessionStorageKey);
				return sessionRedirect;
			}

			return "{{.LoggedInRedirect}}";
		}

		function saveRedirectFromHash() {
			const hash = window.location.hash;
			if (hash[0] === "/") {
				sessionStorage.setItem(sessionStorageKey, hash);
			}
		}

		function handleSignedIn(user) {
			const response = user.getAuthResponse();
			document.cookie = "{{.IDTokenCookieName}}=" + response.id_token +
				";path=/;samesite=lax;{{.SecureCookieOption}}max-age=" + response.expires_in;
			document.cookie = "{{.AccessTokenCookieName}}=" + response.access_token +
				";path=/;samesite=lax;{{.SecureCookieOption}}max-age=" + response.expires_in;
			window.location = getRedirect();
		}

		const initPromise = gapi.auth2.init({
			client_id: "{{.ClientID}}",
			scope: "{{.Scopes}}",
			fetch_basic_profile: false,
			hosted_domain: "{{.HostedDomain}}",
			ux_mode: "redirect",
		});

		initPromise.then(function(auth) {
			if (auth.isSignedIn.get()) {
				const user = auth.currentUser.get();
				handleSignedIn(user);
			} else {
				saveRedirectFromHash();

				const signInPromise = auth.signIn();
				signInPromise.then(function(user) {
					// We are using ux_mode:redirect; we should not get here but just in case:
					handleSignedIn(user);
				}).catch(function (e) {
					console.log("error", e);
				});
			}
		}).catch(function(e) {
			console.log("google auth error", e);
		});
	});
}
</script>
</head>
<body>
<p>Redirecting ...</p>
</body></html>
`))
