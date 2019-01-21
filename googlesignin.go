package googlesignin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const cookieName = "_bc_id"
const minCacheSeconds = 60
const defaultSignInPath = "/__start_signin"

// https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token
const googleJWKURL = "https://www.googleapis.com/oauth2/v3/certs"
const googleIssuer = "accounts.google.com"

var maxAgePattern = regexp.MustCompile(`(?:,|^)\s*(?i:max-age)\s*=\s*([^\s,]+)`)

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

func (c *cachedKeySet) Get() (*jose.JSONWebKeySet, error) {
	if c.keys != nil && time.Now().Before(c.expires) {
		return c.keys, nil
	}

	resp, err := http.Get(c.sourceURL)
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

// Authenticator is an HTTP server middleware for requiring Google Sign-In.
type Authenticator struct {
	// If set, the Google accounts must belong to this domain. See:
	// https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
	HostedDomain string
	// The path to the page used to start and complete Google Sign In. Defaults to /__start_signin.
	SignInPath string
	// If true, users will be redirected to log in if they are not. Otherwise they get a failed
	// response.
	RedirectIfNotSignedIn bool

	clientID     string
	clientSecret string
	signedInPath string
	googleKeySet cachedKeySet
	publicPaths  map[string]bool
}

// New creates a new Authenticator, configured with the provided OAuth configuration. The
// middleware will serve the page to start the sign in publicly at signInPath. Once successful,
// it will redirect back to signedInPath.
func New(clientID string, clientSecret string, signedInPath string) *Authenticator {
	return &Authenticator{
		"", defaultSignInPath, false,
		clientID, clientSecret, signedInPath,
		cachedKeySet{googleJWKURL, nil, time.Time{}},
		make(map[string]bool),
	}
}

// Renders the Google sign-in page, which will eventually set the ID token cookie and redirect
// the user to LoggedInPath.
func (a *Authenticator) StartSignInPage(w http.ResponseWriter, r *http.Request) {
	data := &signInValues{a.clientID, a.signedInPath, cookieName, a.HostedDomain}
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

type googleExtraClaims struct {
	// https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
	HostedDomain string `json:"hd,omitempty"`
	Email        string `json:"email,omitempty"`
}

func findKey(keySet *jose.JSONWebKeySet, token *jwt.JSONWebToken) *jose.JSONWebKey {
	for _, header := range token.Headers {
		keys := keySet.Key(header.KeyID)
		fmt.Println(header.KeyID, keys)
		if len(keys) > 0 {
			return &keys[0]
		}
	}
	return nil
}

// Returns the email for a given request, or an error describing what went wrong. The error
// messages report details about what went wrong, and should not be returned to the client.
// However, they will not leak truly private data (e.g. the token, client secret, etc).
func (a *Authenticator) GetEmail(r *http.Request) (string, error) {
	// Parse the ID token from the cookie
	cookie, err := r.Cookie(cookieName)
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
	keySet, err := a.googleKeySet.Get()
	if err != nil {
		return "", err
	}
	key := findKey(keySet, token)
	if key == nil {
		return "", fmt.Errorf("could not find key for token")
	}
	standardClaims := &jwt.Claims{}
	extraClaims := &googleExtraClaims{}
	err = token.Claims(key, standardClaims, extraClaims)
	if err != nil {
		return "", err
	}
	fmt.Println(standardClaims, extraClaims)
	err = standardClaims.Validate(jwt.Expected{
		Audience: jwt.Audience{a.clientID},
		Issuer:   googleIssuer,
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

// The request must have been served by RequiresLogin.
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

// Requires a user to have signed in, or fails the request with permission denied.
func (a *Authenticator) RequireSignIn(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.isPublic(r.URL.Path) {
			// public request: pass through
			handler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == a.SignInPath {
			// serve the sign in page
			a.StartSignInPage(w, r)
			return
		}

		// requires authentication
		_, err := a.GetEmail(r)
		if err != nil {
			log.Printf("not authenticated: %s", err.Error())
			if a.RedirectIfNotSignedIn {
				http.Redirect(w, r, a.SignInPath, http.StatusSeeOther)
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

// Makes path publicly accessible. This does exact path matching, unlike ServeMux, so "/" only
// permits the root page, and "/dir/" only permits the exact path "/dir/". It is currently not
// possible to permit subdirectories.
func (a *Authenticator) MakePublic(path string) {
	a.publicPaths[path] = true
}

func (a *Authenticator) isPublic(path string) bool {
	return a.publicPaths[path]
}

type signInValues struct {
	ClientID         string
	LoggedInRedirect string
	CookieName       string
	HostedDomain     string
}

var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html><html><head>
<title>Google Sign-In Redirecting ...</title>
<script src="https://apis.google.com/js/platform.js?onload=init" async defer></script>
<script>
function init() {
  gapi.load('auth2', function() {

    const initPromise = gapi.auth2.init({
      client_id: "{{.ClientID}}",
      scope: "email",
      fetch_basic_profile: false,
      hosted_domain: "{{.HostedDomain}}",
      ux_mode: "redirect",
    });

    initPromise.then(function(auth) {
      if (auth.isSignedIn.get()) {
        const user = auth.currentUser.get();
        const response = user.getAuthResponse();
        document.cookie = "{{.CookieName}}=" + response.id_token +
          ";path=/;samesite=lax;max-age=" + response.expires_in;
        window.location = "{{.LoggedInRedirect}}";
      } else {
        const signInPromise = auth.signIn();
        signInPromise.then(function(user) {
          console.log("signed in user:", user);
          // TODO: We are using redirect; we should not get here?
        }).catch(function (e){
          console.log("error", e);
        });
      }
    }).catch(function(e){
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
