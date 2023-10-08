// Package googlesignin implements a Go API to sign in users with Google accounts. It attempts
// to use the most up to date "recommended" API from Google, since they seem to decide to change
// it every few years.
package googlesignin

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/evanj/googlesignin/jwkkeys"
)

const idTokenCookieName = "__gosignin_id"
const defaultSignInPath = "/__start_signin"
const defaultSignOutPath = "/__signout"
const defaultRedirect = "/"
const redirectCookieName = "__gosignin_location"
const redirectCookieExpiration = time.Hour
const htmlUTF8ContentType = "text/html;charset=utf-8"
const forwardedProtoHeader = "X-Forwarded-Proto"
const forwardedSchemeHeader = "X-Forwarded-Scheme"

// See: https://developers.google.com/identity/gsi/web/reference/html-reference#id-token-handler-endpoint
const idTokenFormKey = "credential"
const csrfFormKey = "g_csrf_token"

// context.WithValue recommends type struct{}. See:
// https://github.com/golang/go/issues/33742
type contextKey struct{}

var authenticatorKey = contextKey{}

// Authenticator is an HTTP server middleware for requiring Google Sign-In.
type Authenticator struct {
	// If set, the Google accounts must belong to this domain. See:
	// https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
	HostedDomain string
	// The path used to start and complete Google Sign In. Defaults to "/__start_signin".
	// Must start with /.
	SignInPath string
	// The path used to sign users out. Defaults to "/__signout". Must start with /.
	SignOutPath string
	// The path users will be redirected to after signing out, or when loading the sign in page
	// directly without a redirect (e.g. sometimes when hitting back). Defaults to "/".
	DefaultRedirect string
	// If true, users will be redirected to log in if they are not. Otherwise they get a failed
	// response.
	RedirectIfNotSignedIn bool

	// Gets keys to validate tokens. Should not be changed except in tests.
	CachedKeys jwkkeys.Set

	clientID        string
	publicPaths     map[string]bool
	insecureCookies bool
}

// New creates an Authenticator, configured with the provided OAuth configuration. The
// middleware will serve the page to start the sign in publicly at signInPath.
func New(clientID string) *Authenticator {
	return &Authenticator{"", defaultSignInPath, defaultSignOutPath, defaultRedirect, false,
		jwkkeys.NewGoogle(),
		clientID,
		make(map[string]bool), false,
	}
}

// PermitInsecureCookies configures the Authenticator to allow sending cookies over HTTP
// connections (not setting the Secure cookie option). This should only be used for localhost
// testing. In production, you should only send cookies over HTTPS since they contain sensitive
// user data.
func (a *Authenticator) PermitInsecureCookies() {
	a.insecureCookies = true
}

func getOriginalRequestURL(r *http.Request) *url.URL {
	originalURL := *r.URL
	originalURL.Host = r.Host
	// set the scheme with headers, if they exist
	if r.Header.Get(forwardedProtoHeader) != "" {
		originalURL.Scheme = r.Header.Get(forwardedProtoHeader)
	} else if r.Header.Get(forwardedSchemeHeader) != "" {
		originalURL.Scheme = r.Header.Get(forwardedSchemeHeader)
	} else if r.TLS != nil {
		originalURL.Scheme = "https"
	} else {
		// I'm not sure r.URL.Scheme is ever filled in, but try it in case
		originalURL.Scheme = r.URL.Scheme
		if originalURL.Scheme == "" {
			originalURL.Scheme = "http"
		}
	}
	return &originalURL
}

// Renders the Google sign-in page, which will eventually set the ID token cookie and redirect
// the user to LoggedInPath.
func (a *Authenticator) startSignInPage(w http.ResponseWriter, r *http.Request) {
	// fail sign in over HTTP unless explicitly permitted. This makes the error obvious, rather than
	// ending up in a redirect loop. We trust the X-Forwarded-Proto header, even though it could be
	// added by the original client rather than a proxy, because this is an attempt to prevent
	// configuration mistakes, not a security measure
	servedOverHTTPS := r.URL.Scheme == "https" || r.Header.Get(forwardedProtoHeader) == "https"
	if !servedOverHTTPS && !a.insecureCookies {
		log.Println("ERROR: refusing to serve sign in page over HTTP; Use PermitInsecureCookies() to allow")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		err := a.handleSignInPost(w, r)
		if err != nil {
			log.Printf("ERROR: handling sign-in post: %s", err.Error())
			w.Header().Set("Content-Type", htmlUTF8ContentType)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(failedLoginPage))
		}
		return
	} else if r.Method != http.MethodGet {
		http.Error(w, "only POST and GET HTTP methods are supported", http.StatusMethodNotAllowed)
		return
	}

	// make sign in URL absolute: The JS library warns if we do not
	relativeSignInURL, err := url.Parse(a.SignInPath)
	if err != nil {
		log.Printf("invalid sign in path: %s", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	requestURL := getOriginalRequestURL(r)
	absoluteSignInURL := requestURL.ResolveReference(relativeSignInURL)
	data := &signInValues{a.clientID, absoluteSignInURL.String()}
	buf := &bytes.Buffer{}
	err = signInTemplate.Execute(buf, data)
	if err != nil {
		log.Printf("rendering sign in page failed: %s", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", htmlUTF8ContentType)
	buf.WriteTo(w)
}

func (a *Authenticator) signOutPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "only the GET HTTP method is supported", http.StatusMethodNotAllowed)
		return
	}

	// delete any cookies that might be set
	// TODO: check for existence before deleting?
	http.SetCookie(w, &http.Cookie{Name: idTokenCookieName, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: redirectCookieName, MaxAge: -1})

	// check if the user is signed in
	validatedToken, err := a.GetIDToken(r)
	if err != nil {
		// not signed in: Just redirect
		log.Printf("warning: user was not signed in; redirecting: %s", err.Error())
		http.Redirect(w, r, a.DefaultRedirect, http.StatusSeeOther)
		return
	}

	buf := &bytes.Buffer{}
	data := signOutValues{a.clientID, validatedToken.StandardClaims.Subject, a.DefaultRedirect}
	err = signOutTemplate.Execute(buf, data)
	if err != nil {
		log.Printf("rendering sign out page failed: %s", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", htmlUTF8ContentType)
	buf.WriteTo(w)
}

func (a *Authenticator) handleSignInPost(w http.ResponseWriter, r *http.Request) error {
	// delete any redirect cookie even if there is an error
	http.SetCookie(w, &http.Cookie{Name: redirectCookieName, MaxAge: -1})

	csrfForm := r.PostFormValue(csrfFormKey)
	csrfCookie, err := r.Cookie(csrfFormKey)
	if err != nil {
		return fmt.Errorf("failed to get CSRF cookie name=%s: %w", csrfFormKey, err)
	}
	if csrfForm != csrfCookie.Value {
		return fmt.Errorf("csrf form=%#v did not match cookie=%#v", csrfForm, csrfCookie.Value)
	}

	idToken := r.PostFormValue(idTokenFormKey)
	validatedToken, err := a.validateIDToken(idToken)
	if err != nil {
		return fmt.Errorf("id token in form key=%s is not valid: %w", idTokenFormKey, err)
	}

	redirectPath := a.DefaultRedirect
	if redirectCookie, err := r.Cookie(redirectCookieName); err == nil {
		decoded, err := base64.RawURLEncoding.DecodeString(redirectCookie.Value)
		if err != nil {
			return err
		}
		redirectPath = string(decoded)
	} else {
		// this can happen if the user hits back, since we already deleted the location cookie
		log.Printf("warning: failed getting redirect cookie name=%s: %s; using default redirect", redirectCookieName, err)
	}
	parsedURL, err := url.Parse(redirectPath)
	if err != nil {
		return err
	}
	if parsedURL.IsAbs() || parsedURL.Host != "" {
		return fmt.Errorf("redirect url=%#v is absolute; must be relative", redirectPath)
	}

	// everything worked! Set the ID token in a cookie and redirect
	idTokenCookie := &http.Cookie{
		Name:     idTokenCookieName,
		Value:    idToken,
		Expires:  validatedToken.StandardClaims.Expiry.Time(),
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   !a.insecureCookies,
	}
	http.SetCookie(w, idTokenCookie)
	http.Redirect(w, r, redirectPath, http.StatusSeeOther)
	return nil
}

// validateIDToken returns the parsed token if it is valid.
func (a *Authenticator) validateIDToken(idToken string) (*jwkkeys.ValidatedGoogleToken, error) {
	validatedToken, err := jwkkeys.ValidateGoogleClaims(
		a.CachedKeys, idToken, a.clientID, jwkkeys.GoogleIssuers)
	if err != nil {
		return nil, err
	}

	// extra validation of the Google-specific claims
	if a.HostedDomain != "" && a.HostedDomain != validatedToken.GoogleClaims.HostedDomain {
		return nil, fmt.Errorf("hosted domain does not match: %#v != %#v",
			a.HostedDomain, validatedToken.GoogleClaims.HostedDomain)
	}
	if validatedToken.GoogleClaims.Email == "" {
		return nil, fmt.Errorf("invalid email: %s", validatedToken.GoogleClaims.Email)
	}
	return validatedToken, nil
}

// GetEmail returns the email for a request if it is signed in. This can be used on public pages.
// The error reports details that should not be returned to the client.
func (a *Authenticator) GetEmail(r *http.Request) (string, error) {
	// Parse the ID token from the cookie
	cookie, err := r.Cookie(idTokenCookieName)
	if err == http.ErrNoCookie {
		return "", fmt.Errorf("no ID token cookie found")
	}
	token, err := a.validateIDToken(cookie.Value)
	if err != nil {
		return "", err
	}

	return token.GoogleClaims.Email, nil
}

// GetIDToken returns the valid ID token for an authenticated request. This can be used on public
// pages. The error reports details that should not be returned to the client.
func (a *Authenticator) GetIDToken(r *http.Request) (*jwkkeys.ValidatedGoogleToken, error) {
	cookie, err := r.Cookie(idTokenCookieName)
	if err != nil {
		return nil, err
	}
	return a.validateIDToken(cookie.Value)
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

// IsSignedIn returns true if the user is signed in to an accepted Google account. This can be used
// on public pages, for example to conditionally display content.
func (a *Authenticator) IsSignedIn(r *http.Request) bool {
	_, err := a.GetEmail(r)
	return err == nil
}

// RequireSignIn wraps an existing http.Handler to require a user to be signed in. It will fail
// the request, or will redirect the user to sign in.
func (a *Authenticator) RequireSignIn(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Do a single hash lookup for all known URLs
		if r.URL.Path == a.SignInPath {
			a.startSignInPage(w, r)
			return
		}
		if r.URL.Path == a.SignOutPath {
			a.signOutPage(w, r)
			return
		}

		if a.isPublic(r.URL.Path) {
			// public request: pass through
			handler.ServeHTTP(w, r)
			return
		}

		// requires authentication
		_, err := a.GetEmail(r)
		if err != nil {
			log.Printf("%s: not authenticated: %s", r.URL.String(), err.Error())
			if r.Method == http.MethodGet && a.RedirectIfNotSignedIn {
				// TODO: Add test for query parameter redirects
				redirectPath := r.URL.Path
				if r.URL.RawQuery != "" {
					redirectPath += "?" + r.URL.RawQuery
				}

				// base64 encoded: Path could contain UTF-8 characters
				// TODO: Encrypt this cookie? Unclear to me if this matters, but it wouldn't hurt?
				redirectCookie := &http.Cookie{
					Name:     redirectCookieName,
					Value:    base64.RawURLEncoding.EncodeToString([]byte(redirectPath)),
					MaxAge:   int(redirectCookieExpiration.Seconds()),
					SameSite: http.SameSiteStrictMode,
					HttpOnly: true,
					Secure:   !a.insecureCookies,
				}
				http.SetCookie(w, redirectCookie)
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

// InsecureMakeAuthenticated makes a new *http.Request that is authenticated. It copies r and
// sets idToken and accessToken in the correct cookies, and marks the request as valid for
// MustGetEmail. This should only be called by tests.
func InsecureMakeAuthenticated(r *http.Request, idToken string) *http.Request {
	ctxAuthenticated := context.WithValue(r.Context(), authenticatorKey, authenticatorKey)
	rWithContext := r.WithContext(ctxAuthenticated)
	rWithContext.AddCookie(&http.Cookie{Name: idTokenCookieName, Value: idToken})
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
	SignInPostAbsoluteURL string
}

// The new sign in page *must* display the button that is clicked
var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html><html><head>
<title>Sign In With Google</title>
<script src="https://accounts.google.com/gsi/client" async></script>
</head>
<body>
<div id="g_id_onload"
	data-client_id="{{.ClientID}}"
	data-login_uri="{{.SignInPostAbsoluteURL}}"
	data-ux_mode="redirect"
	data-auto_prompt="false"
	data-auto_select="true">
</div>

<div class="g_id_signin" data-type="standard"></div>

</body></html>
`))

const failedLoginPage = `<!doctype html><html><head>
<title>Google Sign-In Failed</title>
</head>
<body>
<p>Failed to sign in with a Google account.</p>
</body></html>`

type signOutValues struct {
	ClientID     string
	UserID       string
	RedirectPath string
}

var signOutTemplate = template.Must(template.New("signout").Parse(`<!doctype html><html><head>
<title>Signing out ...</title>
<script src="https://accounts.google.com/gsi/client" async defer></script>
<script>
function revokedCallback(revocationResponse) {
	if (!!revocationResponse.error) {
		console.log("warning: revocation failed:", revocationResponse.error);
	}
	console.log("revoked?", revocationResponse);

	// redirect even if failed; use replace so this redirect does not appear when the user clicks back
	window.location.replace("{{.RedirectPath}}");
}

window.onload = function() {
	console.log("onload");
	google.accounts.id.initialize({client_id: "{{.ClientID}}"});
	google.accounts.id.revoke("{{.UserID}}", revokedCallback);
};
</script>
</head>
<body>
<p>Signing out ...</p>
</body></html>
`))
