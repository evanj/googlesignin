package main

import (
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/evanj/googlesignin"
)

const googleTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"

var rootTemplate = template.Must(template.New("root").Parse(`<!doctype html><html><head>
<title>Sign In With Google Example</title>
</head>
<body>
<h1>Sign In With Google Example</h1>
<p>This is an example of using Sign In With Google, via the <a href="https://github.com/evanj/googlesignin">github.com/evanj/googlesignin</a> library. This page is public, but the other pages require you to log in:</p>
<ul>
<li><a href="/page1">Page 1</a></li>
<li><a href="/page2">Page 2</a></li>
<li><a href="/tokeninfo">Show ID token info</a></li>
{{if .LoggedIn}}
<li><a href="{{.SignOutPath}}">Sign Out</a></li>
{{end}}
</ul>
</body></html>`))

type rootValues struct {
	LoggedIn    bool
	SignOutPath string
}

type pageValues struct {
	Email     string
	TokenInfo string
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html><html><head>
<title>Google Sign-In Page</title>
</head>
<body>
<h1>Google Sign-In Page</h1>
<p>Hello {{.Email}}!</p>
{{if .TokenInfo}}
<h2>tokeninfo</h2>
<pre>
{{.TokenInfo}}
</pre>
{{end}}
</body></html>`))

type server struct {
	authenticator *googlesignin.Authenticator
	handler       http.Handler
	tokenInfoURL  string
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		log.Printf("returning 404 (NotFound) for %s", r.URL.String())
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		log.Printf("returning 405 (MethodNotAllowed) for %s", r.URL.String())
		http.Error(w, "URL only supports GET", http.StatusMethodNotAllowed)
		return
	}

	values := rootValues{s.authenticator.IsSignedIn(r), s.authenticator.SignOutPath}
	err := rootTemplate.Execute(w, values)
	if err != nil {
		panic(err)
	}
}

func (s *server) handlePage(w http.ResponseWriter, r *http.Request) {
	values := &pageValues{s.authenticator.MustGetEmail(r), ""}
	err := pageTemplate.Execute(w, values)
	if err != nil {
		panic(err)
	}
}

func (s *server) idTokenPage(w http.ResponseWriter, r *http.Request) {
	validatedToken, err := s.authenticator.GetIDToken(r)
	if err != nil {
		panic(err)
	}
	params := url.Values{}
	params.Set("id_token", validatedToken.IDToken)
	resp, err := http.Get(s.tokenInfoURL + "?" + params.Encode())
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	err2 := resp.Body.Close()
	if err != nil {
		panic(err)
	}
	if err2 != nil {
		panic(err2)
	}
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("failed response code: %d; body: %s", resp.StatusCode, string(body)))
	}

	values := &pageValues{s.authenticator.MustGetEmail(r), string(body)}
	err = pageTemplate.Execute(w, values)
	if err != nil {
		panic(err)
	}
}

func newServer(clientID string) *server {
	authenticator := googlesignin.New(clientID)
	authenticator.RedirectIfNotSignedIn = true

	mux := http.NewServeMux()
	s := &server{authenticator, nil, googleTokenInfoURL}
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/page1", s.handlePage)
	mux.HandleFunc("/page2", s.handlePage)
	mux.HandleFunc("/tokeninfo", s.idTokenPage)

	s.handler = authenticator.RequireSignIn(mux)
	authenticator.MakePublic("/")
	// Returns 404, but that is better than redirecting
	authenticator.MakePublic("/favicon.ico")

	return s
}

type httpStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (h *httpStatusRecorder) WriteHeader(status int) {
	h.status = status
	h.ResponseWriter.WriteHeader(status)
}

func addLogMiddleware(handler http.Handler) http.Handler {
	logHandler := func(w http.ResponseWriter, r *http.Request) {
		wrappedWriter := &httpStatusRecorder{w, http.StatusOK}
		handler.ServeHTTP(wrappedWriter, r)
		log.Printf("%s %s: code %d", r.Method, r.URL.Path, wrappedWriter.status)
	}
	return http.HandlerFunc(logHandler)
}

func main() {
	insecureCookies := flag.Bool("insecureCookies", false,
		"Allow sending cookies over HTTP; use for localhost testing")
	verbose := flag.Bool("verbose", false,
		"Log all HTTP requests")
	flag.Parse()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	const clientIDEnvVar = "CLIENT_ID"
	clientID := os.Getenv(clientIDEnvVar)
	if clientID == "" {
		panic("must specify Google Client ID with environment variable " + clientIDEnvVar)
	}

	s := newServer(clientID)
	if *insecureCookies {
		s.authenticator.PermitInsecureCookies()
		log.Println("warning: permitting insecure HTTP cookies")
	}

	handler := s.handler
	if *verbose {
		handler = addLogMiddleware(handler)
		log.Println("enabling verbose logging")
	}
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
