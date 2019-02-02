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

const rootHTML = `<!doctype html><html><head>
<title>Google Sign-In Example</title>
</head>
<body>
<h1>Google Sign-In Example</h1>
<p>This is an example Google Sign-In application, using <a href="https://github.com/evanj/googlesignin">github.com/evanj/googlesignin</a>. This page is public, but the other pages require you to log in:</p>
<ul>
<li><a href="/page1">Page 1</a></li>
<li><a href="/page2">Page 2</a></li>
<li><a href="/tokeninfo">Show access token info</a></li>
</ul>
</body></html>`

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		log.Printf("root returning 404 for %s", r.URL.String())
		http.NotFound(w, r)
		return
	}
	w.Write([]byte(rootHTML))
}

type pageValues struct {
	Email     string
	TokenInfo string
}

var pageTemplate = template.Must(template.New("page1").Parse(`<!doctype html><html><head>
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

func (s *server) handlePage(w http.ResponseWriter, r *http.Request) {
	values := &pageValues{s.authenticator.MustGetEmail(r), ""}
	err := pageTemplate.Execute(w, values)
	if err != nil {
		panic(err)
	}
}

func (s *server) accessTokenPage(w http.ResponseWriter, r *http.Request) {
	accessToken, err := s.authenticator.GetAccessToken(r)
	if err != nil {
		panic(err)
	}
	params := url.Values{}
	params.Set("access_token", accessToken)
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
		panic(fmt.Sprintf("failed response code: %d", resp.StatusCode))
	}

	values := &pageValues{s.authenticator.MustGetEmail(r), string(body)}
	err = pageTemplate.Execute(w, values)
	if err != nil {
		panic(err)
	}
}

func newServer(clientID string) *server {
	authenticator := googlesignin.New(clientID, "/")
	authenticator.RedirectIfNotSignedIn = true

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	s := &server{authenticator, nil, googleTokenInfoURL}
	mux.HandleFunc("/page1", s.handlePage)
	mux.HandleFunc("/page2", s.handlePage)
	mux.HandleFunc("/tokeninfo", s.accessTokenPage)

	s.handler = authenticator.RequireSignIn(mux)
	authenticator.MakePublic("/")
	// Returns 404, but that is better than redirecting
	authenticator.MakePublic("/favicon.ico")

	return s
}

func main() {
	insecureCookies := flag.Bool("insecureCookies", false,
		"Allow sending cookies over HTTP; use for localhost testing")
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
		log.Printf("warning: permitting insecure HTTP cookies")
	}
	log.Fatal(http.ListenAndServe(":"+port, s.handler))
}
