package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/evanj/googlesignin"
)

const rootHTML = `<!doctype html><html><head>
<title>Google Sign-In Example</title>
</head>
<body>
<h1>Google Sign-In Example</h1>
<p>This is an example Google Sign-In application, using <a href="https://github.com/evanj/googlesignin">github.com/evanj/googlesignin</a>. This page is public, but the other pages require you to log in:</p>
<ul>
<li><a href="/page1">Page 1</a></li>
<li><a href="/page2">Page 2</a></li>
</ul>
</body></html>`

func handleRoot(w http.ResponseWriter, r *http.Request) {
	log.Println("wtf")
	if r.URL.Path != "/" {
		log.Printf("root returning 404 for %s", r.URL.String())
		http.NotFound(w, r)
		return
	}
	w.Write([]byte(rootHTML))
}

type pageValues struct {
	Email string
}

var pageTemplate = template.Must(template.New("page1").Parse(`<!doctype html><html><head>
<title>Google Sign-In Page</title>
</head>
<body>
<h1>Google Sign-In Page</h1>
<p>Hello {{.Email}}!</p>
</body></html>`))

type server struct {
	authenticator *googlesignin.Authenticator
}

func (s *server) handlePage(w http.ResponseWriter, r *http.Request) {
	values := &pageValues{s.authenticator.MustGetEmail(r)}
	err := pageTemplate.Execute(w, values)
	if err != nil {
		panic(err)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	const clientIDEnvVar = "CLIENT_ID"
	clientID := os.Getenv(clientIDEnvVar)
	if clientID == "" {
		panic("must specify Google Client ID with environment variable " + clientIDEnvVar)
	}

	const clientSecretEnvVar = "CLIENT_SECRET"
	clientSecret := os.Getenv(clientSecretEnvVar)
	if clientSecret == "" {
		panic("must specify Google Client ID with environment variable " + clientIDEnvVar)
	}

	authenticator := googlesignin.New(clientID, clientSecret, "/")
	authenticator.RedirectIfNotSignedIn = true

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	s := &server{authenticator}
	mux.HandleFunc("/page1", s.handlePage)
	mux.HandleFunc("/page2", s.handlePage)

	authenticatedHandler := authenticator.RequireSignIn(mux)
	authenticator.MakePublic("/")
	// Returns 404, but that is better than redirecting
	authenticator.MakePublic("/favicon.ico")

	log.Fatal(http.ListenAndServe(":"+port, authenticatedHandler))
}
