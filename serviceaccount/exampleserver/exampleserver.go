package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/evanj/googlesignin/serviceaccount"
)

type rootData struct {
	AuthenticationStatus string
	AccountEmail         string
	ErrorMessage         string
	RequiredAudience     string
}

var rootTemplate = template.Must(template.New("root").Parse(`<!doctype html><html><head>
<title>Google Service Account Authentication Example</title>
</head>
<body>
<h1>Google Service Account Authentication Example</h1>
<p>This is an example of using Google Service Accounts to control access to resources. Send an
authenticated request to this service with <code>aud: {{.RequiredAudience}}</code>.</p>

<p><b>Your request was: {{.AuthenticationStatus}}</b></p>
<p><b>Email</b>: {{.AccountEmail}}</p>
<p><b>Error Message</b>: {{.ErrorMessage}}</p>
</body></html>`))

type server struct {
	authenticator    *serviceaccount.Authenticator
	requiredAudience string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		log.Printf("root returning 404 for %s", r.URL.String())
		http.NotFound(w, r)
		return
	}

	authStatus := "not authenticated"
	accountEmail, err := s.authenticator.ValidateToken(serviceaccount.TokenFromRequest(r))
	errorMessage := ""
	if err != nil {
		errorMessage = err.Error()
	} else {
		authStatus = "AUTHENTICATED!!"
	}

	data := &rootData{
		authStatus, accountEmail, errorMessage, s.requiredAudience,
	}
	err = rootTemplate.Execute(w, data)
	if err != nil {
		panic(err)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	const audienceEnvVar = "AUDIENCE"
	audience := os.Getenv(audienceEnvVar)
	if audience == "" {
		panic("must specify required audience (aud) with environment variable " + audienceEnvVar)
	}

	auth := serviceaccount.NewAuthenticator(audience)
	s := &server{auth, audience}
	log.Fatal(http.ListenAndServe(":"+port, s))
}
