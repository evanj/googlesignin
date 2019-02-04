package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/evanj/googlesignin/iap"
)

type iapTestCase struct {
	Path        string
	Description string
}
type iapValues struct {
	Email     string
	TestPages []iapTestCase
}

var iapTemplate = template.Must(template.New("page1").Parse(`<!doctype html><html><head>
<title>Identity-Aware Proxy Test Page</title>
</head>
<body>
<h1>Identity-Aware Proxy Test Page</h1>
<p>Hello {{.Email}}! This page should be protected by Google's Identity-Aware Proxy.</p>

<h2>Test URLs</h2>
<p>The first one of these links should work. The rest should fail. See <a href="https://cloud.google.com/iap/docs/special-urls-and-headers-howto#testing_jwt_verification">Google's documentation for details</a>.</p>
<ul>
{{range .TestPages}}
<li><a href="{{.Path}}">{{.Path}}</a>: {{.Description}}</li>
{{end}}
</ul>
</body></html>`))

func iapTestPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	email := iap.Email(r)

	values := &iapValues{email, []iapTestCase{
		// https://cloud.google.com/iap/docs/special-urls-and-headers-howto#testing_jwt_verification
		{"NOT_SET", "A valid JWT."},
		{"FUTURE_ISSUE", "Issue date is set in the future."},
		{"PAST_EXPIRATION", "Expiration date is set in the past."},
		{"ISSUER", "Incorrect issuer."},
		{"AUDIENCE", "Incorrect audience."},
		{"SIGNATURE", "Signed using an incorrect signer."},
	}}

	const prefix = "/_gcp_iap/secure_token_test/"
	for i, test := range values.TestPages {
		values.TestPages[i].Path = prefix + test.Path
	}

	err := iapTemplate.Execute(w, values)
	if err != nil {
		panic(err)
	}
}

func iapTokenTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	w.Write([]byte("requested: " + r.URL.String()))
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	const audienceEnvVar = "AUDIENCE"
	audience := os.Getenv(audienceEnvVar)
	if audience == "" {
		panic("must set the expected IAP Audience with environment variable " + audienceEnvVar)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", iapTestPage)
	mux.HandleFunc("/_gcp_iap/", iapTokenTest)

	authenticatedHandler := iap.Required(audience, mux)
	log.Fatal(http.ListenAndServe(":"+port, authenticatedHandler))
}
