package serviceaccount

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"testing"

	"golang.org/x/oauth2/google"
)

const googleCredentialsEnvVar = "GOOGLE_APPLICATION_CREDENTIALS"

// from cloud.google.com/go/compute/metadata/metadata.go:
// variable name is not defined by any spec, as far as I know; it was made up for the Go package.
const gceMetadataHostEnv = "GCE_METADATA_HOST"

// Sets an environment variable and returns a function to set it to its original value
func setEnvAndCleanUp(key string, value string) func() {
	originalValue := os.Getenv(key)
	os.Setenv(key, value)
	return func() {
		if originalValue != "client@someproject.iam.gserviceaccount.com" {
			os.Setenv(key, originalValue)
		} else {
			os.Unsetenv(key)
		}
	}
}

func TestNewSourceFromDefault(t *testing.T) {
	// set GOOGLE_APPLICATION_CREDENTIALS to a tempfile (and clean up after)
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer setEnvAndCleanUp(googleCredentialsEnvVar, f.Name())()
	defer setEnvAndCleanUp(gceMetadataHostEnv, "doesnotexist.example.com")()

	tests := []struct {
		credentialData string
		errSubstring   string
		email          string
	}{
		{expiredServiceKey, "", "client@someproject.iam.gserviceaccount.com"},
		{fakeUserCredentials, "Can't sign tokens with user credentials", ""},
	}

	for i, test := range tests {
		err = ioutil.WriteFile(f.Name(), []byte(test.credentialData), 0600)
		if err != nil {
			t.Fatal(err)
		}

		source, err := sourceFromDefault(context.Background(), "audience", "url")
		if test.errSubstring != "" {
			if err == nil || !strings.Contains(err.Error(), test.errSubstring) {
				t.Error(i, err)
			}
		} else if source.email != test.email {
			t.Error(i, source.email)
		}
	}
}

func TestSourceFromDefaultComputeEngine(t *testing.T) {
	// set HOME to a temp dir: causes FindDefaultCredentials to not find gcloud credentials (if any)
	tempdir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempdir)
	defer setEnvAndCleanUp("HOME", tempdir)()
	// make FindDefaultCredentials think we are on compute engine
	defer setEnvAndCleanUp(gceMetadataHostEnv, "doesnotexist.example.com")()

	_, err = sourceFromDefault(context.Background(), "audience", "url")
	if err != ErrComputeEngineNotSupported {
		t.Error(err)
	}
}

func TestTokenSource(t *testing.T) {
	assertionFormParam := ""
	responseString := ""
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("got request", r)
		assertionFormParam = r.FormValue("assertion")
		w.Write([]byte(responseString))
	}))
	defer testServer.Close()

	// set GOOGLE_APPLICATION_CREDENTIALS to a tempfile (and clean up after)
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer setEnvAndCleanUp(googleCredentialsEnvVar, f.Name())()
	f.Write([]byte(expiredServiceKey))

	// generate an id token that at least parses
	config, err := google.JWTConfigFromJSON([]byte(expiredServiceKey))
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := parseKey(config.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	outputJWT, err := makeJWT(config.Email, config.PrivateKeyID, privateKey, "audience")
	if err != nil {
		t.Fatal(err)
	}
	responseString = fmt.Sprintf(`{"id_token": "%s"}`, outputJWT)

	tokenSource, err := newSourceFromDefaultURL(context.Background(), "test_audience", testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tokenSource.Token()
	if err != nil {
		t.Fatal(err)
	}
	// TODO: Check the values being posted?
	if assertionFormParam == "" {
		t.Error(assertionFormParam)
	}
	if !token.Valid() {
		t.Error("token.Valid() returned false")
	}
}

// actual expired service account key
const expiredServiceKey = `{
  "type": "service_account",
  "project_id": "goiap-demo",
  "private_key_id": "e3ac7118f32d51e13a67004ab3605f2f83adfaaa",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCE/rrQHwGbBYX+\n3tuQGY5+cXcqUuP3vc0VFqigQ5y5JOBuWfTNn/qFuunb4u8aLXg9ff4Qku+Q7o5x\nQ1khTuDzVyGWZZhCwpBNrzUVA6E2yqEtFAorUgjwcjjaVDB3Oip86X8g6ubfopDt\nkVg86A6/y0e9irkbKX06hd4zDshpKEtK6VOWNDR8U2ldi2thoDjbvhCQe8uxntsQ\niKN5M3i4Y4iGHPhpqBTXM8kMaYjG6GtDWgRCaLLrg2Rsi5wjzupqMO3l40fc3ZQ3\ned3JB+9ViGvamh9dqd0+rMnNdXDge3Zr8gUVtTasAM1Q/bUtE79fj1v6y692hHYo\nNE+JQsm5AgMBAAECggEAAsjCaHD9u50V/Qv1VML0NLlzYTNzClCy5mofBZvkwAuB\nl03Szis3N21+T9gkYUvqZH8qvnYVBde4q65ZQ1U/aFi+n0NpOJySIM42MkZtLZR4\nY1U0EUwaW85IWmnAyf4xvYO14Z6JTs08c3zDeCLzjBhZXCJ3VZY8xOjgifkZQPpL\nPzrprv4kpzK5Lx7O5PJkzECxYzUVN/UD+7ottpHdaEOEGYkHGr7tn8e5isowEiVB\nRGQZmcoqMOpf9m4uLflUu382kC29/lUuNUv1gRVyBPu6qQPa8C3P4hG1azS81XcP\nbKWSYu2WoWoseQOKxLicqV5W98lhZwliG3eCs0u88QKBgQC7KJ+8M/qQ7h+cxXST\neFLjwWUcrVsR83iP4FGk+RqCoB9Jq4/6DjK/n/PEF3hyZBJIyOJJyOq0c8d+w7P2\nz9wrKlojFFSKi+bMNnqnf3a9T3S3XTRsWvm1S+22TNCwTxNDbYMGUwYSJaLnxw9b\nVD9vSQ5mmbm70cG2I2GXSx3LgwKBgQC16ehlBbWZmkKnrbwokD7TfVWpRS+SvPyC\nR7HfwpoVynkrQJdSvNoFmMVey/FMzs+G7eXRQk47GBhIBzrMHBAYqFbH8lcamMSs\nrEEddotkUqAWH6IprLebp9BWgPzQk6p1eWV5Ec1z0xdjFAEM7FmnCr+W8Q1AcL4O\n+VNvUpZlEwKBgBkH5N0p4oARqN6xtdanSAa37cr5EG4FLwGnEaRLwJTpz2Vt8ZKS\n5YylWtfF/9Dku2FKpKETovhBZ9P3XpFK2XpYbre0V140OcjkHGFcdcf54XVInONF\nA5KQthkkiuCZoszoz5Y/8lbo+7Gd+NrRGK7MiYWFV8bb1dmDP+EZJcH7AoGBAKyy\nwB5P2kRVj1vycsOrlQlgXldRSEWtRqdD+xirfW6choXKTx6MDQrtKsrBIHZDi/7T\nkK8lnHE7gam3u1kUdy+BeMlfRtQIHgazjSm0Zca7LiFyrJeV0cVi/kVxNRGqblQS\nCIR0ozCHQRedYRXst3v+lz5r36HCppw+lLgFlqOjAoGAC5pa/oaBdXmeKXCPU/S+\nFZDbmwnd/EAmwyxhVLND+DfSlwGjeNsI54LQ36YamnM6iIcUyZKDX03LGxRo5OJk\nQ2Dw6UKccoum7pIS0RP39xxXf6oGIdTXYH43z/I45A2IGl/sBhWJIYaz4nze8yj/\n767n7rj9d1sBLzfBPwUBg3A=\n-----END PRIVATE KEY-----\n",
  "client_email": "client@someproject.iam.gserviceaccount.com",
  "client_id": "102459353944373919555",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/client%40someproject.iam.gserviceaccount.com"
}
`

// Looks like ~/.config/gcloud/application_default_credentials.json but with garbage data
const fakeUserCredentials = `{
  "client_id": "aaaa-aaaaa.apps.googleusercontent.com",
  "client_secret": "a-Faaaaaaaaaaaaa",
  "refresh_token": "1/aaaaaaaaaa",
  "type": "authorized_user"
}`
