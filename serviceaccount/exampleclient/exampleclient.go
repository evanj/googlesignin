package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/evanj/googlesignin/serviceaccount"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
	"golang.org/x/oauth2/jwt"
)

const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
const oauthTokenURL = "https://www.googleapis.com/oauth2/v4/token"
const formContentType = "application/x-www-form-urlencoded"
const iapClientID = "446336824806-0f1kepoin3qgkv6mi9so941o0tbvtmr5.apps.googleusercontent.com"
const tokenExpiration = time.Hour
const headerKeyID = "kid"
const jwtType = "JWT"

// Copied from golang.org/x/oauth2/internal.ParseKey
func parseKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("private key should be a PEM or plain PKCS1 or PKCS8; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is invalid")
	}
	return parsed, nil
}

// Returns a signed and encoded JWT. Mostly copied from jwtAccessTokenSource.Token. We can't use
// go-jose because Google's OAuth implementation does not support the "aud" field as a list of
// strings, in violation the RFC7519: https://tools.ietf.org/html/rfc7519#section-4.1.3
// go-jose only serializes aud as a list of strings
func makeJWT(config *jwt.Config, privateKey *rsa.PrivateKey) (string, error) {
	issuedAt := time.Now()
	expiry := issuedAt.Add(tokenExpiration)
	cs := &jws.ClaimSet{
		Iss: config.Email,
		Sub: config.Email,
		Aud: oauthTokenURL,
		Iat: issuedAt.Unix(),
		Exp: expiry.Unix(),
		PrivateClaims: map[string]interface{}{
			"target_audience": iapClientID,
		},
	}
	hdr := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     config.PrivateKeyID,
	}
	return jws.Encode(hdr, cs, privateKey)
}

type tokenResponse struct {
	IDToken string `json:"id_token,omitempty"`
}

func debugToken(t string) {
	fmt.Println("token:", t)
	parts := strings.Split(t, ".")
	for i, part := range parts {
		if i > len(parts)-2 {
			break
		}

		out, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(out))
	}
}

func main() {
	urlString := flag.String("url", "http://localhost:8080/auth_demo", "URL to send bearer token")
	flag.Parse()

	ctx := context.Background()
	tokenSource, err := serviceaccount.NewSourceFromDefault(ctx, iapClientID)
	if err != nil {
		panic(err)
	}
	authenticatedClient := oauth2.NewClient(ctx, tokenSource)

	log.Printf("requesting %s ...", *urlString)
	resp, err := authenticatedClient.Get(*urlString)
	if err != nil {
		panic(err)
	}
	log.Printf("Status: %s", resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("%s=%s\n", k, strings.Join(v, ", "))
	}
	fmt.Println()
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		panic(err)
	}
	err = resp.Body.Close()
	if err != nil {
		panic(err)
	}
	fmt.Println()
}

//{"alg":"RS256","typ":"JWT","kid":"e3ac7118f32d51e13a67004ab3605f2f83adfc8d"}
//{"iss":"iap-test-client@goiap-demo.iam.gserviceaccount.com","aud":"https://www.googleapis.com/oauth2/v4/token","exp":1553962970,"iat":1553959370,"sub":"iap-test-client@goiap-demo.iam.gserviceaccount.com","target_audience":"446336824806-0f1kepoin3qgkv6mi9so941o0tbvtmr5.apps.googleusercontent.com"}

// {"alg":"RS256","kid":"e3ac7118f32d51e13a67004ab3605f2f83adfc8d","typ":"JWT"}
// {"aud":["https://www.googleapis.com/oauth2/v4/token"],"exp":1553962856,"iat":1553959256,"iss":"iap-test-client@goiap-demo.iam.gserviceaccount.com","sub":"iap-test-client@goiap-demo.iam.gserviceaccount.com","target_audience":"446336824806-0f1kepoin3qgkv6mi9so941o0tbvtmr5.apps.googleusercontent.com"}
