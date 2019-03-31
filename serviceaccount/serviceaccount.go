package serviceaccount

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
)

const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
const googleTokenURL = "https://www.googleapis.com/oauth2/v4/token"
const tokenExpiration = time.Hour

// Compute engine metadata
//2019/03/30 16:40:23 &google.Credentials{ProjectID:"bigquery-tools", TokenSource:(*oauth2.reuseTokenSource)(0xc00000c120), JSON:[]uint8(nil)}
// 2019/03/30 16:40:23 []byte(nil)
// panic: unexpected end of JSON input

// user credentials
// 2019/03/30 12:42:10 &google.Credentials{ProjectID:"", TokenSource:(*oauth2.reuseTokenSource)(0xc000108080), JSON:[]uint8{0x7b, 0xa, 0x20, 0x20, 0x22, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x22, 0x3a, 0x20, 0x22, 0x37, 0x36, 0x34, 0x30, 0x38, 0x36, 0x30, 0x35, 0x31, 0x38, 0x35, 0x30, 0x2d, 0x36, 0x71, 0x72, 0x34, 0x70, 0x36, 0x67, 0x70, 0x69, 0x36, 0x68, 0x6e, 0x35, 0x30, 0x36, 0x70, 0x74, 0x38, 0x65, 0x6a, 0x75, 0x71, 0x38, 0x33, 0x64, 0x69, 0x33, 0x34, 0x31, 0x68, 0x75, 0x72, 0x2e, 0x61, 0x70, 0x70, 0x73, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x75, 0x73, 0x65, 0x72, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x22, 0x2c, 0xa, 0x20, 0x20, 0x22, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x22, 0x3a, 0x20, 0x22, 0x64, 0x2d, 0x46, 0x4c, 0x39, 0x35, 0x51, 0x31, 0x39, 0x71, 0x37, 0x4d, 0x51, 0x6d, 0x46, 0x70, 0x64, 0x37, 0x68, 0x48, 0x44, 0x30, 0x54, 0x79, 0x22, 0x2c, 0xa, 0x20, 0x20, 0x22, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x31, 0x2f, 0x6a, 0x79, 0x57, 0x66, 0x35, 0x73, 0x74, 0x64, 0x78, 0x6d, 0x35, 0x6f, 0x6e, 0x59, 0x59, 0x63, 0x30, 0x34, 0x72, 0x64, 0x52, 0x6d, 0x45, 0x55, 0x55, 0x6b, 0x79, 0x6e, 0x32, 0x51, 0x76, 0x68, 0x44, 0x54, 0x35, 0x49, 0x31, 0x5a, 0x74, 0x70, 0x67, 0x78, 0x48, 0x74, 0x36, 0x35, 0x4d, 0x5f, 0x76, 0x52, 0x69, 0x70, 0x66, 0x64, 0x55, 0x76, 0x65, 0x6b, 0x7a, 0x69, 0x39, 0x74, 0x32, 0x65, 0x22, 0x2c, 0xa, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x22, 0xa, 0x7d}}
// 2019/03/30 12:42:10 "{\n  \"client_id\": \"764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com\",\n  \"client_secret\": \"d-FL95Q19q7MQmFpd7hHD0Ty\",\n  \"refresh_token\": \"1/jyWf5stdxm5onYYc04rdRmEUUkyn2QvhDT5I1ZtpgxHt65M_vRipfdUvekzi9t2e\",\n  \"type\": \"authorized_user\"\n}"

// ErrComputeEngineNotSupported indicates the discovered credentials belong to a Compute Engine
// instance which is not supported.
var ErrComputeEngineNotSupported = errors.New("serviceaccount: Can't sign tokens with Compute Engine credentials")

// ErrUserCredentialsNotSupported indicates the discovered credentials belong to a use account
// which is not supported.
var ErrUserCredentialsNotSupported = errors.New("serviceaccount: Can't sign tokens with user credentials")

// Create an oauth2 token source using the configuration and signing key from the Google
// application default credentials.
func sourceFromDefault(ctx context.Context, targetAudience string, tokenURL string) (*oidcTokenSource, error) {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}
	if len(credentials.JSON) == 0 {
		return nil, ErrComputeEngineNotSupported
	}
	config, err := google.JWTConfigFromJSON(credentials.JSON)
	if err != nil {
		// friendly error message that we found user credentials
		if strings.Contains(err.Error(), "authorized_user") {
			return nil, ErrUserCredentialsNotSupported
		}
		return nil, err
	}
	privateKey, err := parseKey(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &oidcTokenSource{config.Email, config.PrivateKeyID, privateKey, targetAudience, tokenURL}, nil
}

// NewSourceFromDefault returns a new token source from the Google application default credentials.
// The targetAudience must be set to the OAuth client ID for the identity-aware proxy, or any other
// string identifying the desired destination service. The credentials must be from a service
// account key, since a user account and the Compute Engine metadata service do not expose the
// private signing key.
func NewSourceFromDefault(ctx context.Context, targetAudience string) (oauth2.TokenSource, error) {
	return newSourceFromDefaultURL(ctx, targetAudience, googleTokenURL)
}

// An oauth2.TokenSource that uses Google's OpenID Connect to issue tokens. This is almost exactly
// what happens for Google's "native" tokens, with the addition of a "target_audience" claim
// instead of "scopes" ... or something like that. I can't quite keep track.
//
// This source is uncached: each time Token is called, it contacts Google. It should be wrapped
// in an oauth2.ReuseTokenSource so it is cached.
type oidcTokenSource struct {
	email          string
	keyID          string
	privateKey     *rsa.PrivateKey
	targetAudience string
	tokenURL       string
}

func (o *oidcTokenSource) makeJWT() (string, error) {
	return makeJWT(o.email, o.keyID, o.privateKey, o.targetAudience)
}

func (o *oidcTokenSource) Token() (*oauth2.Token, error) {
	// sign a JWT proving that we have access to this key, proving our identity to targetAudience.
	tokenString, err := o.makeJWT()
	if err != nil {
		return nil, err
	}

	// get google to sign this token
	postParams := url.Values{}
	postParams.Set("grant_type", jwtBearerGrantType)
	postParams.Set("assertion", tokenString)
	resp, err := http.PostForm(o.tokenURL, postParams)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("serviceaccount: failed to get signed token: %s", resp.Status)
	}
	decoder := json.NewDecoder(resp.Body)
	idResponse := &tokenResponse{}
	err = decoder.Decode(idResponse)
	if err != nil {
		return nil, err
	}

	// parse the token to determine expiration time etc
	claims, err := jws.Decode(idResponse.IDToken)
	if err != nil {
		return nil, err
	}
	expirationTime := time.Unix(claims.Exp, 0)
	token := &oauth2.Token{AccessToken: idResponse.IDToken, Expiry: expirationTime}
	if !token.Valid() {
		return nil, errors.New("serviceaccount: expired token returned from IDP")
	}
	log.Printf("got token from google expiry:%d %s", claims.Exp, expirationTime.UTC().Format(time.RFC3339))
	return token, nil
}

func newSourceFromDefaultURL(ctx context.Context, targetAudience string, oauthTokenURL string) (oauth2.TokenSource, error) {
	// get the identity and private key from the google default credentials
	source, err := sourceFromDefault(ctx, targetAudience, oauthTokenURL)
	if err != nil {
		return nil, err
	}

	// fetch an initial token to verify that the configuration is correct
	token, err := source.Token()
	if err != nil {
		return nil, err
	}

	// wrap the source in a caching/refreshing layer
	return oauth2.ReuseTokenSource(token, source), nil
}

func parseToken(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("serviceaccount: token has wrong number of parts: %d !=3", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	fmt.Println("XXXXX", string(decoded))
	return nil
}

type tokenResponse struct {
	IDToken string `json:"id_token,omitempty"`
}

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
// email: the email address of the key. Will be used in both the issuer and subject fields.
// keyID: the ID of the private key that will be set in the JWT header.
func makeJWT(email string, keyID string, privateKey *rsa.PrivateKey, targetAudience string) (string, error) {
	issuedAt := time.Now()
	expiry := issuedAt.Add(tokenExpiration)
	cs := &jws.ClaimSet{
		Iss: email,
		Sub: email,
		Aud: googleTokenURL,
		Iat: issuedAt.Unix(),
		Exp: expiry.Unix(),
		PrivateClaims: map[string]interface{}{
			"target_audience": targetAudience,
		},
	}
	hdr := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     keyID,
	}
	return jws.Encode(hdr, cs, privateKey)
}
