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
	"regexp"
	"strings"
	"time"

	"github.com/evanj/googlesignin/jwkkeys"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
)

const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
const googleTokenURL = "https://www.googleapis.com/oauth2/v4/token"
const tokenExpiration = time.Hour

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
// private signing key. This returned source is cached using oauth2.ReuseTokenSource.
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
	log.Printf("got token from google expiry:%d=%s", claims.Exp, expirationTime.UTC().Format(time.RFC3339))
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

var bearerPattern = regexp.MustCompile(`^(?i:bearer\s+)(.*)$`)

// TokenFromRequest returns the bearer token in r, if any is set.
// See https://tools.ietf.org/html/rfc6750
func TokenFromRequest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	matches := bearerPattern.FindStringSubmatch(auth)
	if len(matches) == 0 {
		return ""
	}
	return matches[1]
}

// Authenticator verifies JWTs for Google Service Accounts.
type Authenticator struct {
	// Gets keys to validate tokens. Should not be changed except in tests.
	cachedKeys jwkkeys.Set

	// The audience that must be supplied in the JWT.
	audience string
}

// NewAuthenticator returns an Authenticator that requires audience to be set in the token.
func NewAuthenticator(audience string) *Authenticator {
	return &Authenticator{jwkkeys.NewGoogle(), audience}
}

// ValidateToken returns the identity that issued this token (sub), or an error if it is not valid.
func (a *Authenticator) ValidateToken(jwt string) (string, error) {
	claims, err := jwkkeys.ValidateGoogleClaims(a.cachedKeys, jwt, a.audience, jwkkeys.GoogleIssuers)
	if err != nil {
		return "", err
	}
	return claims.Email, nil
}
