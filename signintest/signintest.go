// Package signintest provides shared test code for testing signing in with Google accounts.
package signintest

import (
	"net/http"
	"time"

	"github.com/evanj/googlesignin"
	"github.com/evanj/googlesignin/jwkkeys"
	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// ClientID is a fake OAuth client ID to be used with googlesignin.Authenticator in tests.
const ClientID = "insecure_test_client_id"

// generated with gopkg.in/square/go-jose.v2/jwk-keygen
const insecurePrivateKey = `{"use":"sig","kty":"EC","crv":"P-256","alg":"ES256","x":"-YdsjSFTEqKWQn7ZjThmkhuDDSasgh3ACWmgFKlo_7w","y":"LejdIY1pMKjXRlf3lStziDpQGPOynW49uF_Jlymcaxg","d":"xK_dS2q20mgRrYFVlwcJHOlNWmVxneJyzWFO-CGZ0BE"}`
const testKeyID = "testkeyid"

// RequestAuthenticator makes requests authenticated for test purposes.
type RequestAuthenticator struct {
	authenticator *googlesignin.Authenticator
	privateKey    jose.JSONWebKey
}

// InsecureMakeAuthenticated makes request an authenticated request, using the insecure test keys.
// It will then be accepted by handlers that use MustGetEmail
func (r *RequestAuthenticator) InsecureMakeAuthenticated(
	request *http.Request, email string,
) *http.Request {
	idToken := InsecureToken(ClientID, jwkkeys.GoogleIssuers[0], email, r.authenticator.HostedDomain)
	return googlesignin.InsecureMakeAuthenticated(request, idToken)
}

type staticKeySet struct {
	key jose.JSONWebKey
}

func (s *staticKeySet) Get(keyID string) (*jose.JSONWebKey, error) {
	return &s.key, nil
}

// InsecureTestAuthenticator modifies the Authenticator accept insecure test keys, returning a
// RequestAuthenticator that can be use to make authorized *http.Request objects. You must use
// signintest.ClientID as the OAuth client ID when creating authenticator.
func InsecureTestAuthenticator(authenticator *googlesignin.Authenticator) *RequestAuthenticator {
	r := &RequestAuthenticator{authenticator, jose.JSONWebKey{}}
	r.loadJSONWebKey(insecurePrivateKey)
	r.privateKey.KeyID = testKeyID
	r.authenticator.CachedKeys = InsecureKeys()
	return r
}

func (r *RequestAuthenticator) loadJSONWebKey(json string) {
	err := r.privateKey.UnmarshalJSON([]byte(json))
	if err != nil {
		panic(err)
	}
	if !r.privateKey.Valid() {
		panic("invalid key")
	}
}

func parsePrivateKey() *jose.JSONWebKey {
	privateKey := &jose.JSONWebKey{}
	err := privateKey.UnmarshalJSON([]byte(insecurePrivateKey))
	if err != nil {
		panic(err)
	}
	return privateKey
}

// InsecureKeys returns a key set containing an insecure test key. Should only be used in tests.
func InsecureKeys() jwkkeys.Set {
	return &staticKeySet{parsePrivateKey().Public()}
}

// InsecureToken returns a new token that is signed by a key in InsecureKeys. Should only be used
// in tests.
func InsecureToken(audience string, issuer string, email string, hostedDomain string) string {
	privateKey := parsePrivateKey()
	signingKey := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(privateKey.Algorithm),
		Key:       privateKey,
	}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	claims := jwt.Claims{
		Subject:   "subject",
		Audience:  jwt.Audience{audience},
		Issuer:    issuer,
		NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	extraClaims := jwkkeys.GoogleExtraClaims{
		Email:        email,
		HostedDomain: hostedDomain,
	}

	raw, err := jwt.Signed(signer).Claims(claims).Claims(extraClaims).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}
