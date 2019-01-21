package signintest

import (
	"net/http"
	"time"

	"github.com/evanj/googlesignin"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const ClientID = "insecure_test_client_id"

// This fake secret is not used, but it makes the uses of this package more readable.
const ClientSecret = "insecure_test_client_secret"

// generated with gopkg.in/square/go-jose.v2/jwk-keygen
const insecurePrivateKey = `{"use":"sig","kty":"EC","crv":"P-256","alg":"ES256","x":"-YdsjSFTEqKWQn7ZjThmkhuDDSasgh3ACWmgFKlo_7w","y":"LejdIY1pMKjXRlf3lStziDpQGPOynW49uF_Jlymcaxg","d":"xK_dS2q20mgRrYFVlwcJHOlNWmVxneJyzWFO-CGZ0BE"}`
const testKeyID = "testkeyid"

// RequestAuthenticator makes requests authenticated for test purposes.
type RequestAuthenticator struct {
	authenticator *googlesignin.Authenticator
	privateKey    jose.JSONWebKey
}

// InsecureAuthenticate makes request an authenticated request, using the insecure test keys. It
// will then be accepted by handlers that use MustGetEmail
func (r *RequestAuthenticator) InsecureMakeAuthenticated(
	request *http.Request, email string,
) *http.Request {
	token := makeSignedToken(&r.privateKey, email, r.authenticator.HostedDomain)
	return googlesignin.InsecureMakeAuthenticated(request, token)
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
	r.authenticator.CachedKeys = &staticKeySet{r.privateKey.Public()}
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

func makeSignedToken(jwk *jose.JSONWebKey, email string, hostedDomain string) string {
	// from https://godoc.org/gopkg.in/square/go-jose.v2/jwt#Signed
	// this library embeds kid if signing with a private key
	signingKey := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk}
	sig, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	claims := jwt.Claims{
		Subject:   "subject",
		Issuer:    googlesignin.Issuer,
		NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Audience:  jwt.Audience{ClientID},
	}
	extraClaims := googlesignin.ExtraClaims{
		Email:        email,
		HostedDomain: hostedDomain,
	}

	raw, err := jwt.Signed(sig).Claims(claims).Claims(extraClaims).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}
