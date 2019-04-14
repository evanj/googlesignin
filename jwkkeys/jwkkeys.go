// Package jwkkeys verifies JWTs using keys published at known URLs. This is mostly intended
// as an internal package, but might be useful to others
package jwkkeys

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const minCacheSeconds = 60

// https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token
// https://accounts.google.com/.well-known/openid-configuration
const googleJWKURL = "https://www.googleapis.com/oauth2/v3/certs"

// GoogleIssuers contains the value of the iss field in Google ID tokens. When using Google Sign-In
// via the JavaScript API, it seems to use accounts.google.com, but when using a service account,
// it uses https://accounts.google.com.
// See: https://developers.google.com/identity/protocols/OpenIDConnect#validatinganidtoken
var GoogleIssuers = []string{"accounts.google.com", "https://accounts.google.com"}

var maxAgePattern = regexp.MustCompile(`(?:,|^)\s*(?i:max-age)\s*=\s*([^\s,]+)`)

// ErrKeyNotFound is the error returned by KeySet.Get when the key ID is not found.
var ErrKeyNotFound = errors.New("key not found")

// GoogleExtraClaims stores the JSON for Google Sign-In's extra claims that are not included in the
// basic OpenID claims.
type GoogleExtraClaims struct {
	// https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
	HostedDomain string `json:"hd,omitempty"`
	Email        string `json:"email,omitempty"`
}

// CachedSet fetches and parses keys from a URL, caching them for as long as permitted.
// It is safe to be used by multiple Goroutines since all accesses are locked.
type CachedSet struct {
	mu        sync.Mutex
	sourceURL string
	keys      *jose.JSONWebKeySet
	expires   time.Time
}

// Set retrieves keys in JWK format to validate tokens.
type Set interface {
	// Get returns the key matching keyID, or an error indicating what happened. Must return
	// ErrKeyNotFound if the key does not exist.
	Get(keyID string) (*jose.JSONWebKey, error)
}

// New returns a new CachedSet that stores keys loaded from url.
func New(url string) *CachedSet {
	return &CachedSet{sync.Mutex{}, url, nil, time.Time{}}
}

// NewGoogle returns a new CachedSet that loads Google's OAuth public keys.
func NewGoogle() *CachedSet {
	return New(googleJWKURL)
}

// Parses the max-age out of a Cache-Control header. Returns minCache if it cannot parse it, or
// if the value is blow the minimum.
// TODO: Use a real header parser that obeys all the various rules? E.g.
// https://github.com/pquerna/cachecontrol
//
// See the specifications:
// Cache-Control: https://tools.ietf.org/html/rfc7234#section-5.2
// ABNF syntax: https://tools.ietf.org/html/rfc7234#appendix-C
func parseMaxAge(cacheControl string) int {
	// parse with a regexp; quoted strings could confuse this but it seems unlikely
	matches := maxAgePattern.FindStringSubmatch(cacheControl)
	if len(matches) == 0 {
		return minCacheSeconds
	}
	if len(matches) != 2 {
		panic("logic bug: must have exactly 1 capturing group")
	}

	parsedSeconds, err := strconv.Atoi(matches[1])
	if err != nil {
		return minCacheSeconds
	}
	if parsedSeconds < minCacheSeconds {
		return minCacheSeconds
	}
	return parsedSeconds
}

// Get returns the key matching keyID, or ErrNotFound if it could not be found.
func (c *CachedSet) Get(keyID string) (*jose.JSONWebKey, error) {
	set, err := c.getKeySet()
	if err != nil {
		return nil, err
	}

	keys := set.Key(keyID)
	if len(keys) > 0 {
		return &keys[0], nil
	}
	return nil, ErrKeyNotFound
}

func (c *CachedSet) getKeySet() (*jose.JSONWebKeySet, error) {
	// this is the only function that modifies the values, so this needs to be synchronized
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.keys != nil && time.Now().Before(c.expires) {
		return c.keys, nil
	}

	resp, err := http.Get(c.sourceURL)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(resp.Body)
	keys := &jose.JSONWebKeySet{}
	err = decoder.Decode(keys)
	err2 := resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if err2 != nil {
		return nil, err2
	}

	cacheSeconds := parseMaxAge(resp.Header.Get("Cache-Control"))
	if cacheSeconds == minCacheSeconds {
		log.Printf("warning: caching for minimum time: Cache-Control: %#v",
			resp.Header.Get("Cache-Control"))
	}
	c.expires = time.Now().Add(time.Duration(cacheSeconds) * time.Second)
	c.keys = keys
	return c.keys, nil
}

// findKey returns the first key in token's headers that is stored in keys. Returns ErrKeyNotFound
// if no keys match.
func findKey(keys Set, token *jwt.JSONWebToken) (*jose.JSONWebKey, error) {
	for _, header := range token.Headers {
		key, err := keys.Get(header.KeyID)
		if err == ErrKeyNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, ErrKeyNotFound
}

// ValidateGoogleClaims parses the JWT, verifies its signature and claims, then returns the
// Google-specific claims.
func ValidateGoogleClaims(
	keys Set, serializedJWT string, audience string, issuers []string,
) (*GoogleExtraClaims, error) {
	token, err := jwt.ParseSigned(serializedJWT)
	if err != nil {
		return nil, err
	}

	// verify the signature and get the claims
	key, err := findKey(keys, token)
	if err != nil {
		return nil, err
	}
	standardClaims := &jwt.Claims{}
	extraClaims := &GoogleExtraClaims{}
	err = token.Claims(key, standardClaims, extraClaims)
	if err != nil {
		return nil, err
	}

	// try all the issuers; return the last error
	for _, issuer := range issuers {
		err = standardClaims.Validate(jwt.Expected{
			Audience: jwt.Audience{audience},
			Issuer:   issuer,
			Time:     time.Now(),
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	return extraClaims, nil
}
