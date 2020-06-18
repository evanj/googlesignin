// Checks how Google rotates its public keyss
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/evanj/googlesignin/serviceaccount"
	"golang.org/x/oauth2/jws"
)

const pollTime = time.Minute

const keyReadAttempts = 1

// https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token

// same contents in: https://www.googleapis.com/oauth2/v1/certs
// documented in: https://cloud.google.com/compute/docs/instances/verifying-instance-identity#verify_signature

// IAP uses DIFFERENT keys
// https://cloud.google.com/iap/docs/signed-headers-howto#verifying_the_jwt_header
// https://www.gstatic.com/iap/verify/public_key-jwk
const publicKeyURL = "https://www.googleapis.com/oauth2/v3/certs"

type jwtParts struct {
	KeyID      string
	Expiration time.Time
}

func base64JSONUnmarshal(s string, v interface{}) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func unverifiedPartsFromJWT(jwt string) (jwtParts, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return jwtParts{}, fmt.Errorf("jwt does contain enough parts: %#v", jwt)
	}
	headerString := parts[0]
	header := &jws.Header{}
	err := base64JSONUnmarshal(headerString, header)
	if err != nil {
		return jwtParts{}, err
	}

	claimsString := parts[1]
	claims := &jws.ClaimSet{}
	err = base64JSONUnmarshal(claimsString, claims)

	expTime := time.Unix(claims.Exp, 0).UTC()

	return jwtParts{header.KeyID, expTime}, nil
}

type keyJSON struct {
	KeyID string `json:"kid"`
}

type keySetJSON struct {
	Keys []keyJSON `json:"keys"`
}

type publicKeyParts struct {
	KeyIDs     []string
	Expiration time.Time
}

var maxAgePattern = regexp.MustCompile(`max-age=(\d+)`)

func getKIDsParts(client *http.Client, url string) (publicKeyParts, error) {
	resp, err := client.Get(url)
	if err != nil {
		return publicKeyParts{}, err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	keys := &keySetJSON{}
	err = decoder.Decode(keys)
	if err != nil {
		return publicKeyParts{}, err
	}
	err = resp.Body.Close()
	if err != nil {
		return publicKeyParts{}, err
	}

	var keyIDs []string
	for _, key := range keys.Keys {
		keyIDs = append(keyIDs, key.KeyID)
	}

	// documents Cache-Control but also sets expires
	matches := maxAgePattern.FindStringSubmatch(resp.Header.Get("Cache-Control"))
	if len(matches) != 2 {
		return publicKeyParts{}, fmt.Errorf("could not parse Cache-Control: %#v",
			resp.Header.Get("Cache-Control"))
	}
	parsed, err := strconv.Atoi(matches[1])
	if err != nil {
		return publicKeyParts{}, fmt.Errorf("could not parse Cache-Control: %#v: %s",
			resp.Header.Get("Cache-Control"), err.Error())
	}
	// TODO: should really use the Date header in the response
	expiration := time.Now().Add(time.Duration(parsed) * time.Second).UTC()

	return publicKeyParts{keyIDs, expiration}, nil
}

func main() {
	ctx := context.Background()
	tokenSource, err := serviceaccount.NewSourceFromDefault(ctx, "https://example.com/")
	if err != nil {
		panic(err)
	}

	ticker := time.NewTicker(pollTime)
	for range ticker.C {
		token, err := tokenSource.Token()
		if err != nil {
			log.Printf("ERROR: %s", err.Error())
			continue
		}

		parts, err := unverifiedPartsFromJWT(token.AccessToken)
		if err != nil {
			log.Printf("ERROR: %s", err.Error())
			continue
		}
		log.Printf("kid=%s expiration=%s", parts.KeyID, parts.Expiration.Format(time.RFC3339))

		// totally hack the token source to expire the token on the next request
		token.Expiry = time.Now().Add(-time.Minute)

		// connections to same server seem to always return the same expiration. However, if you
		// do the DNS lookup again from scratch and reconnect, you will likely get a different
		// server with a different expiration time. I'm leaving this loop here as a reminder.
		for attempt := 0; attempt < keyReadAttempts; attempt++ {
			parts, err := getKIDsParts(http.DefaultClient, publicKeyURL)
			if err != nil {
				log.Printf("ERROR: %s", err.Error())
				continue
			}
			diff := parts.Expiration.Sub(time.Now())
			log.Printf("public key expires=%s (%s) kids=%s",
				parts.Expiration.Format(time.RFC3339), diff.String(), strings.Join(parts.KeyIDs, ","))
		}
	}
}

// func (o *oidcTokenSource) Token() (*oauth2.Token, error) {
// 	// sign a JWT proving that we have access to this key, proving our identity to targetAudience.
// 	tokenString, err := o.makeJWT()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// get google to sign this token
// 	postParams := url.Values{}
// 	postParams.Set("grant_type", jwtBearerGrantType)
// 	postParams.Set("assertion", tokenString)
// 	resp, err := http.PostForm(o.tokenURL, postParams)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusOK {
// 		return nil, fmt.Errorf("serviceaccount: failed to get signed token: %s", resp.Status)
// 	}
// 	decoder := json.NewDecoder(resp.Body)
// 	idResponse := &tokenResponse{}
// 	err = decoder.Decode(idResponse)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// parse the token to determine expiration time etc
// 	claims, err := jws.Decode(idResponse.IDToken)
// 	if err != nil {
// 		return nil, err
// 	}
// 	expirationTime := time.Unix(claims.Exp, 0)
// 	token := &oauth2.Token{AccessToken: idResponse.IDToken, Expiry: expirationTime}
// 	if !token.Valid() {
// 		return nil, errors.New("serviceaccount: expired token returned from IDP")
// 	}
// 	log.Printf("got token from google expiry:%d=%s", claims.Exp, expirationTime.UTC().Format(time.RFC3339))
// 	return token, nil
// }
