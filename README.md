# Google Sign-In

This library provides Go HTTP middleware to require Google Sign-In in a web application, and/or to use the Google Cloud Identity Aware Proxy. This library tries to be as easy to use as possible, and to use secure defaults. It verifies ID tokens on the server side using Google's public keys and [Square's go-jose library](https://github.com/square/go-jose). It requires users to be logged in for all endpoints, except endpoints that are explicitly made public. This is particularly useful for "internal" applications that should be available to users in your domain, but not the public. Just use the `RequiresSignIn` wrapper for all your endpoints, set the `HostedDomain` argument, and you are done! This version cannot be used to request OAuth2 access tokens, at least as of 2021-08-13. Use the `googlesignin/oauth2` version of this API for that.

I've also added some preliminary support for the [GCP Identity-Aware Proxy](https://cloud.google.com/iap/docs/concepts-overview), and authenticating requests using Google Cloud Service accounts as both a client and server.

Google previously recommended web applications use [the "Sign In With Google" JavaScript library, also known as "Google Sign-In Javascript Platform Library"](https://developers.google.com/identity/sign-in/web/). I initially wrote this because I was curious how it compares to the older OAuth redirect approach. In [August 2021, Google announced that this library will stop working after March 2023](https://developers.googleblog.com/2021/08/gsi-jsweb-deprecation.html). This library was updated at that time to the newer [Google Identity Services](https://developers.google.com/identity/gsi/web).


## Example

The example is running at https://gosignin-demo.appspot.com/. It has a main page that is not protected, then three sub-pages that print the user's email address and additional access token information.

To run it yourself:

1. Create a new Google Sign-In OAuth client ID and secret. [Follow Google's instructions to do this](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid).
2. Configure the OAuth client to permit `https://YOURDOMAIN` as an *Authorized JavaScript origin* and `https://YOURDOMAIN/__start_signin` as an *Authorized redirect URI*. For localhost testing, you must add both `http://localhost` and `http://localhost:PORT` to *Authorized JavaScript origin*.
3. Run the example on YOURDOMAIN: `CLIENT_ID=YOURID go run github.com/evanj/googlesignin/example`
4. Visit `https://YOURDOMAIN/` in your browser and click the links.


## Design Overview / Notes

This calls the Google Sign-In JavaScript API and saves the resulting ID token and optionally the access token in a cookie. Malicious JavaScript running on the site could steal these cookie, but they are time limited, so this seems basically as good as setting a a session cookie. It might be slightly better to expose an endpoint that saves them as an encrypted blob in an HTTPOnly cookie.

The Go handler requires these cookies to be set, and validates the ID token on each request. If it is invalid, permission is denied or it redirects to the sign in page. If the token can be refreshed, it is refreshed by the JavaScript, then it redirects back to the original page. The original URL is embedded in the sign in page's `#` hash, and is saved in `sessionStorage` if it needs to redirect to the sign in page.


## Identity-Aware Proxy

The Google Cloud Identity-Aware Proxy lets you control access to web applications using Google's built-in access control. This package provides HTTP middleware to verify the signed header and extract the email address. This performs the same function as the googlesignin package, but for applications using IAP. This repository contains an example. It is running https://goiap-demo.appspot.com/, but you won't be able to access it (sorry!). This is simpler and probably more secure than relying on Google Sign-In, but only works on Google Cloud.

### Simulate the Identity-Aware Proxy

There are many environments that don't support the Identity-Aware Proxy. One of the newest is [Cloud Run](https://cloud.google.com/run/docs/), which has [built-in authentication, but only using `"Authorization: Bearer ..."` headers](https://cloud.google.com/run/docs/authenticating/end-users), so it won't work for web applications. As a hack, I created a proxy server which simulates the Identity-Aware Proxy. It uses this package to redirect requests that are not authenticated to force a user to sign in. If the request is authenticated, then it is proxied through to the original backend.

Demo: https://proxytest-kgdmaenclq-ue.a.run.app/

You can set the `HOSTED_DOMAIN` environment variable to only allow users from a specified Google account domain.


## Google's public key caching/rotation policy

The `rotationcheck` program periodically loads Google's public keys, and checks their cache expiration. I used this to reverse engineer their key caching and rotation policies.

* When fetching public keys from the URL, Google appears to return a `Cache-Control: max-page=` parameter that is a random value between [5h, 7h] from the current time. It seems to be that one server has a specific cache expiration time, since multiple requests to the same IP return that value, but requests to DIFFERENT IPs return different values.

* Google uses a single public key for a LONG time: it looks like 7 days.

* After Google stops using a public key, it keeps publishing it for about 5 days.

* Before using a new public key, Google publishes it well in advance: About 3 days before it uses it.

* When transitioning to issue tokens with a new key, there is a period where both are being used. The transition takes about 30 minutes.

### Specific timeline

This follows a new key (k2) through its entire lifecycle.

* `2020/06/16 21:29:40`: Publishing a new public key (serving 3 keys: old=k0, current=k1, next=k2)
* `2020/06/17 04:44:40`: Reorders the keys: current=k1, next=k2, old=k0
* `2020/06/17 16:44:40`: Removes old public key (serving 2 keys: current=k1, next=k2)
* `2020/06/19 20:27:40` until `2020/06/19 20:53:40`: Issuing tokens with both keys (current=k1, next=k2)
* `2020/06/24 21:29:40`: Publishing next key (serving 3 keys: old=k1, current=k2, next=k3)
* `2020/06/25 04:44:40`: Reorders the keys: current=k2, next=k3, old=k1
* `2020/06/25 16:44:40`: Removes old public key (serving 2 keys: current=k2, next=k3)
* `2020/06/27 20:37:40` - `2020/06/27 20:49:40`: Issuing tokens with both keys (current=k2, next=k3)
* `2020/07/02 21:29:40`: Publishing next key (serving 3 keys: old=k2, current=k3, next=k4)
* `2020/07/03 04:44:40`: Reorders the keys: current=k3, next=k4, old=k2
* `2020/07/03 16:44:40`: Removes old public key (serving 2 keys: current=k3, next=k4)


## Service Account Authentication

To access resources on Google Cloud, humans use user accounts and software uses service accounts. You can re-use those accounts to authenticate other thing. The `serviceaccount` package contains code to make this easy. This lets you use service accounts to send requests to Identity-Aware Proxy protected pages, or to use Google Service Accounts to authenicate other things, like gRPC services. To create a service from Google credentials, use `serviceaccount.NewSourceFromDefault`. To require Google credentials to access server, use `serviceaccount.NewAuthenticator`.

Interesting note: Google's authentication seems to use a 5 minute "grace period." The tokens work for that much longer than the expiration time in the token.

The best reference I've seen on how this actually works is: https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_a_service_account

### Audiences (aud)

If you are using IAP, the audience (aud) field is the Client ID provided by Google. However, if you want to use this yourself, you can use any `https` URL that you would like (e.g. `https://www.example.com`).


### Demo

I have a demo service that will accept credentials from any Google service account. If you [visit the page](https://serviceaccount-dot-gosignin-demo.appspot.com), it will tell you that you are not authenticated. Send it an authorized request with:

```
GOOGLE_APPLICATION_CREDENTIALS=[service account key.json] go run ./serviceaccount/exampleclient/exampleclient.go \
  --audience=https://example.evanjones.ca \
  --url=https://serviceaccount-dot-gosignin-demo.appspot.com
```


### Notes about how this works

1. The client signs a JWT with `"target_audience": "(DESIRED AUDIENCE)"` and sends it to Google. This proves that the client has access to the service account key.
2. Google verifies the JWT and that the service account and key are still active. It returns a JWT signed by Google with `"audience": "(DESIRED AUDIENCE)"`. This proves that the service account and key is currently valid.
3. The client sends this JWT to the desired service.
4. The service verifies that the JWT is correctly signed by Google and is not expired, and has the correct expected audience. This proves that the client had access to the key, and the service account was valid at the time the token was issued. The audience ensures other services can't maliciously reuse the token for other things.

This does mean that revocation takes up to an hour. If this is a concern, you'll need to do some other check with Google to ensure the account is still valid.
