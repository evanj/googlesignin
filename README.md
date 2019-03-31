# Google Sign-In

This library provides Go HTTP middleware to require Google Sign-In in a web application, and/or to use the Google Cloud Identity Aware Proxy.

Google currently recommends web applications use [their JavaScript library to implement "sign in with Google."](https://developers.google.com/identity/sign-in/web/) I was curious about this compares to the older OAuth redirect approach. This library tries to be as easy to use as possible, and implements secure defaults. It verifies ID tokens on the server side using Google's public keys and Square's JOSE library. It requires users to be logged in for all endpoints, except endpoints that are explicitly made public.

This is particularly good for "internal applications" that should be available to users in your domain, but not the public. Just use the `RequiresSignIn` wrapper for all your endpoints, set the `HostedDomain` argument, and you are done! 


## Example

The example is running at https://gosignin-demo.appspot.com/. It has a main page that is not protected, then three sub-pages that print the user's email address and additional access token information.

To run it yourself:

1. Create a new Google Sign-In OAuth client ID and secret. [Follow Google's instructions to do this](https://developers.google.com/identity/sign-in/web/sign-in#before_you_begin).
2. Configure the OAuth client to permit `https://YOURDOMAIN` as an *Authorized JavaScript origin* and `https://YOURDOMAIN/__start_signin` as an *Authorized redirect URI*.
3. `CLIENT_ID=YOURID go run github.com/evanj/googlesignin/example`


## Design Overview / Notes

This calls the Google Sign-In JavaScript API and saves the resulting ID token and optionally the access token in a cookie. Malicious JavaScript running on the site could steal these cookie, but they are time limited, so this seems basically as good as setting a a session cookie. It might be slightly better to expose an endpoint that saves them as an encrypted blob in an HTTPOnly cookie.

The Go handler requires these cookies to be set, and validates the ID token on each request. If it is invalid, permission is denied or it redirects to the sign in page. If the token can be refreshed, it is refreshed by the JavaScript, then it redirects back to the original page. The original URL is embedded in the sign in page's `#` hash, and is saved in `sessionStorage` if it needs to redirect to the sign in page.


## Identity-Aware Proxy

The Google Cloud Identity-Aware Proxy lets you control access to web applications using Google's built-in access control. This package provides HTTP middleware to verify the signed header and extract the email address. This performs the same function as the googlesignin package, but for applications using IAP. This repository contains an example. It is running https://goiap-demo.appspot.com/, but you won't be able to access it (sorry!). This is a lot simpler and probably more secure than relying on Google Sign-In, but only works on Google Cloud.


## Service Account Authentication

To access resources on Google Cloud, humans use user accounts and software uses service accounts. You can re-use those accounts to authenticate other thing. The `serviceaccount` package contains code to make this easy. This lets you use service accounts to send requests to Identity-Aware Proxy protected pages, or to use Google Service Accounts to authenicate other things, like gRPC services. To create a service from Google credentials, use serviceaccount.NewSourceFromDefault. To require Google credentials for a server, use NewMiddleware().

Interesting note: Google's authentication seems to use a 5 minute "grace period." The tokens work for that much longer than the expiration time in the token.

The best reference I've seen on how this actually works is: https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_a_service_account

### Demo

GOOGLE_APPLICATION_CREDENTIALS=[service account key.json] go run serviceaccount/exampleclient/exampleclient.go
