# Google Sign-In

A Go HTTP middleware for the Google Sign-In web application JavaScript library.

Google currently recommends web applications use [their JavaScript library to implement "sign in with Google."](https://developers.google.com/identity/sign-in/web/) I was curious about this compares to the older OAuth redirect approach. This library tries to be as easy to use as possible, and implements secure defaults. It verifies ID tokens on the server side using Google's public keys and Square's JOSE library. It requires users to be logged in for all endpoints, except a list of endpoints that are explicitly public.

This is particularly good for "internal applications" that should be available to users in your domain, but not the public. Just use the `RequiresSignIn` wrapper for all your endpoints, set the `HostedDomain` argument, and you are done! 


## Example

The example is running at https://gosignin-demo.appspot.com/ or [see the code](example/example.go).

To run it yourself:

1. Create a new Google Sign-In OAuth client ID and secret. [Follow Google's instructions to do this](https://developers.google.com/identity/sign-in/web/sign-in#before_you_begin).
2. Configure the OAuth client to permit `https://YOURDOMAIN` as an *Authorized JavaScript origin* and `https://YOURDOMAIN/__start_signin` as an *Authorized redirect URI*.
3. `CLIENT_ID=YOURID go run github.com/evanj/googlesignin/example`


## Design Overview / Notes

This calls the Google Sign-In JavaScript API and saves the resulting ID token and optionally the access token in a cookie. Malicious JavaScript running on the site could steal these cookie, but they are time limited, so this seems basically as good as setting a a session cookie. It might be slightly better to expose an endpoint that saves them as an encrypted blob in an HTTPOnly cookie.

The Go handler requires these cookies to be set, and validates the ID token on each request. If it is invalid, permission is denied or it redirects to the sign in page. If the token can be refreshed, it is refreshed by the JavaScript, then it redirects back to the original page. The original URL is embedded in the sign in page's `#` hash, and is saved in `sessionStorage` if it needs to redirect to the sign in page.
