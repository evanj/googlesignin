# Google Sign-In

A Go HTTP middleware for the Google Sign-In web application JavaScript library.

Google currently recommends web applications use [their JavaScript library to implement "sign in with Google."](https://developers.google.com/identity/sign-in/web/) I was curious about this compares to the older OAuth redirect approach. This library tries to be as easy to use as possible, and implements secure defaults. It verifies ID tokens on the server side using Google's public keys and Square's JOSE library. It requires users to be logged in for all endpoints, except a list of endpoints that are explicitly public.

This is particularly good for "internal applications" that should be available to users in your domain, but not the public. Just use the `RequiresSignIn` wrapper for all your endpoints, set the `HostedDomain` argument, and you are done! 


## Example

The example is running at https://gosignin-demo.appspot.com/

To run it yourself:

1. Create a new Google Sign-In OAuth client ID and secret. [Follow Google's instructions to do this](https://developers.google.com/identity/sign-in/web/sign-in#before_you_begin).
2. Configure the OAuth client to permit `https://YOURDOMAIN` as an *Authorized JavaScript origin* and `https://YOURDOMAIN/__start_signin` as an *Authorized redirect URI*.
3. `CLIENT_ID=YOURID CLIENT_SECRET=YOURSECET go run github.com/evanj/googlesignin/example`
