// Tests of private package internals
package googlesignin

import (
	"testing"
)

func TestMakePublic(t *testing.T) {
	a := New("clientid")
	a.MakePublic("/")
	a.MakePublic("/public")
	a.MakePublic("/publicdir/")

	publicPaths := []string{
		"/",
		"/public",
		"/publicdir/",
	}
	notPublicPaths := []string{
		"/x",
		"/publicx",
		"/public/",
		"/publicdir",
		"/publicdirx",
		"/publicdir/x",
	}
	for i, publicPath := range publicPaths {
		if !a.isPublic(publicPath) {
			t.Errorf("%d: isPublic(%#v) should be true", i, publicPath)
		}
	}
	for i, notPublicPath := range notPublicPaths {
		if a.isPublic(notPublicPath) {
			t.Errorf("%d: isPublic(%#v) should be false", i, notPublicPath)
		}
	}
}
