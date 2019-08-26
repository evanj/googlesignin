package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/evanj/googlesignin"
)

const alternatePort = 65001

// it takes a pretty minimal gunicorn/flask app about 1.5-3s to start on Cloud Run
const startupTimeout = time.Minute
const startupCheckInterval = time.Second
const portEnvVar = "PORT"
const clientIDEnvVar = "CLIENT_ID"
const hostedDomainEnvVar = "HOSTED_DOMAIN"

type processExitStatus struct {
	mu     sync.Mutex
	err    error
	exited bool
}

func (p *processExitStatus) waitGoroutine(cmd *exec.Cmd) {
	err := cmd.Wait()

	p.mu.Lock()
	p.exited = true
	p.err = err
	p.mu.Unlock()
}

func (p *processExitStatus) pollExited() error {
	p.mu.Lock()
	exited := p.exited
	err := p.err
	p.mu.Unlock()

	if !exited {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("process exited with status 0 (success)")
}

func waitForStartup(url string, process *processExitStatus) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	start := time.Now()
	end := start.Add(startupTimeout)
	for time.Now().Before(end) {
		// sleep at start of loop: allow subprocess time to start
		time.Sleep(startupCheckInterval)

		ctx, cancel := context.WithTimeout(context.Background(), startupCheckInterval)
		reqWithTimeout := req.WithContext(ctx)
		resp, err := http.DefaultClient.Do(reqWithTimeout)
		cancel()
		if err != nil {
			fmt.Println("got an error; assuming server has not started up", err)
		} else {
			fmt.Println("got a response with status:", resp.Status)
			resp.Body.Close()
			return nil
		}

		err = process.pollExited()
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("server did not start up in time")
}

// Returns an httputil.ReverseProxy.Director function that fakes IAP headers, after chaining an
// existing director function.
func makeIAPHeadersDirector(
	authenticator *googlesignin.Authenticator, wrappedDirector func(*http.Request),
) func(*http.Request) {
	return func(r *http.Request) {
		email := authenticator.MustGetEmail(r)

		// call the original director
		wrappedDirector(r)

		// Fake the IAP headers
		// TODO: Set X-Goog-IAP-JWT-Assertion?
		r.Header.Set("X-Goog-Authenticated-User-Email", "accounts.google.com:"+email)
	}
}

func main() {
	if len(os.Args) <= 1 {
		fmt.Fprintln(os.Stderr, "ERROR: must pass command line to proxy requests")
		os.Exit(1)
	}

	clientID := os.Getenv(clientIDEnvVar)
	if clientID == "" {
		panic("must specify Google OAuth Client ID with environment variable " + clientIDEnvVar)
	}
	log.Printf("Authenticating with Google OAuth client id: %s", clientID)

	listen := ":8080"
	if os.Getenv(portEnvVar) != "" {
		listen = ":" + os.Getenv(portEnvVar)
	}

	hostedDomain := os.Getenv(hostedDomainEnvVar)
	if hostedDomain != "" {
		log.Printf("Requiring accounts to have Google domain hd=%s", hostedDomain)
	}

	os.Setenv(portEnvVar, strconv.Itoa(alternatePort))

	command := os.Args[1:]
	log.Printf("starting real webserver with PORT=%d command line: %v", alternatePort, command)
	subcommand := exec.Command(command[0], command[1:]...)
	subcommand.Stdout = os.Stdout
	subcommand.Stderr = os.Stderr
	subcommand.Stdin = os.Stdin
	err := subcommand.Start()
	if err != nil {
		panic(err)
	}

	process := &processExitStatus{}
	go process.waitGoroutine(subcommand)

	// wait for the server to start listening
	hostport := fmt.Sprintf("127.0.0.1:%d", alternatePort)
	checkURL := "http://" + hostport + "/"
	parsedDestination, err := url.Parse(checkURL)
	if err != nil {
		panic(err)
	}
	err = waitForStartup(checkURL, process)
	if err != nil {
		panic(err)
	}

	log.Printf("starting proxy server listening on %s", listen)
	proxy := httputil.NewSingleHostReverseProxy(parsedDestination)

	authenticator := googlesignin.New(clientID, "/")
	authenticator.RedirectIfNotSignedIn = true
	authenticator.HostedDomain = hostedDomain
	authenticatedProxy := authenticator.RequireSignIn(proxy)

	proxy.Director = makeIAPHeadersDirector(authenticator, proxy.Director)

	err = http.ListenAndServe(listen, authenticatedProxy)
	if err != nil {
		panic(err)
	}
}
