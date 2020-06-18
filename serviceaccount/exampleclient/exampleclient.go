package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/evanj/googlesignin/serviceaccount"
	"golang.org/x/oauth2"
)

func main() {
	urlString := flag.String("url", "http://localhost:8080/auth_demo", "URL to send bearer token")
	audience := flag.String("audience", "", "Audience expected by the target URL")
	flag.Parse()
	if *audience == "" {
		panic("--audience is required")
	}
	if *urlString == "" {
		panic("--url is required")
	}

	ctx := context.Background()
	tokenSource, err := serviceaccount.NewSourceFromDefault(ctx, *audience)
	if err != nil {
		panic(err)
	}
	authenticatedClient := oauth2.NewClient(ctx, tokenSource)

	log.Printf("requesting %s ...", *urlString)
	resp, err := authenticatedClient.Get(*urlString)
	if err != nil {
		panic(err)
	}
	log.Printf("Status: %s", resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("%s=%s\n", k, strings.Join(v, ", "))
	}
	fmt.Println()
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		panic(err)
	}
	err = resp.Body.Close()
	if err != nil {
		panic(err)
	}
	fmt.Println()
}
