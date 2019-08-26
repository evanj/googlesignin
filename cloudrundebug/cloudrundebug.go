package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

var instanceID string
var startupTime time.Time

var endRequest = []byte("\r\n\r\n")

func readHTTPRequest(r io.Reader) ([]byte, error) {
	buf := bytes.Buffer{}
	chunk := make([]byte, 4096)
	for {
		n, err := r.Read(chunk)
		buf.Write(chunk[:n])
		if bytes.HasSuffix(buf.Bytes(), endRequest) {
			return buf.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
		log.Printf("read a chunk of %d bytes without finding the end", n)
	}
}

const maxString = 700

func truncatedString(b []byte) string {
	if len(b) > maxString {
		b = b[:maxString]
	}
	return string(b)
}

func handleRequest(conn io.ReadWriter) error {
	req, err := readHTTPRequest(conn)
	if err != nil {
		return err
	}
	log.Printf("read request %d bytes starting %#v", len(req), truncatedString(req))

	now := time.Now()
	diff := now.Sub(startupTime)
	responseBody := fmt.Sprintf("instance:%s\nstart:%s\nuptime:%s\n",
		instanceID, startupTime.Format(time.RFC3339), diff.String())

	fullResponse := &bytes.Buffer{}
	fullResponse.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain;charset=utf-8\r\nConnection: close\r\n"))
	fmt.Fprintf(fullResponse, "Date: %s\r\n", now.Format(time.RFC1123))
	fmt.Fprintf(fullResponse, "Content-Length: %d\r\n\r\n", len(responseBody))
	fullResponse.WriteString(responseBody)

	n, err := fullResponse.WriteTo(conn)
	log.Printf("wrote response %d total bytes (%d body)", n, len(responseBody))
	return err
}

func connectionGoroutine(conn net.Conn) {
	log.Printf("received connection from %s", conn.RemoteAddr().String())
	err := handleRequest(conn)
	if err != nil {
		log.Printf("error handling request: %s", err.Error())
	}
	err = conn.Close()
	if err != nil {
		log.Printf("error closing connection: %s", err.Error())
	}
}

func main() {
	startupTime = time.Now().UTC()

	portEnv := os.Getenv("PORT")
	if portEnv == "" {
		portEnv = "8080"
	}
	listenAddr := ":" + portEnv

	randBytes := make([]byte, 4)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	instanceID = hex.EncodeToString(randBytes)
	log.Printf("instance id %s listening on %s", instanceID, listenAddr)

	listen, err := net.Listen("tcp", listenAddr)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			panic(err)
		}
		go connectionGoroutine(conn)
	}
}
