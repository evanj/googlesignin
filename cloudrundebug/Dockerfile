# Go build image
FROM golang:1.20.1-bullseye AS go_builder
COPY . /go/src/cloudrundebug
WORKDIR /go/src/cloudrundebug
RUN go mod init github.com/evanj/googlesignin/cloudrundebug && \
	go install -v /go/src/cloudrundebug

# Runtime image
FROM gcr.io/distroless/base-debian11:latest-amd64
COPY --from=go_builder /go/bin/cloudrundebug /
ENV PORT=8080
ENTRYPOINT ["/cloudrundebug"]
EXPOSE 8080
USER nobody
