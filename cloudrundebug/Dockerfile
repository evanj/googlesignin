# Go build image
FROM golang:1.12.9-stretch AS go_builder
COPY . /go/src/cloudrundebug
RUN go install -v /go/src/cloudrundebug

# Runtime image
FROM gcr.io/distroless/base
COPY --from=go_builder /go/bin/cloudrundebug /
ENV PORT=8080
ENTRYPOINT ["/cloudrundebug"]
EXPOSE 8080
USER nobody
