# Go build image
FROM golang:1.14.4-buster AS go_builder
COPY . /go/src/cloudrundebug
RUN go install -v /go/src/cloudrundebug

# Runtime image
FROM gcr.io/distroless/base-debian10
COPY --from=go_builder /go/bin/cloudrundebug /
ENV PORT=8080
ENTRYPOINT ["/cloudrundebug"]
EXPOSE 8080
USER nobody
