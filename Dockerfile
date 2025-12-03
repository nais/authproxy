FROM golang:1.25 AS builder
ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=0

COPY . /src
WORKDIR /src
RUN go test -count=1 ./... -coverprofile cover.out

ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -o bin/authproxy cmd/authproxy/main.go

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /src/bin/authproxy /app/authproxy
ENTRYPOINT ["/app/authproxy"]
