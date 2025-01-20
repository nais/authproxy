FROM golang:1.23.5-alpine as builder
RUN apk add --no-cache git make curl
ENV GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE=on
COPY . /src
WORKDIR /src
RUN make test
RUN make alpine

FROM alpine:3
RUN export PATH=$PATH:/app
WORKDIR /app
COPY --from=builder /src/bin/authproxy /app/authproxy
ENTRYPOINT ["/app/authproxy"]
