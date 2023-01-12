authproxy:
	go build -o bin/authproxy cmd/authproxy/*.go

test:
	go test -count=1 ./... -coverprofile cover.out

alpine:
	go build -a -installsuffix cgo -o bin/authproxy cmd/authproxy/main.go
