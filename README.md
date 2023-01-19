# authproxy

`authproxy` is a simple HTTP reverse proxy that enforces header based authentication before proxying the request to a upstream service.

**Example use case:** 

You have a deployment in Kubernetes and want to expose a service to the internet. You want to enforce authentication before proxying the request to the service.

* Deploy the authproxy with an ingress that exposes the service
* Deploy the service without an ingress
 
## Features

* Authentication with pre shared key, e.g. an API key
* Authentication with Google IAP JWT, e.g. the JWT produced by Google IAP
* ~~Authentication with any OAuth2 JWT, e.g. an OAuth2 Bearer JWT~~ (TODO)

## Configuration

`authproxy` can be configured using either command-line flags or equivalent environment variables (i.e. `-` -> `_`
and uppercase). E.g.:

```text
auth-provider -> AUTH_PROVIDER
```

The following flags are available:

```shell
  --auth-audience string         Auth audience, the 'aud' claim to expect in the JWT, required for --auth-provider 'iap'
  --auth-pre-shared-key string   Auth pre shared key, the pre shared key to check against, required for --auth-provider 'key'
  --auth-provider string         Auth provider, a string of either 'iap', 'key', or 'no-op'
  --auth-token-header string     Auth token header, which header to check for token, required for --auth-provider 'key'
  --bind-address string          Bind address for the authproxy, default 127.0.0.1:8080 (default "127.0.0.1:8080")
  --log-level string             Which log level to use, default 'info' (default "info")
  --metrics-bind-address string  Bind address for metrics only, default 127.0.0.1:8081 (default "127.0.0.1:8081")
  --upstream-host string         Upstream host, i.e. which host to proxy requests to
  --upstream-scheme string       Upstream scheme, the scheme to use when proxying requests, i.e. http or https (default "https")
```

## Development

### Requirements

- Go 1.19

### Binary

`make wonderwall` and `./bin/wonderwall`

See [configuration](#configuration).

### Sample kubernetes deployment

See [deployment.yaml](hack/deployment.yaml).