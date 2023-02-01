package main

import (
	"flag"
	"net/http"
	"os"
	"strings"

	"authproxy/internal/config"
	"authproxy/internal/server"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var cfg = config.DefaultConfig()

func init() {
	flag.StringVar(&cfg.BindAddress, "bind-address", cfg.BindAddress, "Bind address for the authproxy, default 127.0.0.1:8080")
	flag.StringVar(&cfg.MetricsBindAddress, "metrics-bind-address", cfg.MetricsBindAddress, "Bind address for metrics only, default 127.0.0.1:8081")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "which log level to use, default 'info'")
	flag.StringVar(&cfg.UpstreamHost, "upstream-host", cfg.UpstreamHost, "Upstream host, i.e. which host to proxy requests to")
	flag.StringVar(&cfg.AuthProvider, "auth-provider", cfg.AuthProvider, "Auth provider, a string of either 'iap', 'key', or 'no-op'")
	flag.StringVar(&cfg.AuthAudience, "auth-audience", cfg.AuthAudience, "Auth audience, the 'aud' claim to expect in the JWT, required for --auth-provider 'iap'")
	flag.StringVar(&cfg.AuthJwksUrl, "auth-jwks-url", cfg.AuthJwksUrl, "The URL to fetch the JWKS from, required for --auth-provider 'jwt'")
	flag.StringVar(&cfg.AuthRequiredClaims, "auth-required-claims", cfg.AuthRequiredClaims, "Comma separated list of required JWT claims as key/value pairs, i.e. 'key1=value1,key2=value2'. Used for auth-provider 'jwt'")
	flag.StringVar(&cfg.AuthTokenHeader, "auth-token-header", cfg.AuthTokenHeader, "Auth token header, which header to check for token, required for --auth-provider 'key'")
	flag.StringVar(&cfg.AuthPreSharedKey, "auth-pre-shared-key", cfg.AuthPreSharedKey, "Auth pre shared key, the pre shared key to check against, required for --auth-provider 'key'")
	flag.StringVar(&cfg.UpstreamScheme, "upstream-scheme", cfg.UpstreamScheme, "Upstream scheme, the scheme to use when proxying requests, i.e. http or https")
}

func main() {
	parseFlags()
	setupLogger()

	r := server.Router(cfg)

	go func() {
		err := handleMetrics(cfg.MetricsBindAddress)
		if err != nil {
			log.Fatalf("fatal: metrics server error: %s", err)
		}
	}()

	if err := server.Start(cfg.BindAddress, r); err != nil {
		log.Fatal(err)
	}
}

func handleMetrics(address string) error {
	handler := promhttp.Handler()
	return http.ListenAndServe(address, handler)
}

func parseFlags() {
	err := godotenv.Load()
	if err != nil {
		log.Debugf("loading .env file %v", err)
	}

	flag.VisitAll(func(f *flag.Flag) {
		name := strings.ToUpper(strings.Replace(f.Name, "-", "_", -1))
		if value, ok := os.LookupEnv(name); ok {
			err = flag.Set(f.Name, value)
			if err != nil {
				log.Fatalf("failed setting flag from environment: %v", err)
				return
			}
		}
	})

	flag.Parse()
}

func setupLogger() {
	log.SetFormatter(&log.JSONFormatter{})
	l, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(l)
}
