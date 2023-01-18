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
	flag.StringVar(&cfg.BindAddress, "bind-address", cfg.BindAddress, "Bind address")
	flag.StringVar(&cfg.MetricsBindAddress, "metrics-bind-address", cfg.MetricsBindAddress, "Metrics bind address")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "which log level to output")
	flag.StringVar(&cfg.UpstreamHost, "upstream-host", cfg.UpstreamHost, "Upstream host")
	flag.StringVar(&cfg.AuthProvider, "auth-provider", cfg.AuthProvider, "Auth provider")
	flag.StringVar(&cfg.AuthIssuer, "auth-issuer", cfg.AuthIssuer, "Auth issuer")
	flag.StringVar(&cfg.AuthAudience, "auth-audience", cfg.AuthAudience, "Auth audience")
	flag.StringVar(&cfg.AuthTokenHeader, "auth-token-header", cfg.AuthTokenHeader, "Auth token header")
	flag.StringVar(&cfg.AuthPreSharedKey, "auth-pre-shared-key", cfg.AuthPreSharedKey, "Auth pre shared key")
	flag.StringVar(&cfg.UpstreamScheme, "upstream-scheme", cfg.UpstreamScheme, "Upstream scheme")
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
