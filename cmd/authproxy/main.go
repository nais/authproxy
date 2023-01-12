package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"authproxy/internal/config"
	"authproxy/internal/proxy"
	"authproxy/internal/server"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
)

var cfg = config.DefaultConfig()

func init() {
	flag.StringVar(&cfg.BindAddress, "bind-address", cfg.BindAddress, "Bind address")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "which log level to output")
	flag.StringVar(&cfg.UpstreamHost, "upstream-host", cfg.UpstreamHost, "Upstream host")
	flag.StringVar(&cfg.AuthProvider, "auth-provider", cfg.AuthProvider, "Auth provider")
}

func main() {
	parseFlags()
	setupLogger()

	rp := proxy.New(cfg.UpstreamHost)

	r := chi.NewRouter()
	logger := proxy.LogEntry()
	r.Use(logger.Handler)
	r.Use(chimiddleware.Recoverer)

	auth, err := cfg.Auth()
	if err != nil {
		log.Fatal(err)
	}

	r.HandleFunc("/isalive", func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(writer, "ok\n")
	})
	r.Handle("/*", auth(rp.Handle()))

	if err := server.Start(cfg.BindAddress, r); err != nil {
		log.Fatal(err)
	}
}

func parseFlags() {
	err := godotenv.Load()
	if err != nil {
		log.Infof("loading .env file %v", err)
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
