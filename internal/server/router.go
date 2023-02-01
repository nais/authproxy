package server

import (
	"fmt"
	"net/http"

	"authproxy/internal/config"
	"authproxy/internal/proxy"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"
)

func Router(cfg *config.Config) chi.Router {
	rp := proxy.New(cfg.UpstreamScheme, cfg.UpstreamHost)

	r := chi.NewRouter()
	logger := proxy.LogEntry()
	r.Use(logger.Handler)
	r.Use(chimiddleware.Recoverer)

	r.HandleFunc("/isalive", func(writer http.ResponseWriter, _ *http.Request) {
		_, err := fmt.Fprintf(writer, "ok\n")
		if err != nil {
			log.Error(err)
		}
	})
	r.Handle("/*", requireAuth(cfg, rp.Handle()))
	return r
}

// fail fast if auth is not configured correctly
func requireAuth(cfg *config.Config, handler http.Handler) http.Handler {
	provider, err := cfg.Auth()
	if err != nil {
		log.Fatal(err)
	}
	h, err := provider.Handler()
	if err != nil {
		log.Fatal(err)
	}
	return h(handler)
}
