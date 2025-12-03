package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"
)

var logger *requestLogger

type LogEntryMiddleware struct{}

// LogEntry is copied verbatim from httplog package to replace with our own requestLogger implementation.
func LogEntry() LogEntryMiddleware {
	logger = &requestLogger{Logger: log.StandardLogger()}
	return LogEntryMiddleware{}
}

func (l *LogEntryMiddleware) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		entry := logger.NewLogEntry(r)
		entry.WithRequestLogFields(r).Infof("%s - %s", r.Method, r.URL.Path)

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		t1 := time.Now()
		defer func() {
			entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), nil)
		}()

		next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
	}
	return http.HandlerFunc(fn)
}

func LogEntryFrom(r *http.Request) *log.Entry {
	ctx := r.Context()
	val := ctx.Value(middleware.LogEntryCtxKey)
	entry, ok := val.(*requestLoggerEntry)
	if ok {
		return entry.Logger
	}

	entry = logger.NewLogEntry(r)
	return entry.Logger
}

type requestLogger struct {
	Logger *log.Logger
}

func (l *requestLogger) NewLogEntry(r *http.Request) *requestLoggerEntry {
	entry := &requestLoggerEntry{}
	correlationID := middleware.GetReqID(r.Context())

	fields := log.Fields{
		"correlation_id":     correlationID,
		"request_host":       r.Host,
		"request_method":     r.Method,
		"request_path":       r.URL.Path,
		"request_user_agent": r.UserAgent(),
	}

	entry.Logger = l.Logger.WithFields(fields)
	return entry
}

type requestLoggerEntry struct {
	Logger *log.Entry
}

func (l *requestLoggerEntry) WithRequestLogFields(r *http.Request) *log.Entry {
	referer := r.Referer()
	refererUrl, err := url.Parse(referer)
	if err == nil {
		refererUrl.RawQuery = ""
		refererUrl.RawFragment = ""
		referer = refererUrl.String()
	}

	fields := log.Fields{
		"request_host":       r.Host,
		"request_method":     r.Method,
		"request_path":       r.URL.Path,
		"request_protocol":   r.Proto,
		"request_referer":    referer,
		"request_user_agent": r.UserAgent(),
	}

	return l.Logger.WithFields(fields)
}

func (l *requestLoggerEntry) Write(status, bytes int, _ http.Header, elapsed time.Duration, _ any) {
	msg := fmt.Sprintf("response: HTTP %d (%s)", status, statusLabel(status))
	fields := log.Fields{
		"response_status":     status,
		"response_bytes":      bytes,
		"response_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0, // in milliseconds, with fractional
	}

	entry := l.Logger.WithFields(fields)

	switch {
	case status >= 400:
		entry.Info(msg)
	default:
		entry.Debug(msg)
	}
}

func (l *requestLoggerEntry) Panic(v interface{}, _ []byte) {
	stacktrace := "#"

	fields := log.Fields{
		"stacktrace": stacktrace,
		"error":      fmt.Sprintf("%+v", v),
	}

	l.Logger = l.Logger.WithFields(fields)
}

func statusLabel(status int) string {
	switch {
	case status >= 100 && status < 300:
		return "OK"
	case status >= 300 && status < 400:
		return "Redirect"
	case status >= 400 && status < 500:
		return "Client Error"
	case status >= 500:
		return "Server Error"
	default:
		return "Unknown"
	}
}

type logrusErrorWriter struct{}

func (w logrusErrorWriter) Write(p []byte) (n int, err error) {
	log.Warnf("%s", string(p))
	return len(p), nil
}
