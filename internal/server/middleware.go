package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

// RequestIDHeader carries the per-request identifier back to the client so a
// user reporting a failure can quote something findable in the logs.
const RequestIDHeader = "Trove-Request-Id"

type contextKey int

const (
	requestIDKey contextKey = iota
	loggerKey
)

// RequestID returns the identifier assigned to a request, or "" outside one.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// Logger returns the request-scoped logger, falling back to fallback (or the
// default logger) outside a request.
func Logger(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return l
	}
	if fallback != nil {
		return fallback
	}
	return slog.Default()
}

// newRequestID returns a 128-bit hex identifier. crypto/rand cannot fail in
// practice; if it ever did, a timestamp-derived id is still more useful than
// no id at all, and nothing security-relevant depends on this value.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// WithRequestLogging assigns each request an identifier, attaches a logger
// carrying it to the request context, and logs the outcome once the handler
// returns.
func WithRequestLogging(log *slog.Logger, clock func() time.Time) func(http.Handler) http.Handler {
	if clock == nil {
		clock = time.Now
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(RequestIDHeader)
			if id == "" {
				id = newRequestID()
			}

			reqLog := log.With(
				slog.String("request_id", id),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			)

			ctx := context.WithValue(r.Context(), requestIDKey, id)
			ctx = context.WithValue(ctx, loggerKey, reqLog)

			w.Header().Set(RequestIDHeader, id)
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			start := clock()
			next.ServeHTTP(rec, r.WithContext(ctx))
			elapsed := clock().Sub(start)

			level := slog.LevelInfo
			switch {
			case rec.status >= 500:
				level = slog.LevelError
			case rec.status >= 400:
				level = slog.LevelWarn
			}

			reqLog.LogAttrs(ctx, level, "request",
				slog.Int("status", rec.status),
				slog.Int64("bytes", rec.written),
				slog.Duration("duration", elapsed),
				slog.String("remote_addr", r.RemoteAddr),
			)
		})
	}
}

// statusRecorder captures what a handler wrote so the access log can report
// it. It deliberately implements only the interfaces we use.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	written     int64
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

// Flush forwards to the underlying writer when it supports flushing, so
// streaming responses (blob pulls) are not buffered by this wrapper.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		if !r.wroteHeader {
			r.WriteHeader(http.StatusOK)
		}
		f.Flush()
	}
}
