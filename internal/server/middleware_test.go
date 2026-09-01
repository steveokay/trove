package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixedClock advances by a known amount on each call so duration assertions
// are exact rather than timing-dependent.
func fixedClock(step time.Duration) func() time.Time {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	calls := 0
	return func() time.Time {
		t := base.Add(time.Duration(calls) * step)
		calls++
		return t
	}
}

func runMiddleware(t *testing.T, h http.Handler, req *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()

	var out strings.Builder
	log := slog.New(slog.NewJSONHandler(&out, nil))

	rec := httptest.NewRecorder()
	WithRequestLogging(log, fixedClock(250*time.Millisecond))(h).ServeHTTP(rec, req)

	line := strings.TrimSpace(out.String())
	if line == "" {
		t.Fatal("middleware logged nothing")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("log line is not JSON (%q): %v", line, err)
	}
	return rec, record
}

func TestRequestLoggingRecordsOutcome(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("body"))
	})

	rec, record := runMiddleware(t, h, httptest.NewRequest(http.MethodPost, "/v2/x/blobs/uploads/", nil))

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
	for key, want := range map[string]any{
		"method": "POST",
		"path":   "/v2/x/blobs/uploads/",
		"status": float64(http.StatusCreated),
		"bytes":  float64(4),
		"msg":    "request",
		"level":  "INFO",
	} {
		if record[key] != want {
			t.Errorf("log[%q] = %v, want %v", key, record[key], want)
		}
	}
	if record["duration"] != float64(250*time.Millisecond) {
		t.Errorf("duration = %v, want 250ms in nanoseconds", record["duration"])
	}
	if record["request_id"] == "" || record["request_id"] == nil {
		t.Error("log record has no request_id")
	}
}

func TestRequestLoggingAssignsAndEchoesRequestID(t *testing.T) {
	t.Parallel()

	var seen string
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	})

	rec, record := runMiddleware(t, h, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" {
		t.Fatal("handler saw no request id in its context")
	}
	if got := rec.Header().Get(RequestIDHeader); got != seen {
		t.Errorf("response header = %q, want the context id %q", got, seen)
	}
	if record["request_id"] != seen {
		t.Errorf("log id = %v, want %q", record["request_id"], seen)
	}
	if len(seen) != 32 {
		t.Errorf("request id %q is %d chars, want 32 hex chars", seen, len(seen))
	}
}

func TestRequestLoggingHonoursSuppliedRequestID(t *testing.T) {
	t.Parallel()

	const supplied = "0123456789abcdef0123456789abcdef"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, supplied)

	rec, record := runMiddleware(t, http.NotFoundHandler(), req)

	if got := rec.Header().Get(RequestIDHeader); got != supplied {
		t.Errorf("header = %q, want the supplied id", got)
	}
	if record["request_id"] != supplied {
		t.Errorf("log id = %v, want the supplied id", record["request_id"])
	}
}

func TestRequestLoggingLevelsBySeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int
		want   string
	}{
		{http.StatusOK, "INFO"},
		{http.StatusMovedPermanently, "INFO"},
		{http.StatusNotFound, "WARN"},
		{http.StatusForbidden, "WARN"},
		{http.StatusInternalServerError, "ERROR"},
		{http.StatusServiceUnavailable, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			t.Parallel()

			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			_, record := runMiddleware(t, h, httptest.NewRequest(http.MethodGet, "/", nil))

			if record["level"] != tt.want {
				t.Errorf("level = %v, want %v", record["level"], tt.want)
			}
		})
	}
}

func TestRequestLoggingDefaultsToStatusOK(t *testing.T) {
	t.Parallel()

	// A handler that writes a body without calling WriteHeader still reports 200.
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("implicit"))
	})
	_, record := runMiddleware(t, h, httptest.NewRequest(http.MethodGet, "/", nil))

	if record["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200", record["status"])
	}
	if record["bytes"] != float64(8) {
		t.Errorf("bytes = %v, want 8", record["bytes"])
	}
}

func TestRequestLoggingIgnoresRepeatedWriteHeader(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.WriteHeader(http.StatusInternalServerError) // must not change the record
	})
	_, record := runMiddleware(t, h, httptest.NewRequest(http.MethodGet, "/", nil))

	if record["status"] != float64(http.StatusTeapot) {
		t.Errorf("status = %v, want the first status written", record["status"])
	}
}

func TestRequestLoggingPreservesFlusher(t *testing.T) {
	t.Parallel()

	flushed := false
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("wrapped writer is not an http.Flusher; streaming would buffer")
			return
		}
		f.Flush()
		flushed = true
	})

	_, record := runMiddleware(t, h, httptest.NewRequest(http.MethodGet, "/", nil))

	if !flushed {
		t.Fatal("handler could not flush")
	}
	if record["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200 recorded by the implicit flush", record["status"])
	}
}

func TestContextHelpersOutsideARequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	if got := RequestID(ctx); got != "" {
		t.Errorf("RequestID(background) = %q, want empty", got)
	}

	if got := Logger(ctx, nil); got == nil {
		t.Error("Logger with no fallback returned nil, want the default logger")
	}

	custom := slog.New(slog.NewJSONHandler(nopWriter{}, nil))
	if got := Logger(ctx, custom); got != custom {
		t.Error("Logger did not return the supplied fallback")
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestLoggerReturnsRequestScopedLogger(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	log := slog.New(slog.NewJSONHandler(&out, nil))

	var fromContext *slog.Logger
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		fromContext = Logger(r.Context(), nil)
		fromContext.Info("inside handler")
	})

	WithRequestLogging(log, nil)(h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	if fromContext == nil {
		t.Fatal("handler got no logger from its context")
	}
	if !strings.Contains(out.String(), "inside handler") {
		t.Errorf("handler log line missing from output: %s", out.String())
	}
	// The request-scoped logger carries the request id, so handler lines and
	// the access-log line can be correlated.
	if !strings.Contains(out.String(), `"request_id"`) {
		t.Errorf("handler log line has no request_id: %s", out.String())
	}
}
