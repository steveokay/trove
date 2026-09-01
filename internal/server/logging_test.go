package server

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/config"
)

func TestNewLoggerFormats(t *testing.T) {
	t.Parallel()

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		var out strings.Builder
		log, err := NewLogger(config.Log{Level: "info", Format: "json"}, &out)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		log.Info("hello", slog.String("key", "value"))

		var record map[string]any
		if err := json.Unmarshal([]byte(out.String()), &record); err != nil {
			t.Fatalf("output is not JSON (%q): %v", out.String(), err)
		}
		for _, want := range []string{"time", "level", "msg", "key"} {
			if _, ok := record[want]; !ok {
				t.Errorf("record %v is missing %q", record, want)
			}
		}
		if record["msg"] != "hello" || record["key"] != "value" {
			t.Errorf("record = %v", record)
		}
	})

	t.Run("text", func(t *testing.T) {
		t.Parallel()

		var out strings.Builder
		log, err := NewLogger(config.Log{Level: "info", Format: "text"}, &out)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		log.Info("hello", slog.String("key", "value"))

		got := out.String()
		if strings.HasPrefix(got, "{") {
			t.Errorf("text handler produced JSON: %q", got)
		}
		if !strings.Contains(got, `msg=hello`) || !strings.Contains(got, `key=value`) {
			t.Errorf("output = %q, want key=value pairs", got)
		}
	})
}

func TestNewLoggerLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level     string
		wantDebug bool
		wantInfo  bool
		wantError bool
	}{
		{level: "debug", wantDebug: true, wantInfo: true, wantError: true},
		{level: "info", wantInfo: true, wantError: true},
		{level: "warn", wantError: true},
		{level: "error", wantError: true},
		{level: "INFO", wantInfo: true, wantError: true}, // case-insensitive
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			t.Parallel()

			var out strings.Builder
			log, err := NewLogger(config.Log{Level: tt.level, Format: "json"}, &out)
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}

			log.Debug("d")
			log.Info("i")
			log.Error("e")

			got := out.String()
			if strings.Contains(got, `"msg":"d"`) != tt.wantDebug {
				t.Errorf("debug emitted = %v, want %v", !tt.wantDebug, tt.wantDebug)
			}
			if strings.Contains(got, `"msg":"i"`) != tt.wantInfo {
				t.Errorf("info emitted = %v, want %v", !tt.wantInfo, tt.wantInfo)
			}
			if strings.Contains(got, `"msg":"e"`) != tt.wantError {
				t.Errorf("error emitted = %v, want %v", !tt.wantError, tt.wantError)
			}
		})
	}
}

func TestNewLoggerRejectsUnknownSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  config.Log
		want string
	}{
		{"bad level", config.Log{Level: "chatty", Format: "json"}, "unknown log level"},
		{"bad format", config.Log{Level: "info", Format: "xml"}, "unknown log format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out strings.Builder
			_, err := NewLogger(tt.cfg, &out)
			if err == nil {
				t.Fatal("NewLogger succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
