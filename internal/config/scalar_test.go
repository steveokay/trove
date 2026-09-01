package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "30s", want: 30 * time.Second},
		{in: "15m", want: 15 * time.Minute},
		{in: "12h", want: 12 * time.Hour},
		{in: " 1h30m ", want: 90 * time.Minute},
		{in: "0", want: 0},
		{in: "", wantErr: true},
		{in: "soon", wantErr: true},
		{in: "15", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			got, err := ParseDuration(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseDuration(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q): %v", tt.in, err)
			}
			if got.Std() != tt.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.in, got.Std(), tt.want)
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "0", want: 0},
		{in: "1024", want: 1024},
		{in: "50GB", want: 50 * 1000 * 1000 * 1000},
		{in: "50gb", want: 50 * 1000 * 1000 * 1000},
		{in: "512MiB", want: 512 << 20},
		{in: "1TiB", want: 1 << 40},
		{in: " 2 GiB ", want: 2 << 30},
		{in: "1.5GiB", want: 1610612736},
		{in: "4K", want: 4 << 10},
		{in: "900B", want: 900},
		{in: "", wantErr: true},
		{in: "big", wantErr: true},
		{in: "manyGB", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			got, err := ParseBytes(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBytes(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBytes(%q): %v", tt.in, err)
			}
			if got.Int64() != tt.want {
				t.Errorf("ParseBytes(%q) = %d, want %d", tt.in, got.Int64(), tt.want)
			}
		})
	}
}

func TestBytesString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   Bytes
		want string
	}{
		{0, "0"},
		{1000, "1KB"},
		{50 * 1000 * 1000 * 1000, "50GB"},
		{1 << 10, "1KiB"},
		{512 << 20, "512MiB"},
		{1 << 30, "1GiB"},
		{1 << 40, "1TiB"},
		{-(1 << 20), "-1MiB"},
		{1234, "1234"},
		{999, "999"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := tt.in.String(); got != tt.want {
				t.Errorf("Bytes(%d).String() = %q, want %q", int64(tt.in), got, tt.want)
			}
		})
	}
}

func TestScalarYAMLRoundTrip(t *testing.T) {
	t.Parallel()

	type doc struct {
		D Duration `yaml:"d"`
		B Bytes    `yaml:"b"`
	}

	in := doc{D: Duration(15 * time.Minute), B: 512 << 20}
	data, err := yaml.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out doc
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	if out != in {
		t.Errorf("round trip = %+v, want %+v (yaml was %q)", out, in, data)
	}
}

func TestScalarYAMLErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{"duration not a string", "d: [1, 2]"},
		{"duration unparseable", "d: soon"},
		{"bytes unparseable", "b: enormous"},
		{"bytes wrong shape", "b: {a: 1}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out struct {
				D Duration `yaml:"d"`
				B Bytes    `yaml:"b"`
			}
			if err := yaml.Unmarshal([]byte(tt.yaml), &out); err == nil {
				t.Fatalf("unmarshal(%q) succeeded, want error", tt.yaml)
			}
		})
	}
}

func TestBytesAcceptsPlainYAMLInteger(t *testing.T) {
	t.Parallel()

	var out struct {
		B Bytes `yaml:"b"`
	}
	if err := yaml.Unmarshal([]byte("b: 4096"), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.B != 4096 {
		t.Errorf("B = %d, want 4096", out.B)
	}
}
