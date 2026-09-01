package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where trove looks for a configuration file when none is given.
// Its absence is not an error; its presence and unreadability is.
const DefaultPath = "/etc/trove/trove.yaml"

// EnvPrefix prefixes every environment variable trove reads.
const EnvPrefix = "TROVE_"

// Options supplies Load's inputs. Every external dependency is injected so the
// loader is testable without touching the process environment or disk.
type Options struct {
	// Args are the command-line arguments without the program name.
	Args []string
	// LookupEnv defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// ReadFile defaults to os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Output receives flag usage and errors; defaults to io.Discard.
	Output io.Writer
}

func (o *Options) fill() {
	if o.LookupEnv == nil {
		o.LookupEnv = os.LookupEnv
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	if o.Output == nil {
		o.Output = io.Discard
	}
}

// Load resolves configuration from, in increasing order of precedence:
// defaults, the configuration file, TROVE_* environment variables, and flags.
// The returned config is validated; an invalid configuration is an error and
// the process must refuse to start.
func Load(opts Options) (*Config, error) {
	opts.fill()

	cfg := Defaults()
	sources := newSourceMap(&cfg)

	flagSet, flagValues, err := parseFlags(&cfg, opts)
	if err != nil {
		return nil, err
	}

	path, explicit := configPath(flagSet, opts)
	if err := applyFile(&cfg, sources, path, explicit, opts); err != nil {
		return nil, err
	}
	if err := applyEnv(&cfg, sources, opts.LookupEnv); err != nil {
		return nil, err
	}
	if err := applyFlags(&cfg, sources, flagValues); err != nil {
		return nil, err
	}

	cfg.deriveDefaults()
	cfg.sources = sources

	if err := cfg.validate(sources); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// field is one settable leaf of the configuration tree.
type field struct {
	path   string // dotted YAML path, e.g. "cache.tag_ttl"
	value  reflect.Value
	redact bool
}

// fieldsOf walks the configuration and returns every settable leaf.
func fieldsOf(cfg *Config) []field {
	var out []field

	var walk func(v reflect.Value, prefix string)
	walk = func(v reflect.Value, prefix string) {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			ft, fv := t.Field(i), v.Field(i)

			name, _, _ := strings.Cut(ft.Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}

			if fv.Kind() == reflect.Struct {
				walk(fv, path)
				continue
			}
			out = append(out, field{path: path, value: fv, redact: ft.Tag.Get("redact") == "true"})
		}
	}
	walk(reflect.ValueOf(cfg).Elem(), "")

	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// EnvName returns the environment variable that sets the given config path.
func EnvName(path string) string {
	return EnvPrefix + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

// FlagName returns the command-line flag that sets the given config path.
func FlagName(path string) string {
	return strings.ReplaceAll(path, "_", "-")
}

// setValue assigns a string representation to a configuration leaf.
func setValue(v reflect.Value, raw string) error {
	switch v.Interface().(type) {
	case Duration:
		d, err := ParseDuration(raw)
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(d))
		return nil
	case Bytes:
		b, err := ParseBytes(raw)
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(b))
		return nil
	}

	switch v.Kind() {
	case reflect.String:
		v.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("invalid boolean %q: use true or false", raw)
		}
		v.SetBool(b)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer %q", raw)
		}
		v.SetInt(n)
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported list type %s", v.Type())
		}
		var items []string
		for _, part := range strings.Split(raw, ",") {
			if s := strings.TrimSpace(part); s != "" {
				items = append(items, s)
			}
		}
		v.Set(reflect.ValueOf(items))
	default:
		return fmt.Errorf("unsupported type %s", v.Type())
	}
	return nil
}

// stringify renders a leaf for display.
func stringify(v reflect.Value) string {
	switch t := v.Interface().(type) {
	case Duration:
		return t.String()
	case Bytes:
		return t.String()
	}
	if v.Kind() == reflect.Slice {
		var items []string
		for i := 0; i < v.Len(); i++ {
			items = append(items, v.Index(i).String())
		}
		return strings.Join(items, ",")
	}
	return fmt.Sprintf("%v", v.Interface())
}

// parseFlags registers a flag per configuration leaf and parses args. Values
// are applied later so that flags win over every other layer.
func parseFlags(cfg *Config, opts Options) (*flag.FlagSet, map[string]string, error) {
	fs := flag.NewFlagSet("trove", flag.ContinueOnError)
	fs.SetOutput(opts.Output)

	fs.String("config", "", "path to a YAML configuration file")
	fs.Bool("no-auto-migrate", false, "do not run database migrations on startup")

	for _, f := range fieldsOf(cfg) {
		name := FlagName(f.path)
		usage := "sets " + f.path + " (env " + EnvName(f.path) + ")"
		if f.value.Kind() == reflect.Bool {
			fs.Bool(name, false, usage)
			continue
		}
		fs.String(name, "", usage)
	}

	if err := fs.Parse(opts.Args); err != nil {
		return nil, nil, fmt.Errorf("parsing flags: %w", err)
	}

	values := make(map[string]string)
	fs.Visit(func(f *flag.Flag) { values[f.Name] = f.Value.String() })
	return fs, values, nil
}

func configPath(fs *flag.FlagSet, opts Options) (path string, explicit bool) {
	if f := fs.Lookup("config"); f != nil && f.Value.String() != "" {
		return f.Value.String(), true
	}
	if v, ok := opts.LookupEnv(EnvPrefix + "CONFIG"); ok && v != "" {
		return v, true
	}
	return DefaultPath, false
}

func applyFile(cfg *Config, sources *sourceMap, path string, explicit bool, opts Options) error {
	data, err := opts.ReadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return nil // the default location is optional
		}
		return fmt.Errorf("reading config file %s: %w", path, err)
	}

	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parsing config file %s: %w", path, err)
	}

	for _, p := range presentPaths(data) {
		sources.set(p, "file "+path)
	}
	return nil
}

// presentPaths reports the dotted paths a YAML document actually sets, so
// validation errors can name the layer a value came from.
func presentPaths(data []byte) []string {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var out []string
	var walk func(m map[string]any, prefix string)
	walk = func(m map[string]any, prefix string) {
		for k, v := range m {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if nested, ok := v.(map[string]any); ok {
				walk(nested, path)
				continue
			}
			out = append(out, path)
		}
	}
	walk(raw, "")
	return out
}

func applyEnv(cfg *Config, sources *sourceMap, lookup func(string) (string, bool)) error {
	for _, f := range fieldsOf(cfg) {
		name := EnvName(f.path)
		raw, ok := lookup(name)
		if !ok {
			continue
		}
		if err := setValue(f.value, raw); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		sources.set(f.path, "env "+name)
	}
	return nil
}

func applyFlags(cfg *Config, sources *sourceMap, values map[string]string) error {
	if raw, ok := values["no-auto-migrate"]; ok {
		on, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("-no-auto-migrate: %w", err)
		}
		if on {
			cfg.Database.AutoMigrate = false
			sources.set("database.auto_migrate", "flag -no-auto-migrate")
		}
	}

	for _, f := range fieldsOf(cfg) {
		name := FlagName(f.path)
		raw, ok := values[name]
		if !ok {
			continue
		}
		if err := setValue(f.value, raw); err != nil {
			return fmt.Errorf("-%s: %w", name, err)
		}
		sources.set(f.path, "flag -"+name)
	}
	return nil
}

// sourceMap records which layer last set each configuration path.
type sourceMap struct {
	src map[string]string
}

func newSourceMap(cfg *Config) *sourceMap {
	m := &sourceMap{src: make(map[string]string)}
	for _, f := range fieldsOf(cfg) {
		m.src[f.path] = "default"
	}
	return m
}

func (m *sourceMap) set(path, source string) {
	if _, known := m.src[path]; !known {
		return // unknown keys are rejected by the YAML decoder
	}
	m.src[path] = source
}

// Source reports where the value at path came from: "default", "file <path>",
// "env TROVE_X", or "flag -x".
func (m *sourceMap) Source(path string) string {
	if s, ok := m.src[path]; ok {
		return s
	}
	return "default"
}
