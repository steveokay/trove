package registry_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/registry"
)

// R-008. The /v2/ error envelope is the contract every OCI client parses, and
// §11 says the wire format is golden-tested. These goldens pin the exact bytes
// -- status line, headers, body -- of every shape this package can put on the
// wire: the seven renderer methods the guard calls, and one representative
// envelope per spec error code.
//
// The hidden-vs-absent byte-identity property (ADR 0003, Q18) is Z-018's and
// lives in test/disclosure/suite_test.go alongside the per-route pairs in
// blobs_test.go, manifests_test.go, and referrers_test.go. It is deliberately
// not duplicated here: this suite pins what a refusal looks like, that one
// proves two different refusals look the same.
//
// Run `go test ./internal/registry/ -run Goldens -update` to regenerate the
// files after a deliberate contract change. Review the diff -- a changed byte
// here is a changed contract, not a test to be fixed.
var goldensUpdate = flag.Bool("update", false,
	"rewrite internal/registry/testdata/errors/*.golden from the current renderers")

// goldensDir is where the pinned bytes live, relative to the package
// directory that `go test` makes the working directory.
var goldensDir = filepath.Join("testdata", "errors")

// goldensCodeRow is one representative rendering of a spec error code. The
// messages are fixtures drawn from real call sites (or, where a call site
// formats a runtime value, a fixed stand-in): what the golden pins is the
// envelope, the status, and the escaping -- not the wording.
type goldensCodeRow struct {
	file    string
	code    string
	status  int
	message string
}

// goldensCodes is the inventory of spec error codes, one row per `Code*`
// constant declared in errors.go, in declaration order. It is bound to those
// constants by TestGoldensRatchetCoversEveryCode, which parses errors.go and
// fails if a constant has no row here -- a new code cannot ship unpinned.
var goldensCodes = []goldensCodeRow{
	{"code_blob_unknown", registry.CodeBlobUnknown, http.StatusNotFound,
		"blob unknown to registry"},
	{"code_blob_upload_invalid", registry.CodeBlobUploadInvalid, http.StatusRequestedRangeNotSatisfiable,
		"chunk must continue at offset 512"},
	{"code_blob_upload_unknown", registry.CodeBlobUploadUnknown, http.StatusNotFound,
		"blob upload unknown to registry"},
	{"code_digest_invalid", registry.CodeDigestInvalid, http.StatusBadRequest,
		"manifest payload does not match the digest reference"},
	{"code_manifest_blob_unknown", registry.CodeManifestBlobUnknown, http.StatusNotFound,
		"manifest references blob sha256:0000000000000000000000000000000000000000000000000000000000000000 which is unknown to the registry"},
	// The quotes in this one are load-bearing: they pin how the encoder
	// escapes a message that embeds client input.
	{"code_manifest_invalid", registry.CodeManifestInvalid, http.StatusBadRequest,
		`invalid tag "bad tag"`},
	{"code_manifest_unknown", registry.CodeManifestUnknown, http.StatusNotFound,
		"manifest unknown to registry"},
	{"code_name_invalid", registry.CodeNameInvalid, http.StatusBadRequest,
		"repository name is not a legal path"},
	{"code_name_unknown", registry.CodeNameUnknown, http.StatusNotFound,
		"repository name not known to registry"},
	{"code_denied", registry.CodeDenied, http.StatusForbidden,
		"requested access to the resource is denied"},
	{"code_unauthorized", registry.CodeUnauthorized, http.StatusUnauthorized,
		"authentication required"},
	{"code_unsupported", registry.CodeUnsupported, http.StatusBadRequest,
		"the n parameter must be a non-negative integer"},
	{"code_too_many_requests", registry.CodeTooManyRequests, http.StatusTooManyRequests,
		"too many requests"},
	{"code_unknown", registry.CodeUnknown, http.StatusInternalServerError,
		"internal error"},
}

// goldensEscaping pins encoding/json's HTML escaping of the message field.
// A message that quotes a client-supplied reference can carry these bytes, and
// what leaves the socket is `<`, not `<`. That is the contract whether or
// not it is the one we would have chosen.
var goldensEscaping = goldensCodeRow{
	file: "envelope_escaping", code: registry.CodeManifestInvalid, status: http.StatusBadRequest,
	message: `unsupported media type "<img src=x>" & subject 'a'`,
}

// goldensRenderer is one shape produced by a SpecErrors method. render takes
// the recorder so the closure can fix every argument the method varies on.
type goldensRenderer struct {
	file   string
	render func(w http.ResponseWriter, r *http.Request)
}

// goldensRenderers covers every method of registry.SpecErrors, plus the
// branches inside them that change the bytes: Unauthorized with and without a
// challenge, and TooManyRequests both rounding up and hitting its one-second
// floor. A Retry-After of 0 would invite an immediate retry storm, so the
// floor is pinned rather than left to the reader.
var goldensRenderers = []goldensRenderer{
	{"renderer_unauthorized", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.Unauthorized(w, r, `Bearer realm="https://trove.example/token",service="trove"`)
	}},
	{"renderer_unauthorized_no_challenge", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.Unauthorized(w, r, "")
	}},
	{"renderer_forbidden", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.Forbidden(w, r)
	}},
	{"renderer_not_found", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.NotFound(w, r)
	}},
	{"renderer_bad_request", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.BadRequest(w, r, "repository name is not a legal path")
	}},
	{"renderer_too_many_requests", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.TooManyRequests(w, r, 1500*time.Millisecond)
	}},
	{"renderer_too_many_requests_floor", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.TooManyRequests(w, r, 0)
	}},
	{"renderer_rotation_required", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.RotationRequired(w, r)
	}},
	{"renderer_internal", func(w http.ResponseWriter, r *http.Request) {
		registry.SpecErrors{}.Internal(w, r)
	}},
}

// goldensRequest is the request handed to every renderer. None of them read
// it, and fixing it here keeps that visible: a renderer that starts varying on
// the request will show up as a golden that no longer reproduces.
func goldensRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/v2/team-a/api/manifests/v1", nil)
}

// goldensCanonical serialises a recorded response into the stable text form
// the goldens store: an HTTP-shaped status line, every header sorted by name
// (and values in the order they were set), a blank line, then the body bytes
// verbatim. LF throughout, so the files are identical on every platform.
func goldensCanonical(rec *httptest.ResponseRecorder) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\n", rec.Code, http.StatusText(rec.Code))

	names := make([]string, 0, len(rec.Header()))
	for name := range rec.Header() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range rec.Header().Values(name) {
			fmt.Fprintf(&b, "%s: %s\n", name, value)
		}
	}

	b.WriteString("\n")
	b.Write(rec.Body.Bytes())
	return b.Bytes()
}

// goldensPin compares got against the named golden, or rewrites it under
// -update. It is the only place that touches the files.
func goldensPin(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join(goldensDir, name+".golden")
	if *goldensUpdate {
		if err := os.MkdirAll(goldensDir, 0o750); err != nil {
			t.Fatalf("create %s: %v", goldensDir, err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v (run the suite with -update to create it)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: the wire contract changed.\n got:\n%s\nwant:\n%s", path, got, want)
	}
}

// Every SpecErrors method, byte for byte. These are the refusals the guard
// puts on the /v2/ tree, and `docker login` reads the 401's challenge off the
// wire exactly as pinned here.
func TestGoldensSpecRenderers(t *testing.T) {
	t.Parallel()

	for _, tt := range goldensRenderers {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			tt.render(rec, goldensRequest())
			goldensPin(t, tt.file, goldensCanonical(rec))
		})
	}
}

// Every spec error code the package can emit, one representative envelope
// each. The handlers reach these bytes through the unexported writeError;
// registry.WriteSpecError is the same constructor, so what is pinned is what
// blobs.go, manifests.go, tags.go, referrers.go, and uploads.go send.
func TestGoldensSpecErrorCodes(t *testing.T) {
	t.Parallel()

	rows := append(append([]goldensCodeRow(nil), goldensCodes...), goldensEscaping)
	for _, tt := range rows {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			registry.WriteSpecError(rec, tt.status, tt.code, tt.message)
			goldensPin(t, tt.file, goldensCanonical(rec))
		})
	}
}

// goldensDeclaredCodes parses errors.go and returns every `Code*` constant it
// declares, as name -> value. Reading the source rather than a hand-kept list
// is what makes the ratchet real: a constant added in a later task is visible
// here the moment it is written, with no second place to remember to update.
func goldensDeclaredCodes(t *testing.T) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "errors.go", nil, 0)
	if err != nil {
		t.Fatalf("parse errors.go: %v", err)
	}

	declared := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if !strings.HasPrefix(name.Name, "Code") || i >= len(value.Values) {
					continue
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s = %s: %v", name.Name, lit.Value, err)
				}
				declared[name.Name] = unquoted
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("errors.go declares no Code* constants: the ratchet is reading the wrong file")
	}
	return declared
}

// The ratchet. A spec error code with no golden is a shape that can reach a
// client without anyone having looked at its bytes, so adding a `Code*`
// constant to errors.go fails this test until the code is pinned. It fails the
// other way too: a golden row for a code that no longer exists is stale.
func TestGoldensRatchetCoversEveryCode(t *testing.T) {
	t.Parallel()

	pinned := map[string]string{}
	for _, row := range goldensCodes {
		if previous, ok := pinned[row.code]; ok {
			t.Errorf("%s is pinned twice: %s and %s", row.code, previous, row.file)
		}
		pinned[row.code] = row.file
	}

	declared := goldensDeclaredCodes(t)
	values := map[string]string{}
	for name, value := range declared {
		if _, ok := pinned[value]; !ok {
			t.Errorf("errors.go declares %s = %q with no golden in goldensCodes: "+
				"add a row and run -update, or the code ships unpinned", name, value)
		}
		if previous, ok := values[value]; ok {
			t.Errorf("%s and %s are both %q", previous, name, value)
		}
		values[value] = name
	}
	for code, file := range pinned {
		if _, ok := values[code]; !ok {
			t.Errorf("goldensCodes pins %q (%s) but errors.go no longer declares it", code, file)
		}
	}
}

// goldensBody returns the body half of a golden: everything after the blank
// line that ends the headers.
func goldensBody(t *testing.T, name string, raw []byte) []byte {
	t.Helper()

	_, body, found := bytes.Cut(raw, []byte("\n\n"))
	if !found {
		t.Fatalf("%s: no blank line separating headers from body", name)
	}
	return body
}

// goldensUpperSnake is the shape of a spec error code. Clients switch on these
// strings; a lower-case or hyphenated one would be silently unrecognised.
var goldensUpperSnake = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)

// Whatever the goldens say, they must still be the envelope the spec defines
// and the clients parse. This reads the committed files rather than the
// renderers, so it catches a bad -update as well as a bad renderer.
func TestGoldensBodiesAreTheSpecEnvelope(t *testing.T) {
	t.Parallel()
	if *goldensUpdate {
		t.Skip("-update rewrites the directory this test reads; rerun without it")
	}

	files, err := filepath.Glob(filepath.Join(goldensDir, "*.golden"))
	if err != nil {
		t.Fatalf("glob %s: %v", goldensDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no goldens in %s", goldensDir)
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			t.Parallel()

			raw, err := os.ReadFile(filepath.Clean(file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			// Goldens are compared byte for byte, so a CRLF checkout would
			// fail every test with an unreadable diff. Say why instead.
			if bytes.Contains(raw, []byte("\r")) {
				t.Fatalf("carriage return in the golden: it must be stored with LF endings")
			}
			if !bytes.HasPrefix(raw, []byte("HTTP/1.1 ")) {
				t.Fatalf("golden does not start with a status line")
			}
			if !bytes.Contains(raw, []byte("Content-Type: application/json\n")) {
				t.Errorf("golden does not declare the JSON content type")
			}

			var envelope struct {
				Errors []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"errors"`
			}
			body := goldensBody(t, file, raw)
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&envelope); err != nil {
				t.Fatalf("body is not the spec envelope: %v\nbody: %s", err, body)
			}
			if len(envelope.Errors) != 1 {
				t.Fatalf("envelope carries %d errors, want exactly 1", len(envelope.Errors))
			}
			if got := envelope.Errors[0].Code; !goldensUpperSnake.MatchString(got) {
				t.Errorf("code %q is not UPPER_SNAKE", got)
			}
			if envelope.Errors[0].Message == "" {
				t.Errorf("code %q carries no message", envelope.Errors[0].Code)
			}
		})
	}
}

// No golden without a row that produces it: an orphan is a shape nothing
// renders any more, and it would quietly keep passing the shape test above.
func TestGoldensHaveNoOrphanFiles(t *testing.T) {
	t.Parallel()
	if *goldensUpdate {
		t.Skip("-update rewrites the directory this test reads; rerun without it")
	}

	expected := map[string]bool{goldensEscaping.file: true}
	for _, row := range goldensCodes {
		expected[row.file] = true
	}
	for _, row := range goldensRenderers {
		expected[row.file] = true
	}

	files, err := filepath.Glob(filepath.Join(goldensDir, "*.golden"))
	if err != nil {
		t.Fatalf("glob %s: %v", goldensDir, err)
	}
	found := map[string]bool{}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".golden")
		found[name] = true
		if !expected[name] {
			t.Errorf("%s is not produced by any row: delete it or restore its row", file)
		}
	}
	for name := range expected {
		if !found[name] {
			t.Errorf("%s.golden is missing: run the suite with -update", name)
		}
	}
}
