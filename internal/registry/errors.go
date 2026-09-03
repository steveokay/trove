// Package registry implements the OCI distribution API's hosted handlers
// (Phase 3): blobs and uploads now, manifests, tags, and referrers as their
// tasks land. It is a client of the guarded router (Z-010) and of the blob
// and metadata stores; it owns the spec's wire shapes and nothing else.
package registry

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// The distribution spec's error codes this phase speaks. The envelope and
// codes are contract (§11); R-008 pins them with golden files across every
// route.
const (
	CodeBlobUnknown       = "BLOB_UNKNOWN"
	CodeBlobUploadInvalid = "BLOB_UPLOAD_INVALID"
	CodeBlobUploadUnknown = "BLOB_UPLOAD_UNKNOWN"
	CodeDigestInvalid     = "DIGEST_INVALID"
	CodeNameInvalid       = "NAME_INVALID"
	CodeNameUnknown       = "NAME_UNKNOWN"
	CodeDenied            = "DENIED"
	CodeUnauthorized      = "UNAUTHORIZED"
	CodeUnsupported       = "UNSUPPORTED"
	CodeTooManyRequests   = "TOOMANYREQUESTS"
	CodeUnknown           = "UNKNOWN"
)

// specError is one entry of the spec's error envelope.
type specError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError answers in the spec's envelope. Handlers do not hand-roll
// bodies: one constructor is what keeps the unauthorized-read 404 and the
// genuinely-absent 404 byte-identical (ADR 0003).
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Errors []specError `json:"errors"`
	}{Errors: []specError{{Code: code, Message: message}}})
}

// SpecErrors renders the guard's refusals in the distribution envelope, so
// the /v2/ tree never speaks problem+json (ADR 0015). It is handed to the
// router through server.SplitErrors at wiring time.
type SpecErrors struct{}

// Unauthorized writes 401 with the challenge -- the `docker login` contract.
func (SpecErrors) Unauthorized(w http.ResponseWriter, r *http.Request, challenge string) {
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
}

// Forbidden writes 403 DENIED.
func (SpecErrors) Forbidden(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusForbidden, CodeDenied, "requested access to the resource is denied")
}

// NotFound writes the 404 that is byte-identical for absent and unreadable
// alike (ADR 0003, Q18).
func (SpecErrors) NotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
}

// BadRequest writes 400. On this tree an unusable request target is almost
// always an illegal repository name.
func (SpecErrors) BadRequest(w http.ResponseWriter, r *http.Request, reason string) {
	writeError(w, http.StatusBadRequest, CodeNameInvalid, reason)
}

// TooManyRequests writes 429 with a truthful Retry-After (Z-002).
func (SpecErrors) TooManyRequests(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	seconds := max(int64(retryAfter+time.Second-1)/int64(time.Second), 1)
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeError(w, http.StatusTooManyRequests, CodeTooManyRequests, "too many requests")
}

// RotationRequired writes 403 DENIED with the way out: docker cannot act on
// it, but the operator reading the message can.
func (SpecErrors) RotationRequired(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusForbidden, CodeDenied,
		"password rotation required: change it with POST /api/v1/auth/password, then retry")
}

// Internal writes 500 without explaining itself.
func (SpecErrors) Internal(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
}
