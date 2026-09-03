package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrorRenderer writes the refusals an authorization check produces.
//
// It is an interface because trove serves two error contracts and never mixes
// them (ADR 0015): the admin API answers with RFC 9457 problem+json, and the
// OCI routes answer with the distribution spec's error envelope (R-008).
// Handlers do not hand-roll either -- a 404 that differs by a byte from the
// genuinely-absent one is a disclosure (ADR 0003), so the constructors live in
// one place and the guard calls them.
type ErrorRenderer interface {
	// Unauthorized answers a request that may succeed with credentials, and
	// must carry the challenge: `docker login` depends on it.
	Unauthorized(w http.ResponseWriter, r *http.Request, challenge string)
	// Forbidden answers a request from a subject that can see the resource but
	// may not do this to it.
	Forbidden(w http.ResponseWriter, r *http.Request)
	// NotFound answers both a missing resource and one the subject may not
	// read. The two must be identical.
	NotFound(w http.ResponseWriter, r *http.Request)
	// BadRequest answers a request whose target could not be parsed.
	BadRequest(w http.ResponseWriter, r *http.Request, reason string)
	// TooManyRequests answers a rate-limited request with a truthful
	// Retry-After: the limiter's arithmetic is exact so the promise can be
	// (Z-002, ADR 0004).
	TooManyRequests(w http.ResponseWriter, r *http.Request, retryAfter time.Duration)
	// RotationRequired answers a subject barred pending a password change
	// (Z-014). It must say how to get out: a refusal with no door is a
	// lockout the operator reads as an outage.
	RotationRequired(w http.ResponseWriter, r *http.Request)
	// Internal answers a failure on our side. It never explains itself to the
	// client; the log carries the detail.
	Internal(w http.ResponseWriter, r *http.Request)
}

// Problem is the admin API's error body: RFC 9457 problem+json with a stable
// machine-readable type slug and the request's trace id (ADR 0015).
type Problem struct {
	// Type is the stable slug a client matches on. It is a slug rather than a
	// URL so that it can be matched without resolving anything.
	Type string `json:"type"`
	// Title is the human-readable summary for that type.
	Title string `json:"title"`
	// Status repeats the HTTP status, so a logged body is self-contained.
	Status int `json:"status"`
	// Detail explains this occurrence, when there is anything safe to say.
	Detail string `json:"detail,omitempty"`
	// TraceID ties the response to the server's logs for that request.
	TraceID string `json:"trace_id,omitempty"`
}

// The problem type slugs. They are part of the API contract: a client matches
// on these rather than on the prose, which is free to improve.
const (
	ProblemUnauthorized     = "unauthorized"
	ProblemForbidden        = "forbidden"
	ProblemNotFound         = "not-found"
	ProblemBadRequest       = "bad-request"
	ProblemRateLimited      = "rate-limited"
	ProblemRotationRequired = "rotation-required"
	ProblemInternal         = "internal"
)

// SplitErrors routes refusals by contract (ADR 0015): the /v2/ tree answers
// in the distribution spec's envelope, everything else in problem+json. The
// two are never mixed -- a docker client parsing a problem document, or a
// dashboard parsing the spec envelope, is a bug either way.
type SplitErrors struct {
	// V2 renders for paths under /v2/.
	V2 ErrorRenderer
	// Default renders everything else.
	Default ErrorRenderer
}

var _ ErrorRenderer = SplitErrors{}

func (s SplitErrors) pick(r *http.Request) ErrorRenderer {
	if r.URL.Path == "/v2" || strings.HasPrefix(r.URL.Path, "/v2/") {
		return s.V2
	}
	return s.Default
}

func (s SplitErrors) Unauthorized(w http.ResponseWriter, r *http.Request, challenge string) {
	s.pick(r).Unauthorized(w, r, challenge)
}
func (s SplitErrors) Forbidden(w http.ResponseWriter, r *http.Request) { s.pick(r).Forbidden(w, r) }
func (s SplitErrors) NotFound(w http.ResponseWriter, r *http.Request)  { s.pick(r).NotFound(w, r) }
func (s SplitErrors) BadRequest(w http.ResponseWriter, r *http.Request, reason string) {
	s.pick(r).BadRequest(w, r, reason)
}
func (s SplitErrors) TooManyRequests(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	s.pick(r).TooManyRequests(w, r, retryAfter)
}
func (s SplitErrors) RotationRequired(w http.ResponseWriter, r *http.Request) {
	s.pick(r).RotationRequired(w, r)
}
func (s SplitErrors) Internal(w http.ResponseWriter, r *http.Request) { s.pick(r).Internal(w, r) }

// ProblemErrors renders the admin API's problem+json.
type ProblemErrors struct{}

// assert the interface is satisfied at compile time.
var _ ErrorRenderer = ProblemErrors{}

// Unauthorized writes 401 with the challenge.
func (p ProblemErrors) Unauthorized(w http.ResponseWriter, r *http.Request, challenge string) {
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	p.write(w, r, http.StatusUnauthorized, ProblemUnauthorized,
		"Authentication required", "")
}

// Forbidden writes 403.
func (p ProblemErrors) Forbidden(w http.ResponseWriter, r *http.Request) {
	// Naming the missing permission would be friendlier, and is what
	// `trove auth explain` is for. The response says only that the answer is
	// no, so one message serves every verb.
	p.write(w, r, http.StatusForbidden, ProblemForbidden,
		"Permission denied", "")
}

// NotFound writes 404.
func (p ProblemErrors) NotFound(w http.ResponseWriter, r *http.Request) {
	// Byte-identical whether the resource is absent or merely unreadable
	// (ADR 0003). Nothing here varies with what the subject may see.
	p.write(w, r, http.StatusNotFound, ProblemNotFound, "Not found", "")
}

// BadRequest writes 400 with the reason.
func (p ProblemErrors) BadRequest(w http.ResponseWriter, r *http.Request, reason string) {
	p.write(w, r, http.StatusBadRequest, ProblemBadRequest, "Bad request", reason)
}

// TooManyRequests writes 429 with a Retry-After the client can trust.
func (p ProblemErrors) TooManyRequests(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	// Retry-After is integer seconds; rounding up keeps the promise true --
	// a client that waits the stated time is never refused again for being
	// a fraction of a second early.
	seconds := max(int64(retryAfter+time.Second-1)/int64(time.Second), 1)
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	p.write(w, r, http.StatusTooManyRequests, ProblemRateLimited,
		"Too many requests", "")
}

// RotationRequired writes 403 with the way out in the detail.
func (p ProblemErrors) RotationRequired(w http.ResponseWriter, r *http.Request) {
	p.write(w, r, http.StatusForbidden, ProblemRotationRequired,
		"Password rotation required",
		"change your password with POST /api/v1/auth/password, then retry")
}

// Internal writes 500 without explaining itself.
func (p ProblemErrors) Internal(w http.ResponseWriter, r *http.Request) {
	p.write(w, r, http.StatusInternalServerError, ProblemInternal,
		"Internal server error", "")
}

func (p ProblemErrors) write(w http.ResponseWriter, r *http.Request, status int, slug, title, detail string) {
	body := Problem{
		Type:    slug,
		Title:   title,
		Status:  status,
		Detail:  detail,
		TraceID: RequestID(r.Context()),
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	// A failed write is a client that hung up; there is nothing to say and
	// nowhere to say it.
	_ = json.NewEncoder(w).Encode(body)
}
