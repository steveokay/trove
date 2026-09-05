package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/repo"
)

// Problem type slugs this resource adds to the admin API's contract. Both are
// 409s, and they are two slugs rather than one because a client does two
// different things about them: a taken name needs a different name, a stale
// version needs a re-read.
const (
	// ProblemConflict reports a name that is already in use.
	ProblemConflict = "conflict"
	// ProblemStaleVersion reports a failed optimistic-concurrency check.
	ProblemStaleVersion = "stale-version"
)

// maxRepositoryBodyBytes bounds an admin request body. A repository
// configuration is a handful of fields; anything approaching this is not one.
const maxRepositoryBodyBytes = 1 << 20

// RepositoryAdminStore is the slice of the metadata store the repository admin
// API writes through, declared here by the consumer (§11).
//
// It is deliberately not the whole store: this handler creates, reads,
// reconfigures, and deletes entities, and can reach no content method at all.
//
// The credential methods are the sharper case. Put, Delete and Status are here;
// meta.ProxyCredentialStore's GetProxyCredential -- the one method in the whole
// store that returns a stored secret -- is not. That is the strongest form
// C-003's acceptance criterion can take: "no read path returns a credential"
// is not a rule this handler follows, it is a value this handler's type cannot
// obtain (ADR 0016).
type RepositoryAdminStore interface {
	CreateRepository(ctx context.Context, repository meta.Repository) (meta.Repository, error)
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
	ListRepositories(ctx context.Context, opts meta.ListOptions) (meta.RepositoryPage, error)
	UpdateRepositoryConfig(ctx context.Context, name string, config []byte, expectedVersion int64,
		actor string, at time.Time) (meta.Repository, error)
	DeleteRepository(ctx context.Context, name string) error

	PutProxyCredential(ctx context.Context, cred meta.ProxyCredential) error
	ProxyCredentialStatus(ctx context.Context, repository string) (meta.ProxyCredentialStatus, error)
	DeleteProxyCredential(ctx context.Context, repository string) error
}

// Repositories serves the repository admin API (C-016, ADR 0015):
//
//	POST   /api/v1/repositories
//	GET    /api/v1/repositories
//	GET    /api/v1/repositories/{name}
//	PUT    /api/v1/repositories/{name}/config
//	DELETE /api/v1/repositories/{name}
//	PUT    /api/v1/repositories/{name}/credentials
//	DELETE /api/v1/repositories/{name}/credentials
//
// The resources are repository *entities* -- the rows a name's first path
// segment routes to (ADR 0005) -- not the OCI names that hold content. The
// catalog answers the other question, and the two are separate on purpose: an
// entity is what an operator creates and configures, a content name is what a
// client pulls from.
//
// Three of the seven routes carry a verb the guard settles by itself. Two do
// not, and they are the proxy cases: reading a proxy's configuration needs
// proxy:read on top of the repo:list that admitted the request, and changing
// one needs proxy:write on top of repo:configure. Both are ADR 0002
// conjunctions, and they are made here for the same reason the referrers
// handler makes its own -- a route declares exactly one verb, so the second
// half of a conjunction is the handler's.
//
// The remaining two are the credential routes, and they are the opposite
// shape: proxy:credentials on its own is the whole check, because it is
// implied by nothing (ADR 0002). A subject holding proxy:write and
// repo:configure -- everything needed to point the proxy somewhere else --
// still cannot set or remove its password.
//
// There is deliberately no GET of a credential, at any verb. proxy:credentials
// gates writing it, and ADR 0016 makes the read side stronger than the verb:
// the API returns set/unset and a rotation time and never a value, so there is
// no endpoint to authorize. The status rides on the repository resource, which
// is where a client is already looking.
type Repositories struct {
	// Store persists entities.
	Store RepositoryAdminStore
	// Bindings supplies effective bindings for the handler's own
	// sub-decisions.
	Bindings BindingStore
	// Keys seals an upstream credential before it is stored. Nil means the
	// credential routes refuse: a deployment without key material must not
	// quietly store a password in the clear (ADR 0016).
	//
	// It is the sealing half only. This handler has no way to open a value,
	// which is the same statement RepositoryAdminStore makes about reading one.
	Keys proxy.Sealer
	// Now supplies creation, reconfiguration, and rotation timestamps. Nil
	// means time.Now; no store reads a clock of its own (§7).
	Now func() time.Time
	// Errors renders refusals. Nil means ProblemErrors, the admin API's shape.
	Errors ErrorRenderer
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the seven routes on the table.
//
// The listing is a Listing permission, so the guard compiles the subject's
// bindings into a Visibility and the store filters inside its query -- there
// is no unfiltered read here to forget to filter (ADR 0003). The other six
// name one entity, and their resource comes out of the path, so an unusable
// name is refused before anything is looked up.
func (h *Repositories) Register(r *Router) {
	r.HandleFunc(http.MethodPost, "/api/v1/repositories",
		Permission{Verb: authz.RepoCreate}, h.create)
	r.HandleFunc(http.MethodGet, "/api/v1/repositories",
		Permission{Verb: authz.RepoList, Listing: true}, h.list)
	r.HandleFunc(http.MethodGet, "/api/v1/repositories/{name}",
		Permission{Verb: authz.RepoList, Resource: repositoryPathResource}, h.get)
	r.HandleFunc(http.MethodPut, "/api/v1/repositories/{name}/config",
		Permission{Verb: authz.RepoConfigure, Resource: repositoryPathResource}, h.updateConfig)
	r.HandleFunc(http.MethodDelete, "/api/v1/repositories/{name}",
		Permission{Verb: authz.RepoDelete, Resource: repositoryPathResource}, h.delete)
	r.HandleFunc(http.MethodPut, "/api/v1/repositories/{name}/credentials",
		Permission{Verb: authz.ProxyCredentials, Resource: repositoryPathResource}, h.setCredential)
	r.HandleFunc(http.MethodDelete, "/api/v1/repositories/{name}/credentials",
		Permission{Verb: authz.ProxyCredentials, Resource: repositoryPathResource}, h.deleteCredential)
}

// repositoryPathResource is what the verb applies to: the entity named in the
// path. The grammar check happens here, in the guard's own resolve step, so a
// name that could never be a repository is a 400 rather than a lookup.
func repositoryPathResource(r *http.Request) (authz.Resource, error) {
	return authz.Repository(r.PathValue("name"))
}

// repositoryResource is the wire representation of one entity. Field names are
// stable: the CLI's --json output and the UI both pass them through.
//
// Config is omitted rather than nulled when the subject may not read it, so
// "you may not see this" and "there is nothing here" are the same absence --
// a proxy configuration is behind proxy:read (ADR 0002), and a null would say
// that one exists.
type repositoryResource struct {
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	ConfigVersion int64           `json:"config_version"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Config        json.RawMessage `json:"config,omitempty"`
	// Credential is present for a proxy the subject may read the config of,
	// and absent otherwise -- including on every hosted and group entity,
	// which have no upstream to authenticate to.
	Credential *credentialStatusResource `json:"credential,omitempty"`
}

// credentialStatusResource is everything the API ever says about an upstream
// credential: whether one is set, and when it was last written.
//
// It has no field for a value and never will. ADR 0016 makes this stronger
// than the verb that guards writing one -- proxy:credentials does not buy a
// read, and neither does anything else -- so there is no endpoint returning a
// credential to authorize, and this type is why a future edit cannot
// accidentally add one. It is built from meta.ProxyCredentialStatus, which the
// store fills from a query that selects no column holding the ciphertext.
type credentialStatusResource struct {
	Set bool `json:"set"`
	// RotatedAt is when the credential was last written, or the zero time when
	// none is set. It is always present so a client reads one field either way.
	RotatedAt time.Time `json:"rotated_at"`
}

// credentialRequest is the body of a credential write. Both fields are
// required: a half-filled credential authenticates as nobody and produces an
// upstream 401 that reads like a wrong password rather than a missing one.
type credentialRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// repositoryListResponse is one page of entities. NextCursor is always present
// and empty on the last page: a client checks one field either way, and an
// absent one would be indistinguishable from a client that forgot to look.
type repositoryListResponse struct {
	Repositories []repositoryResource `json:"repositories"`
	NextCursor   string               `json:"next_cursor"`
}

// repositoryCreateRequest is the create body. Config is optional: hosted and
// group entities have nothing to configure yet, and a proxy without an
// upstream is refused by the parse rather than by a special case here.
type repositoryCreateRequest struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// repositoryConfigRequest is the reconfigure body. ExpectedVersion is what the
// caller last read; the store refuses the write if the stored version has
// moved on.
type repositoryConfigRequest struct {
	Config          json.RawMessage `json:"config"`
	ExpectedVersion int64           `json:"expected_version"`
}

// create serves POST /api/v1/repositories under repo:create at the system
// scope: creating an entity is not a permission over a repository, because the
// repository does not exist yet to be scoped against (ADR 0002).
func (h *Repositories) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	var request repositoryCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRepositoryBodyBytes)).Decode(&request); err != nil {
		errs.BadRequest(w, r, "the body must be JSON with name, type, and an optional config object")
		return
	}

	// One legal path segment, and not the reserved `system` prefix. The check
	// lives in internal/repo so the router and the creator cannot disagree
	// about what an entity is -- which is also what reserves `system` here.
	if err := repo.ValidateEntityName(request.Name); err != nil {
		errs.BadRequest(w, r, err.Error())
		return
	}
	repositoryType := meta.RepositoryType(request.Type)
	if !repositoryType.Valid() {
		errs.BadRequest(w, r, "type must be hosted, proxy, or group")
		return
	}
	config, ok := h.parseConfig(w, r, repositoryType, request.Config)
	if !ok {
		return
	}

	now := h.now()
	created, err := h.Store.CreateRepository(ctx, meta.Repository{
		Name:      request.Name,
		Type:      repositoryType,
		Config:    config,
		CreatedAt: now,
		UpdatedAt: now,
	})
	switch {
	case errors.Is(err, meta.ErrConflict):
		// The name is taken, and saying so discloses nothing the creator
		// could not learn by trying every name anyway -- creation is a system
		// permission, so the caller may create at any name.
		repositoryConflict(w, r, "a repository named "+request.Name+" already exists")
		return
	case errors.Is(err, meta.ErrInvalid):
		// The store's own invariants, past the checks above. Nothing should
		// reach here; if something does, it is the request's shape.
		errs.BadRequest(w, r, err.Error())
		return
	case err != nil:
		Logger(ctx, h.Log).Error("create repository", "repository", request.Name, "error", err)
		errs.Internal(w, r)
		return
	}

	w.Header().Set("Location", "/api/v1/repositories/"+created.Name)
	h.writeResource(w, r, http.StatusCreated, resourceOf(created, true))
}

// list serves GET /api/v1/repositories: a permission-filtered, cursor-
// paginated page of entities.
//
// Entries carry no configuration. The single-entity route is where a
// configuration is served, because that is where the proxy:read decision can
// be made about one repository; a listing that inlined configurations would
// either make one decision per row or leak a proxy's upstream to anyone who
// may list it.
func (h *Repositories) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	visibility, ok := VisibilityFrom(ctx)
	if !ok {
		// Unreachable on the route Register puts down: the guard stores a
		// Visibility for every Listing it admits. Without one there is no
		// filter, so this refuses rather than answering unfiltered.
		Logger(ctx, h.Log).Error("the repository listing ran outside a listing route")
		errs.Internal(w, r)
		return
	}

	query := r.URL.Query()
	limit, ok := repositoryPageSize(w, r, errs, query.Get("limit"))
	if !ok {
		return
	}

	page, err := h.Store.ListRepositories(ctx, meta.ListOptions{
		Visibility: visibility,
		Limit:      limit,
		Cursor:     query.Get("cursor"),
	})
	if err != nil {
		Logger(ctx, h.Log).Error("list repositories", "error", err)
		errs.Internal(w, r)
		return
	}

	// The slice is built non-nil so an empty page marshals as `[]`: a client
	// iterates it, and a null would make "nothing you may list" look like a
	// malformed answer.
	resources := make([]repositoryResource, 0, len(page.Repositories))
	for _, repository := range page.Repositories {
		resources = append(resources, resourceOf(repository, false))
	}
	h.writeJSON(w, r, http.StatusOK, repositoryListResponse{
		Repositories: resources,
		NextCursor:   page.NextCursor,
	})
}

// get serves GET /api/v1/repositories/{name}.
//
// A repository the subject may not list and one that does not exist answer
// identically, which is the guard's doing for the first and this handler's for
// the second: both end at the same NotFound constructor, so the two are
// byte-identical (ADR 0003).
func (h *Repositories) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	name := r.PathValue("name")
	repository, ok := h.load(w, r, name)
	if !ok {
		return
	}

	// Everything except a proxy's configuration is readable to whoever may
	// list the entity. A proxy's is its upstream, its routing rules and its
	// TTLs, which is its own permission (ADR 0002) -- so it is included only
	// for a subject that also holds proxy:read on this repository, and
	// omitted entirely otherwise. The rest of the resource still answers: the
	// entity's existence was already disclosed by admitting the request.
	includeConfig := true
	if repository.Type == meta.Proxy {
		allowed, decided := h.allows(ctx, r, authz.ProxyRead, name)
		if !decided {
			errs.Internal(w, r)
			return
		}
		includeConfig = allowed
	}

	resource := resourceOf(repository, includeConfig)
	if repository.Type == meta.Proxy && includeConfig {
		// Whether a proxy authenticates at all is part of reading its
		// configuration, so it rides the same proxy:read decision: an operator
		// diagnosing a 401 from an upstream needs to know a credential exists
		// without being able to see it. proxy:credentials buys nothing extra
		// here -- there is no larger answer for it to unlock (ADR 0016).
		status, err := h.Store.ProxyCredentialStatus(ctx, name)
		if err != nil {
			Logger(ctx, h.Log).Error("read proxy credential status", "repository", name, "error", err)
			errs.Internal(w, r)
			return
		}
		resource.Credential = &credentialStatusResource{Set: status.Set, RotatedAt: status.RotatedAt}
	}
	h.writeResource(w, r, http.StatusOK, resource)
}

// setCredential serves PUT /api/v1/repositories/{name}/credentials.
//
// proxy:credentials is the whole check and it is implied by nothing (ADR
// 0002): the subject who may repoint this proxy at another registry still
// cannot set the password it presents there. There is no second conjunct, so
// unlike updateConfig this handler makes no sub-decision of its own.
//
// The answer is 204 with no body, and that is not laziness. Echoing anything
// back would create a response shape that a later edit could grow a value
// into; the credential's state is readable in exactly one place, on the
// repository resource, and it is set/unset plus a timestamp there.
func (h *Repositories) setCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	name := r.PathValue("name")
	if _, ok := h.loadProxy(w, r, name); !ok {
		return
	}
	if h.Keys == nil {
		// Refusing beats storing something we cannot encrypt. A deployment
		// reaching here has no key material, which is a startup problem
		// (ADR 0016) that this route must not paper over.
		Logger(ctx, h.Log).Error("a credential write arrived with no keyring configured", "repository", name)
		errs.Internal(w, r)
		return
	}

	var request credentialRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRepositoryBodyBytes)).Decode(&request); err != nil {
		errs.BadRequest(w, r, "the body must be JSON with username and password")
		return
	}
	if request.Username == "" || request.Password == "" {
		errs.BadRequest(w, r, "username and password must both be set: "+
			"a half-filled credential authenticates as nobody and looks like a wrong password upstream")
		return
	}

	sealed, err := proxy.SealCredential(h.Keys, name, request.Username, request.Password)
	if err != nil {
		// proxy's errors name the repository and never the value, so this is
		// safe to log. Nothing about it is safe to return.
		Logger(ctx, h.Log).Error("seal proxy credential", "repository", name, "error", err)
		errs.Internal(w, r)
		return
	}

	switch err := h.Store.PutProxyCredential(ctx, meta.ProxyCredential{
		Repository: name, Sealed: sealed, RotatedAt: h.now(),
	}); {
	case errors.Is(err, meta.ErrNotFound):
		// Deleted between the read above and the write.
		errs.NotFound(w, r)
		return
	case errors.Is(err, meta.ErrInvalid):
		// The store's own refusal past the type check above -- the entity
		// stopped being a proxy between the two reads.
		errs.BadRequest(w, r, err.Error())
		return
	case err != nil:
		Logger(ctx, h.Log).Error("store proxy credential", "repository", name, "error", err)
		errs.Internal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteCredential serves DELETE /api/v1/repositories/{name}/credentials,
// reverting the proxy to anonymous access on its next upstream request.
//
// A repository with no credential answers 404, the same as every other delete
// in this resource. It discloses nothing new: the subject holds
// proxy:credentials, and set/unset is already on the repository resource for
// anyone who may read the configuration.
func (h *Repositories) deleteCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	name := r.PathValue("name")
	if _, ok := h.loadProxy(w, r, name); !ok {
		return
	}

	switch err := h.Store.DeleteProxyCredential(ctx, name); {
	case errors.Is(err, meta.ErrNotFound):
		errs.NotFound(w, r)
		return
	case err != nil:
		Logger(ctx, h.Log).Error("delete proxy credential", "repository", name, "error", err)
		errs.Internal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// loadProxy reads one entity and refuses anything that is not a proxy, having
// already written the refusal when it cannot.
//
// A hosted or group entity has no upstream, so it has no credential
// sub-resource; the refusal is a 400 rather than a 404 because
// proxy:credentials already admitted the request and the entity's existence
// and type are not what is being withheld -- naming the mistake is what makes
// it fixable from the response alone.
func (h *Repositories) loadProxy(w http.ResponseWriter, r *http.Request, name string) (meta.Repository, bool) {
	repository, ok := h.load(w, r, name)
	if !ok {
		return meta.Repository{}, false
	}
	if repository.Type != meta.Proxy {
		h.errors().BadRequest(w, r, "the repository "+name+" is a "+string(repository.Type)+
			", not a proxy: only a proxy authenticates to an upstream")
		return meta.Repository{}, false
	}
	return repository, true
}

// updateConfig serves PUT /api/v1/repositories/{name}/config.
//
// repo:configure got the request through the guard. For a proxy that is half
// the answer: changing an upstream, its routing rules or its TTLs is
// proxy:write as well (ADR 0002), the same conjunction the referrers API makes
// between referrer:read and repo:read. The refusal is a 403 rather than a 404
// because repo:configure already admitted the request, so the entity's
// existence is not what is being withheld.
func (h *Repositories) updateConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	name := r.PathValue("name")
	repository, ok := h.load(w, r, name)
	if !ok {
		return
	}
	if repository.Type == meta.Proxy {
		allowed, decided := h.allows(ctx, r, authz.ProxyWrite, name)
		switch {
		case !decided:
			errs.Internal(w, r)
			return
		case !allowed:
			errs.Forbidden(w, r)
			return
		}
	}

	var request repositoryConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRepositoryBodyBytes)).Decode(&request); err != nil {
		errs.BadRequest(w, r, "the body must be JSON with config and expected_version")
		return
	}
	// Validated against the entity's own type, and before the write: a stored
	// configuration is read back on every request path (ADR 0005), so nothing
	// unusable may reach the store even for a moment.
	config, ok := h.parseConfig(w, r, repository.Type, request.Config)
	if !ok {
		return
	}

	subject, _ := SubjectFrom(ctx)
	updated, err := h.Store.UpdateRepositoryConfig(ctx, name, config, request.ExpectedVersion,
		subject.Name, h.now())
	switch {
	case errors.Is(err, meta.ErrStale):
		repositoryStale(w, r, "the repository was reconfigured since you read it: "+
			"re-read GET /api/v1/repositories/"+name+" and retry with its config_version")
		return
	case errors.Is(err, meta.ErrNotFound):
		// Deleted between the read above and the write. The answer is the one
		// an absent repository gets.
		errs.NotFound(w, r)
		return
	case err != nil:
		Logger(ctx, h.Log).Error("update repository config", "repository", name, "error", err)
		errs.Internal(w, r)
		return
	}

	// The configuration is echoed back whatever the type: it is the document
	// the caller just supplied, so returning it discloses nothing they did
	// not already know.
	h.writeResource(w, r, http.StatusOK, resourceOf(updated, true))
}

// delete serves DELETE /api/v1/repositories/{name}.
//
// Deleting a hosted entity destroys content that only exists here, so it takes
// a confirmation: `?confirm=<name>` must repeat the name exactly. The store's
// delete cascades over every content row under the entity (ADR 0005) and the
// blob bytes wait for garbage collection, which is the only grace window there
// is -- there is no trash can (Q16).
//
// Proxy and group deletions need no confirmation, and the difference is not
// leniency. A proxy's content is a cache: every byte of it is re-fetchable
// from the upstream, so deleting one costs a re-fetch. A group stores nothing
// at all -- it resolves to members, and deleting it never touches their
// content (ADR 0005).
func (h *Repositories) delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	name := r.PathValue("name")
	repository, ok := h.load(w, r, name)
	if !ok {
		return
	}
	if repository.Type == meta.Hosted && r.URL.Query().Get("confirm") != name {
		errs.BadRequest(w, r, "deleting the hosted repository "+name+
			" is irreversible: it destroys every manifest, tag, and upload stored under it, "+
			"and the blobs are reclaimed by garbage collection. Repeat the name as ?confirm="+name+" to proceed")
		return
	}

	switch err := h.Store.DeleteRepository(ctx, name); {
	case errors.Is(err, meta.ErrNotFound):
		errs.NotFound(w, r)
		return
	case err != nil:
		Logger(ctx, h.Log).Error("delete repository", "repository", name, "error", err)
		errs.Internal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// load reads one entity, having already written the refusal when it cannot.
func (h *Repositories) load(w http.ResponseWriter, r *http.Request, name string) (meta.Repository, bool) {
	repository, err := h.Store.GetRepository(r.Context(), name)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		h.errors().NotFound(w, r)
		return meta.Repository{}, false
	case err != nil:
		Logger(r.Context(), h.Log).Error("read repository", "repository", name, "error", err)
		h.errors().Internal(w, r)
		return meta.Repository{}, false
	}
	return repository, true
}

// allows answers the handler's own half of an ADR 0002 conjunction against the
// same live bindings the guard used. The second result is false when the
// question could not be answered at all: a check that could not read its
// bindings has decided nothing, and treating that as a grant is how an outage
// becomes a disclosure.
func (h *Repositories) allows(ctx context.Context, r *http.Request, verb authz.Verb, name string) (allowed, decided bool) {
	// The guard put the subject there. Outside a guarded route the zero
	// subject holds no bindings, so this still fails closed.
	subject, _ := SubjectFrom(ctx)

	bindings, err := FetchBindings(ctx, h.Bindings, subject.Name)
	if err != nil {
		Logger(ctx, h.Log).Error("authorization could not read bindings",
			"subject", subject.Name, "verb", verb, "repository", name, "error", err)
		return false, false
	}
	resource, err := authz.Repository(name)
	if err != nil {
		// Unreachable: the guard resolved the same name before admitting the
		// request. A name the grammar rejects grants nothing either way.
		Logger(ctx, h.Log).Error("a guarded repository name failed the grammar",
			"repository", name, "error", err)
		return false, false
	}
	return authz.Allows(bindings, verb, resource), true
}

// parseConfig validates a submitted configuration against the entity type and
// returns its canonical stored form, having written the refusal when it cannot.
//
// The stored bytes are the parsed configuration marshalled again rather than
// the caller's document verbatim. internal/repo owns the shape (ADR 0005), so
// what is stored is what the type means: key order and whitespace never become
// contract, every stored document parses by construction, and the config
// history reads as a sequence of comparable documents.
func (h *Repositories) parseConfig(w http.ResponseWriter, r *http.Request,
	repositoryType meta.RepositoryType, raw json.RawMessage,
) ([]byte, bool) {
	parsed, err := repo.ParseConfig(repositoryType, raw)
	if err != nil {
		// The message names the field that was refused, which is what makes a
		// typo in a config key fixable from the response alone.
		h.errors().BadRequest(w, r, err.Error())
		return nil, false
	}
	config, err := json.Marshal(parsed)
	if err != nil {
		// A validated config that will not marshal is a bug in this process,
		// not in the request.
		Logger(r.Context(), h.Log).Error("render repository config", "error", err)
		h.errors().Internal(w, r)
		return nil, false
	}
	return config, true
}

// resourceOf renders a stored repository. withConfig is the proxy:read
// decision for a proxy and true otherwise.
func resourceOf(repository meta.Repository, withConfig bool) repositoryResource {
	resource := repositoryResource{
		Name:          repository.Name,
		Type:          string(repository.Type),
		ConfigVersion: repository.ConfigVersion,
		CreatedAt:     repository.CreatedAt,
		UpdatedAt:     repository.UpdatedAt,
	}
	if withConfig {
		// A row written before this API existed may hold no bytes at all.
		// `{}` is what the zero configuration of every type marshals to, so
		// that is what an empty column means.
		resource.Config = json.RawMessage(`{}`)
		if len(repository.Config) > 0 {
			resource.Config = repository.Config
		}
	}
	return resource
}

// repositoryPageSize reads the ADR 0015 `limit`. Absent means the store's
// default, and so does an explicit zero -- a client asking for nothing is
// asking for the default rather than for an empty page it could not paginate
// out of. Anything unparseable or negative is named as the client's mistake:
// a silent fallback would page differently from what the client asked for.
func repositoryPageSize(w http.ResponseWriter, r *http.Request, errs ErrorRenderer, raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 0 {
		errs.BadRequest(w, r, "the limit parameter must be a non-negative integer")
		return 0, false
	}
	return limit, true
}

// repositoryConflict and repositoryStale render the two 409s.
//
// ErrorRenderer has no method for either, and deliberately: a conflict is not
// a refusal an authorization check can produce, so the guard has no use for
// one. These routes live only under /api/v1, where the contract is problem+json
// whichever renderer is injected, so they go through the same constructor the
// rest of the admin API's problems do (ADR 0015).
func repositoryConflict(w http.ResponseWriter, r *http.Request, detail string) {
	ProblemErrors{}.write(w, r, http.StatusConflict, ProblemConflict, "Conflict", detail)
}

func repositoryStale(w http.ResponseWriter, r *http.Request, detail string) {
	ProblemErrors{}.write(w, r, http.StatusConflict, ProblemStaleVersion, "Stale version", detail)
}

func (h *Repositories) writeResource(w http.ResponseWriter, r *http.Request, status int, resource repositoryResource) {
	h.writeJSON(w, r, status, resource)
}

func (h *Repositories) writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is gone; all that is left is to say so.
		Logger(r.Context(), h.Log).Error("write repository response", "error", err)
	}
}

func (h *Repositories) now() time.Time {
	if h.Now == nil {
		return time.Now()
	}
	return h.Now()
}

func (h *Repositories) errors() ErrorRenderer {
	if h.Errors == nil {
		return ProblemErrors{}
	}
	return h.Errors
}
