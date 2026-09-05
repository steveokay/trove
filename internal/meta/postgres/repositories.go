package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
)

const repositoryColumns = `name, type, config, config_version, created_at, updated_at`

func scanRepository(sc sqlutil.Scanner) (meta.Repository, error) {
	var (
		repo    meta.Repository
		typ     string
		config  []byte
		created sql.NullInt64
		updated sql.NullInt64
	)
	if err := sc.Scan(&repo.Name, &typ, &config, &repo.ConfigVersion, &created, &updated); err != nil {
		return meta.Repository{}, err
	}
	repo.Type = meta.RepositoryType(typ)
	repo.Config = json.RawMessage(config)
	repo.CreatedAt = sqlutil.AsTime(created)
	repo.UpdatedAt = sqlutil.AsTime(updated)
	return repo, nil
}

// CreateRepository stores a new repository.
func (s *Store) CreateRepository(ctx context.Context, repo meta.Repository) (meta.Repository, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Repository{}, err
	}
	if repo.Name == "" {
		return meta.Repository{}, meta.Invalid("name", "must not be empty")
	}
	if !repo.Type.Valid() {
		return meta.Repository{}, meta.Invalid("type", fmt.Sprintf("unknown repository type %q", repo.Type))
	}

	stored := repo
	stored.ConfigVersion = 1
	err := sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		taken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM repositories WHERE name = $1`, repo.Name)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("repository", repo.Name)
		}
		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO repositories (`+repositoryColumns+`) VALUES ($1, $2, $3, $4, $5, $6)`,
			repo.Name, string(repo.Type), []byte(repo.Config), 1, sqlutil.Millis(repo.CreatedAt), sqlutil.Millis(repo.UpdatedAt))
		return asConflict(err, "repository", repo.Name)
	})
	if err != nil {
		return meta.Repository{}, err
	}
	return stored, nil
}

// GetRepository returns one repository by name.
func (s *Store) GetRepository(ctx context.Context, name string) (meta.Repository, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Repository{}, err
	}
	return s.repository(ctx, s.db, name)
}

func (s *Store) repository(ctx context.Context, q sqlutil.Querier, name string) (meta.Repository, error) {
	repo, err := scanRepository(q.QueryRowContext(ctx,
		`SELECT `+repositoryColumns+` FROM repositories WHERE name = $1`, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Repository{}, meta.NotFound("repository", name)
	case err != nil:
		return meta.Repository{}, fmt.Errorf("scan repository: %w", err)
	default:
		return repo, nil
	}
}

// ListRepositories returns a permission-filtered page ordered by name.
func (s *Store) ListRepositories(ctx context.Context, opts meta.ListOptions) (meta.RepositoryPage, error) {
	if err := s.ready(ctx); err != nil {
		return meta.RepositoryPage{}, err
	}

	// The scope filter numbers its own parameters, so the cursor and the limit
	// continue from wherever it stopped.
	where, args := sqlutil.VisibilityClause("name", opts.Visibility, sqlutil.Dollar, 1)
	limit := opts.EffectiveLimit()
	cursorArg := sqlutil.Dollar(len(args) + 1)
	limitArg := sqlutil.Dollar(len(args) + 2)
	args = append(args, opts.Cursor, limit+1)

	repos, err := sqlutil.Collect(ctx, s.db,
		`SELECT `+repositoryColumns+` FROM repositories
		 WHERE `+where+` AND name > `+cursorArg+` ORDER BY name LIMIT `+limitArg,
		args, scanRepositoryRow)
	if err != nil {
		return meta.RepositoryPage{}, err
	}

	page := meta.RepositoryPage{Repositories: repos}
	if len(repos) > limit {
		page.Repositories = repos[:limit]
		page.NextCursor = repos[limit-1].Name
	}
	return page, nil
}

func scanRepositoryRow(rows *sql.Rows) (meta.Repository, error) { return scanRepository(rows) }

// UpdateRepositoryConfig replaces configuration under an optimistic version
// check, so two concurrent editors cannot silently overwrite each other, and
// records the superseded revision in the same transaction.
func (s *Store) UpdateRepositoryConfig(ctx context.Context, name string, config []byte, expectedVersion int64,
	actor string, at time.Time,
) (meta.Repository, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Repository{}, err
	}

	var updated meta.Repository
	err := sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		current, err := s.repository(ctx, tx, name)
		if err != nil {
			return err
		}
		if current.ConfigVersion != expectedVersion {
			return fmt.Errorf("%w: repository %q is at version %d, not %d",
				meta.ErrStale, name, current.ConfigVersion, expectedVersion)
		}
		// The revision goes in before the row moves on, and inside the same
		// transaction: a lineage with a gap in it is worse than no lineage,
		// because it reads as a version nobody changed (ADR 0005).
		if _, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO repository_config_history (repo_name, version, config, actor, at)
			 VALUES ($1, $2, $3, $4, $5)`,
			name, current.ConfigVersion, []byte(current.Config), actor, sqlutil.Millis(at)); err != nil {
			return err
		}
		if _, err := sqlutil.Execute(ctx, tx,
			`UPDATE repositories SET config = $1, config_version = config_version + 1, updated_at = $2
			 WHERE name = $3`,
			config, sqlutil.Millis(at), name); err != nil {
			return err
		}
		updated, err = s.repository(ctx, tx, name)
		return err
	})
	if err != nil {
		return meta.Repository{}, err
	}
	return updated, nil
}

// ListConfigHistory returns a repository's superseded configurations, oldest
// version first.
func (s *Store) ListConfigHistory(ctx context.Context, name string) ([]meta.ConfigRevision, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT repo_name, version, config, actor, at
		 FROM repository_config_history WHERE repo_name = $1 ORDER BY version`,
		[]any{name}, scanConfigRevision)
}

func scanConfigRevision(rows *sql.Rows) (meta.ConfigRevision, error) {
	var (
		revision meta.ConfigRevision
		config   []byte
		at       sql.NullInt64
	)
	if err := rows.Scan(&revision.Repository, &revision.Version, &config, &revision.Actor, &at); err != nil {
		return meta.ConfigRevision{}, err
	}
	revision.Config = json.RawMessage(config)
	revision.At = sqlutil.AsTime(at)
	return revision, nil
}

// --- proxy credentials ---

// PutProxyCredential stores or replaces a proxy repository's sealed upstream
// credential. The type check and the write share a transaction, so a
// repository converted or deleted between the two cannot leave a credential
// behind on something that is no longer a proxy.
func (s *Store) PutProxyCredential(ctx context.Context, cred meta.ProxyCredential) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if cred.Sealed == "" {
		return meta.Invalid("sealed", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		owner, err := s.repository(ctx, tx, cred.Repository)
		if err != nil {
			return err
		}
		if owner.Type != meta.Proxy {
			return meta.Invalid("repository",
				fmt.Sprintf("repository %q is a %s, not a proxy: only a proxy authenticates to an upstream",
					cred.Repository, owner.Type))
		}
		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO proxy_credentials (repo_name, sealed, rotated_at) VALUES ($1, $2, $3)
			 ON CONFLICT (repo_name) DO UPDATE SET
			     sealed = excluded.sealed,
			     rotated_at = excluded.rotated_at`,
			cred.Repository, cred.Sealed, sqlutil.Millis(cred.RotatedAt))
		return err
	})
}

// GetProxyCredential returns the sealed credential. See the interface: this is
// the one method that returns a stored secret, and the proxy client is its
// only caller.
func (s *Store) GetProxyCredential(ctx context.Context, repository string) (meta.ProxyCredential, error) {
	if err := s.ready(ctx); err != nil {
		return meta.ProxyCredential{}, err
	}

	var (
		cred    meta.ProxyCredential
		rotated sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT repo_name, sealed, rotated_at FROM proxy_credentials WHERE repo_name = $1`,
		repository).Scan(&cred.Repository, &cred.Sealed, &rotated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.ProxyCredential{}, meta.NotFound("proxy credential", repository)
	case err != nil:
		return meta.ProxyCredential{}, fmt.Errorf("scan proxy credential: %w", err)
	}
	cred.RotatedAt = sqlutil.AsTime(rotated)
	return cred, nil
}

// ProxyCredentialStatus reports set/unset and the rotation time, and selects
// no column that could carry the value.
func (s *Store) ProxyCredentialStatus(ctx context.Context, repository string) (meta.ProxyCredentialStatus, error) {
	if err := s.ready(ctx); err != nil {
		return meta.ProxyCredentialStatus{}, err
	}

	status := meta.ProxyCredentialStatus{Repository: repository}
	var rotated sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT rotated_at FROM proxy_credentials WHERE repo_name = $1`, repository).Scan(&rotated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return status, nil
	case err != nil:
		return meta.ProxyCredentialStatus{}, fmt.Errorf("scan proxy credential status: %w", err)
	}
	status.Set = true
	status.RotatedAt = sqlutil.AsTime(rotated)
	return status, nil
}

// DeleteProxyCredential removes a repository's credential.
func (s *Store) DeleteProxyCredential(ctx context.Context, repository string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db, `DELETE FROM proxy_credentials WHERE repo_name = $1`, repository)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("proxy credential", repository)
	}
	return nil
}

// DeleteRepository removes a repository entity and everything stored under it.
//
// Content is keyed by full name and no longer holds a key to this row (0004),
// so the sweep is explicit and by name: the entity itself, plus everything
// beneath it. Deleting the manifests takes their tags and reference edges with
// them through the keys 0004 kept, which is why those two tables are not
// listed here. Membership rows still cascade from the repositories row, so a
// group cannot resolve to an entity that is gone, and configuration history
// (0005) and the upstream credential (0007) cascade with them: a repository
// created at this name afterwards is a different repository and must inherit
// neither a predecessor's lineage nor its password.
//
// It is one transaction: an entity deleted without its content would leave
// content nothing can route to, and content deleted without its entity would
// lose the rows that say what it was.
func (s *Store) DeleteRepository(ctx context.Context, name string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	low, high := sqlutil.EntityContentRange(name)
	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		for _, table := range []string{"upload_sessions", "manifests"} {
			if _, err := sqlutil.Execute(ctx, tx,
				`DELETE FROM `+table+` WHERE repo_name = $1 OR (repo_name >= $2 AND repo_name < $3)`,
				name, low, high); err != nil {
				return err
			}
		}

		affected, err := sqlutil.Execute(ctx, tx, `DELETE FROM repositories WHERE name = $1`, name)
		if err != nil {
			return err
		}
		if affected == 0 {
			// Nothing existed to delete, so nothing should have been: the
			// rollback takes the content deletions above with it.
			return meta.NotFound("repository", name)
		}
		return nil
	})
}

// SetGroupMembers replaces a group's ordered member list atomically.
func (s *Store) SetGroupMembers(ctx context.Context, group string, members []meta.GroupMember) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		owner, err := s.repository(ctx, tx, group)
		if err != nil {
			return err
		}
		if owner.Type != meta.Group {
			return meta.Invalid("group", fmt.Sprintf("repository %q is a %s, not a group", group, owner.Type))
		}
		if err := s.validateMembers(ctx, tx, group, members); err != nil {
			return err
		}

		if _, err := sqlutil.Execute(ctx, tx, `DELETE FROM group_members WHERE group_name = $1`, group); err != nil {
			return err
		}
		for _, m := range members {
			if _, err := sqlutil.Execute(ctx, tx,
				`INSERT INTO group_members (group_name, member_name, position, required, write_target)
				 VALUES ($1, $2, $3, $4, $5)`,
				group, m.Repository, m.Position, m.Required, m.WriteTarget); err != nil {
				return err
			}
		}
		return nil
	})
}

// validateMembers enforces the rules that make group resolution deterministic:
// members exist, groups do not nest, positions are unique, and at most one
// member is writable (ADR 0005).
func (s *Store) validateMembers(ctx context.Context, tx *sql.Tx, group string, members []meta.GroupMember) error {
	seenPosition := make(map[int]bool, len(members))
	writeTargets := 0

	for _, m := range members {
		member, err := s.repository(ctx, tx, m.Repository)
		if err != nil {
			return err
		}
		if m.Repository == group {
			return meta.Invalid("members", "a group cannot contain itself")
		}
		if member.Type == meta.Group {
			return meta.Invalid("members", fmt.Sprintf("member %q is a group; groups do not nest (ADR 0005)", m.Repository))
		}
		if seenPosition[m.Position] {
			return meta.Invalid("members", fmt.Sprintf("duplicate position %d: member order must be unambiguous", m.Position))
		}
		seenPosition[m.Position] = true
		if m.WriteTarget {
			writeTargets++
		}
	}
	if writeTargets > 1 {
		return meta.Invalid("members", "at most one member may be the write target (ADR 0005)")
	}
	return nil
}

// ListGroupMembers returns members in resolution order.
func (s *Store) ListGroupMembers(ctx context.Context, group string) ([]meta.GroupMember, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if _, err := s.repository(ctx, s.db, group); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT member_name, position, required, write_target
		 FROM group_members WHERE group_name = $1 ORDER BY position`,
		[]any{group},
		func(rows *sql.Rows) (meta.GroupMember, error) {
			var m meta.GroupMember
			return m, rows.Scan(&m.Repository, &m.Position, &m.Required, &m.WriteTarget)
		})
}
