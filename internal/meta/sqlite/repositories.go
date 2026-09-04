package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

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
		taken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM repositories WHERE name = ?`, repo.Name)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("repository", repo.Name)
		}
		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO repositories (`+repositoryColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
			repo.Name, string(repo.Type), []byte(repo.Config), 1, sqlutil.Millis(repo.CreatedAt), sqlutil.Millis(repo.UpdatedAt))
		return err
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
		`SELECT `+repositoryColumns+` FROM repositories WHERE name = ?`, name))
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

	where, args := sqlutil.VisibilityClause("name", opts.Visibility, sqlutil.Question, 1)
	limit := opts.EffectiveLimit()
	args = append(args, opts.Cursor, limit+1)

	repos, err := sqlutil.Collect(ctx, s.db,
		`SELECT `+repositoryColumns+` FROM repositories WHERE `+where+` AND name > ? ORDER BY name LIMIT ?`,
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
// check, so two concurrent editors cannot silently overwrite each other.
func (s *Store) UpdateRepositoryConfig(ctx context.Context, name string, config []byte, expectedVersion int64) (meta.Repository, error) {
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
		if _, err := sqlutil.Execute(ctx, tx,
			`UPDATE repositories SET config = ?, config_version = config_version + 1 WHERE name = ?`,
			config, name); err != nil {
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

// DeleteRepository removes a repository entity and everything stored under it.
//
// Content is keyed by full name and no longer holds a key to this row (0004),
// so the sweep is explicit and by name: the entity itself, plus everything
// beneath it. Deleting the manifests takes their tags and reference edges with
// them through the keys 0004 kept, which is why those two tables are not
// listed here. Membership rows still cascade from the repositories row, so a
// group cannot resolve to an entity that is gone.
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
				`DELETE FROM `+table+` WHERE repo_name = ? OR (repo_name >= ? AND repo_name < ?)`,
				name, low, high); err != nil {
				return err
			}
		}

		affected, err := sqlutil.Execute(ctx, tx, `DELETE FROM repositories WHERE name = ?`, name)
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

		if _, err := sqlutil.Execute(ctx, tx, `DELETE FROM group_members WHERE group_name = ?`, group); err != nil {
			return err
		}
		for _, m := range members {
			if _, err := sqlutil.Execute(ctx, tx,
				`INSERT INTO group_members (group_name, member_name, position, required, write_target)
				 VALUES (?, ?, ?, ?, ?)`,
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
		 FROM group_members WHERE group_name = ? ORDER BY position`,
		[]any{group},
		func(rows *sql.Rows) (meta.GroupMember, error) {
			var m meta.GroupMember
			return m, rows.Scan(&m.Repository, &m.Position, &m.Required, &m.WriteTarget)
		})
}
