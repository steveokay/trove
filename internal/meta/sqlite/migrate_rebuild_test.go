package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta/migrate"
)

// 0004 rebuilds two tables to drop a foreign key SQLite cannot drop in place.
// A rebuild that loses rows is the worst kind of migration bug -- it succeeds,
// it is recorded in the ledger, and the data is gone -- and the specific
// hazard here is that dropping `manifests` while `tags` and `manifest_refs`
// still reference it fires their ON DELETE CASCADE. So the rebuild is run
// against a database holding a row in every table it touches, and every row is
// counted back afterwards.

// migrationsUpTo returns the migrations at or below version, which is how a
// test gets a database at the schema an upgrade would find.
func migrationsUpTo(t *testing.T, version int) []migrate.Migration {
	t.Helper()

	all, err := migrate.Load(migrationFiles)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var out []migrate.Migration
	for _, m := range all {
		if m.Version <= version {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no migrations at or below version %d", version)
	}
	return out
}

func TestMigration0004PreservesEveryRowItRebuilds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db, err := sql.Open("sqlite", dsn(filepath.Join(t.TempDir(), "rebuild.db"), time.Second))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	all, err := migrate.Load(migrationFiles)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := migrate.Apply(ctx, db, dialect, migrationsUpTo(t, 3), failureTestTime); err != nil {
		t.Fatalf("apply up to 0003: %v", err)
	}

	// One row in each table the rebuild moves, wired together the way the
	// schema intends: a manifest with an edge, a tag pointing at it, and an
	// upload session beside them.
	seed := []struct {
		what string
		stmt string
		args []any
	}{
		{"repository", `INSERT INTO repositories (name, type, config_version) VALUES ('team-a', 'hosted', 1)`, nil},
		{"manifest", `INSERT INTO manifests (repo_name, digest, media_type, artifact_type, subject_digest, payload, size, created_at)
			VALUES ('team-a', 'sha256:aa', 'application/vnd.oci.image.manifest.v1+json', 'app/spdx', 'sha256:bb', ?, 19, 1000)`,
			[]any{[]byte(`{"schemaVersion":2}`)}},
		{"manifest ref", `INSERT INTO manifest_refs (repo_name, manifest_digest, ordinal, child_digest, kind)
			VALUES ('team-a', 'sha256:aa', 0, 'sha256:cc', 'layer')`, nil},
		{"tag", `INSERT INTO tags (repo_name, name, manifest_digest, created_at, updated_at)
			VALUES ('team-a', 'latest', 'sha256:aa', 1000, 2000)`, nil},
		{"upload session", `INSERT INTO upload_sessions (id, repo_name, digest, bytes, started_at, last_chunk_at)
			VALUES ('u1', 'team-a', 'sha256:dd', 42, 1000, 2000)`, nil},
	}
	for _, s := range seed {
		if _, err := db.ExecContext(ctx, s.stmt, s.args...); err != nil {
			t.Fatalf("seed %s: %v", s.what, err)
		}
	}

	if _, err := migrate.Apply(ctx, db, dialect, all, failureTestTime); err != nil {
		t.Fatalf("apply 0004: %v", err)
	}

	for _, table := range []string{"repositories", "manifests", "manifest_refs", "tags", "upload_sessions"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("%s holds %d rows after the rebuild, want the 1 it started with", table, count)
		}
	}

	// The manifest's columns survive the copy, blob payload included: a rebuild
	// that dropped a default or reordered a column would show up here.
	var (
		mediaType string
		artifact  string
		subject   string
		payload   []byte
		size      int64
		created   int64
	)
	if err := db.QueryRowContext(ctx,
		`SELECT media_type, artifact_type, subject_digest, payload, size, created_at
		   FROM manifests WHERE repo_name = 'team-a' AND digest = 'sha256:aa'`).
		Scan(&mediaType, &artifact, &subject, &payload, &size, &created); err != nil {
		t.Fatalf("read the rebuilt manifest: %v", err)
	}
	if mediaType != "application/vnd.oci.image.manifest.v1+json" || artifact != "app/spdx" ||
		subject != "sha256:bb" || string(payload) != `{"schemaVersion":2}` || size != 19 || created != 1000 {
		t.Errorf("manifest came back as %q/%q/%q/%q/%d/%d", mediaType, artifact, subject, payload, size, created)
	}

	// The point of the whole migration: content whose name has a remainder,
	// with only its entity in repositories, is now storable.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO manifests (repo_name, digest) VALUES ('team-a/api', 'sha256:ee')`); err != nil {
		t.Errorf("content under a remainder is still refused: %v", err)
	}

	// The keys that stayed are still enforced: a tag may not point at a
	// manifest that is not there.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tags (repo_name, name, manifest_digest) VALUES ('team-a', 'ghost', 'sha256:ff')`); err == nil {
		t.Error("a tag pointing at a missing manifest was accepted: the rebuild lost the manifests key")
	}

	// And the cascade the rebuilt schema relies on still fires.
	if _, err := db.ExecContext(ctx, `DELETE FROM manifests WHERE repo_name = 'team-a' AND digest = 'sha256:aa'`); err != nil {
		t.Fatalf("delete the manifest: %v", err)
	}
	for _, table := range []string{"manifest_refs", "tags"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s kept %d rows after its manifest went: the cascade did not survive the rebuild", table, count)
		}
	}
}
