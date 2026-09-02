package postgres

import (
	"embed"

	"github.com/steveokay/trove/internal/meta/migrate"
)

// migrationFiles holds the schema, compiled into the binary so a deployment is
// one file and an air-gapped install needs nothing extra (Q6).
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// dialect is Postgres's half of the shared migration runner: the ledger table
// and the two statements that touch it. Everything else about applying a
// migration is engine-neutral and lives in internal/meta/migrate.
var dialect = migrate.Dialect{
	CreateLedger: `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at BIGINT NOT NULL
)`,
	SelectVersions: `SELECT version FROM schema_migrations ORDER BY version`,
	InsertVersion:  `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`,
}
