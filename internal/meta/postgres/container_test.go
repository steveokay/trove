package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	// The pgx stdlib driver, registered as "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"
)

// The Postgres store is tested against a real Postgres, not a mock: half of
// what this implementation has to get right is what the engine does with it.
// One container is shared by the whole package and each test gets its own
// database inside it, which keeps the suite honest without paying for a
// container per case.

const postgresImage = "postgres:17-alpine"

var (
	sharedOnce sync.Once
	sharedDSN  string
	sharedErr  error
	dbCounter  atomicCounter
)

// atomicCounter hands out unique database names without pulling in a mutex per
// use site.
type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (c *atomicCounter) next() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.n
}

// containerDSN starts the shared container on first use. It returns an error
// rather than skipping: a machine with no Docker cannot run this suite, and
// the coverage gate would notice a silent skip anyway.
func containerDSN(ctx context.Context) (string, error) {
	sharedOnce.Do(func() {
		container, err := tcpostgres.Run(ctx, postgresImage,
			tcpostgres.WithDatabase("trove"),
			tcpostgres.WithUsername("trove"),
			tcpostgres.WithPassword("trove"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(2*time.Minute)),
		)
		if err != nil {
			sharedErr = fmt.Errorf("start %s: %w", postgresImage, err)
			return
		}
		sharedDSN, sharedErr = container.ConnectionString(ctx, "sslmode=disable")
	})
	return sharedDSN, sharedErr
}

// requireDSN returns a DSN for a fresh, empty database, skipping the test when
// Docker is not available at all.
func requireDSN(t *testing.T) string {
	t.Helper()

	ctx := context.Background()
	base, err := containerDSN(ctx)
	if err != nil {
		if _, set := os.LookupEnv("CI"); set {
			t.Fatalf("Postgres container unavailable in CI: %v", err)
		}
		t.Skipf("Postgres container unavailable: %v", err)
	}

	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	defer func() { _ = admin.Close() }()

	// The database is created with an ICU collation on purpose. A real
	// deployment rarely runs on a C-collated database, and under any other
	// collation Postgres orders punctuation differently from SQLite's byte
	// comparison -- which is exactly what the schema's COLLATE "C" columns
	// exist to prevent. Testing on a C database would make that protection
	// untestable, and the parity of listing order unprovable.
	name := fmt.Sprintf("trove_test_%d", dbCounter.next())
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name+
		` TEMPLATE template0 LOCALE_PROVIDER icu ICU_LOCALE 'en-US' LOCALE 'C' ENCODING 'UTF8'`); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	return replaceDatabase(base, name)
}

// replaceDatabase swaps the database name in the container's DSN.
func replaceDatabase(dsn, name string) string {
	rest, query, _ := strings.Cut(dsn, "?")
	trimmed := strings.TrimSuffix(rest, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		trimmed = trimmed[:i]
	}
	out := trimmed + "/" + name
	if query != "" {
		out += "?" + query
	}
	return out
}

func TestContainerStarts(t *testing.T) {
	dsn := requireDSN(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	var one int
	if err := db.QueryRowContext(context.Background(), `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if one != 1 {
		t.Errorf("SELECT 1 = %d", one)
	}
}
