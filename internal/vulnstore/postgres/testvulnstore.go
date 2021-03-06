package postgres

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib" // needed for sqlx.Open
	"github.com/jmoiron/sqlx"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/libvuln/migrations"
	"github.com/quay/claircore/test/integration"
)

func TestStore(ctx context.Context, t testing.TB) (*sqlx.DB, *Store, string, func()) {
	cmd := exec.Command("go", "list", "-f", "{{.Dir}}", "github.com/quay/claircore/internal/vulnstore/postgres")
	o, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	o = bytes.TrimSpace(o)

	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatalf("unable to create test database: %w", err)
	}
	cfg := db.Config()
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	// setup sqlx
	dsn := fmt.Sprintf("host=%s port=%d database=%s user=%s",
		cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database, cfg.ConnConfig.User)
	sx, err := sqlx.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed to sqlx Open: %v", err)
	}

	// run migrations
	migrator := migrate.NewPostgresMigrator(sx.DB)
	migrator.Table = migrations.MigrationTable
	err = migrator.Exec(migrate.Up, migrations.Migrations...)
	if err != nil {
		t.Fatalf("failed to perform migrations: %w", err)
	}

	s := NewVulnStore(sx, pool)

	return sx, s, dsn, func() {
		db.Close(ctx, t)
	}
}
