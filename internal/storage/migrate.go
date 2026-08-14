package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Table names, without the operator's prefix.
const (
	metaTable     = "meta"
	SessionsTable = "sessions"
)

// versionKey is the meta row recording how far the schema has been migrated.
const versionKey = "schema_version"

// migration is one forward-only schema step.
//
// Three rules bind every migration, and each is a consequence of what the
// storage layer has to support rather than a style preference:
//
//   - IDEMPOTENT. Two replicas starting at the same moment both find the same
//     pending steps and both run them, and there is no advisory lock portable
//     across MySQL, PostgreSQL and SQLite to serialize that. So every statement
//     has to be safe to run twice — in practice, CREATE TABLE IF NOT EXISTS.
//   - ADDITIVE. MySQL does not roll DDL back, so a step that fails partway
//     cannot be undone. The version is bumped only once every statement of a
//     step has succeeded, which makes "run it again" the recovery path — and
//     that only works if the step never destroys anything.
//   - PORTABLE. Statements must be legal on every driver.StorageHost engine.
//     That is a narrower intersection than it looks: notably CREATE INDEX IF
//     NOT EXISTS is NOT valid on MySQL, so secondary indexes cannot be added
//     idempotently and this schema has none (see below).
type migration struct {
	version int
	name    string
	sql     func(s *Store) []string
}

// schema is the metadata schema in full. The list is the schema: there is no
// separate DDL file to drift from it.
func schema() []migration {
	return []migration{
		{
			version: 1,
			name:    "sessions",
			sql: func(s *Store) []string {
				// The session ENVELOPE and nothing more. There is no column for
				// a credential, and none for the account either: a row with no
				// live payload behind it is indistinguishable from a session
				// that has not logged in yet, which is precisely the semantics
				// the durable store wants (see internal/storage/session.go).
				//
				// No index on last_seen. The reaper scans the whole table, and
				// CREATE INDEX IF NOT EXISTS is unavailable on MySQL, so adding
				// one would break the run-it-twice rule above for no measurable
				// gain.
				//
				// What bounds that scan is storage.max_sessions when it is
				// positive, and NOTHING when an operator sets it to zero, which
				// is their deliberate choice. Even positive it bounds ADMISSION
				// per replica rather than the table: nothing trims rows to fit, so
				// a cluster's overshoot clears only on the ordinary session clock
				// — inactivity for idle_timeout plus the sweep's touch lag, and no
				// sooner than absolute_timeout for a session still in use — and
				// only on the next SUCCESSFUL sweep, since a failed selectAll
				// reaps locally alone.
				return []string{
					"CREATE TABLE IF NOT EXISTS " + s.Table(SessionsTable) + " (" +
						s.Col("id") + " " + s.ddl.ID + " NOT NULL PRIMARY KEY, " +
						s.Col("csrf") + " " + s.ddl.ID + " NOT NULL, " +
						s.Col("created") + " " + s.ddl.Int64 + " NOT NULL, " +
						s.Col("last_seen") + " " + s.ddl.Int64 + " NOT NULL)" +
						s.ddl.TableOptions,
				}
			},
		},
	}
}

// Col quotes a metadata column name. Every name in this schema is safe unquoted
// on every engine — which is why they are spelled "k"/"v" rather than
// "key"/"value" — but the project's rule is that an identifier reaching SQL goes
// through QuoteIdent, and a rule with exceptions is a rule nobody checks.
func (s *Store) Col(name string) string { return s.d.QuoteIdent(name) }

// migrate brings the schema up to date. It runs inside Open, so a database that
// cannot be migrated is a startup failure rather than a surprise at the first
// request.
func (s *Store) migrate(ctx context.Context) error {
	meta := s.Table(metaTable)
	if _, err := s.DB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+meta+" ("+
		s.Col("k")+" "+s.ddl.ID+" NOT NULL PRIMARY KEY, "+
		s.Col("v")+" "+s.ddl.Text+" NOT NULL)"+s.ddl.TableOptions); err != nil {
		return fmt.Errorf("creating the bookkeeping table %s: %w", meta, err)
	}
	current, err := s.readVersion(ctx)
	if err != nil {
		return err
	}
	steps := schema()
	if err := checkSteps(steps); err != nil {
		return err
	}
	for _, m := range steps {
		if m.version <= current {
			continue
		}
		for _, stmt := range m.sql(s) {
			if _, err := s.DB().ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
			}
		}
		if err := s.setVersion(ctx, current, m.version); err != nil {
			return err
		}
		current = m.version
	}
	s.version = current
	return nil
}

// checkSteps guards the schema list itself: versions must be positive and
// strictly increasing. A duplicate or out-of-order entry would silently skip a
// step on a database that had already passed it, so it is a programming error
// worth failing loudly on rather than a possibility to handle.
func checkSteps(steps []migration) error {
	prev := 0
	for _, m := range steps {
		if m.version <= prev {
			return fmt.Errorf("schema is malformed: migration %q has version %d, which does not follow %d", m.name, m.version, prev)
		}
		prev = m.version
	}
	return nil
}

// readVersion returns the applied schema version, 0 when the bookkeeping row is
// absent (a fresh database).
func (s *Store) readVersion(ctx context.Context) (int, error) {
	var raw string
	err := s.DB().QueryRowContext(ctx,
		"SELECT "+s.Col("v")+" FROM "+s.Table(metaTable)+" WHERE "+s.Col("k")+" = "+s.Placeholder(1),
		versionKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading the schema version: %w", err)
	}
	n, cerr := strconv.Atoi(strings.TrimSpace(raw))
	if cerr != nil || n < 0 {
		return 0, fmt.Errorf("the schema version in %s is %q, which is not a version number — is this database really TableX's metadata store?", s.Table(metaTable), raw)
	}
	return n, nil
}

// setVersion records that the schema has reached `to`, having been at `from`.
//
// The write is conditional on the old value, which makes two replicas migrating
// the same fresh database resolve cleanly: exactly one of them moves the
// version, and the other discovers the schema is already at least as far along
// as it was trying to take it. Only a version that went somewhere ELSE is an
// error, because then this process does not know what shape the schema is in.
func (s *Store) setVersion(ctx context.Context, from, to int) error {
	meta, target := s.Table(metaTable), strconv.Itoa(to)
	if from == 0 {
		// A fresh database has no row to update. A losing race here is a primary
		// key violation, which is not a failure: it means the row now holds what
		// this process was about to write, so fall through and reconcile.
		if _, err := s.DB().ExecContext(ctx,
			"INSERT INTO "+meta+" ("+s.Col("k")+", "+s.Col("v")+") VALUES ("+s.Placeholder(1)+", "+s.Placeholder(2)+")",
			versionKey, target); err == nil {
			return nil
		}
	}
	res, err := s.DB().ExecContext(ctx,
		"UPDATE "+meta+" SET "+s.Col("v")+" = "+s.Placeholder(1)+
			" WHERE "+s.Col("k")+" = "+s.Placeholder(2)+" AND "+s.Col("v")+" = "+s.Placeholder(3),
		target, versionKey, strconv.Itoa(from))
	if err != nil {
		return fmt.Errorf("recording schema version %d: %w", to, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 1 {
		return nil
	}
	got, err := s.readVersion(ctx)
	if err != nil {
		return err
	}
	if got >= to {
		return nil
	}
	return fmt.Errorf("schema version is %d after applying migration %d — another process moved it somewhere unexpected", got, to)
}
