// Package storage is TableX's own metadata database: the small amount of state
// the application itself needs to outlive a process, kept in a database the
// operator configures. It is deliberately separate from the databases a user
// administers — everywhere else TableX acts only as the logged-in user, whereas
// here it writes on its own behalf.
//
// It is entirely optional. With no [storage] block configured, TableX behaves
// exactly as it always has: sessions live in process memory and are gone on
// restart. Nothing here is on the path of a request until an operator turns it
// on, so the zero-configuration single-binary story is unchanged.
//
// # What is kept here, and what never is
//
// Kept: the session envelope — its id, its CSRF token and its two timestamps
// (see internal/session).
//
// Never kept: a database credential, or anything derived from one. The password
// a user types at login lives only in that session's in-memory payload and is
// dropped as soon as the session ends (docs/security.md §2). Persisting it —
// even encrypted, since the key would have to be readable by the same process —
// would turn one read of this database into a compromise of every server TableX
// can reach. There is therefore no column for it, and the durable session store
// keeps authenticated sessions node-local as a direct consequence.
//
// That said, a session id IS a bearer credential: anything that can read this
// database can impersonate every live session in it, exactly as with any other
// server-side session store. Treat the storage database as being as sensitive
// as the cookies it stands in for.
//
// # Portability
//
// The same schema has to work on every engine implementing driver.StorageHost,
// so everything here stays inside the portable intersection: CREATE TABLE IF
// NOT EXISTS, positional placeholders, and the three column types a dialect
// spells for us (driver.StorageDDL). Instants are stored as Unix microseconds
// rather than a date type, so no engine's time-zone handling can reach the data.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
)

// Config is the operator's storage configuration. Engine empty means "no
// metadata database" — the default.
//
// Unlike a user's login, these credentials are admin-defined and read from the
// operator's own config file or environment, which is the same exception
// predefined servers already carry (docs/security.md §2).
type Config struct {
	Engine   string
	Host     string
	Port     int
	Socket   string
	User     string
	Password string
	Database string
	FilePath string
	SSLMode  string
	Params   map[string]string

	// TablePrefix is prepended to every table name so the metadata tables can
	// share a database with something else without colliding. It goes into DDL,
	// so it is validated as an identifier prefix before it is ever used.
	TablePrefix string
}

// Enabled reports whether a metadata database is configured.
func (c Config) Enabled() bool { return strings.TrimSpace(c.Engine) != "" }

// DefaultTablePrefix is used when the operator sets none.
const DefaultTablePrefix = "tablex_"

// maxTablePrefix bounds the prefix so prefix+name stays inside the shortest
// identifier limit among the supported engines (PostgreSQL's 63 bytes).
const maxTablePrefix = 32

// Pool sizing for the metadata database. It is small and deliberately so: this
// pool serves TableX's own bookkeeping, not user queries, and it must never be
// the reason an engine runs out of connections. It is separate from the
// per-session pools PoolCap governs.
const (
	maxOpenConns = 4
	maxIdleConns = 2
)

// openTimeout bounds the startup dial. A metadata database that cannot be
// reached is a hard startup failure — silently continuing without it would mean
// sessions quietly stop being durable, which the operator would discover only
// after a restart lost them.
const openTimeout = 20 * time.Second

// Store is an open metadata database.
type Store struct {
	conn    *driver.Connection
	d       driver.Dialect
	ddl     driver.StorageDDL
	prefix  string
	engine  string
	version int
}

// Open dials the configured metadata database, creates or verifies the schema,
// and returns a ready Store. It fails rather than degrading: every error here is
// a misconfiguration the operator has to see at startup.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	engine := strings.TrimSpace(cfg.Engine)
	if engine == "" {
		return nil, fmt.Errorf("storage: no engine configured")
	}
	d, ok := driver.Get(engine)
	if !ok {
		return nil, fmt.Errorf("storage: unknown engine %q (want one of %s)",
			engine, strings.Join(driver.RegisteredNames(), ", "))
	}
	// Checked here rather than after dialing so an engine that simply cannot
	// host the store says so instantly, without a connection attempt.
	if _, ok := d.(driver.StorageHost); !ok {
		return nil, fmt.Errorf("storage: engine %q cannot host TableX's metadata database", engine)
	}
	prefix, err := ValidTablePrefix(cfg.TablePrefix)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	if !d.Capabilities().IsNetworkEngine {
		if err := bootstrapFile(cfg.FilePath); err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	conn, err := driver.Open(dialCtx, d, driver.ConnParams{
		Host:     cfg.Host,
		Socket:   cfg.Socket,
		Port:     cfg.Port,
		User:     cfg.User,
		Password: cfg.Password,
		Database: cfg.Database,
		FilePath: cfg.FilePath,
		SSLMode:  cfg.SSLMode,
		Params:   cfg.Params,
		Tuning:   driver.Tuning{MaxOpenConns: maxOpenConns, MaxIdleConns: maxIdleConns},
		// No DialControl: this host comes from the operator's own config, which
		// is trusted exactly as a predefined server's host is. The SSRF guard
		// exists to stop a VISITOR naming an internal address.
	})
	if err != nil {
		return nil, fmt.Errorf("storage: connecting to the %s metadata database: %w", engine, err)
	}

	s := &Store{conn: conn, d: conn.Dialect(), prefix: prefix, engine: engine}
	// Take the type spellings from the SPECIALIZED dialect the connection
	// carries (driver.Open may have replaced it with a server-aware copy),
	// falling back to the registry value if that copy dropped the capability.
	if h, ok := s.d.(driver.StorageHost); ok {
		s.ddl = h.StorageDDL()
	} else {
		s.ddl = d.(driver.StorageHost).StorageDDL()
	}

	if err := s.migrate(dialCtx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("storage: preparing the schema: %w", err)
	}
	return s, nil
}

// bootstrapFile creates an empty metadata database file when the configured path
// does not exist yet.
//
// This is a deliberate exception to the rule a predefined server follows, where
// a missing file is a configuration error rather than an invitation to create
// one (see the sqlite dialect's BuildDSN). The difference is ownership: a
// predefined server points at a database somebody else made and TableX only
// visits, whereas this file IS TableX's, and refusing to create it while
// happily creating the tables inside it would be an arbitrary line to draw.
//
// The scope stays as narrow as it can be. O_EXCL, so a race creates it once and
// never truncates an existing database. 0600, because the contents are live
// session ids. No directory creation — a missing parent directory is still a
// configuration error, since guessing where an operator meant to put this is not
// TableX's business.
//
// It assumes an empty file is an acceptable empty database, which is true of
// SQLite and is the reason a zero-byte file works there at all. The assumption
// checks itself rather than failing silently: an engine that cannot open what
// was just created fails in driver.Open moments later, with that engine's own
// error.
func bootstrapFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("a file path is required for a file-backed metadata database")
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cannot access the metadata database %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil // another process won the race; its file is the one to use
		}
		return fmt.Errorf("creating the metadata database %s: %w", path, err)
	}
	return f.Close()
}

// ValidTablePrefix checks a configured table prefix and returns the value to
// use (DefaultTablePrefix when empty).
//
// The prefix is concatenated into DDL, so it is validated rather than escaped:
// quoting would let a prefix of `"; DROP …` through as a legal — if absurd —
// identifier, and there is no reason to accept one. The accepted shape is the
// portable intersection of an unquoted identifier on every supported engine.
func ValidTablePrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return DefaultTablePrefix, nil
	}
	if len(prefix) > maxTablePrefix {
		return "", fmt.Errorf("table_prefix %q is longer than %d characters", prefix, maxTablePrefix)
	}
	for i, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return "", fmt.Errorf("table_prefix %q may contain only letters, digits and underscores, and may not start with a digit", prefix)
		}
	}
	return prefix, nil
}

// Close shuts the metadata pool down.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.conn.Close()
}

// DB exposes the pool. Callers build their own statements with Table and
// Placeholder; there is no query builder here because there are only a handful
// of statements and they are all in this package's callers.
func (s *Store) DB() *sql.DB { return s.conn.DB() }

// Engine reports the configured engine name ("sqlite", "postgres", …).
func (s *Store) Engine() string { return s.engine }

// SchemaVersion reports the applied schema version.
func (s *Store) SchemaVersion() int { return s.version }

// Ping reports whether the metadata database is reachable right now.
//
// It exists for /metrics, and only there. It is deliberately NOT wired into
// /healthz: that endpoint is unauthenticated so a container probe never needs a
// credential, and answering it from the metadata database would both leak
// internal state to anonymous callers and make a degraded store — which this
// package is built to survive — read as a dead process.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil {
		return errors.New("no metadata database is configured")
	}
	return s.conn.DB().PingContext(ctx)
}

// Describe renders a one-line, credential-free summary for the startup log.
func (s *Store) Describe() string {
	where := s.conn.Info().Host
	if where == "" {
		where = s.conn.Info().Database
	}
	if where == "" {
		where = "local"
	}
	return fmt.Sprintf("%s (%s), tables %s*, schema v%d", s.engine, where, s.prefix, s.version)
}

// Table returns the quoted, prefixed name of one metadata table. Metadata
// tables are unqualified: they live in whatever schema the configured
// connection defaults to, which is the one thing the operator controls directly
// and the only choice that is portable across engines with and without schemas.
func (s *Store) Table(name string) string { return s.d.QuoteIdent(s.prefix + name) }

// Placeholder renders the nth bind placeholder (1-based) for this engine.
func (s *Store) Placeholder(n int) string { return s.d.Placeholder(n) }

// Micros converts an instant to the integer representation the schema uses:
// Unix microseconds, UTC. Microseconds rather than nanoseconds because MySQL's
// own temporal precision stops there, and a value that survives a round trip
// through a DATETIME(6) column keeps this comparable if the schema ever changes.
func Micros(t time.Time) int64 { return t.UTC().UnixMicro() }

// FromMicros is the inverse of Micros.
func FromMicros(us int64) time.Time { return time.UnixMicro(us).UTC() }
