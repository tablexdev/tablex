package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// --- Databases -----------------------------------------------------------------

// onUpdateRE extracts the automatic-update clause from information_schema's
// EXTRA ("on update CURRENT_TIMESTAMP", "DEFAULT_GENERATED on update
// CURRENT_TIMESTAMP(3)"), so model.Column.OnUpdate carries it as a typed value
// and no engine-neutral caller has to read MySQL's EXTRA vocabulary.
var onUpdateRE = regexp.MustCompile(`(?i)\bon update\s+(current_timestamp(?:\(\d+\))?)`)

// parseOnUpdate returns the normalized automatic-update expression in an EXTRA
// value, or "" when there is none.
func parseOnUpdate(extra string) string {
	if m := onUpdateRE.FindStringSubmatch(extra); len(m) == 2 {
		return strings.ToUpper(m[1])
	}
	return ""
}

var mysqlSystemDBs = map[string]bool{
	"information_schema": true, "mysql": true, "performance_schema": true, "sys": true,
}

func (dialect) ListDatabases(ctx context.Context, db *sql.DB) ([]model.Database, error) {
	// TABLE_TYPE filter: TableCount must equal the number of relations the
	// database structure page lists (see model.Database.TableCount), and that
	// page skips MariaDB SEQUENCE objects — they are metadata, not browsable
	// relations. Everything else it shows is counted, including views.
	//
	// The condition belongs in the JOIN, not a WHERE clause: a WHERE would turn
	// the LEFT JOIN into an inner one and drop every empty database from the
	// list entirely.
	rows, err := db.QueryContext(ctx, `
		SELECT s.SCHEMA_NAME, s.DEFAULT_COLLATION_NAME,
		       COUNT(t.TABLE_NAME), COALESCE(SUM(COALESCE(t.DATA_LENGTH,0)+COALESCE(t.INDEX_LENGTH,0)),0)
		FROM information_schema.SCHEMATA s
		LEFT JOIN information_schema.TABLES t
		       ON t.TABLE_SCHEMA = s.SCHEMA_NAME AND t.TABLE_TYPE <> 'SEQUENCE'
		GROUP BY s.SCHEMA_NAME, s.DEFAULT_COLLATION_NAME
		ORDER BY s.SCHEMA_NAME`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Database
	for rows.Next() {
		var d model.Database
		var coll sql.NullString
		var count, size sql.NullInt64
		if err := rows.Scan(&d.Name, &coll, &count, &size); err != nil {
			return nil, err
		}
		d.Collation = coll.String
		d.TableCount = int(count.Int64)
		d.Size = size.Int64
		d.IsSystem = mysqlSystemDBs[d.Name]
		out = append(out, d)
	}
	return out, rows.Err()
}

func (dialect) ListSchemas(context.Context, *sql.DB, string) ([]model.Schema, error) {
	return nil, nil // MySQL has no schema level
}

// --- Tables --------------------------------------------------------------------

func (dialect) ListTables(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Table, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, DATA_LENGTH, INDEX_LENGTH,
		       TABLE_COLLATION, TABLE_COMMENT, CREATE_TIME, UPDATE_TIME
		FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ?
		ORDER BY TABLE_NAME`, scope.Database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Table
	for rows.Next() {
		var t model.Table
		var typ, engine, coll, comment sql.NullString
		var trows, dlen, ilen sql.NullInt64
		var ctime, utime sql.NullTime
		if err := rows.Scan(&t.Name, &typ, &engine, &trows, &dlen, &ilen,
			&coll, &comment, &ctime, &utime); err != nil {
			return nil, err
		}
		t.Schema = ""
		t.Type = mapTableType(typ.String)
		t.Engine = engine.String
		t.Rows = nullInt(trows, -1)
		t.DataSize = nullInt(dlen, -1)
		t.IndexSize = nullInt(ilen, -1)
		t.Size = sumSize(dlen, ilen)
		t.Collation = coll.String
		t.Comment = comment.String
		if ctime.Valid {
			tt := ctime.Time
			t.Created = &tt
		}
		if utime.Valid {
			tt := utime.Time
			t.Updated = &tt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func mapTableType(s string) model.TableType {
	switch strings.ToUpper(s) {
	case "VIEW":
		return model.TableView
	case "SYSTEM VIEW":
		return model.TableSystem
	case "SEQUENCE":
		// MariaDB exposes CREATE SEQUENCE objects in information_schema.TABLES with
		// TABLE_TYPE 'SEQUENCE'; they are metadata, not browsable data tables.
		return model.TableSequence
	default:
		return model.TableBase
	}
}

// --- Cheap listings & estimates (driver.NameLister / driver.RowEstimator) -------

// ListDatabaseNames lists schema names only. Unlike ListDatabases it never joins
// information_schema.TABLES, whose size/row aggregation makes the server load
// (and with information_schema_stats_expiry=0 recompute) statistics for every
// table on the server.
func (dialect) ListDatabaseNames(ctx context.Context, db *sql.DB) ([]model.Database, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Database
	for rows.Next() {
		var d model.Database
		if err := rows.Scan(&d.Name); err != nil {
			return nil, err
		}
		d.TableCount = -1
		d.Size = -1
		d.IsSystem = mysqlSystemDBs[d.Name]
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListTableNames lists table names and kinds only. Selecting only dictionary
// columns (TABLE_NAME, TABLE_TYPE) lets the server answer from the data
// dictionary without touching cached table statistics.
func (dialect) ListTableNames(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Table, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME`, scope.Database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Table
	for rows.Next() {
		var t model.Table
		var typ sql.NullString
		if err := rows.Scan(&t.Name, &typ); err != nil {
			return nil, err
		}
		t.Type = mapTableType(typ.String)
		t.Rows, t.Size, t.DataSize, t.IndexSize = -1, -1, -1, -1
		out = append(out, t)
	}
	return out, rows.Err()
}

// EstimateRows returns the statistics-kept row estimate (what SHOW TABLE STATUS
// reports). NULL — a view, or statistics never collected — maps to -1 so the
// caller falls back to an exact COUNT(*).
func (dialect) EstimateRows(ctx context.Context, db *sql.DB, t driver.TableRef) (int64, error) {
	var n sql.NullInt64
	err := db.QueryRowContext(ctx, `
		SELECT TABLE_ROWS FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`, t.Database, t.Table).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, nil
	}
	if err != nil {
		return 0, err
	}
	if !n.Valid {
		return -1, nil
	}
	return n.Int64, nil
}

// --- Columns -------------------------------------------------------------------

func (d dialect) Columns(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.Column, error) {
	m, err := d.bulkColumns(ctx, db, t.Database, t.Table)
	if err != nil {
		return nil, err
	}
	return m[t.Table], nil
}

// BulkColumns returns the columns of every table in the scope's database with
// one information_schema query (driver.BulkIntrospector) — the designer /
// export-preflight fast path that replaces a per-table N+1.
func (d dialect) BulkColumns(ctx context.Context, db *sql.DB, scope driver.Scope) (map[string][]model.Column, error) {
	return d.bulkColumns(ctx, db, scope.Database, "")
}

// bulkColumns is the single column-introspection scan: one table when table is
// non-empty (the SQL still filters, so a structure page never reads the whole
// schema), the entire database otherwise. One shared query/scan keeps the
// per-table and bulk paths from ever drifting.
func (d dialect) bulkColumns(ctx context.Context, db *sql.DB, database, table string) (map[string][]model.Column, error) {
	// MariaDB and MySQL classify expression defaults differently (see
	// mysqlDefaultKind). Prefer the flavor the Connection already parsed at
	// connect (threaded via context) over a per-call VERSION() probe; fall back to
	// the probe only when the flavor wasn't threaded (e.g. a direct dialect call).
	mariadb := false
	switch flavor := driver.ServerFlavorFromContext(ctx); flavor {
	case "":
		mariadb = isMariaDB(ctx, db)
	default:
		mariadb = strings.EqualFold(flavor, "MariaDB")
	}
	query := `
		SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, COLUMN_TYPE, DATA_TYPE, IS_NULLABLE,
		       COLUMN_DEFAULT, COLUMN_KEY, EXTRA, COLUMN_COMMENT,
		       COLLATION_NAME, CHARACTER_SET_NAME, GENERATION_EXPRESSION
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = ?`
	args := []any{database}
	if table != "" {
		query += ` AND TABLE_NAME = ?`
		args = append(args, table)
	}
	query += ` ORDER BY TABLE_NAME, ORDINAL_POSITION`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]model.Column{}
	for rows.Next() {
		var tbl string
		var c model.Column
		var colType, dataType, nullable, key, extra, comment sql.NullString
		var def, coll, charset, genExpr sql.NullString
		if err := rows.Scan(&tbl, &c.Name, &c.Position, &colType, &dataType, &nullable,
			&def, &key, &extra, &comment, &coll, &charset, &genExpr); err != nil {
			return nil, err
		}
		c.DataType = colType.String
		c.BaseType = strings.ToLower(dataType.String)
		c.Nullable = nullable.String == "YES"
		if def.Valid {
			// d.noBackslashEscapes comes from the specialized dialect's parsed
			// sql_mode — the same flag the writer's QuoteString consults, so
			// read and write decode/encode under one grammar. An unspecialized
			// direct call reads false, matching QuoteString's own default.
			val, isExpr, isNull := mysqlDefaultKind(mariadb, d.noBackslashEscapes, def, extra.String)
			c.Default = &val
			c.DefaultIsExpr = isExpr
			c.DefaultIsNull = isNull
		}
		c.IsPrimaryKey = key.String == "PRI"
		c.IsAutoIncrement = strings.Contains(extra.String, "auto_increment")
		// Only a true generated column ("VIRTUAL GENERATED"/"STORED GENERATED")
		// is generated. A column with an expression DEFAULT reports
		// "DEFAULT_GENERATED" — which must NOT be treated as generated, or it
		// would be wrongly omitted from insert/edit.
		extraUpper := strings.ToUpper(extra.String)
		switch {
		case strings.Contains(extraUpper, "STORED GENERATED"):
			c.IsGenerated, c.GeneratedKind = true, "stored"
		case strings.Contains(extraUpper, "VIRTUAL GENERATED"):
			c.IsGenerated, c.GeneratedKind = true, "virtual"
		}
		// GENERATION_EXPRESSION is the empty string for non-generated columns and
		// the stored formula (engine-quoted) for generated ones — carry it for the
		// structure page's formula display.
		if c.IsGenerated && genExpr.String != "" {
			c.GeneratedExpr = genExpr.String
		}
		c.Extra = extra.String
		// The automatic-update clause is parsed HERE, where the EXTRA vocabulary
		// is known, and carried as a typed field. It used to be recovered by the
		// column editor running this regex over every engine's Extra.
		c.OnUpdate = parseOnUpdate(extra.String)
		c.Comment = comment.String
		c.Collation = coll.String
		c.Charset = charset.String
		out[tbl] = append(out[tbl], c)
	}
	return out, rows.Err()
}

// --- Indexes -------------------------------------------------------------------

func (d dialect) Indexes(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.Index, error) {
	// A functional key part (MySQL >= 8.0.13) has a NULL COLUMN_NAME and carries
	// its body in EXPRESSION; select that column only where it exists, so the
	// query still runs on MariaDB and older MySQL.
	hasExpr := d.hasFunctionalIndexExpr()
	// COLLATION is 'A' (ascending), 'D' (descending, MySQL 8.0+ real DESC
	// indexes), or NULL (unsorted, e.g. HASH).
	// SUB_PART is the prefix length of a partial key part (NULL for a whole
	// column). It is part of the key's identity, so an index on tag(8) must not
	// be reported as an index on tag.
	query := `
		SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, INDEX_TYPE, COLLATION, SUB_PART
		FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
		ORDER BY INDEX_NAME, SEQ_IN_INDEX`
	if hasExpr {
		query = `
		SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, INDEX_TYPE, COLLATION, SUB_PART, EXPRESSION
		FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
		ORDER BY INDEX_NAME, SEQ_IN_INDEX`
	}
	rows, err := db.QueryContext(ctx, query, t.Database, t.Table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g := driver.NewGrouper[string, model.Index]()
	for rows.Next() {
		var name, colName, idxType, collation, expr sql.NullString
		var nonUnique, seq, subPart sql.NullInt64
		dest := []any{&name, &nonUnique, &seq, &colName, &idxType, &collation, &subPart}
		if hasExpr {
			dest = append(dest, &expr)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		idx := g.GetOrAdd(name.String, func() model.Index {
			return model.Index{
				Name:    name.String,
				Unique:  nonUnique.Int64 == 0,
				Primary: name.String == "PRIMARY",
				Type:    idxType.String,
			}
		})
		col := model.IndexColumn{Name: colName.String}
		if hasExpr && !colName.Valid && expr.Valid {
			col = model.IndexColumn{Expr: expr.String}
		}
		col.Descending = collation.String == "D"
		if subPart.Valid && subPart.Int64 > 0 {
			col.Prefix = int(subPart.Int64)
		}
		idx.Columns = append(idx.Columns, col)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.Slice(), nil
}

// --- Foreign keys --------------------------------------------------------------

func (d dialect) ForeignKeys(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.ForeignKey, error) {
	m, err := d.bulkForeignKeys(ctx, db, t.Database, t.Table)
	if err != nil {
		return nil, err
	}
	return m[t.Table], nil
}

// BulkForeignKeys returns the foreign keys of every table in the scope's
// database with one query (driver.BulkIntrospector).
func (d dialect) BulkForeignKeys(ctx context.Context, db *sql.DB, scope driver.Scope) (map[string][]model.ForeignKey, error) {
	return d.bulkForeignKeys(ctx, db, scope.Database, "")
}

// bulkForeignKeys is the single FK-introspection scan (see bulkColumns for the
// shared-query rationale). Constraint names are grouped per (table, name):
// MySQL FK names are unique per schema, but grouping by table keeps the shape
// obviously correct either way.
func (dialect) bulkForeignKeys(ctx context.Context, db *sql.DB, database, table string) (map[string][]model.ForeignKey, error) {
	query := `
		SELECT k.TABLE_NAME, k.CONSTRAINT_NAME, k.COLUMN_NAME, k.REFERENCED_TABLE_SCHEMA,
		       k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME, r.UPDATE_RULE, r.DELETE_RULE
		FROM information_schema.KEY_COLUMN_USAGE k
		JOIN information_schema.REFERENTIAL_CONSTRAINTS r
		  ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
		WHERE k.TABLE_SCHEMA = ? AND k.REFERENCED_TABLE_NAME IS NOT NULL`
	args := []any{database}
	if table != "" {
		query += ` AND k.TABLE_NAME = ?`
		args = append(args, table)
	}
	query += ` ORDER BY k.TABLE_NAME, k.CONSTRAINT_NAME, k.ORDINAL_POSITION`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g := driver.NewNestedGrouper[string, string, model.ForeignKey]()
	for rows.Next() {
		var tbl string
		var name, col, refSchema, refTable, refCol, onUpd, onDel sql.NullString
		if err := rows.Scan(&tbl, &name, &col, &refSchema, &refTable, &refCol, &onUpd, &onDel); err != nil {
			return nil, err
		}
		fk := g.GetOrAdd(tbl, name.String, func() model.ForeignKey {
			return model.ForeignKey{
				Name:      name.String,
				RefSchema: refSchema.String,
				RefTable:  refTable.String,
				OnUpdate:  onUpd.String,
				OnDelete:  onDel.String,
			}
		})
		fk.Columns = append(fk.Columns, col.String)
		fk.RefColumns = append(fk.RefColumns, refCol.String)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.Map(), nil
}

// --- DDL -----------------------------------------------------------------------

func (d dialect) CreateSQL(ctx context.Context, db *sql.DB, t driver.TableRef) (string, error) {
	// SHOW CREATE TABLE names its DDL column "Create Table"; match by the "Create"
	// prefix (the same shape SHOW CREATE VIEW/EVENT use) via the shared scanner.
	return showCreateColumnMatch(ctx, db, "SHOW CREATE TABLE "+d.QualifyTable(t),
		func(c string) bool { return strings.HasPrefix(c, "Create") })
}

// --- Extended introspection ----------------------------------------------------

func (dialect) ListViews(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.View, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TABLE_NAME, VIEW_DEFINITION
		FROM information_schema.VIEWS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME`, scope.Database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.View
	for rows.Next() {
		var v model.View
		var def sql.NullString
		if err := rows.Scan(&v.Name, &def); err != nil {
			return nil, err
		}
		v.Definition = def.String
		out = append(out, v)
	}
	return out, rows.Err()
}

func (dialect) ListRoutines(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Routine, error) {
	// Language: EXTERNAL_LANGUAGE names the implementation language of an
	// external routine and reads "SQL" for an ordinary one — but only on MySQL
	// 8.0.32+; MariaDB (11.4 verified) leaves it NULL for every routine, which is
	// why this column rendered as a permanent "—". ROUTINE_BODY is the standard
	// fallback: "SQL" for a SQL routine, "EXTERNAL" otherwise. Preferring
	// EXTERNAL_LANGUAGE keeps a real external language (JAVASCRIPT) visible where
	// the server reports one.
	rows, err := db.QueryContext(ctx, `
		SELECT ROUTINE_NAME, ROUTINE_TYPE, DTD_IDENTIFIER,
		       COALESCE(NULLIF(EXTERNAL_LANGUAGE,''), ROUTINE_BODY),
		       ROUTINE_DEFINITION, ROUTINE_COMMENT
		FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? ORDER BY ROUTINE_NAME`, scope.Database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Routine
	for rows.Next() {
		var r model.Routine
		var ret, lang, def, comment sql.NullString
		if err := rows.Scan(&r.Name, &r.Type, &ret, &lang, &def, &comment); err != nil {
			return nil, err
		}
		r.ReturnType = ret.String
		r.Language = lang.String
		// Body only — no signature, no DEFINER. ObjectDefinition reads SHOW
		// CREATE for the replayable statement.
		r.Definition = def.String
		r.Comment = comment.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// ObjectDefinition implements driver.DefinitionViewer over SHOW CREATE, the only
// source of a replayable definition on this engine (information_schema stores
// bodies without their signature — see DumpObjects).
//
// Unlike the dump path this deliberately does NOT pin character_set_results to
// binary. The dump needs the raw stored bytes so it can re-tag them with the
// object's original character_set_client; this text is going straight into an
// HTML page, so the server's conversion to the connection charset is exactly
// what is wanted.
func (d dialect) ObjectDefinition(ctx context.Context, db *sql.DB, scope driver.Scope, kind driver.ProgramKind, name string) (string, error) {
	var stmt, col string
	switch kind {
	case driver.ProgramProcedure:
		stmt, col = "PROCEDURE", "create procedure"
	case driver.ProgramFunction:
		stmt, col = "FUNCTION", "create function"
	case driver.ProgramTrigger:
		// SHOW CREATE TRIGGER reports its DDL under "SQL Original Statement".
		stmt, col = "TRIGGER", "sql original statement"
	case driver.ProgramEvent:
		stmt, col = "EVENT", "create event"
	default:
		return "", fmt.Errorf("mysql: no definition available for object kind %q", kind)
	}
	qualified := d.QuoteIdent(scope.Database) + "." + d.QuoteIdent(name)
	ddl, _, err := showCreateContext(ctx, db, "SHOW CREATE "+stmt+" "+qualified, col)
	if err != nil {
		return "", err
	}
	if ddl == "" {
		// Mirrors the dump path: the statement succeeds but returns an empty DDL
		// column for an account without SHOW_ROUTINE (MySQL 8.0.20+).
		return "", fmt.Errorf("mysql: SHOW CREATE %s %s returned no definition (missing SHOW_ROUTINE privilege?)", stmt, name)
	}
	return ddl, nil
}

func (dialect) ListTriggers(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Trigger, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TRIGGER_NAME, EVENT_OBJECT_TABLE, ACTION_TIMING, EVENT_MANIPULATION, ACTION_STATEMENT
		FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ? ORDER BY TRIGGER_NAME`, scope.Database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Trigger
	for rows.Next() {
		var tr model.Trigger
		if err := rows.Scan(&tr.Name, &tr.Table, &tr.Timing, &tr.Event, &tr.Definition); err != nil {
			return nil, err
		}
		out = append(out, tr)
	}
	return out, rows.Err()
}

func (dialect) ListEvents(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT EVENT_NAME, EVENT_TYPE, STATUS, COALESCE(EXECUTE_AT,''),
		       COALESCE(CONCAT(INTERVAL_VALUE,' ',INTERVAL_FIELD),''), EVENT_DEFINITION
		FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ? ORDER BY EVENT_NAME`, scope.Database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var execAt, interval sql.NullString
		if err := rows.Scan(&e.Name, &e.Type, &e.Status, &execAt, &interval, &e.Definition); err != nil {
			return nil, err
		}
		e.ExecuteAt = execAt.String
		e.Interval = interval.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// shouldRetryListUsersWithoutJoin reports whether a failed MariaDB >=10.4.2
// ListUsers query should be retried against the plain mysql.user query. The
// mysql.global_priv JSON join (the only shape that reads it) hard-fails for a
// login without privileges on that table; retrying without the lock column
// degrades gracefully. It never retries a cancelled context or a query that did
// not use the join. Pure, for unit testing.
func shouldRetryListUsersWithoutJoin(hasRole, hasLocked bool, queryErr, ctxErr error) bool {
	return queryErr != nil && ctxErr == nil && hasRole && hasLocked
}

func (d dialect) ListUsers(ctx context.Context, db *sql.DB) ([]model.User, error) {
	// Lock/role columns are flavor/version-gated so the query still runs on
	// servers that predate them. A locked account or a MariaDB role is not
	// login-capable — reporting either as such is the bug this fixes.
	//
	// Mechanisms differ per flavor (live-verified against MySQL 8.4 and
	// MariaDB 11.4):
	//   - MySQL >= 5.7.6: mysql.user.account_locked ('Y'/'N').
	//   - MariaDB >= 10.0.5: mysql.user.is_role ('Y'/'N'); from 10.4.2 account
	//     locking exists but lives in mysql.global_priv's Priv JSON — the
	//     mysql.user compatibility view does NOT expose an account_locked
	//     column — so it is read via JSON_VALUE through a LEFT JOIN
	//     (JSON true scans as "1"; an absent attribute coalesces to "false").
	hasRole := d.isMariaDBFlavor() && d.atLeast(10, 0, 5)
	hasLocked := d.hasAccountLocked()
	query := `SELECT User, Host, Super_priv FROM mysql.user ORDER BY User, Host`
	switch {
	case hasRole && hasLocked: // MariaDB >= 10.4.2
		query = `
			SELECT u.User, u.Host, u.Super_priv, u.is_role,
			       COALESCE(JSON_VALUE(g.Priv, '$.account_locked'), 'false')
			FROM mysql.user u
			LEFT JOIN mysql.global_priv g ON g.User = u.User AND g.Host = u.Host
			ORDER BY u.User, u.Host`
	case hasRole: // MariaDB 10.0.5 .. 10.4.1 (no lock support)
		query = `SELECT User, Host, Super_priv, is_role FROM mysql.user ORDER BY User, Host`
	case hasLocked: // MySQL >= 5.7.6
		query = `SELECT User, Host, Super_priv, account_locked FROM mysql.user ORDER BY User, Host`
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		if shouldRetryListUsersWithoutJoin(hasRole, hasLocked, err, ctx.Err()) {
			// The mysql.global_priv join fails for a login lacking privileges on
			// that table; drop the lock column and retry the plain mysql.user
			// query (keeping the role column). The Locked attribute is degraded.
			joinErr := err
			hasLocked = false
			rows, err = db.QueryContext(ctx, `SELECT User, Host, Super_priv, is_role FROM mysql.user ORDER BY User, Host`)
			if err != nil {
				return nil, fmt.Errorf("listing users: reading mysql.global_priv failed (%v); the mysql.user fallback also failed: %w", joinErr, err)
			}
		} else {
			return nil, fmt.Errorf("listing users requires privileges on mysql.user: %w", err)
		}
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		var super, locked, role sql.NullString
		dest := []any{&u.Name, &u.Host, &super}
		if hasRole {
			dest = append(dest, &role)
		}
		if hasLocked {
			dest = append(dest, &locked)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		// 'Y' (MySQL enum), '1'/'true' (MariaDB JSON boolean spellings).
		isLocked := hasLocked && (locked.String == "Y" || locked.String == "1" || strings.EqualFold(locked.String, "true"))
		isRole := hasRole && role.String == "Y"
		u.IsSuper = super.String == "Y"
		u.CanLogin = !isLocked && !isRole
		var attrs []string
		if isRole {
			attrs = append(attrs, "Role")
		}
		if u.IsSuper {
			attrs = append(attrs, "Super")
		}
		if isLocked {
			attrs = append(attrs, "Locked")
		}
		u.Attributes = strings.Join(attrs, ", ")
		out = append(out, u)
	}
	return out, rows.Err()
}

// Privileges lists schema- or table-scoped grants from information_schema. The
// table branch unions COLUMN_PRIVILEGES in: a column grant is a distinct grant
// that only its own REVOKE removes, so listing only TABLE_PRIVILEGES would show
// an account as having no access to a table it can in fact read two columns of
// — and leave that grant unrevokable from the UI.
func (dialect) Privileges(ctx context.Context, db *sql.DB, ref driver.TableRef) ([]model.Privilege, error) {
	var (
		rows *sql.Rows
		err  error
	)
	object := ref.Database
	if ref.Table != "" {
		object = ref.Database + "." + ref.Table
		rows, err = db.QueryContext(ctx, `
			SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE, '', ''
			FROM information_schema.TABLE_PRIVILEGES
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
			UNION ALL
			SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE, '', COLUMN_NAME
			FROM information_schema.COLUMN_PRIVILEGES
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
			ORDER BY 1, 5, 2`, ref.Database, ref.Table, ref.Database, ref.Table)
	} else {
		// SCHEMA_PRIVILEGES stores the pattern as it was granted. TableX escapes
		// _/% by design (grantTarget), so its own grants store the escaped form
		// ("my\_app"), but a grant created externally (e.g. `GRANT ... ON my_app.*`
		// from the mysql CLI) stores the raw form ("my_app"). Match BOTH so a
		// db-scope Privileges page on a _/%-named database shows and can revoke
		// externally-created grants too, regardless of server version /
		// @@partial_revokes. IN with an identical raw==escaped pair (no _/%) does
		// not duplicate rows. TABLE_SCHEMA rides along as the stored pattern so
		// the revoke path can target the grant row exactly as stored.
		rows, err = db.QueryContext(ctx, `
			SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE, TABLE_SCHEMA, ''
			FROM information_schema.SCHEMA_PRIVILEGES
			WHERE TABLE_SCHEMA IN (?, ?)
			ORDER BY GRANTEE, PRIVILEGE_TYPE`, ref.Database, escapeGrantDatabasePattern(ref.Database))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Privilege
	for rows.Next() {
		var grantee, priv, grantable, stored, column string
		if err := rows.Scan(&grantee, &priv, &grantable, &stored, &column); err != nil {
			return nil, err
		}
		user, host := splitGrantee(grantee)
		out = append(out, model.Privilege{
			User: user, Host: host, Object: object,
			Privilege: priv, Grantable: grantable == "YES",
			StoredObject: stored, Column: column,
		})
	}
	return out, rows.Err()
}

// splitGrantee parses MySQL's "'user'@'host'" grantee form, collapsing a doubled
// quote back to one (a user O'Brien is stored with that quote doubled).
// It is the information_schema-decoding companion to driver.SplitAccount (which
// the handlers use on already-decoded / CURRENT_USER() strings and so does NOT
// collapse doubled quotes) — keep the split boilerplate of the two in step.
func splitGrantee(g string) (user, host string) {
	g = strings.TrimSpace(g)
	if i := strings.LastIndex(g, "@"); i >= 0 {
		return unquoteGrantPart(g[:i]), unquoteGrantPart(g[i+1:])
	}
	return unquoteGrantPart(g), ""
}

// unquoteGrantPart strips a surrounding '/`/" quote and collapses a doubled quote
// of the same kind to one; an unquoted value is returned trimmed.
func unquoteGrantPart(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if q := s[0]; (q == '\'' || q == '`' || q == '"') && s[len(s)-1] == q {
			return strings.ReplaceAll(s[1:len(s)-1], string([]byte{q, q}), string(q))
		}
	}
	return strings.Trim(s, "'`\"")
}

// accountRef renders the "'user'@'host'" account reference (splitGrantee's
// inverse — keep the two in lockstep). Both parts are string literals in the
// MySQL account grammar, so each goes through QuoteString, never QuoteIdent.
// It emits the host verbatim (no blank→'%' coercion): the "any host" default
// belongs only to create_user and is applied in the handler, so drop/set-
// password/grant/revoke of an account whose real host is the EMPTY string
// target that exact account rather than aliasing to '%'.
func (d dialect) accountRef(name, host string) string {
	return d.QuoteString(name) + "@" + d.QuoteString(host)
}

// escapeGrantDatabasePattern backslash-escapes the LIKE-pattern
// metacharacters (_ and %) in a database name for a GRANT/REVOKE "ON db.*"
// target and the matching SCHEMA_PRIVILEGES lookup. In MySQL's GRANT grammar
// the database part is a pattern, so an unescaped `my_app`.* would also grant
// on `myXapp`; the grant tables store the escaped form, so the introspection
// that lists/revokes those grants must match it the same way. The table part
// and the table-scope database part are literal, so they are not escaped.
func escapeGrantDatabasePattern(db string) string {
	db = strings.ReplaceAll(db, `\`, `\\`)
	db = strings.ReplaceAll(db, "_", `\_`)
	db = strings.ReplaceAll(db, "%", `\%`)
	return db
}

// --- Monitor (status / variables / processes) ----------------------------------

func (dialect) Status(ctx context.Context, db *sql.DB) ([]model.Variable, error) {
	return scanVariables(ctx, db, "SHOW GLOBAL STATUS")
}

func (dialect) Variables(ctx context.Context, db *sql.DB) ([]model.Variable, error) {
	return scanVariables(ctx, db, "SHOW GLOBAL VARIABLES")
}

func (dialect) Processes(ctx context.Context, db *sql.DB) (*driver.ResultSet, error) {
	rows, err := db.QueryContext(ctx, "SHOW FULL PROCESSLIST")
	if err != nil {
		return nil, err
	}
	return driver.ScanResult(rows, 1000)
}

// --- ProcessManager --------------------------------------------------------------

// ProcessIDColumn is SHOW FULL PROCESSLIST's first column.
func (dialect) ProcessIDColumn() string { return "Id" }

// KillProcessSQL emits KILL, which on MySQL and MariaDB defaults to KILL
// CONNECTION — terminating the session, not just its current statement. The
// spelling is explicit so that default cannot drift into KILL QUERY, which
// would leave the connection alive and make the button look like it failed.
func (dialect) KillProcessSQL(id int64) string {
	return "KILL CONNECTION " + strconv.FormatInt(id, 10)
}

func scanVariables(ctx context.Context, db *sql.DB, query string) ([]model.Variable, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Variable
	for rows.Next() {
		var name string
		var val sql.NullString
		if err := rows.Scan(&name, &val); err != nil {
			return nil, err
		}
		out = append(out, model.Variable{Name: name, Value: val.String})
	}
	return out, rows.Err()
}
