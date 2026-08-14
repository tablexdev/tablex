package audit_test

import (
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/audit"
)

// TestRedactCredentialLiterals pins the grammar shapes RedactCredentialLiterals
// must mask — every supported engine's account DCL, escaped-quote forms
// included — and the shapes it must leave alone. The secret never survives; the
// statement's own keywords always do (redaction, not omission).
func TestRedactCredentialLiterals(t *testing.T) {
	const pw = "hunter2-uniq"
	masked := []struct{ name, in string }{
		{"mysql identified by", `CREATE USER 'app'@'%' IDENTIFIED BY 'hunter2-uniq'`},
		{"mysql identified by hash", `ALTER USER 'app'@'%' IDENTIFIED BY PASSWORD 'hunter2-uniq'`},
		{"mariadb via using", `CREATE USER app IDENTIFIED VIA mysql_native_password USING 'hunter2-uniq'`},
		{"mariadb with as", `CREATE USER app IDENTIFIED WITH ed25519 AS 'hunter2-uniq'`},
		{"mysql8 with by", `CREATE USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY 'hunter2-uniq'`},
		{"mysql8 alter with by", `ALTER USER app IDENTIFIED WITH mysql_native_password BY 'hunter2-uniq'`},
		{"mysql8 replace clause", `ALTER USER app IDENTIFIED BY 'new-pw' REPLACE 'hunter2-uniq'`},
		{"mysql8 with by replace", `ALTER USER app IDENTIFIED WITH caching_sha2_password BY 'new-pw' REPLACE 'hunter2-uniq' RETAIN CURRENT PASSWORD`},
		{"postgres role", `CREATE ROLE app LOGIN PASSWORD 'hunter2-uniq'`},
		{"postgres encrypted", `ALTER ROLE app ENCRYPTED PASSWORD 'hunter2-uniq' VALID UNTIL 'infinity'`},
		{"set password", `SET PASSWORD FOR 'app'@'%' = 'hunter2-uniq'`},
		{"set password func", `SET PASSWORD = PASSWORD('hunter2-uniq')`},
		{"old_password", `SET PASSWORD = OLD_PASSWORD('hunter2-uniq')`},
		{"escaped quote doubling", `CREATE ROLE app PASSWORD 'hunter2-uniq''s'`},
		{"backslash escape", `CREATE USER app IDENTIFIED BY 'hunter2-uniq\'s'`},
		{"lower case", `create user app identified by 'hunter2-uniq'`},
		{"multiline", "ALTER USER app\n  IDENTIFIED BY\n  'hunter2-uniq'"},
		{"double-quoted (mysql string mode)", `CREATE USER app IDENTIFIED BY "hunter2-uniq"`},
	}
	for _, tc := range masked {
		got := audit.RedactCredentialLiterals(tc.in)
		if strings.Contains(got, pw) {
			t.Errorf("%s: the credential survived: %q", tc.name, got)
		}
		if !strings.Contains(got, "'***'") {
			t.Errorf("%s: no mask emitted: %q", tc.name, got)
		}
	}

	// Untouched shapes: no password-bearing position, nothing to mask.
	untouched := []string{
		`SELECT * FROM users WHERE name = 'password'`,
		`INSERT INTO notes (v) VALUES ('password')`,
		`CREATE TABLE t (password TEXT)`,
		`ALTER ROLE app PASSWORD NULL`,
		`DROP USER 'app'@'%'`,
		`REPLACE INTO notes (v) VALUES ('kept')`,
		`SELECT REPLACE(v, 'from', 'to') FROM notes`,
	}
	for _, in := range untouched {
		if got := audit.RedactCredentialLiterals(in); got != in {
			t.Errorf("statement with no credential position was altered:\n in: %q\nout: %q", in, got)
		}
	}
}
