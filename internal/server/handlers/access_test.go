package handlers

import (
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

var (
	hostCaps = driver.Capabilities{AccountHasHost: true}  // MySQL-shaped accounts
	roleCaps = driver.Capabilities{AccountHasHost: false} // PostgreSQL-shaped roles
)

// TestValidAccountName pins the engine-shaped account-name rules: the
// ValidNewIdentifier character policy (quotes, backtick, semicolon, backslash,
// control bytes incl. DEL, space padding) with per-engine length caps — 128
// runes for host-qualified engines (MariaDB 10.6's limit), 63 bytes for
// role-based engines (PostgreSQL NAMEDATALEN-1, where the server would
// silently truncate).
func TestValidAccountName(t *testing.T) {
	valid := []string{"alice", "app-user", "user.name", "mail@example.com", "Ünïcode"}
	for _, s := range valid {
		if !validAccountName(hostCaps, s) || !validAccountName(roleCaps, s) {
			t.Errorf("validAccountName(%q) = false, want true", s)
		}
	}
	invalid := []string{"", " padded", "padded ", "a'b", `a"b`, "a`b", "a;b", `a\b`, "a\x00b", "a\x7fb"}
	for _, s := range invalid {
		if validAccountName(hostCaps, s) || validAccountName(roleCaps, s) {
			t.Errorf("validAccountName(%q) = true, want false", s)
		}
	}
	// Length caps: 63 bytes is the role-engine bound, 128 runes the host-engine one.
	name63 := strings.Repeat("a", 63)
	name64 := strings.Repeat("a", 64)
	name128 := strings.Repeat("a", 128)
	name129 := strings.Repeat("a", 129)
	if !validAccountName(roleCaps, name63) || validAccountName(roleCaps, name64) {
		t.Error("role-engine cap should be exactly 63 bytes")
	}
	if !validAccountName(hostCaps, name128) || validAccountName(hostCaps, name129) {
		t.Error("host-engine cap should be exactly 128 runes")
	}
	// The role-engine cap counts BYTES (PostgreSQL truncates at NAMEDATALEN-1
	// bytes): 32 two-byte runes are 64 bytes and must be rejected.
	if validAccountName(roleCaps, strings.Repeat("é", 32)) {
		t.Error("role-engine cap must count bytes, not runes")
	}
}

func TestValidHostPattern(t *testing.T) {
	valid := []string{"%", "localhost", "192.168.1.%", "10.0.0.0/255.255.255.0", "::1", "app_%.example.com"}
	for _, s := range valid {
		if !validHostPattern(s) {
			t.Errorf("validHostPattern(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "h;st", "h'st", "h st", "h`st", `h\st`, strings.Repeat("a", 256)}
	for _, s := range invalid {
		if validHostPattern(s) {
			t.Errorf("validHostPattern(%q) = true, want false", s)
		}
	}
}

// TestSplitAccount pins the last-@ split shared by the grantee decode and the
// self-lockout guard (driver.SplitAccount, the handler-facing companion to the
// MySQL dialect's splitGrantee): TrimSpace first, split on the LAST @, trim
// ' ` " from both parts.
func TestSplitAccount(t *testing.T) {
	cases := []struct{ in, user, host string }{
		{"alice@%", "alice", "%"},
		{"'alice'@'localhost'", "alice", "localhost"},
		{" root@localhost ", "root", "localhost"},
		{"mail@example.com@10.0.0.1", "mail@example.com", "10.0.0.1"}, // user names may contain @
		{"`quoted`@`host`", "quoted", "host"},
		{`"dq"@"h"`, "dq", "h"},
		{"norole", "norole", ""},
	}
	for _, c := range cases {
		u, h := driver.SplitAccount(c.in)
		if u != c.user || h != c.host {
			t.Errorf("SplitAccount(%q) = (%q,%q), want (%q,%q)", c.in, u, h, c.user, c.host)
		}
	}
}

// TestAccountsEqual pins the self-lockout comparison: exact, case-sensitive
// user names; case-insensitive hosts on host-qualified engines (MySQL host
// names are not case-sensitive); no wildcard expansion.
func TestAccountsEqual(t *testing.T) {
	if !accountsEqual(hostCaps, "alice", "LOCALHOST", "alice", "localhost") {
		t.Error("host comparison must be case-insensitive")
	}
	if accountsEqual(hostCaps, "Alice", "localhost", "alice", "localhost") {
		t.Error("user comparison must be case-sensitive")
	}
	if accountsEqual(hostCaps, "alice", "%", "alice", "localhost") {
		t.Error("no wildcard expansion: 'alice'@'%' is not 'alice'@'localhost'")
	}
	if !accountsEqual(roleCaps, "carol", "", "carol", "ignored") {
		t.Error("role engines compare the name only")
	}
}

func TestIsPublicGrantee(t *testing.T) {
	if !isPublicGrantee(roleCaps, "PUBLIC") {
		t.Error("PUBLIC is the PostgreSQL pseudo-role")
	}
	if isPublicGrantee(roleCaps, "public") {
		t.Error("only the exact PUBLIC keyword qualifies")
	}
	if isPublicGrantee(hostCaps, "PUBLIC") {
		t.Error("on host-qualified engines PUBLIC is an ordinary user name")
	}
}

func TestFindAccount(t *testing.T) {
	users := []model.User{
		{Name: "alice", Host: "%"},
		{Name: "alice", Host: "localhost"},
		{Name: "carol"},
	}
	if _, ok := findAccount(hostCaps, users, "alice", "LocalHost"); !ok {
		t.Error("host-insensitive match should find 'alice'@'localhost'")
	}
	if _, ok := findAccount(hostCaps, users, "alice", "10.0.0.1"); ok {
		t.Error("unknown host must not match")
	}
	if _, ok := findAccount(roleCaps, users, "carol", ""); !ok {
		t.Error("role match by name should succeed")
	}
	if _, ok := findAccount(roleCaps, users, "mallory", ""); ok {
		t.Error("unknown role must not match")
	}
}
