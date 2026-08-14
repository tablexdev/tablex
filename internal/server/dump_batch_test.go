package server_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSQLDumpMultiBatch pins writeSQLDump's ≥2-batch flush (L3): rows are grouped
// into extended multi-row INSERTs of ~512 KiB each rather than one statement per
// row, so a table whose data exceeds the budget emits MORE THAN ONE INSERT — the
// boundary flush and the trailing partial batch both fire. Each batch re-emits
// the full "INSERT INTO … VALUES" prefix, so counting them in the table's data
// section counts the batches.
func TestSQLDumpMultiBatch(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Seed ~600 KiB across 50 rows of ~12 KiB each — comfortably past the 512 KiB
	// per-INSERT budget, so the stream flushes once mid-table and once at the end.
	conn := inspectConn(t, dbPath)
	if _, err := conn.Exec(context.Background(), "CREATE TABLE bigrows (id INTEGER PRIMARY KEY, blob TEXT)"); err != nil {
		t.Fatalf("create bigrows: %v", err)
	}
	pad := strings.Repeat("x", 12000)
	for range 50 {
		if _, err := conn.DB().ExecContext(context.Background(), "INSERT INTO bigrows (blob) VALUES (?)", pad); err != nil {
			t.Fatalf("seed bigrows: %v", err)
		}
	}

	resp, err := client.PostForm(ts.URL+"/db/main/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d", resp.StatusCode)
	}
	dump := string(dumpBytes)

	// Isolate bigrows' data section so widgets' INSERT isn't miscounted.
	const marker = "-- Data: bigrows"
	i := strings.Index(dump, marker)
	if i < 0 {
		t.Fatalf("dump has no bigrows data section:\n%.500s", dump)
	}
	section := dump[i:]
	if j := strings.Index(section[len(marker):], "-- Data: "); j >= 0 {
		section = section[:len(marker)+j]
	}
	batches := strings.Count(section, "INSERT INTO")
	if batches < 2 {
		t.Errorf("bigrows emitted %d INSERT batches, want >= 2 (512 KiB boundary flush + trailing partial)", batches)
	}

	// Every batch must be a terminated multi-row statement — the flush closes each
	// with ";\n". A missing terminator would fuse two batches and break re-import,
	// so the ';' count in the section must match the batch count.
	if terms := strings.Count(section, ");\n"); terms < batches {
		t.Errorf("bigrows section has %d batch terminators for %d batches — a batch is unterminated", terms, batches)
	}
}
