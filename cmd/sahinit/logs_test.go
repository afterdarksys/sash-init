// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"github.com/afterdarksys/sahinit/internal/journal"
	"os"
	"testing"
)

func TestLogsAndEventsFilter(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	j, err := journal.Open(dir, 64*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	j.Emit(journal.Record{Unit: "a", Stream: "stdout", Data: []byte("needle")})
	j.Emit(journal.Record{Unit: "b", Stream: "stderr", Data: []byte("other")})
	j.Emit(journal.Record{Unit: "a", Stream: "event", Event: []byte(`{"kind":"ready"}`)})
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := runLogs("logs", []string{"--dir", dir, "--unit", "a", "--contains", "needle"}, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	if bytes.Count(out.Bytes(), []byte("\n")) != 1 || !bytes.Contains(out.Bytes(), []byte(`"stream":"stdout"`)) {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := runLogs("events", []string{"--dir", dir, "--since", "2"}, &out, &stderr); code != 0 {
		t.Fatal(code)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"kind":"ready"`)) {
		t.Fatal(out.String())
	}
}
