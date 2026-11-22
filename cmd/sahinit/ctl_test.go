package main

import (
	"bytes"
	"net"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahinit/internal/frame"
)

func TestCtlDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock")
	// macOS Unix sockets have a short path limit.
	if len(path) > 100 {
		t.Skip("socket path too long")
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		raw, err := frame.Read(c)
		if err != nil {
			done <- err
			return
		}
		if string(raw) != `{"name":"agent","op":"diagnostics"}` {
			t.Errorf("request %s", raw)
		}
		done <- frame.Write(c, []byte(`{"ok":true,"error":"","diagnostics":{"name":"agent"}}`))
	}()
	var out, stderr bytes.Buffer
	if code := run([]string{"ctl", "--socket", path, "diagnostics", "agent"}, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"name":"agent"`)) {
		t.Fatal(out.String())
	}
}
