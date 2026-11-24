// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/frame"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestTailBounded(t *testing.T) {
	var tail tail
	input := bytes.Repeat([]byte{0, 255, 1, 2, 3}, 5000)
	for _, p := range [][]byte{input[:3], input[3:]} {
		n, err := tail.Write(p)
		if n != len(p) || err != nil {
			t.Fatal(n, err)
		}
	}
	got := tail.snapshot()
	if !bytes.Equal(got.Data, input[len(input)-logCapacity:]) || got.Dropped != uint64(len(input)-logCapacity) {
		t.Fatal("tail mismatch")
	}
}

func TestExecutionDiagnostics(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\nprintf '%s:%s' \"$APP\" \"$PWD\"\nprintf 'problem' >&2\nexit 7\n")
	svc := newSvc("test", "oneshot", "exit", "no", false, time.Second, shExec(script))
	svc.Execution = unit.Execution{Directory: "/tmp", Environment: []string{"APP=hello"}}
	sup := mustSup(t, map[string]*unit.Service{"test": svc})
	if err := sup.Boot(context.Background(), [][]string{{"test"}}); err == nil {
		t.Fatal("expected nonzero exit")
	}
	d, err := sup.Diagnostics("test")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if string(d.Stdout.Data) != "hello:"+dir || string(d.Stderr.Data) != "problem" {
		t.Fatalf("output: %+v", d)
	}
	row := d
	if row.LastExit == nil || row.LastExit.Code != 7 || row.LastExit.Signal != 0 {
		t.Fatalf("exit: %+v", row)
	}
	if len(d.Events) < 3 || d.Events[len(d.Events)-1].Kind != "exited" {
		t.Fatalf("events: %+v", d.Events)
	}
	resp := sup.dispatch("diagnostics", "test", "")
	raw, err := json.Marshal(resp)
	if err != nil || len(raw) > frame.Max || !resp.OK {
		t.Fatal(err, string(raw))
	}
}

func TestDiagnosticsBoundedAndPrivate(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"test": newSvc("test", "simple", "exec", "no", false, time.Second, []string{"/bin/true"})})
	s := sup.rt["test"]
	s.stdout.Write(bytes.Repeat([]byte{255}, 100000))
	s.stderr.Write(bytes.Repeat([]byte{255}, 100000))
	s.mu.Lock()
	for i := 0; i < 1000; i++ {
		s.eventLocked("exited", "", &Exit{Code: 7, Time: time.Now().UTC()})
	}
	s.mu.Unlock()
	resp := sup.dispatch("diagnostics", "test", "")
	raw, err := json.Marshal(resp)
	if err != nil || len(raw) > frame.Max || len(resp.Diagnostics.Events) != eventCapacity {
		t.Fatal("unbounded diagnostics", len(raw), err)
	}
	if resp.Diagnostics.Events[0].Sequence != 937 {
		t.Fatal("missing event gap")
	}
	if strings.Contains(string(raw), "environment") {
		t.Fatal("environment exposed")
	}
	if sup.dispatch("diagnostics", "missing", "").OK {
		t.Fatal("missing accepted")
	}
}

func TestOutputFloodDoesNotBlockExit(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\ni=0\nwhile [ $i -lt 2000 ]; do printf 'abcdefghij'; printf 'abcdefghij' >&2; i=$((i+1)); done\n")
	svc := newSvc("test", "oneshot", "exit", "no", false, 5*time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"test": svc})
	if err := sup.Boot(context.Background(), [][]string{{"test"}}); err != nil {
		t.Fatal(err)
	}
	d, err := sup.Diagnostics("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []LogTail{d.Stdout, d.Stderr} {
		if len(stream.Data) != logCapacity || stream.Dropped != 20000-logCapacity {
			t.Fatalf("incorrect bounded capture: len=%d dropped=%d", len(stream.Data), stream.Dropped)
		}
	}
}
