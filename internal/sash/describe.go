package sash

// The sash-describe/1 document (sash cmd/sash --describe, golden
// cmd/sash/testdata/app.describe.json): what sahinit derives a sash unit's
// ordering, readiness, stop and restart from.
//
// Threats: the document is sash's output, read from a process running as
// the unit's uid; it is untrusted input. It is decoded strictly (unknown
// fields, trailing data, a wrong version, an out-of-range duration or count
// are sash_describe) and capped in size by the runner. It only describes:
// every verb is still checked against the grant when it is called.

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// DescribeVersion is the only describe document sahinit reads.
const DescribeVersion = "sash-describe/1"

// MaxDescribe caps the describe output read.
const MaxDescribe = 1 << 20

// maxDuration bounds every describe duration: sahinit's own unit timeout
// limit is five minutes; a restart window may be longer.
const maxDuration = 24 * time.Hour

// Description is the decoded service block and entries.
type Description struct {
	Name     string
	User     string
	Group    string
	Requires []string
	After    []string
	Wants    []string
	Run      []string
	Ready    *Ready
	Stop     *Stop
	Restart  *Restart
	Entries  []string
}

// Ready is how sahinit waits after start.
type Ready struct {
	Kind    string // tcp, unix, file, notify, none
	Target  string
	Timeout time.Duration
}

// Stop is the signal and timeout before the cgroup is killed.
type Stop struct {
	Signal  string
	Timeout time.Duration
}

// Restart is the restart policy: never, on-failure or always.
type Restart struct {
	Policy string
	Delay  time.Duration
	Burst  int
	Within time.Duration
}

type describeDoc struct {
	V        string          `json:"v"`
	Service  describeService `json:"service"`
	Entries  []string        `json:"entries"`
	Needs    json.RawMessage `json:"needs"`
	Complete bool            `json:"complete"`
}

type describeService struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Requires    []string `json:"requires"`
	After       []string `json:"after"`
	Wants       []string `json:"wants"`
	User        string   `json:"user"`
	Group       string   `json:"group"`
	Run         []string `json:"run"`
	Ready       *struct {
		Kind      string `json:"kind"`
		Target    string `json:"target"`
		TimeoutMS int64  `json:"timeout_ms"`
	} `json:"ready"`
	Stop *struct {
		Signal    string `json:"signal"`
		TimeoutMS int64  `json:"timeout_ms"`
	} `json:"stop"`
	Restart *struct {
		Policy   string `json:"policy"`
		DelayMS  int64  `json:"delay_ms"`
		Burst    int    `json:"burst"`
		WithinMS int64  `json:"within_ms"`
	} `json:"restart"`
}

// Signals are the signal names sash allows (contract item 8).
var Signals = map[string]bool{"HUP": true, "INT": true, "QUIT": true, "KILL": true, "USR1": true, "USR2": true, "TERM": true, "CONT": true, "STOP": true, "WINCH": true}

var entryNames = map[string]bool{"start": true, "stop": true, "reload": true, "check": true, "run": true}

// ParseDescribe decodes raw strictly. Any problem is sash_describe.
func ParseDescribe(raw []byte) (*Description, error) {
	bad := func() (*Description, error) { return nil, fail.E("sash_describe") }
	if len(raw) == 0 || len(raw) > MaxDescribe {
		return bad()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d describeDoc
	if err := dec.Decode(&d); err != nil {
		return bad()
	}
	if _, err := dec.Token(); err != io.EOF {
		return bad()
	}
	s := d.Service
	if d.V != DescribeVersion || !ServiceName.MatchString(s.Name) || s.Requires == nil || s.After == nil || s.Wants == nil || s.Run == nil || d.Entries == nil {
		return bad()
	}
	if (s.User != "" && !UnixName.MatchString(s.User)) || (s.Group != "" && !UnixName.MatchString(s.Group)) {
		return bad()
	}
	for _, list := range [][]string{s.Requires, s.After, s.Wants} {
		if len(list) > 64 {
			return bad()
		}
		for _, n := range list {
			if !ServiceName.MatchString(n) {
				return bad()
			}
		}
	}
	if len(s.Run) > 32 {
		return bad()
	}
	seen := map[string]bool{}
	for _, e := range d.Entries {
		if !entryNames[e] || seen[e] {
			return bad()
		}
		seen[e] = true
	}
	dur := func(ms int64) (time.Duration, bool) {
		if ms < 0 || time.Duration(ms)*time.Millisecond > maxDuration {
			return 0, false
		}
		return time.Duration(ms) * time.Millisecond, true
	}
	out := &Description{Name: s.Name, User: s.User, Group: s.Group, Requires: s.Requires, After: s.After, Wants: s.Wants, Run: s.Run, Entries: d.Entries}
	if r := s.Ready; r != nil {
		t, ok := dur(r.TimeoutMS)
		switch {
		case !ok:
			return bad()
		case r.Kind == "tcp" || r.Kind == "unix" || r.Kind == "file":
			if r.Target == "" {
				return bad()
			}
		case r.Kind == "notify" || r.Kind == "none":
		default:
			return bad()
		}
		out.Ready = &Ready{Kind: r.Kind, Target: r.Target, Timeout: t}
	}
	if st := s.Stop; st != nil {
		t, ok := dur(st.TimeoutMS)
		if !ok || !Signals[st.Signal] {
			return bad()
		}
		out.Stop = &Stop{Signal: st.Signal, Timeout: t}
	}
	if r := s.Restart; r != nil {
		delay, ok1 := dur(r.DelayMS)
		within, ok2 := dur(r.WithinMS)
		if !ok1 || !ok2 || r.Burst < 0 || r.Burst > 1000 {
			return bad()
		}
		switch r.Policy {
		case "never", "on-failure", "always":
		default:
			return bad()
		}
		out.Restart = &Restart{Policy: r.Policy, Delay: delay, Burst: r.Burst, Within: within}
	}
	return out, nil
}

// Entry is the entry sahinit starts: start when the file defines it, else
// run when the block has run (decision B4; sahinit always uses --entry run
// in batch 1). "" means the file has neither.
func (d *Description) Entry() string {
	if d.Has("start") {
		return "start"
	}
	if len(d.Run) > 0 {
		return "run"
	}
	return ""
}

// Has reports whether the file defines entry.
func (d *Description) Has(entry string) bool {
	for _, e := range d.Entries {
		if e == entry {
			return true
		}
	}
	return false
}
