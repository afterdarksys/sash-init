package sash

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// testdata/app.describe.json is sash's golden (cmd/sash/testdata), copied
// with the app.sash it describes.
func TestDescribeGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/app.describe.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDescribe(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "app" || d.User != "app" || d.Group != "app" || strings.Join(d.Requires, ",") != "postgres" || strings.Join(d.After, ",") != "postgres,network-online" || len(d.Wants) != 0 {
		t.Fatalf("%+v", d)
	}
	if d.Ready == nil || d.Ready.Kind != "tcp" || d.Ready.Target != "127.0.0.1:8080" || d.Ready.Timeout != time.Minute {
		t.Fatalf("ready %+v", d.Ready)
	}
	if d.Stop == nil || d.Stop.Signal != "TERM" || d.Stop.Timeout != 30*time.Second || d.Restart == nil || d.Restart.Policy != "on-failure" || d.Restart.Burst != 3 {
		t.Fatalf("stop %+v restart %+v", d.Stop, d.Restart)
	}
	if d.Entry() != "start" || !d.Has("check") || d.Has("reload") {
		t.Fatalf("entries %v", d.Entries)
	}
}

func TestDescribeRefusals(t *testing.T) {
	raw, err := os.ReadFile("testdata/app.describe.json")
	if err != nil {
		t.Fatal(err)
	}
	good := string(raw)
	for name, edit := range map[string][2]string{
		"version":    {`"sash-describe/1"`, `"sash-describe/2"`},
		"unknown":    {`"complete": true`, `"complete": true, "extra": 1`},
		"ready kind": {`"kind": "tcp"`, `"kind": "http"`},
		"signal":     {`"signal": "TERM"`, `"signal": "SEGV"`},
		"policy":     {`"policy": "on-failure"`, `"policy": "sometimes"`},
		"negative":   {`"delay_ms": 5000`, `"delay_ms": -1`},
		"entry": {`"check"
  ]`, `"check", "check"
  ]`},
		"name": {`"name": "app"`, `"name": "App"`},
		"dep name": {`"postgres"
    ],
    "after"`, `"../x"
    ],
    "after"`},
		"null list": {`"wants": []`, `"wants": null`},
	} {
		bad := strings.Replace(good, edit[0], edit[1], 1)
		if bad == good {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := ParseDescribe([]byte(bad)); fail.Token(err) != "sash_describe" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseDescribe([]byte(good + "{}")); fail.Token(err) != "sash_describe" {
		t.Fatal("trailing value accepted")
	}
	run := strings.Replace(strings.Replace(good, `"run": []`, `"run": ["/usr/bin/sleep", "100"]`, 1), `"start",`, ``, 1)
	d, err := ParseDescribe([]byte(run))
	if err != nil || d.Entry() != "run" {
		t.Fatalf("run entry: %v %v", d, err)
	}
}
