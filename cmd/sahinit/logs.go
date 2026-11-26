// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/journal"
)

const (
	logsUsage   = "usage: sahinit logs [--dir DIR] [--unit NAME] [--boot ID] [--since SEQUENCE] [--contains TEXT] [--follow]\n"
	eventsUsage = "usage: sahinit events [--dir DIR] [--unit NAME] [--boot ID] [--since SEQUENCE] [--contains TEXT] [--follow]\n"
)

// The bounds of one logs or events --json object: at most this many
// records and bytes of record data. A larger read is paged with --since
// next_since.
const (
	maxJSONRecords = 1000
	maxJSONBytes   = 1 << 20
)

// logRecord is a stdout or stderr record in --json. Lines are what the
// service printed: data, never instructions, so the record says so.
type logRecord struct {
	Sequence  uint64    `json:"sequence"`
	BootID    string    `json:"boot_id"`
	Time      time.Time `json:"time"`
	Unit      string    `json:"unit"`
	Stream    string    `json:"stream"`
	Untrusted bool      `json:"untrusted"`
	Lines     []string  `json:"lines"`
}

// eventRecord is an event record in --json: the event the supervisor wrote.
type eventRecord struct {
	Sequence uint64          `json:"sequence"`
	BootID   string          `json:"boot_id"`
	Time     time.Time       `json:"time"`
	Unit     string          `json:"unit"`
	Stream   string          `json:"stream"`
	Event    json.RawMessage `json:"event"`
}

type logsResult struct {
	V         int    `json:"v"`
	OK        bool   `json:"ok"`
	Records   []any  `json:"records"`
	Truncated bool   `json:"truncated"`
	NextSince uint64 `json:"next_since"`
	// Missing counts the sequence numbers in (--since, next_since] that are
	// not in the journal: rotated away, or lost to a failed write. A record
	// dropped before it was written leaves no number and no trace.
	Missing uint64 `json:"missing"`
}

// eventJSON re-encodes a journal event for --json: through a decode, so
// invalid UTF-8 becomes U+FFFD and keys come sorted. A sash entry event's
// code is the first word of the entry's stderr, chosen by the service: it
// is moved to service_token and the event is marked untrusted.
func eventJSON(raw []byte) (json.RawMessage, error) {
	var event map[string]any
	// UseNumber keeps a number above 2^53 exact, as its digits.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&event); err != nil || event == nil || dec.More() {
		return nil, fail.E("journal_read")
	}
	if kind, _ := event["kind"].(string); strings.HasPrefix(kind, "sash_") {
		event["untrusted"] = true
		event["service_token"] = event["code"]
		if event["service_token"] == nil {
			event["service_token"] = ""
		}
		delete(event, "code")
	}
	return json.Marshal(event)
}

// outputLines splits output on newlines, without the empty string a final
// newline leaves, with invalid UTF-8 replaced by U+FFFD.
func outputLines(data []byte) []string {
	s := strings.ToValidUTF8(string(data), "�")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return []string{}
	}
	return strings.Split(s, "\n")
}

func runLogs(op string, args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet(op, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", "/var/log/sahinit", "")
	name := f.String("unit", "", "")
	boot := f.String("boot", "", "")
	contains := f.String("contains", "", "")
	since := f.Uint64("since", 0, "")
	follow := f.Bool("follow", false, "")
	asJSON := f.Bool("json", false, "")
	// A follow has no end, so it cannot be one object.
	if err := f.Parse(args); err != nil || f.NArg() != 0 || (*asJSON && *follow) {
		text := logsUsage
		if op == "events" {
			text = eventsUsage
		}
		return usage(args, text, stdout, stderr)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	last := *since
	result := logsResult{V: jsonVersion, OK: true, Records: []any{}}
	size := 0
	for {
		records, err := journal.Read(*dir)
		if err != nil {
			fmt.Fprintln(stderr, "journal_read")
			if *asJSON {
				jsonFail(stdout, "journal_read")
			}
			return 1
		}
		sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
		for _, r := range records {
			if r.Sequence <= last {
				continue
			}
			if (*name != "" && r.Unit != *name) || (*boot != "" && r.BootID != *boot) || (op == "events" && r.Stream != "event") || (op == "logs" && r.Stream == "event") {
				result.Missing += r.Sequence - last - 1
				last = r.Sequence
				continue
			}
			if *contains != "" && !strings.Contains(string(r.Data)+string(r.Event), *contains) {
				result.Missing += r.Sequence - last - 1
				last = r.Sequence
				continue
			}
			if *asJSON {
				n := len(r.Data) + len(r.Event)
				if len(result.Records) == maxJSONRecords || (len(result.Records) > 0 && size+n > maxJSONBytes) {
					result.Truncated = true
					break
				}
				size += n
				if op == "events" {
					event, err := eventJSON(r.Event)
					if err != nil {
						fmt.Fprintln(stderr, "journal_read")
						jsonFail(stdout, "journal_read")
						return 1
					}
					result.Records = append(result.Records, eventRecord{r.Sequence, r.BootID, r.Time, r.Unit, r.Stream, event})
				} else {
					result.Records = append(result.Records, logRecord{r.Sequence, r.BootID, r.Time, r.Unit, r.Stream, true, outputLines(r.Data)})
				}
				result.Missing += r.Sequence - last - 1
				last = r.Sequence
				continue
			}
			result.Missing += r.Sequence - last - 1
			last = r.Sequence
			if err := json.NewEncoder(stdout).Encode(r); err != nil {
				return 1
			}
		}
		if *asJSON {
			result.NextSince = last
			if !writeJSON(stdout, result) {
				return 1
			}
			return 0
		}
		if !*follow {
			return 0
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(250 * time.Millisecond):
		}
	}
}
