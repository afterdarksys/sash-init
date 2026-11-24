// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
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

	"github.com/afterdarksys/sahinit/internal/journal"
)

func runLogs(op string, args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet(op, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", "/var/log/sahinit", "")
	name := f.String("unit", "", "")
	boot := f.String("boot", "", "")
	contains := f.String("contains", "", "")
	since := f.Uint64("since", 0, "")
	follow := f.Bool("follow", false, "")
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		fmt.Fprint(stderr, "usage: sahinit logs [--dir DIR] [--unit NAME] [--boot ID] [--since SEQUENCE] [--contains TEXT] [--follow]\n"+
			"usage: sahinit events [--dir DIR] [--unit NAME] [--boot ID] [--since SEQUENCE] [--contains TEXT] [--follow]\n")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	last := *since
	for {
		records, err := journal.Read(*dir)
		if err != nil {
			fmt.Fprintln(stderr, "journal_read")
			return 1
		}
		sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
		for _, r := range records {
			if r.Sequence <= last {
				continue
			}
			last = r.Sequence
			if (*name != "" && r.Unit != *name) || (*boot != "" && r.BootID != *boot) || (op == "events" && r.Stream != "event") || (op == "logs" && r.Stream == "event") {
				continue
			}
			if *contains != "" && !strings.Contains(string(r.Data)+string(r.Event), *contains) {
				continue
			}
			if err := json.NewEncoder(stdout).Encode(r); err != nil {
				return 1
			}
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
