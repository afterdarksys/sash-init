// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/afterdarksys/sahinit/internal/frame"
)

// runCtl exposes the local framed protocol without a shell or remote transport.
func runCtl(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", "", "")
	catalog := fs.String("dir", "", "catalog for diff/apply")
	if err := fs.Parse(args); err != nil || *socket == "" || fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	op := fs.Arg(0)
	switch op {
	case "status", "diagnostics", "explain", "start", "stop", "restart", "reload", "check", "diff", "apply", "rollback", "activate":
	default:
		fmt.Fprintln(stderr, "unknown_op")
		return 2
	}
	if ((op == "diff" || op == "apply") && (*catalog == "" || fs.NArg() != 1)) || ((op != "diff" && op != "apply") && *catalog != "") || ((op == "rollback" || op == "activate") && fs.NArg() != 1) {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	if op != "status" && op != "diff" && op != "apply" && op != "rollback" && op != "activate" && fs.NArg() != 2 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	conn, err := net.DialTimeout("unix", *socket, 5*time.Second)
	if err != nil {
		fmt.Fprintln(stderr, "failed")
		return 1
	}
	defer conn.Close()
	// A restart can use both the maximum stop and readiness timeouts.
	if err := conn.SetDeadline(time.Now().Add(11 * time.Minute)); err != nil {
		fmt.Fprintln(stderr, "failed")
		return 1
	}
	request := map[string]string{"op": op, "name": fs.Arg(1)}
	if *catalog != "" {
		request["arg"] = *catalog
	}
	raw, _ := json.Marshal(request)
	if err := frame.Write(conn, raw); err != nil {
		fmt.Fprintln(stderr, "failed")
		return 1
	}
	raw, err = frame.Read(conn)
	if err != nil {
		fmt.Fprintln(stderr, "failed")
		return 1
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintln(stderr, "failed")
		return 1
	}
	if _, err := fmt.Fprintln(stdout, string(raw)); err != nil {
		return 1
	}
	if !result.OK {
		return 1
	}
	return 0
}
