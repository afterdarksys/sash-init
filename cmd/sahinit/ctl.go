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
	if err := fs.Parse(args); err != nil || *socket == "" || fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	op := fs.Arg(0)
	switch op {
	case "status", "diagnostics", "start", "stop", "restart":
	default:
		fmt.Fprintln(stderr, "unknown_op")
		return 2
	}
	if op != "status" && fs.NArg() != 2 {
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
	raw, _ := json.Marshal(map[string]string{"op": op, "name": fs.Arg(1)})
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
