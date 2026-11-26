// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/frame"
	"github.com/afterdarksys/sahinit/internal/supervise"
)

// ctlOps are the operations ctl sends.
var ctlOps = []string{"status", "diagnostics", "explain", "start", "stop", "restart", "reload", "check", "diff", "apply", "rollback", "activate"}

// ctlJSONOps are the read-only operations that take --json. check is not
// one: it runs the sash unit's check entry.
var ctlJSONOps = []string{"status", "explain", "diff"}

// ctlResult is the --json object of ctl: the response re-encoded through
// the typed structs, so it holds exactly the documented fields.
type ctlResult struct {
	V           int                    `json:"v"`
	OK          bool                   `json:"ok"`
	Code        string                 `json:"code,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Unit        string                 `json:"unit,omitempty"`
	Rows        *[]supervise.Row       `json:"rows,omitempty"`
	Explanation *supervise.Explanation `json:"explanation,omitempty"`
	Diff        *supervise.CatalogDiff `json:"diff,omitempty"`
}

// runCtl exposes the local framed protocol without a shell or remote transport.
//
// Threats: --json changes only how the response is printed. The request
// is the same bytes with and without it, so the supervisor authorises it
// exactly as the plain form (peer rules, root_required).
func runCtl(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", "", "")
	catalog := fs.String("dir", "", "catalog for diff/apply")
	asJSON := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil || *socket == "" || fs.NArg() < 1 || fs.NArg() > 2 {
		return usage(args, usageText, stdout, stderr)
	}
	op := fs.Arg(0)
	if !slices.Contains(ctlOps, op) {
		fmt.Fprintln(stderr, "unknown_op")
		if *asJSON {
			jsonFail(stdout, "unknown_op")
		}
		return 2
	}
	if ((op == "diff" || op == "apply") && (*catalog == "" || fs.NArg() != 1)) || ((op != "diff" && op != "apply") && *catalog != "") || ((op == "rollback" || op == "activate") && fs.NArg() != 1) {
		return usage(args, usageText, stdout, stderr)
	}
	if op != "status" && op != "diff" && op != "apply" && op != "rollback" && op != "activate" && fs.NArg() != 2 {
		return usage(args, usageText, stdout, stderr)
	}
	if *asJSON && !slices.Contains(ctlJSONOps, op) {
		return usage(args, usageText, stdout, stderr)
	}
	clientFail := func(message string) int {
		fmt.Fprintln(stderr, "failed")
		if *asJSON {
			writeJSON(stdout, failure{V: jsonVersion, Code: "failed", Message: message})
		}
		return 1
	}
	conn, err := net.DialTimeout("unix", *socket, 5*time.Second)
	if err != nil {
		return clientFail("The control socket could not be reached.")
	}
	defer conn.Close()
	// A restart can use both the maximum stop and readiness timeouts.
	if err := conn.SetDeadline(time.Now().Add(11 * time.Minute)); err != nil {
		return clientFail("The control connection could not be set up.")
	}
	request := map[string]string{"op": op, "name": fs.Arg(1)}
	if *catalog != "" {
		request["arg"] = *catalog
	}
	raw, _ := json.Marshal(request)
	if err := frame.Write(conn, raw); err != nil {
		return clientFail("The request could not be sent to the supervisor.")
	}
	raw, err = frame.Read(conn)
	if err != nil {
		return clientFail("No response was read from the supervisor.")
	}
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return clientFail("The supervisor's response is not valid JSON.")
	}
	// Only --json reads the payload, so a payload this client cannot type
	// never changes the plain form, which prints the response as it came.
	var payload struct {
		Rows        []supervise.Row        `json:"rows"`
		Explanation *supervise.Explanation `json:"explanation"`
		Diff        *supervise.CatalogDiff `json:"diff"`
	}
	if *asJSON {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return clientFail("The supervisor's response does not have the documented shape.")
		}
	}
	if *asJSON {
		out := ctlResult{V: jsonVersion, OK: result.OK}
		if !result.OK {
			out.Code = result.Error
			if out.Code == "" {
				out.Code = "failed"
			}
			out.Message = fail.Message(out.Code)
			out.Unit = fs.Arg(1)
		} else {
			switch op {
			case "status":
				rows := payload.Rows
				if rows == nil {
					rows = []supervise.Row{}
				}
				out.Rows = &rows
			case "explain":
				out.Explanation = payload.Explanation
			case "diff":
				out.Diff = payload.Diff
			}
		}
		if !writeJSON(stdout, out) {
			return 1
		}
	} else if _, err := fmt.Fprintln(stdout, string(raw)); err != nil {
		return 1
	}
	if !result.OK {
		return 1
	}
	return 0
}
