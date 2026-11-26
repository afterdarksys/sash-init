// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"

	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const versionUsage = "usage: sahinit version [--json]\n"

// version is set with -ldflags "-X main.version=..."; without it the
// module version from the build info is reported ("(devel)" for a build
// from a checkout).
var version string

// buildTags are the build tags that change what this binary does. This
// branch has none.
var buildTags = []string{}

// unitFeatures are features named after the unit field that carries them:
// each is reported only while the loader reads that field.
var unitFeatures = map[string]string{
	"cgroup_limits":   "memory_max",
	"essential":       "essential",
	"restart_backoff": "restart_delay",
	"sash_units":      "sash",
	"socket_paths":    "sandbox.socket_paths",
	"unit_caps":       "sandbox.caps",
	"watchdog":        "watchdog",
}

// ctlFeatures are features named after the ctl operation that carries them.
var ctlFeatures = map[string]string{
	"deployments":  "activate",
	"live_catalog": "apply",
}

// features lists, sorted, every feature whose field or operation exists.
func features() []string {
	out := []string{}
	for name, field := range unitFeatures {
		if unit.HasField(field) {
			out = append(out, name)
		}
	}
	for name, op := range ctlFeatures {
		if slices.Contains(ctlOps, op) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

type versionInfo struct {
	V              int      `json:"v"`
	OK             bool     `json:"ok"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Commit         string   `json:"commit"`
	Go             string   `json:"go"`
	UnitSchema     int      `json:"unit_schema"`
	GrantVersions  []string `json:"grant_versions"`
	LandlockABIMax int      `json:"landlock_abi_max"`
	CapsGrantable  []string `json:"caps_grantable"`
	Features       []string `json:"features"`
	Build          []string `json:"build"`
}

// currentVersion reads every value from the constant the code checks
// against: the unit schema, the grant version the grant check compares,
// the Landlock ABI the sandbox caps at, and the capability allowlist.
func currentVersion() versionInfo {
	v := versionInfo{
		V: jsonVersion, OK: true, Name: "sahinit", Version: version, Commit: "unknown", Go: runtime.Version(),
		UnitSchema: unit.Schema, GrantVersions: []string{sash.GrantVersion}, LandlockABIMax: sandbox.MaxLandlockABI,
		CapsGrantable: unit.GrantableCaps(), Features: features(), Build: buildTags,
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v.Version == "" {
			v.Version = info.Main.Version
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				v.Commit = s.Value
			}
		}
	}
	if v.Version == "" {
		v.Version = "(devel)"
	}
	return v
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usage(args, versionUsage, stdout, stderr)
	}
	v := currentVersion()
	if *asJSON {
		if !writeJSON(stdout, v) {
			return 1
		}
		return 0
	}
	build := strings.Join(v.Build, " ")
	if build == "" {
		build = "(none)"
	}
	_, err := fmt.Fprintf(stdout, "sahinit %s\ncommit %s\ngo %s\nunit_schema %d\ngrant_versions %s\nlandlock_abi_max %d\ncaps_grantable %s\nfeatures %s\nbuild %s\n",
		v.Version, v.Commit, v.Go, v.UnitSchema, strings.Join(v.GrantVersions, " "), v.LandlockABIMax,
		strings.Join(v.CapsGrantable, " "), strings.Join(v.Features, " "), build)
	if err != nil {
		return 1
	}
	return 0
}
