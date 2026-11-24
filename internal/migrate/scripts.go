// SPDX-License-Identifier: GPL-3.0-or-later

package migrate

import (
	"os"
	"path/filepath"
	"strings"
)

func (r *Report) daemontools(path string, u *Unit) {
	entries, err := os.ReadDir(path)
	if err != nil {
		r.note(path, 0, "error", err.Error())
		return
	}
	for _, e := range entries {
		switch e.Name() {
		case "run":
		case "down":
			u.Boot = false
		case "supervise": // runtime state is not configuration
		default:
			r.note(filepath.Join(path, e.Name()), 0, "error", "unsupported service content (including log, env or finish); migrate explicitly")
		}
	}
	raw, ok := r.load(filepath.Join(path, "run"))
	if !ok {
		return
	}
	if !strings.HasPrefix(raw, "#!/bin/sh\n") && !strings.HasPrefix(raw, "#!/bin/bash\n") {
		r.note(path+"/run", 1, "error", "run must use a plain /bin/sh or /bin/bash shebang")
		return
	}
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "exec ") || len(u.Exec) > 0 {
			r.note(path+"/run", i+1, "error", "only a single literal exec command is supported; shell setup must be migrated explicitly")
			continue
		}
		args, err := words(strings.TrimSpace(strings.TrimPrefix(line, "exec ")))
		if err != nil {
			r.note(path+"/run", i+1, "error", err.Error())
			continue
		}
		u.Exec = args
	}
	if len(u.Exec) == 0 {
		r.note(path+"/run", 0, "error", "missing exec command")
	}
	u.Restart = "always"
	r.note(path, 0, "warning", "daemontools runs in the service directory and retries indefinitely; SAHINIT runs in / with a bounded restart burst. Verify the command does not depend on cwd or inherited environment.")
}

func (r *Report) openrc(path string, u *Unit) {
	raw, ok := r.load(path)
	if !ok {
		return
	}
	if !strings.HasPrefix(raw, "#!/sbin/openrc-run\n") && !strings.HasPrefix(raw, "#!/usr/sbin/openrc-run\n") {
		r.note(path, 1, "error", "expected an openrc-run shebang")
		return
	}
	values := map[string]string{}
	inDeps := false
	seenDeps := false
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "depend() {" || line == "depend()" {
			if seenDeps {
				r.note(path, i+1, "error", "repeated or nested depend function")
			}
			seenDeps = true
			inDeps = true
			continue
		}
		if inDeps {
			if line == "{" {
				continue
			}
			if line == "}" {
				inDeps = false
				continue
			}
			args, err := words(line)
			if err != nil || len(args) < 2 || args[0] != "after" {
				r.note(path, i+1, "error", "only literal 'after SERVICE...' dependencies are supported; need/use/provide/before require manual lifecycle mapping")
				continue
			}
			u.After = append(u.After, args[1:]...)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != key || strings.TrimSpace(value) != value {
			r.note(path, i+1, "error", "unsupported shell statement or hook; source scripts are never executed")
			continue
		}
		switch key {
		case "command", "command_args", "command_args_foreground", "supervisor", "name", "description":
		default:
			r.note(path, i+1, "error", "unsupported OpenRC setting: "+key)
			continue
		}
		if _, exists := values[key]; exists {
			r.note(path, i+1, "error", "repeated assignment: "+key)
			continue
		}
		args, err := words(value)
		if err != nil || len(args) != 1 {
			r.note(path, i+1, "error", "expected a single literal assignment value")
			continue
		}
		values[key] = args[0]
	}
	if inDeps {
		r.note(path, 0, "error", "unterminated depend function")
	}
	u.Exec = []string{values["command"]}
	for _, key := range []string{"command_args", "command_args_foreground"} {
		if key == "command_args_foreground" && values[key] != "" && values["supervisor"] != "supervise-daemon" {
			r.note(path, 0, "error", "command_args_foreground requires supervisor=supervise-daemon")
			continue
		}
		args, err := words(values[key])
		if err != nil {
			r.note(path, 0, "error", err.Error())
			continue
		}
		u.Exec = append(u.Exec, args...)
	}
	switch values["supervisor"] {
	case "", "start-stop-daemon":
	case "supervise-daemon":
		u.Restart = "always"
	default:
		r.note(path, 0, "error", "unsupported OpenRC supervisor")
	}
	r.note(path, 0, "warning", "OpenRC conf.d, rc.conf, runlevels and dependency shutdown semantics are not imported. Supply self-contained foreground commands and review any external configuration first.")
}
