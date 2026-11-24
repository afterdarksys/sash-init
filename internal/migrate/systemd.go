// SPDX-License-Identifier: GPL-3.0-or-later

package migrate

import (
	"strings"
)

func (r *Report) systemd(path string, u *Unit) {
	raw, ok := r.load(path)
	if !ok {
		return
	}
	section := ""
	seen := map[string]bool{}
	typ := "simple"
	remain := "no"
	for i, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			r.note(path, i+1, "error", "continuations require manual flattening")
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if section != "Unit" && section != "Service" && section != "Install" {
				r.note(path, i+1, "error", "unsupported section: "+section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok {
			r.note(path, i+1, "error", "expected section directive; continuations are unsupported")
			continue
		}
		full := section + "." + key
		if seen[full] {
			r.note(path, i+1, "error", "repeated/reset directive requires manual flattening: "+full)
			continue
		}
		seen[full] = true
		switch full {
		case "Unit.Description", "Unit.Documentation":
		case "Install.WantedBy", "Install.RequiredBy", "Install.Alias", "Install.Also":
			r.note(path, i+1, "warning", full+" is not imported; --boot explicitly selects startup, aliases and additional units are not created")
		case "Service.Type":
			typ = value
		case "Service.ExecStart":
			args, err := words(value)
			if err != nil {
				r.note(path, i+1, "error", err.Error())
				continue
			}
			u.Exec = args
		case "Service.Restart":
			u.Restart = value
		case "Service.RemainAfterExit":
			remain = value
		case "Unit.After":
			for _, dep := range strings.Fields(value) {
				if !strings.HasSuffix(dep, ".service") {
					r.note(path, i+1, "error", "non-service ordering dependency requires manual migration: "+dep)
					continue
				}
				u.After = append(u.After, strings.TrimSuffix(dep, ".service"))
			}
		default:
			r.note(path, i+1, "error", "unsupported directive: "+full+"; its behavior cannot be silently discarded")
		}
	}
	switch typ {
	case "simple", "exec":
		if remain != "no" && remain != "false" {
			r.note(path, 0, "error", "RemainAfterExit is only supported for oneshot units")
		}
	case "oneshot":
		u.Type = "oneshot"
		u.Ready = "exit"
		if remain != "yes" && remain != "true" {
			r.note(path, 0, "error", "oneshot requires RemainAfterExit=yes to match SAHINIT's completed state")
		}
	default:
		r.note(path, 0, "error", "unsupported Type="+typ+"; notify protocols, forking and D-Bus activation need adapters")
	}
	if len(u.Exec) == 0 {
		r.note(path, 0, "error", "missing ExecStart")
	}
	if len(u.After) > 0 {
		r.note(path, 0, "warning", "After is boot ordering only; runtime dependency stop/restart propagation is not implemented")
	}
}
