// Package migrate converts explicit, offline service catalogs. It never executes
// source scripts, reads the host service-manager state, or switches init systems.
package migrate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

const maxSource = 64 * 1024

type Diagnostic struct {
	Source   string `json:"source"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Unit struct {
	Name    string   `json:"name"`
	Exec    []string `json:"exec"`
	Type    string   `json:"type"`
	Ready   string   `json:"ready"`
	Restart string   `json:"restart"`
	Boot    bool     `json:"boot"`
	After   []string `json:"after,omitempty"`
}

type Report struct {
	Format      string       `json:"format"`
	Units       []Unit       `json:"units"`
	Diagnostics []Diagnostic `json:"diagnostics"`
	Written     bool         `json:"written"`
}

func (r *Report) note(source string, line int, severity, message string) {
	r.Diagnostics = append(r.Diagnostics, Diagnostic{source, line, severity, message})
}
func (r *Report) Blocked() bool {
	for _, d := range r.Diagnostics {
		if d.Severity == "error" {
			return true
		}
	}
	return false
}

// Scan requires an explicitly selected catalog, not an installation root.
// Boot is an operator choice, not inferred from systemd [Install] or runlevels.
func Scan(format, source string, boot bool) (*Report, error) {
	switch format {
	case "systemd", "daemontools", "openrc":
	default:
		return nil, fmt.Errorf("unknown source format %q", format)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("source must be a real directory")
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 || len(entries) > 256 {
		return nil, fmt.Errorf("source must contain 1..256 entries")
	}
	r := &Report{Format: format, Units: []Unit{}, Diagnostics: []Diagnostic{}}
	r.note(source, 0, "warning", "Review required: output uses SAHINIT's clean environment, / working directory, discarded stdout/stderr, five-second timeouts and restart burst limits. No host enablement, global configuration or implicit dependencies are imported.")
	for _, e := range entries {
		path := filepath.Join(source, e.Name())
		name := e.Name()
		if format == "systemd" {
			name = strings.TrimSuffix(name, ".service")
		}
		if e.Type()&os.ModeSymlink != 0 {
			r.note(path, 0, "error", "symlinks, aliases and masked units are unsupported; supply a resolved standalone catalog")
			continue
		}
		if !unit.NameOK(name) {
			r.note(path, 0, "error", "name is not a SAHINIT name; rename explicitly and update dependencies")
			continue
		}
		u := Unit{Name: name, Type: "simple", Ready: "exec", Restart: "no", Boot: boot}
		before := len(r.Diagnostics)
		switch format {
		case "systemd":
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				r.note(path, 0, "error", "only standalone .service files are supported; drop-ins, targets, sockets and timers need manual migration")
				continue
			}
			r.systemd(path, &u)
		case "daemontools":
			if !e.IsDir() {
				r.note(path, 0, "error", "expected service directory containing run")
				continue
			}
			r.daemontools(path, &u)
		case "openrc":
			if e.IsDir() {
				r.note(path, 0, "error", "expected an OpenRC service script")
				continue
			}
			r.openrc(path, &u)
		}
		bad := false
		for _, d := range r.Diagnostics[before:] {
			if d.Severity == "error" {
				bad = true
			}
		}
		if !bad {
			r.Units = append(r.Units, u)
		}
	}
	catalog := make(map[string]*unit.Service)
	for _, u := range r.Units {
		b, _ := json.Marshal(u)
		s, err := unit.Parse(b, u.Name)
		if err != nil {
			r.note(u.Name, 0, "error", "generated unit rejected by SAHINIT: "+err.Error())
			continue
		}
		catalog[u.Name] = s
	}
	if !r.Blocked() {
		if _, err := graph.Plan(catalog); err != nil {
			r.note(source, 0, "error", "catalog rejected by SAHINIT planner: "+err.Error())
		}
	}
	return r, nil
}

func readSource(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() > maxSource {
		return "", fmt.Errorf("expected regular file of at most 64 KiB")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() {
		return "", fmt.Errorf("expected regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSource+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxSource || strings.ContainsRune(string(b), 0) {
		return "", fmt.Errorf("oversized file or NUL byte")
	}
	return string(b), nil
}

// Write refuses blockers and existing destinations. Only unit JSON is written
// into the catalog; diagnostics belong on stdout, not in the unit directory.
func (r *Report) Write(out string) (err error) {
	if r.Blocked() {
		return fmt.Errorf("migration has blockers; no files written")
	}
	if len(r.Units) == 0 {
		return fmt.Errorf("no units to write")
	}
	if err = os.Mkdir(out, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(out)
		}
	}()
	for _, u := range r.Units {
		b, e := json.MarshalIndent(u, "", "  ")
		if e != nil {
			return e
		}
		if err = os.WriteFile(filepath.Join(out, u.Name+".json"), append(b, '\n'), 0o600); err != nil {
			return err
		}
	}
	r.Written = true
	return nil
}

// words accepts a deliberately small literal quoting grammar common to these
// formats. Expansions, escapes and shell operators require manual conversion.
func words(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	var quote rune
	started := false
	for _, c := range s {
		if strings.ContainsRune("\\$`%;|&<>(){}*?[]~#\n\r", c) {
			return nil, fmt.Errorf("expansions, escapes and shell operators are unsupported")
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			started = true
		case ' ', '\t':
			if started {
				out = append(out, b.String())
				b.Reset()
				started = false
			}
		default:
			b.WriteRune(c)
			started = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if started {
		out = append(out, b.String())
	}
	return out, nil
}

func (r *Report) load(path string) (string, bool) {
	raw, err := readSource(path)
	if err != nil {
		r.note(path, 0, "error", err.Error())
		return "", false
	}
	return raw, true
}
