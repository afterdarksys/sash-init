// SPDX-License-Identifier: GPL-3.0-or-later

package unit

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/jsonobj"
)

// Execution is explicit process context. Nil UID/GID inherits the supervisor's
// identity; explicit IDs always replace supplementary groups (empty by default).
type Execution struct {
	UID         *uint32  `json:"uid,omitempty"`
	GID         *uint32  `json:"gid,omitempty"`
	Groups      []uint32 `json:"groups,omitempty"`
	Directory   string   `json:"directory,omitempty"`
	Environment []string `json:"environment,omitempty"`
}

var executionKeys = map[string]struct{}{"uid": {}, "gid": {}, "groups": {}, "directory": {}, "environment": {}}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func parseExecution(raw json.RawMessage) (Execution, error) {
	var e Execution
	if raw == nil {
		return e, nil
	}
	obj, err := jsonobj.Decode(raw, executionKeys)
	if err != nil {
		return e, err
	}
	for k, v := range obj {
		var dest any
		switch k {
		case "uid":
			dest = &e.UID
		case "gid":
			dest = &e.GID
		case "groups":
			dest = &e.Groups
		case "directory":
			dest = &e.Directory
		case "environment":
			dest = &e.Environment
		}
		if err := jsonobj.Unmarshal(v, dest); err != nil {
			return e, err
		}
	}
	return e, e.Validate()
}

func (e Execution) Validate() error {
	bad := func() error { return fail.E("execution_invalid") }
	if (e.UID == nil) != (e.GID == nil) || (e.UID == nil && e.Groups != nil) || len(e.Groups) > 64 {
		return bad()
	}
	if e.UID != nil && (*e.UID == ^uint32(0) || *e.GID == ^uint32(0)) {
		return bad()
	}
	seenGroups := map[uint32]bool{}
	for _, g := range e.Groups {
		if g == ^uint32(0) || seenGroups[g] {
			return bad()
		}
		seenGroups[g] = true
	}
	if e.Directory != "" && (!path.IsAbs(e.Directory) || path.Clean(e.Directory) != e.Directory || len(e.Directory) > 4096 || strings.ContainsRune(e.Directory, 0)) {
		return bad()
	}
	if len(e.Environment) > 128 {
		return bad()
	}
	seen := map[string]bool{}
	total := 0
	for _, v := range e.Environment {
		key, _, ok := strings.Cut(v, "=")
		total += len(v)
		if !ok || !envName.MatchString(key) || strings.HasPrefix(key, "SAHINIT_") || seen[key] || strings.ContainsRune(v, 0) || total > 16384 {
			return bad()
		}
		seen[key] = true
	}
	return nil
}

// Env never inherits the supervisor environment. PATH can be explicitly replaced.
func (e Execution) Env() []string {
	env := []string{}
	hasPath := false
	for _, v := range e.Environment {
		if strings.HasPrefix(v, "PATH=") {
			hasPath = true
		}
		env = append(env, v)
	}
	if !hasPath {
		env = append(env, "PATH=/usr/bin:/bin:/usr/sbin:/sbin")
	}
	return env
}
