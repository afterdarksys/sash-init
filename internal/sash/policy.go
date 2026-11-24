// SPDX-License-Identifier: GPL-3.0-or-later

package sash

// The spawn environment denylist, copied from sash's internal/grant/policy.go
// (feat/init-phase1 at f28285b). testdata/sash-grant-vectors.json holds
// sash's own answer for each name, and TestEnvTableMatchesSash compares.
//
// Threats: a spawn env name that makes the child load code (LD_PRELOAD,
// interpreter search paths, OPENSSL_CONF, GIT_SSH_COMMAND). The signed
// env_names is the allowlist; this table is a second gate a careless signer
// cannot open.

import (
	"regexp"
	"strings"
)

// EnvName is the form of a spawn environment name.
var EnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

var envDenied = map[string]bool{
	"GCONV_PATH": true, "LOCPATH": true, "NLSPATH": true, "HOSTALIASES": true, "RES_OPTIONS": true,
	"GLIBC_TUNABLES": true, "TZDIR": true, "BASH_ENV": true, "ENV": true, "IFS": true, "SHELLOPTS": true,
	"PYTHONPATH": true, "PYTHONHOME": true, "PYTHONSTARTUP": true, "PYTHONWARNINGS": true,
	"PERLLIB": true, "PERL5LIB": true, "PERL5OPT": true, "PERL5DB": true,
	"RUBYLIB": true, "RUBYOPT": true, "NODE_OPTIONS": true, "NODE_PATH": true,
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "CLASSPATH": true,
	"LUA_PATH": true, "LUA_CPATH": true, "OPENSSL_CONF": true, "OPENSSL_ENGINES": true,
}

var envDeniedPrefix = []string{"LD_", "DYLD_", "MALLOC_", "GIT_"}

// EnvDenied reports a name on the denylist.
func EnvDenied(name string) bool {
	for _, p := range envDeniedPrefix {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return envDenied[name]
}
