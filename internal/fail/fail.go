// SPDX-License-Identifier: GPL-3.0-or-later

// Package fail is the closed error vocabulary for sahinit.
// Error text is the token and nothing else, so a caller cannot leak a path,
// a request id, or an OS error string onto the control socket.
package fail

import "errors"

// Error is a stable machine token.
type Error struct {
	Token string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Token
}

func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other != nil && e.Token == other.Token
}

// E returns a token error. The same token always compares equal.
func E(token string) error {
	return &Error{Token: token}
}

// Token returns the stable token. Errors that are not tokens become "failed"
// so raw OS text never crosses the socket.
func Token(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) && e.Token != "" {
		return e.Token
	}
	return "failed"
}
