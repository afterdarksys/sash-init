// Package jsonobj decodes one JSON object and rejects duplicate keys.
// encoding/json keeps the last duplicate, which is the systemd failure mode
// this supervisor exists to refuse.
package jsonobj

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// Decode parses one JSON object. Unknown keys and duplicate keys are refused.
// Trailing values are refused. allow is the closed key set.
func Decode(raw []byte, allow map[string]struct{}) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, fail.E("failed")
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fail.E("failed")
	}
	out := make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fail.E("failed")
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fail.E("failed")
		}
		if _, exists := out[key]; exists {
			return nil, fail.E("duplicate_field")
		}
		if _, known := allow[key]; !known {
			return nil, fail.E("unknown_field")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fail.E("failed")
		}
		out[key] = value
	}
	end, err := dec.Token()
	if err != nil {
		return nil, fail.E("failed")
	}
	endDelim, ok := end.(json.Delim)
	if !ok || endDelim != '}' {
		return nil, fail.E("failed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail.E("failed")
	}
	return out, nil
}

// Unmarshal decodes one already-isolated JSON value into dest.
// A second value in the raw message is refused.
func Unmarshal(raw json.RawMessage, dest any) error {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fail.E("failed")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return fail.E("failed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return fail.E("failed")
	}
	return nil
}
