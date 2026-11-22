package jsonobj

import (
	"errors"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func TestDecodeRejects(t *testing.T) {
	allow := map[string]struct{}{"a": {}}
	cases := []struct {
		raw   string
		token string
	}{
		{`{"a":1,"a":2}`, "duplicate_field"},
		{`{"a":1,"b":2}`, "unknown_field"},
		{`{"a":1}{"b":2}`, "failed"},
		{`[]`, "failed"},
		{`null`, "failed"},
		{`{"a":`, "failed"},
		{``, "failed"},
	}
	for _, tc := range cases {
		_, err := Decode([]byte(tc.raw), allow)
		if !errors.Is(err, fail.E(tc.token)) {
			t.Fatalf("%s: got %v", tc.raw, err)
		}
	}
}

func TestDecodeKeepsValue(t *testing.T) {
	allow := map[string]struct{}{"a": {}, "b": {}}
	obj, err := Decode([]byte(`{"a":1,"b":"x"}`), allow)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := Unmarshal(obj["a"], &n); err != nil || n != 1 {
		t.Fatalf("a: %v %d", err, n)
	}
}

func TestDecodeEmptyObject(t *testing.T) {
	obj, err := Decode([]byte(`{}`), map[string]struct{}{"a": {}})
	if err != nil || len(obj) != 0 {
		t.Fatalf("%v %#v", err, obj)
	}
	_, err = Decode([]byte(`{"a":1,}`), map[string]struct{}{"a": {}})
	if !errors.Is(err, fail.E("failed")) {
		t.Fatal(err)
	}
}

func TestUnmarshalRejectsNullAndTrailing(t *testing.T) {
	var s string
	if err := Unmarshal([]byte("null"), &s); !errors.Is(err, fail.E("failed")) {
		t.Fatal(err)
	}
	var n int
	if err := Unmarshal([]byte("1 2"), &n); !errors.Is(err, fail.E("failed")) {
		t.Fatal(err)
	}
}
