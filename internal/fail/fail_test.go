package fail

import (
	"errors"
	"fmt"
	"testing"
)

func TestTokenAndIs(t *testing.T) {
	if Token(nil) != "" {
		t.Fatal(Token(nil))
	}
	if Token(E("cycle")) != "cycle" || E("cycle").Error() != "cycle" {
		t.Fatal(E("cycle"))
	}
	var nilErr *Error
	if nilErr.Error() != "" {
		t.Fatal(nilErr.Error())
	}
	if Token(E("")) != "failed" {
		t.Fatal(Token(E("")))
	}
	if Token(errors.New("/tmp/secret os text")) != "failed" {
		t.Fatal("os text leaked")
	}
	wrapped := fmt.Errorf("wrap: %w", E("uid_denied"))
	if Token(wrapped) != "uid_denied" {
		t.Fatal(Token(wrapped))
	}
	if !errors.Is(E("cycle"), E("cycle")) {
		t.Fatal("same token")
	}
	if errors.Is(E("cycle"), E("failed")) || errors.Is(E("cycle"), errors.New("cycle")) {
		t.Fatal("different token")
	}
	if errors.Is(nil, E("cycle")) {
		t.Fatal("nil")
	}
}
