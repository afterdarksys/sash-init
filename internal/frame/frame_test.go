package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, []byte(`{"op":"status"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"op":"status"}` {
		t.Fatalf("payload %q", got)
	}
}

func TestReadRejectsLengthBeforeAlloc(t *testing.T) {
	for _, n := range []uint32{0, Max + 1} {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], n)
		_, err := Read(&stopReader{b: hdr[:]})
		if !errors.Is(err, fail.E("frame_size")) {
			t.Fatalf("len %d: %v", n, err)
		}
	}
}

func TestReadShortHeaderAndBody(t *testing.T) {
	_, err := Read(bytes.NewReader([]byte{0, 0}))
	if err == nil || errors.Is(err, fail.E("frame_size")) {
		t.Fatal(err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 4)
	_, err = Read(bytes.NewReader(hdr[:]))
	if err == nil || errors.Is(err, fail.E("frame_size")) {
		t.Fatal(err)
	}
}

func TestWriteRejectsEmptyAndOversize(t *testing.T) {
	if err := Write(&bytes.Buffer{}, nil); !errors.Is(err, fail.E("frame_size")) {
		t.Fatal(err)
	}
	if err := Write(&bytes.Buffer{}, bytes.Repeat([]byte("a"), Max+1)); !errors.Is(err, fail.E("frame_size")) {
		t.Fatal(err)
	}
}

// stopReader fails if the frame reader goes past the header.
type stopReader struct {
	b []byte
}

func (s *stopReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, errors.New("payload was read")
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}
