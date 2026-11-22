// Package frame is the sash-shaped control frame: a big-endian uint32 length
// followed by that many JSON bytes. The length is checked before allocation.
package frame

import (
	"encoding/binary"
	"io"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// Max is the largest accepted payload. The declared length is rejected
// before a buffer of that size is allocated.
const Max = 64 * 1024

// Read reads one frame. A declared length above Max returns frame_size and
// does not allocate the payload.
func Read(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > Max {
		return nil, fail.E("frame_size")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Write writes one frame. Payloads above Max are refused.
func Write(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > Max {
		return fail.E("frame_size")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
