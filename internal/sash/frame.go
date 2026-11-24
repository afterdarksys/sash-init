package sash

// The verb frames between sash and its parent: a big-endian uint32 length
// and one JSON object (sash internal/proto). sahinit has its own reader and
// writer; testdata/sash-mux-frames.json, copied from sash, pins them.
//
// Threats: a length above MaxFrame is refused before the body is read, and
// the session is then closed; a request with an unknown field (a mux hello
// included) is answered with sash's exact "old agent" reply,
// {"error":"frame body"}, so sash stays on the serial wire, which is all
// sahinit speaks. A response carries only kind, bytes, rows, cols, exit and
// error: sash's decoder refuses anything else.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// MaxFrame is the largest request sahinit reads. sash allows 8 MiB; no
// batch 1 verb needs more than a spawn's options.
const MaxFrame = 1 << 20

// errFrameLength is a declared length past MaxFrame: the session ends.
var errFrameLength = errors.New("frame length")

// Request is one verb from sash. Body is the decoded base64 body.
type Request struct {
	Key  string
	Argv []string
	Path string
	Body []byte
	Mode string
}

type wireRequest struct {
	Key  string   `json:"key"`
	Argv []string `json:"argv"`
	Path string   `json:"path"`
	Body string   `json:"body"`
	Mode string   `json:"mode,omitempty"`
}

// Row is one result row: column to text.
type Row map[string]string

// Response is one result. A non-empty Error is sent alone.
type Response struct {
	Kind  string
	Bytes []byte
	Rows  []Row
	Cols  []string
	Exit  int
	Error string
}

type wireResponse struct {
	Kind  string   `json:"kind,omitempty"`
	Bytes string   `json:"bytes,omitempty"`
	Rows  []Row    `json:"rows,omitempty"`
	Cols  []string `json:"cols,omitempty"`
	Exit  int      `json:"exit"`
}

type wireError struct {
	Error string `json:"error"`
}

// ReadFrame reads one frame body. io.EOF is a clean end between frames.
func ReadFrame(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fail.E("failed")
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > MaxFrame {
		return nil, errFrameLength
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fail.E("failed")
	}
	return body, nil
}

// DecodeRequest parses one request body strictly. Any error is answered
// with "frame body".
func DecodeRequest(body []byte) (Request, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var w wireRequest
	if err := dec.Decode(&w); err != nil {
		return Request{}, fail.E("frame body")
	}
	if _, err := dec.Token(); err != io.EOF {
		return Request{}, fail.E("frame body")
	}
	req := Request{Key: w.Key, Argv: w.Argv, Path: w.Path, Mode: w.Mode}
	if w.Body != "" {
		b, err := base64.StdEncoding.DecodeString(w.Body)
		if err != nil {
			return Request{}, fail.E("frame body")
		}
		req.Body = b
	}
	return req, nil
}

// EncodeResponse is the frame body for resp.
func EncodeResponse(resp Response) ([]byte, error) {
	if resp.Error != "" {
		return json.Marshal(wireError{Error: resp.Error})
	}
	w := wireResponse{Kind: resp.Kind, Rows: resp.Rows, Cols: resp.Cols, Exit: resp.Exit}
	if w.Kind == "" {
		w.Kind = "bytes"
	}
	if len(resp.Bytes) > 0 {
		w.Bytes = base64.StdEncoding.EncodeToString(resp.Bytes)
	}
	return json.Marshal(w)
}

// WriteFrame sends one frame body.
func WriteFrame(w io.Writer, body []byte) error {
	if len(body) > 8<<20 {
		return fail.E("failed")
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}
