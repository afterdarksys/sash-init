package sash

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// testdata/sash-mux-frames.json is sash's internal/proto golden (shared with
// the systemapi agent), copied byte for byte. sahinit speaks only its serial
// part: every request before the hello decodes, every serial reply
// re-encodes to the same bytes, and the hello is answered as an agent
// without mux answers it.
func TestGoldenFrames(t *testing.T) {
	raw, err := os.ReadFile("testdata/sash-mux-frames.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Source string `json:"source"`
		Steps  []struct {
			Op    string `json:"op"`
			Frame string `json:"frame"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil || golden.Source == "" {
		t.Fatalf("golden: %v", err)
	}
	sent, replied, hello := 0, 0, false
	for _, st := range golden.Steps {
		if strings.HasPrefix(st.Frame, `{"mux"`) {
			if st.Op == "send" {
				hello = true
				if _, err := DecodeRequest([]byte(st.Frame)); err == nil {
					t.Fatal("hello decoded as a verb")
				}
			}
			break
		}
		switch st.Op {
		case "send":
			req, err := DecodeRequest([]byte(st.Frame))
			if err != nil || req.Key == "" || len(req.Argv) == 0 {
				t.Fatalf("serial request %s: %v", st.Frame, err)
			}
			sent++
		case "expect":
			var w wireResponse
			dec := json.NewDecoder(strings.NewReader(st.Frame))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&w); err != nil {
				t.Fatal(err)
			}
			resp := Response{Kind: w.Kind, Rows: w.Rows, Cols: w.Cols, Exit: w.Exit}
			got, err := EncodeResponse(resp)
			if err != nil || string(got) != st.Frame {
				t.Fatalf("reply %s, sash expects %s", got, st.Frame)
			}
			replied++
		}
	}
	if sent < 3 || replied < 3 || !hello {
		t.Fatalf("golden coverage: %d sent, %d replied, hello %v", sent, replied, hello)
	}
	// The reply to a hello is sash's helloOld, byte for byte.
	got, _ := EncodeResponse(Response{Error: "frame body"})
	if string(got) != `{"error":"frame body"}` {
		t.Fatalf("hello reply %s", got)
	}
}

func TestFrameLimits(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte(`{"key":"ps","argv":["ps"],"path":"","body":""}`)); err != nil {
		t.Fatal(err)
	}
	body, err := ReadFrame(&buf)
	if err != nil || !strings.Contains(string(body), `"ps"`) {
		t.Fatalf("%s %v", body, err)
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("clean end: %v", err)
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], MaxFrame+1)
	if _, err := ReadFrame(bytes.NewReader(n[:])); err != errFrameLength {
		t.Fatalf("over length: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0})); err == nil || err == io.EOF {
		t.Fatalf("short header: %v", err)
	}
	for _, bad := range []string{`{"key":"ps","argv":["ps"],"path":"","body":"","extra":1}`, `{"key":"ps"} {}`, `{"key":"x","body":"!!"}`, `[]`} {
		if _, err := DecodeRequest([]byte(bad)); err == nil {
			t.Errorf("%s decoded", bad)
		}
	}
}
