package bootpolicy

import (
	"os"
	"testing"
)

func FuzzVerify(f *testing.F) {
	golden, err := os.ReadFile("testdata/policy.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(golden)
	f.Add([]byte(`{"key_id":"x","key_id":"y"}`))
	f.Add([]byte(`null`))
	trust, _, _ := fixture()
	f.Fuzz(func(t *testing.T, raw []byte) {
		d, err := Verify(raw, trust)
		if err == nil && (d == nil || len(d.Bytes()) > MaxEnvelope || len(d.Digest()) != 64) {
			t.Fatal("invalid success")
		}
	})
}
