package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

const policyUsage = "usage: sahinit policy verify|cache|status --trust FILE [--document FILE] [--cache DIR] [--trust-system-clock]\n"

type policyReport struct {
	Verified          bool             `json:"verified"`
	Enforcement       string           `json:"enforcement"`
	State             bootpolicy.State `json:"state"`
	Error             string           `json:"error"`
	Sequence          uint64           `json:"sequence,omitempty"`
	CatalogGeneration uint64           `json:"catalog_generation,omitempty"`
	PolicySHA256      string           `json:"policy_sha256,omitempty"`
	ExpiresAt         int64            `json:"expires_at,omitempty"`
	OfflineUntil      int64            `json:"offline_until,omitempty"`
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	usage := func() int { fmt.Fprint(stderr, policyUsage); return 2 }
	if len(args) == 0 {
		return usage()
	}
	op := args[0]
	if op != "verify" && op != "cache" && op != "status" {
		return usage()
	}
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	trustPath := fs.String("trust", "", "")
	docPath := fs.String("document", "", "")
	cache := fs.String("cache", "", "")
	trustClock := fs.Bool("trust-system-clock", false, "assert the Linux system clock is already trustworthy")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *trustPath == "" {
		return usage()
	}
	if (op == "verify" && (*docPath == "" || *cache != "")) || (op == "cache" && (*docPath == "" || *cache == "")) || (op == "status" && (*docPath != "" || *cache == "")) {
		return usage()
	}
	refuse := func(err error) int { fmt.Fprintln(stderr, fail.Token(err)); return 1 }
	raw, err := policyFile(*trustPath, 64*1024, true)
	if err != nil {
		return refuse(err)
	}
	var trust bootpolicy.Trust
	if err := bootpolicy.DecodeStrict(raw, &trust); err != nil {
		return refuse(err)
	}
	if err := trust.Validate(); err != nil {
		return refuse(err)
	}
	var clock bootpolicy.Clock
	if *trustClock {
		clock = bootpolicy.NewClock(time.Now())
	}
	var d *bootpolicy.Document
	if op == "verify" || op == "cache" {
		raw, err = policyFile(*docPath, bootpolicy.MaxEnvelope, false)
		if err != nil {
			return refuse(err)
		}
	}
	if op == "verify" {
		d, err = bootpolicy.Verify(raw, trust)
	} else {
		store, e := bootpolicy.OpenStore(*cache, trust, clock)
		if e != nil {
			return refuse(e)
		}
		defer store.Close()
		if op == "cache" {
			d, err = store.Install(raw)
		} else {
			d, err = store.Load()
		}
	}
	if err != nil {
		return refuse(err)
	}
	p := d.Policy()
	report := policyReport{Verified: true, Enforcement: "metadata_only", State: d.State(clock), Sequence: p.Sequence, CatalogGeneration: p.CatalogGeneration, PolicySHA256: d.Digest(), ExpiresAt: p.ExpiresAt, OfflineUntil: p.OfflineUntil}
	if op == "verify" {
		err = d.CheckFresh(clock)
		report.Error = fail.Token(err)
	}
	if e := json.NewEncoder(stdout).Encode(report); e != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func policyFile(path string, limit int64, trusted bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fail.E("policy_read_failed")
	}
	defer f.Close()
	if trusted {
		var st unix.Stat_t
		if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
			return nil, fail.E("policy_bad_trust")
		}
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fail.E("policy_read_failed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fail.E("policy_read_failed")
	}
	return raw, nil
}
