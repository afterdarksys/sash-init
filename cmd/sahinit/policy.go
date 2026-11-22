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

const policyUsage = "usage: sahinit policy verify|cache|status|floor-install|floor-show --trust FILE [--document FILE] [--cache DIR] [--trust-system-clock]\n"

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
	Lifetime          string           `json:"lifetime,omitempty"`
	FloorMinSequence  uint64           `json:"floor_min_sequence,omitempty"`
}

type floorReport struct {
	Verified    bool   `json:"verified"`
	Enforcement string `json:"enforcement"`
	MinSequence uint64 `json:"min_sequence"`
	IssuedAt    int64  `json:"issued_at"`
	FloorSHA256 string `json:"floor_sha256"`
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	usage := func() int { fmt.Fprint(stderr, policyUsage); return 2 }
	if len(args) == 0 {
		return usage()
	}
	op := args[0]
	if op != "verify" && op != "cache" && op != "status" && op != "floor-install" && op != "floor-show" {
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
	install := op == "cache" || op == "floor-install"
	if (op == "verify" && (*docPath == "" || *cache != "")) || (install && (*docPath == "" || *cache == "")) || ((op == "status" || op == "floor-show") && (*docPath != "" || *cache == "")) {
		return usage()
	}
	refuse := func(err error) int { fmt.Fprintln(stderr, fail.Token(err)); return 1 }
	raw, err := policyFile(*trustPath, 64*1024, true)
	if err != nil {
		return refuse(err)
	}
	trust, err := bootpolicy.DecodeTrust(raw)
	if err != nil {
		return refuse(err)
	}
	var clock bootpolicy.Clock
	if *trustClock {
		clock = bootpolicy.NewClock(time.Now())
	}
	var d *bootpolicy.Document
	if op == "verify" || install {
		raw, err = policyFile(*docPath, bootpolicy.MaxEnvelope, false)
		if err != nil {
			return refuse(err)
		}
	}
	var floor *bootpolicy.FloorDocument
	if op == "verify" {
		d, err = bootpolicy.Verify(raw, trust)
	} else {
		store, e := bootpolicy.OpenStore(*cache, trust, clock)
		if e != nil {
			return refuse(e)
		}
		defer store.Close()
		switch op {
		case "cache":
			d, err = store.Install(raw)
		case "floor-install":
			floor, err = store.InstallFloor(raw)
		case "floor-show":
			floor, err = store.Floor()
		default:
			d, err = store.Load()
			if err == nil || fail.Token(err) == "policy_revoked" {
				if floor, e = store.Floor(); e != nil && fail.Token(e) != "policy_floor_missing" {
					return refuse(e)
				}
			}
		}
	}
	if fail.Token(err) == "policy_revoked" && op == "status" && floor != nil {
		// Revoked metadata is reported, never returned; exit 1 like any refusal.
		json.NewEncoder(stdout).Encode(policyReport{Enforcement: "metadata_only", State: bootpolicy.Revoked, Error: fail.Token(err), FloorMinSequence: floor.Floor().MinSequence})
		return 1
	}
	if err != nil {
		return refuse(err)
	}
	if d == nil {
		f := floor.Floor()
		if e := json.NewEncoder(stdout).Encode(floorReport{Verified: true, Enforcement: "metadata_only", MinSequence: f.MinSequence, IssuedAt: f.IssuedAt, FloorSHA256: floor.Digest()}); e != nil {
			return 1
		}
		return 0
	}
	p := d.Policy()
	report := policyReport{Verified: true, Enforcement: "metadata_only", State: d.State(clock), Sequence: p.Sequence, CatalogGeneration: p.CatalogGeneration, PolicySHA256: d.Digest(), ExpiresAt: p.ExpiresAt, OfflineUntil: p.OfflineUntil, Lifetime: p.Lifetime}
	if floor != nil {
		report.FloorMinSequence = floor.Floor().MinSequence
	}
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
