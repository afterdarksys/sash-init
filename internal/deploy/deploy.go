// SPDX-License-Identifier: GPL-3.0-or-later

// Package deploy verifies immutable local bundles and maintains separate pending
// and active pointers. A pending policy never changes an active catalog's lease.
//
// Threats: a bundle, its manifest and its policy are untrusted until the
// policy verifies under the local trust and the manifest's exact bytes match
// the signed catalog digest; every file is then hash checked when staged and
// again when loaded, and each service's executable once more on every launch
// (sandbox.Options.SHA256). A revocation floor refuses admission below its
// sequence. Deployments carry exec units only: sash units and boot jobs are
// refused.
package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

const MaxArtifact = 64 << 20

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest is the bundle's file list. Jobs and Resources are part of the
// format but must be empty: boot jobs are not supported (deployment_jobs).
type Manifest struct {
	Resources []json.RawMessage `json:"resources"`
	Version   string            `json:"version"`
	Units     []File            `json:"units"`
	Artifacts []File            `json:"artifacts"`
	Jobs      []File            `json:"jobs"`
}
type State struct {
	Active   string `json:"active"`
	Pending  string `json:"pending"`
	Previous string `json:"previous"`
}
type Manager struct {
	Root  string
	Trust bootpolicy.Trust
	Clock bootpolicy.Clock
}
type Catalog struct {
	ID, Dir  string
	Document *bootpolicy.Document
	Manifest Manifest
	Units    map[string]*unit.Service
}

var generationName = regexp.MustCompile(`^[1-9][0-9]{0,15}-[a-f0-9]{16}$`)
var digestName = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Open(root string, trust bootpolicy.Trust, clock bootpolicy.Clock) (*Manager, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fail.E("deployment_path")
	}
	if err := trust.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	root, err := unit.TrustedDir(root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(root); err != nil || st.Mode().Perm()&0077 != 0 {
		return nil, fail.E("deployment_perm")
	}
	if err := os.MkdirAll(filepath.Join(root, "generations"), 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "policy"), 0700); err != nil {
		return nil, err
	}
	return &Manager{root, trust, clock}, nil
}
func (m *Manager) Lock() (*os.File, error) {
	f, err := openRegular(filepath.Join(m.Root, "lock"), unix.O_RDWR|unix.O_CREAT, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fail.E("deployment_busy")
	}
	return f, nil
}
func openRegular(path string, flags int, mode uint32) (*os.File, error) {
	parent, err := unit.TrustedDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(parent, filepath.Base(path)), flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		f.Close()
		return nil, fail.E("deployment_perm")
	}
	return f, nil
}
func ReadFile(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fail.E("deployment_size")
	}
	return b, nil
}
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validPath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != ".." && !strings.HasPrefix(path, "../") && !strings.ContainsRune(path, 0) && len(path) < 256
}
func parseManifest(raw []byte) (Manifest, error) {
	var manifest Manifest
	if err := bootpolicy.DecodeStrict(raw, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Version != "sahinit-catalog/1" || manifest.Resources == nil || manifest.Jobs == nil || len(manifest.Units) == 0 || len(manifest.Units) > 256 || len(manifest.Artifacts) > 256 {
		return manifest, fail.E("manifest_shape")
	}
	if len(manifest.Jobs) != 0 || len(manifest.Resources) != 0 {
		return manifest, fail.E("deployment_jobs")
	}
	seen := map[string]bool{}
	for _, files := range [][]File{manifest.Units, manifest.Artifacts} {
		for _, f := range files {
			if !validPath(f.Path) || !digestName.MatchString(f.SHA256) || seen[f.Path] {
				return manifest, fail.E("manifest_path")
			}
			seen[f.Path] = true
		}
	}
	for _, f := range manifest.Units {
		if filepath.Dir(f.Path) != "units" || !strings.HasSuffix(f.Path, ".json") || !unit.NameOK(strings.TrimSuffix(filepath.Base(f.Path), ".json")) {
			return manifest, fail.E("manifest_unit")
		}
	}
	for _, f := range manifest.Artifacts {
		if !strings.HasPrefix(f.Path, "artifacts/") {
			return manifest, fail.E("manifest_artifact")
		}
	}
	return manifest, nil
}
func (m *Manager) State() (State, error) {
	var state State
	b, err := ReadFile(filepath.Join(m.Root, "state.json"), 4096)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := bootpolicy.DecodeStrict(b, &state); err != nil {
		return state, err
	}
	for _, id := range []string{state.Active, state.Pending, state.Previous} {
		if id != "" && !generationName.MatchString(id) {
			return state, fail.E("deployment_state")
		}
	}
	return state, nil
}
func atomicWrite(dir, name string, b []byte) error {
	f, err := os.CreateTemp(dir, ".commit-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return fail.E("deployment_durability")
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fail.E("deployment_durability")
	}
	return nil
}
func (m *Manager) save(state State) error {
	b, _ := json.Marshal(state)
	return atomicWrite(m.Root, "state.json", b)
}

func (m *Manager) Stage(document, manifestRaw []byte, bundle string) (*Catalog, error) {
	lock, err := m.Lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	doc, err := bootpolicy.Verify(document, m.Trust)
	if err != nil {
		return nil, err
	}
	if err := doc.CheckFresh(m.Clock); err != nil {
		return nil, err
	}
	if Hash(manifestRaw) != doc.Policy().CatalogSHA256 {
		return nil, fail.E("catalog_digest")
	}
	if len(doc.Policy().Jobs) != 0 || len(doc.Policy().OfflineJobs) != 0 {
		return nil, fail.E("deployment_jobs")
	}
	manifest, err := parseManifest(manifestRaw)
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("%d-%s", doc.Policy().Sequence, Hash(manifestRaw)[:16])
	base := filepath.Join(m.Root, "generations")
	dest := filepath.Join(base, id)
	if _, err := os.Lstat(dest); err == nil {
		c, err := m.Load(id)
		if err != nil {
			return nil, err
		}
		if c.Document.Digest() != doc.Digest() {
			return nil, fail.E("generation_conflict")
		}
	} else {
		if !os.IsNotExist(err) {
			return nil, err
		}
		tmp, err := os.MkdirTemp(base, ".stage-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), manifestRaw, 0600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(tmp, "policy.json"), document, 0600); err != nil {
			return nil, err
		}
		var total int64
		for _, files := range [][]File{manifest.Units, manifest.Artifacts} {
			for _, f := range files {
				limit := int64(MaxArtifact)
				if strings.HasPrefix(f.Path, "units/") {
					limit = 64 * 1024
				}
				b, err := ReadFile(filepath.Join(bundle, f.Path), limit)
				if err != nil {
					return nil, err
				}
				total += int64(len(b))
				if total > 256<<20 {
					return nil, fail.E("deployment_size")
				}
				if Hash(b) != f.SHA256 {
					return nil, fail.E("artifact_digest")
				}
				path := filepath.Join(tmp, f.Path)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					return nil, err
				}
				mode := os.FileMode(0400)
				if strings.HasPrefix(f.Path, "artifacts/") {
					mode = 0555
				}
				if err := os.WriteFile(path, b, mode); err != nil {
					return nil, err
				}
			}
		}
		if _, err := m.loadDir(tmp, id); err != nil {
			return nil, err
		}
		if err := syncTree(tmp); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, dest); err != nil {
			return nil, err
		}
		d, _ := os.Open(base)
		if d != nil {
			err = d.Sync()
			d.Close()
			if err != nil {
				return nil, err
			}
		}
	}
	cache, err := bootpolicy.OpenStore(filepath.Join(m.Root, "policy"), m.Trust, m.Clock)
	if err != nil {
		return nil, err
	}
	defer cache.Close()
	if _, err := cache.Install(document); err != nil {
		return nil, err
	}
	state, err := m.State()
	if err != nil {
		return nil, err
	}
	state.Pending = id
	if err := m.save(state); err != nil {
		return nil, err
	}
	return m.Load(id)
}
func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	})
}
func (m *Manager) Load(id string) (*Catalog, error) {
	if !generationName.MatchString(id) {
		return nil, fail.E("generation_invalid")
	}
	return m.loadDir(filepath.Join(m.Root, "generations", id), id)
}
func (m *Manager) loadDir(dir, id string) (*Catalog, error) {
	raw, err := ReadFile(filepath.Join(dir, "policy.json"), bootpolicy.MaxEnvelope)
	if err != nil {
		return nil, err
	}
	doc, err := bootpolicy.Verify(raw, m.Trust)
	if err != nil {
		return nil, err
	}
	raw, err = ReadFile(filepath.Join(dir, "manifest.json"), 256*1024)
	if err != nil {
		return nil, err
	}
	if Hash(raw) != doc.Policy().CatalogSHA256 {
		return nil, fail.E("catalog_digest")
	}
	if len(doc.Policy().Jobs) != 0 || len(doc.Policy().OfflineJobs) != 0 {
		return nil, fail.E("deployment_jobs")
	}
	manifest, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	if id != fmt.Sprintf("%d-%s", doc.Policy().Sequence, Hash(raw)[:16]) {
		return nil, fail.E("generation_conflict")
	}
	files := map[string][]byte{}
	var total int64
	for _, list := range [][]File{manifest.Units, manifest.Artifacts} {
		for _, f := range list {
			limit := int64(MaxArtifact)
			if !strings.HasPrefix(f.Path, "artifacts/") {
				limit = 64 * 1024
			}
			b, err := ReadFile(filepath.Join(dir, f.Path), limit)
			if err != nil {
				return nil, err
			}
			total += int64(len(b))
			if total > 256<<20 {
				return nil, fail.E("deployment_size")
			}
			if Hash(b) != f.SHA256 {
				return nil, fail.E("artifact_digest")
			}
			if !strings.HasPrefix(f.Path, "artifacts/") {
				files[f.Path] = b
			}
		}
	}
	units := map[string]*unit.Service{}
	for _, f := range manifest.Units {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(files[f.Path], &obj); err != nil {
			return nil, err
		}
		if _, ok := obj["sash"]; ok {
			return nil, fail.E("deployment_sash")
		}
		var argv []string
		if err := json.Unmarshal(obj["exec"], &argv); err != nil || len(argv) == 0 {
			return nil, fail.E("manifest_exec")
		}
		if !strings.HasPrefix(argv[0], "@/") {
			return nil, fail.E("manifest_exec")
		}
		artifact := strings.TrimPrefix(argv[0], "@/")
		found := false
		for _, a := range manifest.Artifacts {
			if a.Path == artifact {
				found = true
			}
		}
		if !found {
			return nil, fail.E("manifest_exec")
		}
		// Parse the original object with a substituted executable; duplicate
		// fields must still be rejected before map decoding discards them.
		if err := rejectDuplicates(files[f.Path]); err != nil {
			return nil, err
		}
		argv[0] = filepath.Join(dir, artifact)
		obj["exec"], _ = json.Marshal(argv)
		encoded, _ := json.Marshal(obj)
		name := strings.TrimSuffix(filepath.Base(f.Path), ".json")
		svc, err := unit.Parse(encoded, name)
		if err != nil {
			return nil, err
		}
		svc.Path = argv[0]
		for _, a := range manifest.Artifacts {
			if a.Path == artifact {
				svc.SHA256 = a.SHA256
			}
		}
		units[name] = svc
	}
	p := doc.Policy()
	if len(p.Units) != len(units) {
		return nil, fail.E("catalog_units")
	}
	for _, u := range p.Units {
		svc, ok := units[u.ID]
		if !ok || !sameNames(u.Needs, svc.Needs) {
			return nil, fail.E("catalog_dependencies")
		}
	}
	if _, err := graph.Plan(units); err != nil {
		return nil, err
	}
	return &Catalog{id, dir, doc, manifest, units}, nil
}
func sameNames(a, b []string) bool {
	a = append([]string{}, a...)
	b = append([]string{}, b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func (m *Manager) Admit(c *Catalog, name string, restart bool) error {
	cache, err := bootpolicy.OpenStore(filepath.Join(m.Root, "policy"), m.Trust, m.Clock)
	if err != nil {
		return err
	}
	defer cache.Close()
	floor, err := cache.Floor()
	if err != nil && fail.Token(err) != "policy_floor_missing" {
		return err
	}
	if floor != nil && c.Document.Policy().Sequence < floor.Floor().MinSequence {
		return fail.E("policy_revoked")
	}
	p := c.Document.Policy()
	contains := func(names []string) bool {
		for _, n := range names {
			if n == name {
				return true
			}
		}
		return false
	}
	if _, ok := c.Units[name]; !ok {
		return fail.E("policy_unit_denied")
	}
	switch c.Document.State(m.Clock) {
	case bootpolicy.Valid:
		return nil
	case bootpolicy.Grace:
		if contains(p.OfflineUnits) {
			return nil
		}
	case bootpolicy.Expired:
		if restart && contains(p.RuntimeRestartUnits) {
			return nil
		}
	case bootpolicy.NotYetValid:
		return fail.E("policy_not_yet_valid")
	default:
		return fail.E("policy_clock_uncertain")
	}
	return fail.E("policy_unit_denied")
}

// CommitActive is called with the deployment lock held and only after the
// supervisor successfully applies this exact verified candidate.
func (m *Manager) CommitActive(id string) error {
	state, err := m.State()
	if err != nil {
		return err
	}
	if state.Pending != id {
		return fail.E("pending_changed")
	}
	state.Previous, state.Active, state.Pending = state.Active, id, ""
	return m.save(state)
}
