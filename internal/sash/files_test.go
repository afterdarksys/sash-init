package sash

import (
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func fileServer() (*Server, *fakeHost) {
	s, h := newServer()
	s.G.Entitlements = append(s.G.Entitlements, "file.write", "fs.mount")
	s.G.Mounts = []string{"/mnt/app", "/run/app/tmp", "/var"}
	s.G.MountSources = []string{"tmpfs", "proc", "/srv/static"}
	return s, h
}

func fileReq(argv ...string) Request {
	return Request{Key: "file.write", Argv: argv, Path: argv[1]}
}

func TestFileVerbsAccepted(t *testing.T) {
	s, h := fileServer()
	for _, a := range [][]string{
		{"mkdir", "/run/app/work", "mode", "0750", "owner", "app:app"},
		{"mkdir", "/run/app/plain"},
		{"chown", "/run/app/x", "app:app"},
		{"chmod", "/run/app/x", "1777"},
		{"touch", "/var/log/app/a.log"},
		{"ln", "/run/app/cur", "/run/app/v2"},
		{"rm", "/run/app/old"},
	} {
		if r := s.Handle(fileReq(a...)); r.Error != "" {
			t.Errorf("%v: %+v", a, r)
		}
	}
	if len(h.files) != 7 {
		t.Fatalf("host got %d", len(h.files))
	}
	mk := h.files[0]
	if mk.Root != "/run/app" || mk.Mode != 0o750 || !mk.Owner || mk.User != "app" {
		t.Fatalf("mkdir %+v", mk)
	}
	if h.files[1].Mode != -1 || h.files[1].Owner {
		t.Fatalf("plain mkdir %+v", h.files[1])
	}
	if h.files[3].Mode != 0o1777 || h.files[4].Root != "/var/log/app" || h.files[5].Target != "/run/app/v2" {
		t.Fatalf("%+v", h.files)
	}
}

func TestFileVerbRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		req  Request
		want string
	}{
		"outside":        {fileReq("mkdir", "/etc/app"), "denied"},
		"dotdot":         {fileReq("mkdir", "/run/app/../../etc"), "denied"},
		"relative":       {fileReq("touch", "run/app/x"), "denied"},
		"sibling":        {fileReq("touch", "/run/apple"), "denied"},
		"nul":            {fileReq("touch", "/run/app/a\x00b"), "denied"},
		"path differs":   {Request{Key: "file.write", Argv: []string{"touch", "/run/app/x"}, Path: "/run/app/y"}, "denied"},
		"setuid":         {fileReq("chmod", "/run/app/x", "4755"), "denied"},
		"setgid":         {fileReq("chmod", "/run/app/x", "2755"), "denied"},
		"mode shape":     {fileReq("chmod", "/run/app/x", "u+s"), "denied"},
		"mkdir setuid":   {fileReq("mkdir", "/run/app/x", "mode", "4755"), "denied"},
		"chown root":     {fileReq("chown", "/run/app/x", "root:root"), "denied"},
		"chown other":    {fileReq("chown", "/run/app/x", "app:wheel"), "denied"},
		"mkdir owner":    {fileReq("mkdir", "/run/app/x", "owner", "root:app"), "denied"},
		"mkdir twice":    {fileReq("mkdir", "/run/app/x", "mode", "0750", "mode", "0700"), "denied"},
		"mkdir unknown":  {fileReq("mkdir", "/run/app/x", "parents", "yes"), "denied"},
		"rm root":        {fileReq("rm", "/run/app"), "denied"},
		"ln root":        {fileReq("ln", "/run/app", "/run/app/x"), "denied"},
		"ln target out":  {fileReq("ln", "/run/app/x", "/etc/shadow"), "denied"},
		"ln target dots": {fileReq("ln", "/run/app/x", "/run/app/../../etc"), "denied"},
		"rm extra":       {fileReq("rm", "/run/app/x", "-r"), "denied"},
		"plain write":    {fileReq(">", "/run/app/x"), "unsupported"},
	} {
		s, h := fileServer()
		if r := s.Handle(c.req); r.Error != c.want {
			t.Errorf("%s: %+v, want %s", name, r, c.want)
		}
		if len(h.files) != 0 {
			t.Errorf("%s: reached the host", name)
		}
	}
	s, _ := fileServer()
	s.Check = true
	if r := s.Handle(fileReq("touch", "/run/app/x")); r.Error != "check_read_only" {
		t.Fatalf("check session: %+v", r)
	}
	s, _ = fileServer()
	s.G.Entitlements = []string{"svc.spawn"}
	if r := s.Handle(fileReq("touch", "/run/app/x")); r.Error != "denied" {
		t.Fatalf("no key: %+v", r)
	}
	// A host refusal token passes through; anything else is failed.
	s, h := fileServer()
	h.err = fail.E("symlink")
	if r := s.Handle(fileReq("touch", "/run/app/x")); r.Error != "symlink" {
		t.Fatalf("host symlink: %+v", r)
	}
	h.err = fail.E("EPERM: /etc/shadow")
	if r := s.Handle(fileReq("touch", "/run/app/x")); r.Error != "failed" {
		t.Fatalf("host other: %+v", r)
	}
}

func mountReq(argv ...string) Request { return Request{Key: "fs.mount", Argv: argv} }

func TestMountChecks(t *testing.T) {
	s, h := fileServer()
	if r := s.Handle(mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "size=1m,nosuid,nodev,noexec")); r.Error != "" {
		t.Fatalf("tmpfs: %+v", r)
	}
	m := h.mounts[0]
	if m.Type != "tmpfs" || m.Bind || len(m.Data) != 1 || m.Data[0] != "size=1m" || !exact(m.Flags, "noexec") || !exact(m.Flags, "nosuid") {
		t.Fatalf("plan %+v", m)
	}
	if r := s.Handle(mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "nosuid,nodev")); r.Error != "exists" {
		t.Fatalf("second mount: %+v", r)
	}
	if r := s.Handle(mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "remount,ro,nosuid,nodev")); r.Error != "" || !h.mounts[1].Remount {
		t.Fatalf("remount: %+v", r)
	}
	if r := s.Handle(mountReq("umount", "/mnt/app")); r.Error != "" || len(h.umounts) != 1 {
		t.Fatalf("umount: %+v", r)
	}
	if r := s.Handle(mountReq("umount", "/mnt/app")); r.Error != "not_mounted" {
		t.Fatalf("umount twice: %+v", r)
	}
	if r := s.Handle(mountReq("mount", "/srv/static/img", "/mnt/app", "opts", "rbind,ro,nosuid,nodev")); r.Error != "" || !h.mounts[2].Bind || !h.mounts[2].Rec {
		t.Fatalf("bind: %+v %+v", r, h.mounts)
	}
	for name, c := range map[string]struct {
		req  Request
		want string
	}{
		"unlisted dir":     {mountReq("mount", "tmpfs", "/mnt/other", "type", "tmpfs", "opts", "nosuid,nodev"), "denied"},
		"dir under root":   {mountReq("mount", "tmpfs", "/run/app/tmp", "type", "tmpfs", "opts", "nosuid,nodev"), "mount_overlap"},
		"dir holds root":   {mountReq("mount", "tmpfs", "/var", "type", "tmpfs", "opts", "nosuid,nodev"), "mount_overlap"},
		"bind of /":        {mountReq("mount", "/", "/mnt/app", "opts", "bind,nosuid,nodev"), "denied"},
		"bind outside":     {mountReq("mount", "/etc", "/mnt/app", "opts", "bind,nosuid,nodev"), "denied"},
		"bind dotdot":      {mountReq("mount", "/srv/static/../../etc", "/mnt/app", "opts", "bind,nosuid,nodev"), "denied"},
		"overlay":          {mountReq("mount", "overlay", "/mnt/app", "type", "overlay", "opts", "lowerdir=/etc,nosuid,nodev"), "mount_opt_refused"},
		"lowerdir":         {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "lowerdir=/etc,nosuid,nodev"), "mount_opt_refused"},
		"suid":             {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "suid,nodev"), "mount_opt_refused"},
		"dev":              {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "nosuid,dev"), "mount_opt_refused"},
		"exec":             {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "nosuid,nodev,exec"), "mount_opt_refused"},
		"no nosuid":        {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "nodev"), "mount_opt_refused"},
		"no nodev":         {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "nosuid"), "mount_opt_refused"},
		"proc as tmpfs":    {mountReq("mount", "tmpfs", "/mnt/app", "type", "proc", "opts", "nosuid,nodev"), "mount_opt_refused"},
		"unlisted source":  {mountReq("mount", "sysfs", "/mnt/app", "type", "sysfs", "opts", "nosuid,nodev"), "denied"},
		"remount not ours": {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "remount,nosuid,nodev"), "not_mounted"},
		"umount not ours":  {mountReq("umount", "/mnt/app"), "not_mounted"},
		"umount unlisted":  {mountReq("umount", "/proc"), "denied"},
		"stray word":       {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "nosuid,nodev", "x"), "denied"},
		"type twice":       {mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "type", "tmpfs", "opts", "nosuid,nodev"), "denied"},
	} {
		s, h := fileServer()
		if r := s.Handle(c.req); r.Error != c.want {
			t.Errorf("%s: %+v, want %s", name, r, c.want)
		}
		if len(h.mounts)+len(h.umounts) != 0 {
			t.Errorf("%s: reached the host", name)
		}
	}
	s, _ = fileServer()
	s.Check = true
	if r := s.Handle(mountReq("mount", "tmpfs", "/mnt/app", "type", "tmpfs", "opts", "nosuid,nodev")); r.Error != "check_read_only" {
		t.Fatalf("check session: %+v", r)
	}
}
