#!/bin/sh
set -eu
cp /boot/vmlinuz-* /out/kernel

# sash_root replaces the probe units with sash services: svc (boot) makes a
# directory and a file, mounts a tmpfs and spawns a process; revoked (not
# boot) has a grant below its floor; sashcheck starts the driver that checks
# both through the control socket. The fleet key is new on every run and its
# private half never leaves sashfix.
sash_root() {
  r=$1
  rm -f "$r/etc/sahinit/units/"*.json
  mkdir -p "$r/etc/sahinit/services" "$r/etc/sahinit/grants" "$r/srv/svc" "$r/mnt/svc" "$r/var/lib/sahinit"
  mkdir -m 0700 "$r/var/lib/sahinit/sash"
  chown 65534:65534 "$r/srv/svc"
  cp /assets/sash "$r/sash"
  printf 'root:x:0:0:root:/:/probe\nnobody:x:65534:65534:nobody:/nonexistent:/probe\n' > "$r/etc/passwd"
  printf 'root:x:0:\nnogroup:x:65534:\n' > "$r/etc/group"
  keys=$(mktemp -d)
  /assets/sashfix "$keys"
  cp "$keys/fleet.pub" "$r/etc/sahinit/fleet.pub"
  cp "$keys/svc.grant" "$keys/revoked.grant" "$r/etc/sahinit/grants/"
  /assets/sahinit sash floor-install --dir "$r/var/lib/sahinit/sash" --fleet-pub "$r/etc/sahinit/fleet.pub" "$keys/revoked.floor"
  rm -rf "$keys"
  cat > "$r/etc/sahinit/services/svc.sash" <<'SASH'
service {
  name svc
  user nobody
  group nogroup
  ready notify timeout 60s
  stop signal TERM timeout 20s
}

fn start() {
  mkdir /srv/svc/d mode 0750 owner nobody:nogroup
  touch /srv/svc/d/f
  mount tmpfs /mnt/svc type tmpfs opts "size=1m,noexec"
  spawn main /probe sleeper
}

fn stop() {
  signal main TERM
  try { wait main timeout 10s } catch e { signal main KILL }
  touch /srv/svc/stopped
}
SASH
  cat > "$r/etc/sahinit/services/revoked.sash" <<'SASH'
service {
  name revoked
  user nobody
  group nogroup
}

fn start() {
  spawn main /probe sleeper
}
SASH
  for s in svc revoked; do
    boot=true
    if [ "$s" = revoked ]; then boot=false; fi
    echo '{"name":"'$s'","sash":{"file":"/etc/sahinit/services/'$s'.sash","grant":"/etc/sahinit/grants/'$s'.grant"},"execution":{"uid":65534,"gid":65534},"sandbox":{"read_only_paths":["/"]},"boot":'$boot'}' > "$r/etc/sahinit/units/$s.json"
  done
  echo '{"name":"sashcheck","exec":["/probe","sashlaunch"],"type":"oneshot","ready":"exit","boot":true,"timeout":"10s"}' > "$r/etc/sahinit/units/sashcheck.json"
}

for scenario in poweroff reboot badconfig bootfail runtimefail crash stuck retry sash; do
  root=/tmp/root-$scenario
  mkdir -p "$root/etc/sahinit/units" "$root/dev" "$root/proc" "$root/sys" "$root/run"
  cp /assets/sahinit "$root/init"
  cp /assets/probe "$root/probe"
  echo "$scenario" > "$root/scenario"
  cat > "$root/etc/sahinit/units/provider.json" <<'EOF'
{"name":"provider","exec":["/probe","provider"],"type":"simple","ready":"exec","boot":true,"timeout":"2s"}
EOF
  cat > "$root/etc/sahinit/units/app.json" <<'EOF'
{"name":"app","exec":["/probe","app"],"type":"simple","ready":"exec","boot":true,"needs":["provider"],"timeout":"2s","pids_max":64,"memory_max":"128M"}
EOF
  if [ "$scenario" = badconfig ] || [ "$scenario" = retry ]; then echo '{invalid' > "$root/etc/sahinit/units/app.json"; fi
  if [ "$scenario" = bootfail ]; then
    echo '{"name":"app","exec":["/probe","fail"],"type":"oneshot","ready":"exit","boot":true}' > "$root/etc/sahinit/units/app.json"
  fi
  if [ "$scenario" = sash ]; then sash_root "$root"; fi
  (cd "$root" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "/out/$scenario.cpio.gz"
done
