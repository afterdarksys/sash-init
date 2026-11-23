#!/bin/sh
set -eu
cp /boot/vmlinuz-* /out/kernel
for scenario in poweroff reboot badconfig bootfail runtimefail crash stuck retry; do
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
  (cd "$root" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "/out/$scenario.cpio.gz"
done
