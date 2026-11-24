#!/usr/bin/env python3
"""Boot the actual PID 1 in QEMU; no host mounts or host power operations."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--assets", type=Path, help="reuse an existing image directory")
parser.add_argument("--timeout", type=int, default=90)
scenarios = ("poweroff", "reboot", "badconfig", "bootfail", "runtimefail", "crash", "stuck", "retry", "sash", "notify", "persistent")
parser.add_argument("--scenario", action="append", choices=scenarios, help="run only these (repeatable)")
parser.add_argument("--sash-src", type=Path, help="sash repository to build sash from (SASH_SRC, default ../sash-initp1)")
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent
sash_src = (args.sash_src or Path(os.environ.get("SASH_SRC") or repo.parent / "sash-initp1")).resolve()
assets = args.assets or Path(tempfile.mkdtemp(prefix="sahinit-boot-"))
assets.mkdir(parents=True, exist_ok=True)
if not args.assets:
    if not (sash_src / "go.mod").is_file():
        raise SystemExit(f"the images include sash, built from {sash_src}: set SASH_SRC or --sash-src")
    subprocess.run(["docker", "build", "--platform", "linux/amd64", "--build-context", f"sash={sash_src}", "-f", "tests/boot/Dockerfile", "-t", "sahinit-boot-test", "."], cwd=repo, check=True)
    subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{assets}:/out", "sahinit-boot-test"], check=True)
qemu = shutil.which("qemu-system-x86_64")
if not qemu:
    raise SystemExit("qemu-system-x86_64 is required")
print(f"VM assets and serial logs: {assets}", flush=True)
selected = args.scenario or scenarios
for scenario in selected:
    if scenario == "persistent":
        continue
    init_args = "--recovery /probe --shutdown-timeout 8s"
    if scenario == "sash":
        init_args += " --sash /sash --sash-fleet-pub /etc/sahinit/fleet.pub --sash-floor-dir /var/lib/sahinit/sash"
    command = [qemu, "-machine", "q35", "-accel", "tcg", "-m", "256", "-smp", "2", "-nographic", "-monitor", "none", "-no-reboot", "-nic", "none", "-kernel", str(assets / "kernel"), "-initrd", str(assets / f"{scenario}.cpio.gz"), "-append", f"console=ttyS0 panic=1 rdinit=/init -- {init_args}"]
    try:
        # sash's sessions are slow under TCG: the scenario took about 75 s.
        timeout = max(args.timeout, 180) if scenario == "sash" else args.timeout
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        (assets / f"{scenario}.log").write_bytes(exc.stdout or b"")
        raise SystemExit(f"FAIL {scenario}: VM did not stop; see {assets}")
    log = result.stdout.decode(errors="replace")
    (assets / f"{scenario}.log").write_text(log)
    required = ["sahinit-init: started pid=1", "sahinit-init: shutdown action="]
    if scenario in ("poweroff", "reboot", "stuck", "retry"):
        required += ["BOOTTEST: service cgroup", "BOOTTEST: orphan adopted", "BOOTTEST: orphan reaped"]
    if scenario in ("poweroff", "reboot", "retry"):
        required += ["BOOTTEST: app stopped", "BOOTTEST: reverse shutdown"]
    if scenario in ("badconfig", "bootfail", "runtimefail", "crash"):
        required += [f"BOOTTEST: recovery {scenario}"]
    if scenario == "stuck":
        required += ["BOOTTEST: ignoring TERM"]
    if scenario == "retry":
        required += ["BOOTTEST: recovery retry"]
    if scenario == "sash":
        required += ["BOOTTEST: sash driver detached", "BOOTTEST: sash service ready", "BOOTTEST: sash spawn in cgroup sahinit/svc.service as 65534",
                     "BOOTTEST: sash file verbs", "BOOTTEST: sash tmpfs mount", "sash_grant revoked sash_grant_revoked", "BOOTTEST: sash grant below floor refused",
                     "BOOTTEST: sash stop entry", "BOOTTEST: sash cgroup killed", "BOOTTEST: sash mounts removed"]
    if scenario == "notify":
        required += ["BOOTTEST: sd_notify ready", "BOOTTEST: sd_notify heartbeats stopped", "BOOTTEST: watchdog killed unresponsive service"]
    required += ["Restarting system" if scenario == "reboot" else "Power down"]
    missing = [text for text in required if text not in log]
    if result.returncode or missing or "BOOTTEST: FAIL" in log or "Kernel panic" in log:
        raise SystemExit(f"FAIL {scenario}: exit={result.returncode}, missing={missing}; see {assets / (scenario+'.log')}")
    print(f"PASS {scenario}", flush=True)

if "persistent" in selected:
    disk = assets / "persistent-run.ext4"
    shutil.copyfile(assets / "root.ext4", disk)
    for boot in (1, 2):
        command = [qemu, "-machine", "q35", "-accel", "tcg", "-m", "512", "-smp", "2", "-nographic", "-monitor", "none", "-no-reboot", "-nic", "none", "-kernel", str(assets / "kernel"), "-initrd", str(assets / "persistent.cpio.gz"), "-drive", f"file={disk},format=raw,if=virtio", "-append", "console=ttyS0 panic=1 rdinit=/init sahinit.root=/dev/vda"]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=args.timeout)
        except subprocess.TimeoutExpired as exc:
            (assets / f"persistent-{boot}.log").write_bytes(exc.stdout or b"")
            raise SystemExit(f"FAIL persistent boot {boot}: timeout; see {assets}")
        log = result.stdout.decode(errors="replace")
        (assets / f"persistent-{boot}.log").write_text(log)
        required = ["sahinit-root: checked ext4 root; handing off", "sahinit-init: started pid=1", f"BOOTTEST: persistent boot {boot}", "Power down"]
        missing = [text for text in required if text not in log]
        if result.returncode or missing or "Kernel panic" in log or "BOOTTEST: FAIL" in log or "unmount/remount /:" in log:
            raise SystemExit(f"FAIL persistent boot {boot}: {missing}; see {assets}")
        subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "/sbin/e2fsck", "-v", f"{assets}:/out:ro", "sahinit-boot-test", "-fn", "/out/persistent-run.ext4"], check=True)
        print(f"PASS persistent boot {boot}: filesystem clean after shutdown", flush=True)
    result = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "/sbin/debugfs", "-v", f"{assets}:/out:ro", "sahinit-boot-test", "-R", "cat /var/lib/sahinit/boots", "/out/persistent-run.ext4"], capture_output=True, text=True, check=True)
    if result.stdout.strip() != "2":
        raise SystemExit("FAIL persistent marker did not survive two boots")
    print("PASS persistent data across two boots", flush=True)
