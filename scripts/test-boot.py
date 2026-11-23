#!/usr/bin/env python3
"""Boot the actual PID 1 in QEMU; no host mounts or host power operations."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--assets", type=Path, help="reuse an existing image directory")
parser.add_argument("--timeout", type=int, default=90)
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent
assets = args.assets or Path(tempfile.mkdtemp(prefix="sahinit-boot-"))
assets.mkdir(parents=True, exist_ok=True)
if not args.assets:
    subprocess.run(["docker", "build", "--platform", "linux/amd64", "-f", "tests/boot/Dockerfile", "-t", "sahinit-boot-test", "."], cwd=repo, check=True)
    subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{assets}:/out", "sahinit-boot-test"], check=True)
qemu = shutil.which("qemu-system-x86_64")
if not qemu:
    raise SystemExit("qemu-system-x86_64 is required")
print(f"VM assets and serial logs: {assets}", flush=True)
for scenario in ("poweroff", "reboot", "badconfig", "bootfail", "runtimefail", "crash", "stuck", "retry"):
    command = [qemu, "-machine", "q35", "-accel", "tcg", "-m", "256", "-smp", "2", "-nographic", "-monitor", "none", "-no-reboot", "-nic", "none", "-kernel", str(assets / "kernel"), "-initrd", str(assets / f"{scenario}.cpio.gz"), "-append", "console=ttyS0 panic=1 rdinit=/init -- --recovery /probe --shutdown-timeout 8s"]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=args.timeout)
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
    required += ["Restarting system" if scenario == "reboot" else "Power down"]
    missing = [text for text in required if text not in log]
    if result.returncode or missing or "BOOTTEST: FAIL" in log or "Kernel panic" in log:
        raise SystemExit(f"FAIL {scenario}: exit={result.returncode}, missing={missing}; see {assets / (scenario+'.log')}")
    print(f"PASS {scenario}", flush=True)
