"""Run generated catalogs on Linux; this does not boot the source init systems."""
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time


def run(*args, code=0):
    result = subprocess.run(["sahinit", *args], capture_output=True, text=True, timeout=10)
    assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def receive(conn, length):
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        assert chunk, "unexpected EOF"
        data += chunk
    return data


def rpc(path, op):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(3)
        conn.connect(str(path))
        body = json.dumps({"op": op, "name": "demo"}).encode()
        conn.sendall(struct.pack(">I", len(body)) + body)
        size = struct.unpack(">I", receive(conn, 4))[0]
        response = json.loads(receive(conn, size))
        assert response["ok"], response
        return response["rows"][0]


def gone(pid):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    raise AssertionError(f"service process {pid} remains alive")


for source in ("systemd", "daemontools", "openrc"):
    with tempfile.TemporaryDirectory(prefix="migration-") as temp:
        root = Path(temp)
        catalog = root / "units"
        fixture = f"/tests/fixtures/{source}"
        preview = json.loads(run("migrate", "--from", source, "--source", fixture))
        assert not preview["written"] and not preview["units"][0]["boot"]
        report = json.loads(run("migrate", "--from", source, "--source", fixture,
                                "--out", str(catalog), "--boot"))
        assert report["written"] and len(report["units"]) == 1
        assert run("plan", "--dir", str(catalog)).strip() == "demo"
        sock = root / "control.sock"
        process = subprocess.Popen(["sahinit", "supervise", "--dir", str(catalog),
                                    "--socket", str(sock), "--no-cgroups"], stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, "supervisor exited"
                if sock.exists():
                    row = rpc(sock, "status")
                    if row["state"] == "running":
                        break
                assert time.monotonic() < deadline, "boot timed out"
                time.sleep(0.01)
            first = row["pid"]
            assert row["ready"] and first > 0
            restarted = rpc(sock, "restart")
            assert restarted["state"] == "running" and restarted["pid"] != first
            gone(first)
            second = restarted["pid"]
            stopped = rpc(sock, "stop")
            assert stopped["state"] == "stopped" and stopped["pid"] == 0
            gone(second)
            third = rpc(sock, "start")["pid"]
            assert third > 0
            process.send_signal(signal.SIGTERM)
            _, errors = process.communicate(timeout=5)
            assert process.returncode == 0 and not errors, errors
            gone(third)
            assert not sock.exists()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        print(f"PASS {source}: convert, validate, boot, restart, stop, start, shutdown", flush=True)

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    src = root / "source"
    src.mkdir()
    (src / "demo.service").write_text("[Service]\nExecStart=/bin/sleep 300\nUser=nobody\n")
    out = root / "output"
    report = json.loads(run("migrate", "--from", "systemd", "--source", str(src),
                            "--out", str(out), code=1))
    assert any(d["severity"] == "error" for d in report["diagnostics"])
    assert not out.exists()
    print("PASS unsupported privilege change: blocker, no output", flush=True)
