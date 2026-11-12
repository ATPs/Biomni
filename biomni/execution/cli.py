"""Command-line contract for one job folder, used by the Django supervisor.

Run on the job's server (locally or through ``ssh``) with the ``biomni`` environment's
interpreter and ``PYTHONPATH`` pointing at this repository. Every command prints one JSON
object on stdout. Exit codes: 0 success, 2 invalid request, 3 busy (not enough headroom),
4 unconfirmed (state could not be verified; inspect before resubmitting).

- ``run``: the agent/command worker; reads the task envelope (with task credentials) on
  stdin and emits protocol events on stdout. Same as ``python -m biomni.execution.worker``.
- ``preflight``: checks identity, the job folder, inputs and current CPU/memory headroom.
- ``probe``: reports whether the job's worker is still running (``running``/``absent``).
- ``cancel``: verifies the worker identity and terminates its process group
  (``terminated``/``absent``).
"""

import argparse
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import sys
import time

EXIT_OK, EXIT_INVALID, EXIT_BUSY, EXIT_UNCONFIRMED = 0, 2, 3, 4


class Unconfirmed(Exception):
    pass


def _job_folder(path, job_id):
    folder = Path(path)
    if not folder.is_absolute() or folder.is_symlink() or not folder.is_dir():
        raise ValueError("Job folder must be an existing absolute directory")
    if folder.stat().st_uid != os.getuid():
        raise PermissionError("Job folder belongs to another account")
    record = json.loads((folder / "job.json").read_text())
    if record.get("job_id") != job_id:
        raise ValueError("Job identity mismatch")
    return folder


def _proc_fields(pid):
    with open(f"/proc/{pid}/stat") as handle:
        return handle.read().split(") ", 1)[1].split()


def worker_alive(identity):
    """True only for the same host, UID, PID and start time, and not a zombie."""
    if identity.get("host") not in (None, socket.gethostname()):
        raise Unconfirmed("Worker ran on a different host")
    pid = int(identity["pid"])
    try:
        fields = _proc_fields(pid)
        return (os.stat(f"/proc/{pid}").st_uid == os.getuid() and fields[19] == identity["start_ticks"]
                and fields[0] not in ("Z", "X"))
    except (OSError, IndexError):
        return False


def worker_identity(folder, job_id):
    path = folder / ".worker-identity.json"
    if not path.exists():
        return None
    identity = json.loads(path.read_text())
    if identity.get("job_id") != job_id or identity.get("uid") != os.getuid():
        raise Unconfirmed("Worker identity mismatch")
    return identity


def probe(folder, job_id):
    identity = worker_identity(folder, job_id)
    return {"state": "running" if identity and worker_alive(identity) else "absent", "host": socket.gethostname()}


def cancel(folder, job_id, *, grace=5.0):
    identity = worker_identity(folder, job_id)
    if identity is None or not worker_alive(identity):
        return {"state": "absent", "host": socket.gethostname()}
    pid = int(identity["pid"])
    if os.getpgid(pid) != pid:
        raise Unconfirmed("Worker is not its own process-group leader")
    os.killpg(pid, signal.SIGTERM)  # The worker also terminates detached descendants on SIGTERM.
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and worker_alive(identity):
        time.sleep(0.2)
    if worker_alive(identity):
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        time.sleep(0.5)
    if worker_alive(identity):
        raise Unconfirmed("Worker still running after SIGKILL")
    return {"state": "terminated", "host": socket.gethostname()}


def preflight(folder, job_id, *, inputs=(), cpus=1, memory_gb=4.0):
    user = pwd.getpwuid(os.getuid())
    unreadable = [p for p in inputs if not os.access(p, os.R_OK)]
    if unreadable:
        raise ValueError("Input not readable on this server: " + ", ".join(unreadable[:5]))
    with open("/proc/meminfo") as handle:
        available = next(int(line.split()[1]) / 1024**2 for line in handle if line.startswith("MemAvailable:"))
    load, threads = os.getloadavg()[0], os.cpu_count() or 1
    evidence = {"host": socket.gethostname(), "user": user.pw_name, "uid": user.pw_uid, "memory_gb": round(available, 1),
                "load": round(load, 2), "cpus": threads, "python": sys.executable}
    evidence["ok"] = available * 0.90 >= memory_gb and threads * 0.85 - load >= cpus
    return evidence


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["run"]:
        from .worker import main as worker_main
        return worker_main()
    parser = argparse.ArgumentParser(prog="python -m biomni.execution.cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="run the worker (envelope on stdin)")
    for name in ("preflight", "probe", "cancel"):
        command = commands.add_parser(name)
        command.add_argument("--job-dir", required=True)
        command.add_argument("--job-id", required=True)
        if name == "preflight":
            command.add_argument("--input", action="append", default=[])
            command.add_argument("--cpus", type=int, default=1)
            command.add_argument("--memory-gb", type=float, default=4.0)
    args = parser.parse_args(argv)
    try:
        folder = _job_folder(args.job_dir, args.job_id)
        if args.command == "probe":
            result, code = probe(folder, args.job_id), EXIT_OK
        elif args.command == "cancel":
            result, code = cancel(folder, args.job_id), EXIT_OK
        else:
            result = preflight(folder, args.job_id, inputs=args.input, cpus=args.cpus, memory_gb=args.memory_gb)
            code = EXIT_OK if result["ok"] else EXIT_BUSY
    except Unconfirmed as exc:
        result, code = {"state": "unconfirmed", "error": str(exc), "host": socket.gethostname()}, EXIT_UNCONFIRMED
    except (ValueError, PermissionError, OSError, KeyError) as exc:
        result, code = {"error": str(exc)[:500]}, EXIT_INVALID
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
