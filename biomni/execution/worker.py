"""Versioned worker protocol on stdout; analysis output is redirected to stderr."""

import contextlib
import json
import os
import pwd
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from .models import JobSpec
from .store import atomic_json, private_directory


def terminate_descendants(signum, frame):
    """Clean up descendant sessions as well as ordinary process-group members."""
    descendants = {}
    pending = {os.getpid()}
    candidates = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            if path.stat().st_uid != os.getuid():
                continue
            fields = path.read_text().split(") ", 1)[1].split()
            candidates[int(path.parent.name)] = (int(fields[1]), fields[19])
        except (OSError, IndexError, ValueError):
            continue
    while pending:
        children = {pid for pid, (parent, _) in candidates.items() if parent in pending and pid not in descendants}
        for pid in children:
            descendants[pid] = candidates[pid][1]
        pending = children
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, ticks in descendants.items():
            try:
                if Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[19] == ticks:
                    os.kill(pid, sig)
            except (OSError, IndexError):
                pass
        if sig == signal.SIGTERM:
            time.sleep(0.2)
    raise SystemExit(128 + signum)


def final_answer(log):
    """Return the last <solution> block of an agent log, or the last message text."""
    import re

    for entry in reversed([str(item) for item in log]):
        found = re.findall(r"<solution>(.*?)</solution>", entry, re.DOTALL)
        if found:
            return found[-1].strip()[:200000]
    return (str(log[-1]) if log else "")[-200000:]


def main():
    raw = sys.stdin.buffer.readline(8000001)
    if not raw or len(raw) > 8000000:
        raise ValueError("Invalid worker envelope size")
    envelope = json.loads(raw)
    if envelope["protocol_version"] != 1:
        raise ValueError("Unsupported worker protocol")
    spec = JobSpec.from_dict(envelope["spec"])
    if spec.owner != pwd.getpwuid(os.getuid()).pw_name or os.geteuid() != os.getuid():
        raise PermissionError("Worker must run under the task owner's Unix account")
    job_id = envelope["job_id"]
    directory = private_directory(envelope["job_directory"])
    if json.loads((directory / "job.json").read_text())["job_id"] != job_id:
        raise ValueError("Task directory identity mismatch")
    if os.getpgrp() != os.getpid():
        os.setsid()
    signal.signal(signal.SIGTERM, terminate_descendants)
    signal.signal(signal.SIGINT, terminate_descendants)
    identity = {
        "job_id": job_id,
        "uid": os.getuid(),
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "start_ticks": Path("/proc/self/stat").read_text().split(") ", 1)[1].split()[19],
    }
    atomic_json(directory / ".worker-identity.json", identity)
    credentials = envelope.get("task_credentials", {})
    if set(credentials) - {"token", "gateway_url", "protocol"}:
        raise ValueError("Only task-scoped credentials are accepted")
    token = credentials.get("token", "")

    def emit(kind, data):
        text = json.dumps({"protocol_version": 1, "job_id": job_id, "type": kind, "data": data})
        if token:
            text = text.replace(token, "[REDACTED]")
        sys.__stdout__.write(text + chr(10))
        sys.__stdout__.flush()

    os.umask(0o077)
    os.environ["BIOMNI_WORKER"] = "1"
    for name in list(os.environ):
        if any(key in name.upper() for key in ("API_KEY", "TOKEN", "PASSWORD", "SECRET", "JUPYTERHUB")):
            os.environ.pop(name)
    os.chdir(private_directory(directory / "artifacts"))
    emit(
        "started",
        {"owner": spec.owner, "uid": os.getuid(), "actual_host": socket.gethostname(), "python": sys.executable},
    )
    answer = ""
    try:
        if spec.command:
            from biomni.localenv.adapters import require_no_install

            require_no_install(spec.command)
            result = subprocess.run(
                spec.command, stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr, check=False
            )
            if result.returncode:
                raise RuntimeError(f"Command exited {result.returncode}")
        else:
            from dataclasses import replace

            from biomni.localenv import RuntimeProfile

            profile = RuntimeProfile.from_dict(spec.runtime_profile)
            # A shared, read-mostly reference folder (absolute data_path holding biomni_data/data_lake) is used
            # as is; otherwise each job gets its own empty data folder.
            shared = Path(profile.data_path)
            if not (shared.is_absolute() and (shared / "biomni_data" / "data_lake").is_dir()):
                profile = replace(profile, data_path=str(directory / "data"))
            if not credentials.get("gateway_url") or not token:
                raise ValueError("Agent tasks require an admitted model connection")
            with contextlib.redirect_stdout(sys.stderr):
                from biomni.agent import A1

                agent = A1(
                    runtime_profile=profile,
                    llm=spec.model,
                    source="Custom",
                    base_url=credentials["gateway_url"],
                    api_key=token,
                    protocol=credentials["protocol"],
                    load_datalake=False,
                )
                for event in agent.go_stream(spec.prompt):
                    emit("progress", event)
                result = getattr(agent, "log", [])
                Path("result.txt").write_text(chr(10).join(map(str, result)))
                answer = final_answer(result)
        atomic_json(
            Path("run-manifest.json"),
            {
                "job_id": job_id,
                "owner": spec.owner,
                "requested_host": spec.server,
                "actual_host": socket.gethostname(),
                "python": sys.executable,
                "model": spec.model,
                "provider": spec.provider,
                "cpu_threads": spec.cpu_threads,
                "memory_gb": spec.memory_gb,
            },
        )
        emit("completed", {"exit_code": 0, "answer": answer})
        return 0
    except Exception as exc:
        emit("failed", {"message": str(exc)[:4000]})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
