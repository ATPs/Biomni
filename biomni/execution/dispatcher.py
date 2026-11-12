"""User-owned job dispatcher, launched by the root helper after privilege reduction.

It inherits one end of a socketpair (``BIOMNI_DISPATCHER_FD``) connected to the web
service and has no network listener. The web service never names the owner: every
operation acts on the current Unix account's private job store. When the control
connection closes (service restart), active work is cancelled and recorded as
interrupted; nothing is replayed automatically.
"""

import argparse
import fcntl
import json
import os
import pwd
import socket
import stat
import time
from pathlib import Path

from biomni.localenv import RuntimeProfile
from biomni.server.ipc import PROTOCOL_VERSION, Channel, RemoteError, serve

from .models import JobSpec
from .runner import Dispatcher
from .store import LocalJobStore, private_directory

CREATE_FIELDS = {
    "server",
    "prompt",
    "model",
    "provider",
    "cpu_threads",
    "memory_gb",
    "gpu",
    "input_paths",
    "parent_job",
}


class DispatcherService:
    def __init__(self, dispatcher, profile):
        self.dispatcher, self.profile = dispatcher, profile
        self.reconcile_report = []

    def handlers(self):
        return {name[3:]: getattr(self, name) for name in dir(self) if name.startswith("op_")}

    def op_hello(self):
        d = self.dispatcher
        return {
            "protocol_version": PROTOCOL_VERSION,
            "owner": d.owner,
            "uid": d.uid,
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "reconcile": self.reconcile_report,
        }

    def op_create(self, **fields):
        if set(fields) - CREATE_FIELDS:
            raise ValueError("Unsupported task field")
        d = self.dispatcher
        prompt = fields["prompt"]
        parent = fields.get("parent_job")
        if parent:
            previous = d.get(parent)
            if previous["status"] != "succeeded":
                raise ValueError("Continue only a completed task")
            history = [e["data"] for e in d.events(parent) if e["type"] == "progress"]
            paths = [str(d.artifact_path(parent, a.relative_path)) for a in d.artifacts(parent)]
            prompt = (
                "Previous task: "
                + previous["spec"]["prompt"][-20000:]
                + "\nPrevious result: "
                + json.dumps(history, ensure_ascii=False)[-30000:]
                + "\nPrevious artifacts: "
                + json.dumps(paths)
                + "\nNew task: "
                + prompt
            )
        # Owner, runtime profile, command and timeout come from this process, not the request.
        spec = JobSpec(
            owner=d.owner,
            server=fields["server"],
            prompt=prompt,
            model=fields["model"],
            provider=fields["provider"],
            cpu_threads=fields.get("cpu_threads", 1),
            memory_gb=fields.get("memory_gb", 4),
            gpu=fields.get("gpu", False),
            runtime_profile=self.profile.to_dict(),
            input_paths=tuple(fields.get("input_paths", ())),
            timeout_seconds=self.profile.timeout_seconds,
        )
        return d.create(spec)

    def op_list(self):
        """Summaries keep replies small; use ``get`` for a full record."""
        records = self.dispatcher.list()
        for record in records:
            spec = record.get("spec", {})
            record["spec"] = {**spec, "prompt": spec.get("prompt", "")[:500], "runtime_profile": {}}
        return records

    def op_get(self, id):
        return self.dispatcher.get(id)

    def op_events(self, id, after=0):
        if type(after) is not int or after < 0:
            raise ValueError("Invalid event offset")
        return self.dispatcher.events(id, after)

    def op_artifacts(self, id):
        from dataclasses import asdict

        return [asdict(a) for a in self.dispatcher.artifacts(id)]

    def op_open_artifact(self, id, path):
        resolved = self.dispatcher.artifact_path(id, path)
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                raise PermissionError("Artifact must be a job-owned regular file")
        except BaseException:
            os.close(fd)
            raise
        return {"name": resolved.name, "size": info.st_size}, [fd]

    def op_preflight(self, id):
        try:
            return self.dispatcher.preflight(id)
        except BlockingIOError:
            raise
        except Exception:
            message = "Worker preflight failed; check the selected server and this user's SSH/input access"
            self.dispatcher.store.update(id, status="failed", error=message, termination_confirmed=True)
            self.dispatcher.store.event(id, "failed", {"message": message})
            raise RemoteError(message, "failed") from None

    def op_start(self, id, credentials, evidence=None):
        return self.dispatcher.start(id, credentials, evidence)

    def op_reject(self, id, message):
        """Admission refused (for example a revoked grant): fail a queued job without running it."""
        record = self.dispatcher.get(id)
        if record["status"] != "queued":
            return record
        record = self.dispatcher.store.update(id, status="failed", error=str(message)[:500], termination_confirmed=True)
        self.dispatcher.store.event(id, "failed", {"message": str(message)[:500]})
        return record

    def op_cancel(self, id):
        return self.dispatcher.cancel(id)

    def op_reconcile(self):
        self.reconcile_report = self.dispatcher.reconcile()
        return self.reconcile_report


def acquire_lock(path, timeout=60):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() > deadline:
                os.close(fd)
                raise RuntimeError("Another dispatcher for this user is still running") from None
            time.sleep(0.5)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--local-server", required=True)
    parser.add_argument("--fd", type=int, default=None)
    parser.add_argument("--state-dir", default=None, help="Defaults to ~/.local/share/biomni of the current user")
    args = parser.parse_args(argv)
    if os.getuid() == 0 or os.geteuid() != os.getuid() or os.getgid() != os.getegid():
        raise SystemExit("The dispatcher must run as an unprivileged, non-setuid user")
    fd = args.fd if args.fd is not None else int(os.environ.pop("BIOMNI_DISPATCHER_FD"))
    sock = socket.socket(fileno=fd)
    if sock.family != socket.AF_UNIX:
        raise SystemExit("Control descriptor must be a Unix socket")
    os.umask(0o077)
    state = private_directory(args.state_dir or Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/share/biomni")
    log_fd = os.open(state / "dispatcher.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    os.dup2(log_fd, 2)  # The service launches dispatchers with stderr discarded.
    os.close(log_fd)
    os.chdir(state)
    lock = acquire_lock(state / "dispatcher.lock")
    profile = RuntimeProfile.from_file(args.profile)
    dispatcher = Dispatcher(
        profile.servers,
        local_server=args.local_server,
        agent_python=profile.python(),
        repo_root=profile.repository,
        store=LocalJobStore(state / "runs"),
    )
    service = DispatcherService(dispatcher, profile)
    service.reconcile_report = dispatcher.reconcile()
    try:
        serve(Channel(sock), service.handlers(), on_eof=dispatcher.shutdown)
    finally:
        os.close(lock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
