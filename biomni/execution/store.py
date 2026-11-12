"""Atomic user-owned task records; no credentials or automatic resubmission."""

import json
import os
import pwd
import re
import stat
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from .models import Artifact


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise PermissionError("User workspace cannot contain symlinks")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise PermissionError("Workspace must belong to the current Unix UID")
    path.chmod(0o700)
    return path


class LocalJobStore:
    def __init__(self, root=None):
        if os.getuid() != os.geteuid():
            raise PermissionError("Do not run an analysis dispatcher with a privileged effective UID")
        self.owner = pwd.getpwuid(os.getuid()).pw_name
        self.uid = os.getuid()
        self.root = private_directory(root or Path.home() / ".local/share/biomni/runs")
        self.lock = threading.RLock()

    def create(self, spec):
        if spec.owner != self.owner:
            raise PermissionError("Task owner must be the current Unix user")
        id = uuid.uuid4().hex
        directory = private_directory(self.root / datetime.now().astimezone().date().isoformat() / id)
        private_directory(directory / "artifacts")
        record = {
            "schema_version": 1,
            "job_id": id,
            "owner": self.owner,
            "server": spec.server,
            "status": "queued",
            "created_at": time.time(),
            "updated_at": time.time(),
            "spec": spec.to_dict(),
            "job_directory": str(directory),
        }
        atomic_json(directory / "job.json", record)
        self.event(id, "queued", {"server": spec.server})
        return record

    def directory(self, id):
        if not isinstance(id, str) or not re.fullmatch(r"[0-9a-f]{32}", id):
            raise ValueError("Invalid task ID")
        matches = list(self.root.glob("*/" + id))
        if len(matches) != 1:
            raise FileNotFoundError("Task not found")
        path = matches[0]
        if any(p.is_symlink() for p in [path, path.parent]) or path.stat().st_uid != self.uid:
            raise PermissionError("Task directory ownership mismatch")
        return path

    def get(self, id):
        path = self.directory(id) / "job.json"
        if path.is_symlink() or path.stat().st_uid != self.uid:
            raise PermissionError("Task record ownership mismatch")
        record = json.loads(path.read_text())
        if record["owner"] != self.owner or record["job_id"] != id:
            raise PermissionError("Task owner mismatch")
        return record

    def update(self, id, **changes):
        with self.lock:
            record = self.get(id)
            record.update(changes, updated_at=time.time())
            atomic_json(self.directory(id) / "job.json", record)
            return record

    def event(self, id, kind, data):
        with self.lock:
            path = self.directory(id) / "events.jsonl"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                if os.fstat(fd).st_uid != self.uid:
                    raise PermissionError("Event log ownership mismatch")
                event = {"protocol_version": 1, "job_id": id, "type": kind, "time": time.time(), "data": data}
                os.write(fd, (json.dumps(event) + chr(10)).encode())
            finally:
                os.close(fd)

    def events(self, id, after=0):
        path = self.directory(id) / "events.jsonl"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            return [{"seq": i, **json.loads(line)} for i, line in enumerate(stream, 1) if i > after]

    def list(self):
        records = []
        for path in self.root.glob("*/*/job.json"):
            try:
                records.append(self.get(path.parent.name))
            except (OSError, ValueError, PermissionError):
                continue
        return sorted(records, key=lambda r: r["created_at"], reverse=True)

    def artifact_path(self, id, relative):
        root = self.directory(id) / "artifacts"
        path = Path(relative)
        if path.is_absolute() or not relative or ".." in path.parts or root.is_symlink():
            raise PermissionError("Invalid artifact path")
        current = root
        for part in path.parts:
            current /= part
            if current.is_symlink():
                raise PermissionError("Artifact symlinks are not served")
        resolved = current.resolve(strict=True)
        info = resolved.stat()
        if (
            not resolved.is_relative_to(root.resolve())
            or info.st_uid != self.uid
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise PermissionError("Artifact must be a job-owned regular file, without links")
        return resolved

    def artifacts(self, id):
        root = self.directory(id) / "artifacts"
        result = []
        for path in root.rglob("*"):
            try:
                relative = path.relative_to(root).as_posix()
                valid = self.artifact_path(id, relative)
                info = valid.stat()
                result.append(Artifact(self.owner, id, relative, info.st_size, info.st_mtime))
            except (OSError, PermissionError):
                continue
        return result
