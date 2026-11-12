"""User-owned dispatch. No root broker executes analysis code."""

import json
import math
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from biomni.localenv.profiles import ServerProfile

from .models import JobSpec
from .store import LocalJobStore, atomic_json

SSH_OPTIONS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-o",
    "ConnectTimeout=10",
]
PREFLIGHT = """import json,os,pwd,socket,sys
r=json.loads(sys.argv[1])
assert pwd.getpwuid(os.getuid()).pw_name==r['owner'] and os.getuid()==r['uid'], 'Unix identity mismatch'
assert os.path.isdir(r['repo']) and os.path.isfile(r['job']+'/job.json'), 'Shared paths unavailable'
assert json.load(open(r['job']+'/job.json'))['job_id']==r['id'], 'Shared job identity mismatch'
assert all(os.access(p,os.R_OK) for p in r['inputs']), 'Input inaccessible'
mem=next(int(x.split()[1])/1024**2 for x in open('/proc/meminfo') if x.startswith('MemAvailable:'))
load=os.getloadavg()[0]
print(json.dumps(dict(uid=os.getuid(),owner=pwd.getpwuid(os.getuid()).pw_name,host=socket.gethostname(),memory_gb=mem,load=load,cpus=os.cpu_count())))
"""
REMOTE_CANCEL = """import json,os,signal,socket,sys,time
path=sys.argv[1]+'/.worker-identity.json'
if not os.path.exists(path):
    print('absent'); raise SystemExit(0)
p=json.load(open(path))
assert p['job_id']==sys.argv[2] and p['uid']==os.getuid(), 'Worker identity mismatch'
assert p.get('host') in (None, socket.gethostname()), 'Worker ran on a different host'
pid=p['pid']
def alive():
    try:
        f=open('/proc/'+str(pid)+'/stat').read().split(') ',1)[1].split()
        return os.stat('/proc/'+str(pid)).st_uid==os.getuid() and f[19]==p['start_ticks'] and f[0] not in ('Z','X')
    except (OSError, IndexError):
        return False
if not alive():
    print('absent'); raise SystemExit(0)
assert os.getpgid(pid)==pid, 'Worker group mismatch'
os.killpg(pid,signal.SIGTERM)
for _ in range(20):
    time.sleep(.25)
    if not alive(): break
else:
    try: os.killpg(pid,signal.SIGKILL)
    except ProcessLookupError: pass
    time.sleep(.5)
assert not alive(), 'Worker still running'
print('terminated')
"""
TERMINAL = {"succeeded", "failed", "cancelled", "interrupted"}


class Dispatcher:
    def __init__(
        self, servers, *, local_server, agent_python=None, repo_root=None, store=None, ssh_executable="/usr/bin/ssh"
    ):
        self.store = store or LocalJobStore()
        self.owner, self.uid = self.store.owner, self.store.uid
        self.servers = {
            k: (v if isinstance(v, ServerProfile) else ServerProfile(**{"alias": k, **v})) for k, v in servers.items()
        }
        if local_server not in self.servers:
            raise ValueError("Configure the actual local server explicitly")
        self.local_server = local_server
        self.agent_python = agent_python or sys.executable
        self.repo_root = Path(repo_root or Path(__file__).resolve().parents[2]).resolve()
        if not Path(self.agent_python).is_absolute():
            raise ValueError("Worker interpreter must be absolute")
        self.ssh = ssh_executable
        self.active, self.processes, self.cancelling, self.remote_terminated = {}, {}, set(), set()
        self.remote_cancel_done = {}  # job_id -> Event set once a remote cancel has reported
        self.shutting_down = False
        self.lock = threading.RLock()

    def create(self, spec):
        node = self.servers[spec.server]
        if spec.cpu_threads > math.floor(node.cpu_threads * 0.85) or spec.memory_gb > node.memory_gb * 0.90:
            raise ValueError("Request exceeds configured capacity after headroom")
        if spec.gpu and not node.gpu:
            raise ValueError("Selected GPU profile has not been validated")
        record = self.store.create(spec)
        catalog = spec.runtime_profile.get("catalog_file")
        if catalog:
            from biomni.localenv import Catalog

            snapshot = self.store.directory(record["job_id"]) / "catalog.json"
            atomic_json(snapshot, Catalog.from_file(catalog).to_dict())
            snapshot_spec = {
                **spec.to_dict(),
                "runtime_profile": {**spec.runtime_profile, "catalog_file": str(snapshot)},
            }
            record = self.store.update(record["job_id"], spec=snapshot_spec)
        return record

    def get(self, id):
        return self.store.get(id)

    def list(self):
        return self.store.list()

    def events(self, id, after=0):
        return self.store.events(id, after)

    def artifacts(self, id):
        return self.store.artifacts(id)

    def artifact_path(self, id, path):
        return self.store.artifact_path(id, path)

    def start(self, id, task_credentials=None, evidence=None):
        credentials = dict(task_credentials or {})
        if set(credentials) - {"token", "gateway_url", "protocol"}:
            raise ValueError("Only task-scoped model credentials are accepted")
        with self.lock:
            record = self.get(id)
            if record["status"] != "queued" or id in self.cancelling or self.shutting_down:
                raise ValueError("Only queued, uncancelled jobs can start")
            if self.active:
                raise BlockingIOError("One active task per user; leave additional jobs queued")
            thread = threading.Thread(
                target=self._run, args=(id, credentials, evidence), daemon=True, name="biomni-" + id[:8]
            )
            self.active[id] = thread
            thread.start()
        return self.get(id)

    def _ssh_command(self, server, command):
        return [self.ssh, *SSH_OPTIONS, self.owner + "@" + self.servers[server].address, shlex.join(command)]

    def preflight(self, id):
        record = self.get(id)
        spec = JobSpec.from_dict(record["spec"])
        request = {
            "owner": self.owner,
            "uid": self.uid,
            "repo": str(self.repo_root),
            "job": record["job_directory"],
            "id": id,
            "inputs": spec.input_paths,
        }
        command = [self.agent_python, "-c", PREFLIGHT, json.dumps(request)]
        if spec.server != self.local_server:
            command = self._ssh_command(spec.server, command)
        response = subprocess.run(command, capture_output=True, text=True, timeout=25, check=False)
        if response.returncode:
            raise RuntimeError("User SSH/shared-path preflight failed; configure this user's access and inspect inputs")
        evidence = json.loads(response.stdout)
        if (
            evidence["memory_gb"] * 0.90 < spec.memory_gb
            or evidence["cpus"] * 0.85 - evidence["load"] < spec.cpu_threads
        ):
            raise BlockingIOError("Target currently lacks available CPU or memory headroom")
        if spec.gpu:
            # Device presence alone does not enable a profile; the configured profile is already gated.
            probe = ["/usr/bin/nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"]
            if spec.server != self.local_server:
                probe = self._ssh_command(spec.server, probe)
            gpu = subprocess.run(probe, capture_output=True, text=True, timeout=15, check=False)
            if gpu.returncode or not any(float(x) > 1024 for x in gpu.stdout.splitlines()):
                raise BlockingIOError("No verified free GPU is available")
        return evidence

    def _run(self, id, credentials, evidence=None):
        record = self.get(id)
        spec = JobSpec.from_dict(record["spec"])
        directory = self.store.directory(id)
        token = credentials.get("token", "")
        process = None

        def redact(value):
            return str(value).replace(token, "[REDACTED]") if token else str(value)

        try:
            if evidence is None:
                evidence = self.preflight(id)
            env = {
                k: v
                for k, v in os.environ.items()
                if not any(x in k.upper() for x in ("API_KEY", "TOKEN", "PASSWORD", "SECRET", "JUPYTERHUB"))
            }
            env["PYTHONPATH"] = str(self.repo_root)
            command = [self.agent_python, "-m", "biomni.execution.worker"]
            if spec.server != self.local_server:
                command = self._ssh_command(
                    spec.server, ["/usr/bin/env", "PYTHONPATH=" + str(self.repo_root), *command]
                )
            envelope = {
                "protocol_version": 1,
                "job_id": id,
                "spec": spec.to_dict(),
                "job_directory": str(directory),
                "task_credentials": credentials,
            }
            with (directory / "stderr.log").open("w", encoding="utf-8") as error_log:
                os.chmod(directory / "stderr.log", 0o600)
                # Check cancellation and register the process atomically: cancel() either
                # sees this process or marks the job before it can be launched.
                with self.lock:
                    if id in self.cancelling:
                        final = "interrupted" if self.shutting_down else "cancelled"
                        self.store.update(id, status=final, termination_confirmed=True)
                        self.store.event(id, final, {"message": "Cancelled before the worker started"})
                        return
                    process = subprocess.Popen(
                        command,
                        cwd=directory,
                        env=env,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        start_new_session=True,
                        bufsize=1,
                    )
                    self.processes[id] = process
                self.store.update(
                    id, status="running", dispatcher_pid=process.pid, evidence=evidence, worker_python=self.agent_python
                )
                self.store.event(id, "running", evidence)

                def copy_errors():
                    for line in process.stderr:
                        error_log.write(redact(line))
                        error_log.flush()

                errors = threading.Thread(target=copy_errors, daemon=True)
                errors.start()
                process.stdin.write(json.dumps(envelope) + chr(10))
                process.stdin.close()
                deadline = time.monotonic() + spec.timeout_seconds

                def timeout():
                    while process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.2)
                    if process.poll() is None:
                        self.cancel(id)

                threading.Thread(target=timeout, daemon=True).start()
                valid_result, valid_failure = False, False
                for line in process.stdout:
                    try:
                        event = json.loads(redact(line))
                        if event["job_id"] != id or event["protocol_version"] != 1:
                            raise ValueError()
                        self.store.event(id, event["type"], event.get("data", {}))
                        valid_result = valid_result or event["type"] == "completed"
                        valid_failure = valid_failure or event["type"] == "failed"
                    except (ValueError, KeyError):
                        self.store.event(id, "protocol_error", {"message": "Invalid worker event"})
                code = process.wait()
                errors.join(timeout=5)
            remote = spec.server != self.local_server
            with self.lock:
                done = self.remote_cancel_done.get(id)
            if done is not None:  # Killing the remote worker ends SSH before cancel() records the outcome.
                done.wait(45)
            with self.lock:
                cancelled, remote_confirmed = id in self.cancelling, id in self.remote_terminated
            if cancelled:
                status = "interrupted" if self.shutting_down else "cancelled"
            else:
                status = "succeeded" if code == 0 and valid_result else "failed"
            # A lost SSH client says nothing about the remote worker unless it reported an outcome.
            confirmed = not remote or valid_result or valid_failure or remote_confirmed
            if remote and not confirmed:
                status = "interrupted"
            self.store.update(
                id,
                status=status,
                return_code=code,
                termination_confirmed=bool(confirmed),
                **({"error": "Remote worker state unconfirmed; inspect before resubmission"} if not confirmed else {}),
            )
            self.store.event(id, status, {"exit_code": code, "termination_confirmed": bool(confirmed)})
        except BlockingIOError as exc:
            self.store.update(id, status="queued", error=redact(exc))
        except Exception as exc:
            # Stop a still-running local worker before recording a confirmed terminal state.
            if process is not None and process.poll() is None and spec.server == self.local_server:
                self._signal(process, signal.SIGKILL)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            uncertain = process is not None and (spec.server != self.local_server or process.poll() is None)
            status = "interrupted" if uncertain else "failed"
            self.store.update(id, status=status, error=redact(exc), termination_confirmed=not uncertain)
            self.store.event(id, status, {"message": redact(exc)})
        finally:
            if process is not None and process.poll() is None and spec.server == self.local_server:
                self._signal(process, signal.SIGKILL)
                process.wait(timeout=5)
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream and not stream.closed:
                        stream.close()
            with self.lock:
                self.active.pop(id, None)
                self.processes.pop(id, None)
                self.cancelling.discard(id)
                self.remote_terminated.discard(id)
                self.remote_cancel_done.pop(id, None)

    def cancel(self, id):
        with self.lock:
            record = self.get(id)
            if record["status"] in TERMINAL:
                return record
            self.cancelling.add(id)
            process = self.processes.get(id)
            if process is None:
                if id in self.active:  # Preflight/startup: _run observes the flag before launching.
                    return self.store.update(id, status="cancelling")
                final = "interrupted" if self.shutting_down else "cancelled"
                self.cancelling.discard(id)
                record = self.store.update(id, status=final, termination_confirmed=True)
                self.store.event(id, final, {"message": "Cancelled while queued"})
                return record
            self.store.update(id, status="cancelling")
        if record["server"] != self.local_server:
            done = threading.Event()
            with self.lock:
                self.remote_cancel_done[id] = done
            command = self._ssh_command(
                record["server"], [self.agent_python, "-c", REMOTE_CANCEL, record["job_directory"], id]
            )
            detail = ""
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                confirmed = result.returncode == 0 and result.stdout.strip() in {"absent", "terminated"}
                detail = (result.stderr.strip().splitlines() or [""])[-1][:300]
            except subprocess.TimeoutExpired:
                confirmed = False
            if confirmed:
                with self.lock:
                    self.remote_terminated.add(id)
            done.set()
            if not confirmed and process.poll() is None:
                self.store.update(
                    id,
                    status="interrupted",
                    termination_confirmed=False,
                    error="Remote cancellation unconfirmed; inspect worker before resubmission. " + detail,
                )
                raise RuntimeError("Remote cancellation could not be confirmed")
        self._signal(process, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._signal(process, signal.SIGKILL)
        return self.get(id)

    @staticmethod
    def _signal(process, sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def _local_worker_state(self, directory, id):
        """Return 'absent' or 'terminated' after verifying identity; raise if uncertain."""
        result = subprocess.run(
            [sys.executable, "-I", "-c", REMOTE_CANCEL, str(directory), id],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        state = result.stdout.strip()
        if result.returncode or state not in {"absent", "terminated"}:
            raise RuntimeError("Local worker state could not be confirmed")
        return state

    def reconcile(self):
        """After a restart: never replay. Terminate verified leftovers and report certainty."""
        report = []
        for record in self.list():
            id = record["job_id"]
            if id in self.active:
                continue
            status = record["status"]
            if status == "queued":
                self.store.update(
                    id,
                    status="interrupted",
                    termination_confirmed=True,
                    error="Service restarted before this task started; resubmit explicitly",
                )
                report.append({"job_id": id, "status": "interrupted", "termination_confirmed": True})
            elif status in {"running", "cancelling"} or (
                status == "interrupted" and not record.get("termination_confirmed", True)
            ):
                try:
                    if record["server"] == self.local_server:
                        state = self._local_worker_state(record["job_directory"], id)
                    else:
                        command = self._ssh_command(
                            record["server"], [self.agent_python, "-c", REMOTE_CANCEL, record["job_directory"], id]
                        )
                        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                        state = result.stdout.strip()
                        if result.returncode or state not in {"absent", "terminated"}:
                            raise RuntimeError("Remote worker state could not be confirmed")
                    self.store.update(
                        id,
                        status="interrupted",
                        termination_confirmed=True,
                        error="Service restarted; worker " + state + ". Resubmit explicitly",
                    )
                    report.append({"job_id": id, "status": "interrupted", "termination_confirmed": True})
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    self.store.update(
                        id,
                        status="interrupted",
                        termination_confirmed=False,
                        error="Service restarted; worker state unconfirmed. Inspect before resubmission",
                    )
                    report.append({"job_id": id, "status": "interrupted", "termination_confirmed": False})
        return report

    def shutdown(self, wait=60):
        """Control connection lost (service restart): request cancellation of all work."""
        with self.lock:
            self.shutting_down = True
            ids = [r["job_id"] for r in self.list() if r["status"] in {"queued", "running", "cancelling"}]
        for id in ids:
            try:
                self.cancel(id)
            except Exception:
                pass
        deadline = time.monotonic() + wait
        for thread in list(self.active.values()):
            thread.join(timeout=max(0, deadline - time.monotonic()))


def build_parallel_command(job_file, *, jobs, distributed=False, sshlogin=None, joblog=None):
    if type(jobs) is not int or jobs < 1 or distributed != bool(sshlogin):
        raise ValueError("Explicit distributed selection and positive job count required")
    if sshlogin and not all(
        re.fullmatch(r"[1-9][0-9]*/[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+", entry) for entry in sshlogin.split(",")
    ):
        raise ValueError("Use canonical slots/user@host entries")
    command = ["parallel", "--shell", "/bin/bash", "--jobs", str(jobs), "--workdir", str(Path.cwd())]
    if sshlogin:
        command.extend(["--sshlogin", sshlogin])
    if joblog:
        command.extend(["--joblog", str(Path(joblog).absolute())])
    return [*command, "::::", str(Path(job_file).absolute())]
