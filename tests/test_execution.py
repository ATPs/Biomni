import json
import os
import pwd
import sys
import tempfile
import time
import unittest
from pathlib import Path

from biomni.execution import Dispatcher, JobSpec, LocalJobStore, build_parallel_command


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = LocalJobStore(Path(self.tmp.name) / "runs")
        self.dispatcher = Dispatcher(
            {"test": {"address": "127.0.0.1", "cpu_threads": 8, "memory_gb": 32}}, local_server="test", store=self.store
        )
        self.dispatcher.preflight = lambda id: {"uid": os.getuid(), "host": "test-fixture"}
        self.owner = pwd.getpwuid(os.getuid()).pw_name

    def spec(self, command, **changes):
        values = {
            "owner": self.owner,
            "server": "test",
            "prompt": "fixture",
            "model": "fake",
            "provider": "personal",
            "command": command,
        }
        values.update(changes)
        return JobSpec(**values)

    def wait(self, id):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            record = self.dispatcher.get(id)
            if record["status"] in {"succeeded", "failed", "cancelled", "interrupted"} and not self.dispatcher.active:
                return record
            time.sleep(0.03)
        self.fail("Worker failed to stop within 10 seconds")

    def test_local_worker_real_subprocess_artifacts_and_no_secret_persistence(self):
        command = (
            sys.executable,
            "-c",
            "from pathlib import Path;Path('answer.txt').write_text('42');print('scientific stdout')",
        )
        job = self.dispatcher.create(self.spec(command))
        self.dispatcher.start(
            job["job_id"],
            {"token": "task-secret", "gateway_url": "http://unused.example", "protocol": "chat_completions"},
        )
        result = self.wait(job["job_id"])
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(self.dispatcher.artifact_path(job["job_id"], "answer.txt").read_text(), "42")
        names = [a.relative_path for a in self.dispatcher.artifacts(job["job_id"])]
        self.assertIn("run-manifest.json", names)
        self.assertIn("completed", [e["type"] for e in self.dispatcher.events(job["job_id"])])
        for path in self.store.directory(job["job_id"]).rglob("*"):
            if path.is_file():
                self.assertNotIn("task-secret", path.read_text())

    def test_cancellation_terminates_worker_and_child(self):
        command = (
            sys.executable,
            "-c",
            "import os,time;from pathlib import Path;Path('child.pid').write_text(str(os.getpid()));time.sleep(60)",
        )
        job = self.dispatcher.create(self.spec(command))
        id = job["job_id"]
        self.dispatcher.start(id)
        pidpath = self.store.directory(id) / "artifacts/child.pid"
        deadline = time.monotonic() + 5
        while not pidpath.exists() and time.monotonic() < deadline:
            time.sleep(0.03)
        self.assertTrue(pidpath.exists())
        pid = int(pidpath.read_text())
        self.dispatcher.cancel(id)
        self.assertEqual(self.wait(id)["status"], "cancelled")
        proc = Path(f"/proc/{pid}/stat")
        if proc.exists():
            self.assertEqual(proc.read_text().split(") ", 1)[1].split()[0], "Z")

    def test_traversal_symlinks_hardlinks_and_owner_are_rejected(self):
        with self.assertRaises(PermissionError):
            self.dispatcher.create(self.spec(("/usr/bin/true",), owner="different-user"))
        job = self.dispatcher.create(self.spec(("/usr/bin/true",)))
        root = self.store.directory(job["job_id"]) / "artifacts"
        target = Path(self.tmp.name) / "outside"
        target.write_text("private")
        (root / "link").symlink_to(target)
        os.link(target, root / "hardlink")
        for relative in ("../job.json", "/etc/passwd", "link", "hardlink"):
            with self.subTest(path=relative), self.assertRaises(PermissionError):
                self.dispatcher.artifact_path(job["job_id"], relative)

    def test_install_command_is_refused_without_execution(self):
        job = self.dispatcher.create(self.spec((sys.executable, "-m", "pip", "install", "never-install")))
        self.dispatcher.start(job["job_id"])
        self.assertEqual(self.wait(job["job_id"])["status"], "failed")

    def test_cancel_during_preflight_never_launches_worker(self):
        import threading

        gate = threading.Event()

        def slow_preflight(id):
            gate.wait(5)
            return {"uid": os.getuid()}

        self.dispatcher.preflight = slow_preflight
        command = (sys.executable, "-c", "from pathlib import Path;Path('ran.txt').write_text('1')")
        job = self.dispatcher.create(self.spec(command))
        self.dispatcher.start(job["job_id"])
        self.assertEqual(self.dispatcher.cancel(job["job_id"])["status"], "cancelling")
        gate.set()
        record = self.wait(job["job_id"])
        self.assertEqual(record["status"], "cancelled")
        self.assertTrue(record["termination_confirmed"])
        self.assertFalse((self.store.directory(job["job_id"]) / "artifacts/ran.txt").exists())
        with self.assertRaises(ValueError):
            self.dispatcher.start(job["job_id"])

    def test_restart_reconciliation_terminates_verified_worker(self):
        command = (sys.executable, "-c", "import time;time.sleep(60)")
        job = self.dispatcher.create(self.spec(command))
        id = job["job_id"]
        self.dispatcher.start(id)
        identity = self.store.directory(id) / ".worker-identity.json"
        deadline = time.monotonic() + 10
        while not identity.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        pid = json.loads(identity.read_text())["pid"]
        queued = self.dispatcher.create(self.spec(("/usr/bin/true",)))
        restarted = Dispatcher(
            {"test": {"address": "127.0.0.1", "cpu_threads": 8, "memory_gb": 32}}, local_server="test", store=self.store
        )
        report = {r["job_id"]: r for r in restarted.reconcile()}
        self.assertTrue(report[id]["termination_confirmed"])
        self.assertTrue(report[queued["job_id"]]["termination_confirmed"])
        self.assertEqual(restarted.get(queued["job_id"])["status"], "interrupted")
        stat = Path(f"/proc/{pid}/stat")
        self.assertTrue(not stat.exists() or stat.read_text().split(") ", 1)[1].split()[0] == "Z")
        self.wait(id)

    def test_shutdown_interrupts_running_and_queued_work(self):
        job = self.dispatcher.create(self.spec((sys.executable, "-c", "import time;time.sleep(60)")))
        queued = self.dispatcher.create(self.spec(("/usr/bin/true",)))
        self.dispatcher.start(job["job_id"])
        deadline = time.monotonic() + 10
        while self.dispatcher.get(job["job_id"])["status"] != "running" and time.monotonic() < deadline:
            time.sleep(0.05)
        self.dispatcher.shutdown(wait=15)
        for id in (job["job_id"], queued["job_id"]):
            record = self.dispatcher.get(id)
            self.assertEqual(record["status"], "interrupted", record)
            self.assertTrue(record["termination_confirmed"])

    def test_parallel_requires_explicit_distribution(self):
        local = build_parallel_command("jobs.txt", jobs=2)
        self.assertEqual(local[:5], ["parallel", "--shell", "/bin/bash", "--jobs", "2"])
        self.assertNotIn("--sshlogin", local)
        with self.assertRaises(ValueError):
            build_parallel_command("jobs.txt", jobs=2, sshlogin="2/x@host")
        self.assertIn("2/x@host", build_parallel_command("jobs.txt", jobs=2, distributed=True, sshlogin="2/x@host"))


if __name__ == "__main__":
    unittest.main()
