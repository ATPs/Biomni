import asyncio
import json
import os
import pwd
import socket
import sys
import tempfile
import time
import unittest
from io import BytesIO
from pathlib import Path
from urllib.parse import quote

from biomni.server.accounts import Accounts, LoginFailed, launch_dispatcher
from biomni.server.app import IngressHTTPServer, Service, create_app
from biomni.server.ipc import Channel
from biomni.server.security import AccessDenied, allowed_client, provider_url
from biomni.server.state import Sessions, State
from cryptography.fernet import Fernet
from tornado.httpclient import HTTPRequest, HTTPResponse
from tornado.testing import AsyncHTTPTestCase

REPO = Path(__file__).resolve().parents[1]
ME = pwd.getpwuid(os.getuid()).pw_name


def make_state(path=":memory:", users=("admin", "alice", "bob")):
    admins = {"admin"}

    def user_check(user):
        if user not in set(users):
            raise AccessDenied("Unknown system user")

    state = State(path, Fernet.generate_key(), admin_check=lambda u: u in admins, user_check=user_check)
    for user in users:
        if user != "admin":
            state.access("admin", user, True)
    state.save_provider(
        "admin",
        id="shared",
        name="Shared",
        url="https://provider.example/v1",
        api_key="shared-secret",
        models=["allowed", "other"],
    )
    for user in users:
        if user != "admin":
            state.grant("admin", user, "shared", "allowed", True)
    return state, admins


PROFILE = {
    "servers": {
        "test": {"cpu_threads": 8, "memory_gb": 32, "max_jobs": 2},
        "second": {"cpu_threads": 8, "memory_gb": 32},
    }
}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.state, self.admins = make_state()
        self.addCleanup(self.state.close)
        self.sessions = Sessions(self.state)

    def issue(self, **changes):
        arguments = {
            "username": "alice",
            "session": "session",
            "job_id": "a" * 32,
            "server": "test",
            "cpus": 1,
            "memory_gb": 4,
            "provider": "shared",
            "model": "allowed",
            "profile": PROFILE,
        }
        arguments.update(changes)
        return self.sessions.issue(**arguments)[0]

    def test_cipher_and_public_provider_redaction(self):
        provider = self.state.provider("shared")
        self.assertNotIn(b"shared-secret", provider["secret"])
        self.assertEqual(self.state.key(provider), "shared-secret")
        self.assertNotIn("secret", self.state.provider("shared", public=True))

    def test_admin_group_is_rechecked_and_users_cannot_self_approve(self):
        with self.assertRaises(AccessDenied):
            self.state.access("alice", "bob", True)
        self.admins.clear()
        with self.assertRaises(AccessDenied):
            self.state.providers("admin")

    def test_grants_and_revocation(self):
        token = self.issue()
        self.assertEqual(self.sessions.lookup(token).model, "allowed")
        with self.assertRaises(AccessDenied):
            self.state.authorize_model("alice", "shared", "other")
        self.state.grant("admin", "alice", "shared", "allowed", False)
        with self.assertRaises(AccessDenied):
            self.sessions.lookup(token)
        self.assertEqual(len(self.state.leases()), 1)  # Kept until worker termination is confirmed.

    def test_same_model_id_at_another_provider_is_not_granted(self):
        self.state.save_provider(
            "admin", id="second", name="Second", url="https://second.example/v1", api_key="k", models=["allowed"]
        )
        with self.assertRaises(AccessDenied):
            self.state.authorize_model("alice", "second", "allowed")

    def test_disabled_users_and_session_only_personal_models(self):
        self.sessions.set_personal(
            "alice", "session", {"url": "https://personal.example/v1", "api_key": "p", "protocol": "responses"}
        )
        token = self.issue(provider="personal", model="unrestricted-personal-model")
        self.assertEqual(self.sessions.lookup(token).protocol, "responses")
        self.assertFalse(Sessions(self.state).personal)  # Restart loses personal credentials.
        self.state.access("admin", "alice", False)
        with self.assertRaises(AccessDenied):
            self.sessions.lookup(token)

    def test_clearing_one_session_keeps_other_sessions_and_shared_tokens(self):
        for session in ("one", "two"):
            self.sessions.set_personal(
                "alice", session, {"url": "https://p.example/v1", "api_key": "k", "protocol": "chat_completions"}
            )
        personal_one = self.issue(session="one", job_id="1" * 32, provider="personal", model="m")
        self.sessions.finish("alice", "1" * 32)
        personal_one = self.issue(session="one", job_id="2" * 32, provider="personal", model="m")
        self.state.release_lease("admin", "2" * 32)
        personal_two = self.issue(session="two", job_id="3" * 32, provider="personal", model="m")
        self.state.release_lease("admin", "3" * 32)
        shared = self.issue(session="one", job_id="4" * 32)
        self.assertEqual(self.sessions.clear("alice", "one"), ["2" * 32])
        with self.assertRaises(AccessDenied):
            self.sessions.lookup(personal_one)
        self.assertEqual(self.sessions.lookup(personal_two).job_id, "3" * 32)
        self.assertEqual(self.sessions.lookup(shared).job_id, "4" * 32)
        self.sessions.get_personal("alice", "two")

    def test_reservations_survive_restart_and_finish_is_owner_scoped(self):
        self.issue()
        sessions = Sessions(self.state)
        with self.assertRaises(BlockingIOError):
            sessions.issue(
                username="alice",
                session="x",
                job_id="b" * 32,
                server="test",
                cpus=1,
                memory_gb=4,
                provider="shared",
                model="allowed",
                profile=PROFILE,
            )
        sessions.finish("bob", "a" * 32)
        self.assertEqual(len(self.state.leases()), 1)
        with self.assertRaises(AccessDenied):
            self.state.release_lease("alice", "a" * 32)
        self.state.release_lease("admin", "a" * 32)
        self.assertEqual(self.state.leases(), [])

    def test_network_exact_boundaries(self):
        for ip in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "::ffff:10.1.2.3",
        ]:
            self.assertTrue(allowed_client(ip), ip)
        for ip in [
            "172.15.255.255",
            "172.32.0.0",
            "192.169.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "11.0.0.1",
            "::1",
            "fd00::1",
            "bad",
        ]:
            self.assertFalse(allowed_client(ip), ip)

    def test_provider_urls(self):
        self.assertEqual(provider_url("http://10.1.2.3:8317/v1/"), "http://10.1.2.3:8317/v1")
        for url in [
            "file:///etc/passwd",
            "http://127.0.0.1/v1",
            "http://169.254.169.254/v1",
            "http://user:pw@api.example/v1",
            "http://api.example/v1?api_key=x",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                provider_url(url)
        with self.assertRaises(ValueError):
            provider_url("http://10.1.2.3:8765/v1", forbidden_ports=(8765,))


class IPCAndAccountTests(unittest.TestCase):
    def test_frames_carry_descriptors_in_order(self):
        left, right = socket.socketpair()
        a, b = Channel(left), Channel(right)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with tempfile.TemporaryFile() as handle:
            handle.write(b"artifact")
            handle.flush()
            a.send({"n": 1})
            a.send({"n": 2, "large": "x" * 200000}, [handle.fileno()])
            a.send({"n": 3})
            self.assertEqual(b.recv(), ({"n": 1}, []))
            message, fds = b.recv()
            self.assertEqual((message["n"], len(fds)), (2, 1))
            with os.fdopen(fds[0], "rb") as received:
                received.seek(0)
                self.assertEqual(received.read(), b"artifact")
            self.assertEqual(b.recv(), ({"n": 3}, []))

    def test_root_system_and_unknown_accounts_are_refused(self):
        accounts = Accounts(authenticate=lambda u, p: True, account_valid=lambda u: True, min_uid=1000)
        for name in ("root", "bin", "no-such-user-biomni", "", "x" * 100):
            with self.subTest(name=name), self.assertRaises(LoginFailed):
                accounts.login_user(name)

    def test_failed_logins_are_throttled(self):
        accounts = Accounts(authenticate=lambda u, p: False, account_valid=lambda u: True, min_uid=0, max_failures=2)
        import biomni.server.accounts as module

        original, module.time.sleep = module.time.sleep, lambda s: None
        try:
            for _ in range(2):
                with self.assertRaises(LoginFailed):
                    accounts.authenticate(ME, "wrong", "10.0.0.9")
            with self.assertRaisesRegex(LoginFailed, "Too many"):
                accounts.authenticate(ME, "right", "10.0.0.9")
        finally:
            module.time.sleep = original


def lan_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 9))  # No packet is sent for UDP connect.
            address = probe.getsockname()[0]
        return address if allowed_client(address) else None
    except OSError:
        return None


class ReviewRegressionTests(unittest.TestCase):
    def test_safe_resolver_accepts_private_and_rejects_loopback(self):
        from biomni.server.providers import SafeResolver

        resolver = SafeResolver()
        with self.assertRaisesRegex(ValueError, "protected"):
            asyncio.run(resolver.resolve("127.0.0.1", 80))
        if lan_address():
            self.assertTrue(asyncio.run(resolver.resolve(lan_address(), 80)))

    @unittest.skipUnless(lan_address(), "no private LAN address on this host")
    def test_real_transport_discovery_and_chat(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from biomni.server.providers import ProviderTransport

        seen = []

        class Handler(BaseHTTPRequestHandler):
            def reply(self, payload):
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                self.reply({"data": [{"id": "gpt-6.1-sol"}, {"id": "other"}]})

            def do_POST(self):
                seen.append((self.path, self.headers.get("Authorization")))
                self.rfile.read(int(self.headers["Content-Length"]))
                self.reply({"choices": [{"message": {"content": "ok"}}]})

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer((lan_address(), 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            transport = ProviderTransport(timeout=10)
            settings = {
                "url": transport.normalize(f"http://{lan_address()}:{server.server_port}/v1/"),
                "api_key": "k-123",
            }

            async def exercise():
                models = await transport.discover(settings)
                response = await transport.fetch(settings, "chat/completions", {"model": "gpt-6.1-sol", "messages": []})
                return models, response.code

            self.assertEqual(asyncio.run(exercise()), (["gpt-6.1-sol", "other"], 200))
            self.assertEqual(seen, [("/v1/models", "Bearer k-123"), ("/v1/chat/completions", "Bearer k-123")])
            with self.assertRaises(ValueError):
                asyncio.run(transport.fetch({**settings, "api_key": "k\n"}, "models"))
        finally:
            server.shutdown()
            server.server_close()

    def test_api_keys_with_control_characters_are_refused(self):
        state, _ = make_state()
        self.addCleanup(state.close)
        with self.assertRaises(ValueError):
            state.save_provider("admin", id="bad", name="Bad", url="https://p.example/v1", api_key="sk-1\nx")
        state.save_provider("admin", id="ok", name="OK", url="https://p.example/v1", api_key="  sk-1  ")
        self.assertEqual(state.key(state.provider("ok")), "sk-1")

    def test_rpc_client_never_blocks_on_a_stalled_peer(self):
        from biomni.server.ipc import RPCClient

        left, right = socket.socketpair()
        self.addCleanup(right.close)
        client = RPCClient(left, max_queued=4)
        start = time.monotonic()
        futures = [client.call("create", prompt="x" * 1_000_000) for _ in range(20)]
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertTrue(any(f.done() and isinstance(f.exception(), ConnectionError) for f in futures))
        client.close()

    def test_undeclared_descriptors_are_closed(self):
        import struct

        left, right = socket.socketpair()
        receiver = Channel(right)
        self.addCleanup(left.close)
        self.addCleanup(receiver.close)
        payload = json.dumps({"n": 1, "_fds": 0}).encode()
        with tempfile.TemporaryFile() as handle:
            left.sendmsg(
                [struct.pack("!I", len(payload)) + payload],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("2i", handle.fileno(), handle.fileno()))],
            )
            self.assertEqual(receiver.recv(), ({"n": 1}, []))
            self.assertEqual(len(receiver.fds), 0)

    def test_oversized_reply_becomes_an_error(self):
        import threading

        from biomni.server.ipc import RemoteError, RPCClient, serve

        left, right = socket.socketpair()
        server_channel = Channel(right, max_frame=1024)
        thread = threading.Thread(target=serve, args=(server_channel, {"big": lambda: "x" * 5000}), daemon=True)
        thread.start()
        client = RPCClient(left)
        with self.assertRaisesRegex(RemoteError, "too large"):
            client.call("big").result(timeout=5)
        client.close()
        thread.join(timeout=5)


class FakeTransport:
    def __init__(self):
        self.calls = []

    def normalize(self, url):
        return provider_url(url, resolve=False)

    async def discover(self, settings):
        return ["allowed", "discovered"]

    async def fetch(self, settings, path, body=None, stream=None):
        self.calls.append((settings, path, body))
        payload = {
            "id": "fixture",
            "object": "chat.completion",
            "model": body.get("model"),
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "<solution>fixture complete</solution>"},
                }
            ],
        }
        if stream:
            stream(b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\n')
        return HTTPResponse(
            HTTPRequest("https://provider.example/v1/" + path), 200, buffer=BytesIO(json.dumps(payload).encode())
        )


class WebTests(AsyncHTTPTestCase):
    """Real dispatcher and worker subprocesses as the current user; fake PAM and provider only."""

    cidrs = ("127.0.0.0/8",)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        super().setUp()

    def get_app(self):
        root = Path(self.tmp.name)
        self.state, _ = make_state(users=("admin", ME))
        profile = {
            "version": 1,
            "agent_python": sys.executable,
            "repository": str(REPO),
            "data_path": str(root / "data"),
            "timeout_seconds": 300,
            "servers": {"local": {"address": "127.0.0.1", "cpu_threads": 8, "memory_gb": 32}},
        }
        (root / "profile.json").write_text(json.dumps(profile))
        command = [
            sys.executable,
            "-s",
            "-m",
            "biomni.execution.dispatcher",
            "--profile",
            str(root / "profile.json"),
            "--local-server",
            "local",
            "--state-dir",
            str(root / "state"),
        ]
        self.transport = FakeTransport()
        accounts = Accounts(
            authenticate=lambda u, p: u == ME and p == "correct", account_valid=lambda u: True, min_uid=0
        )
        self.service = Service(
            state=self.state,
            profile=profile,
            accounts=accounts,
            transport=self.transport,
            gateway_url="",
            cidrs=self.cidrs,
            launcher=lambda user: launch_dispatcher(user, command, extra_env={"PYTHONPATH": str(REPO)}),
        )
        return create_app(self.service)

    def get_http_server(self):
        return IngressHTTPServer(self._app, cidrs=self.cidrs, **self.get_httpserver_options())

    def tearDown(self):
        for link in list(self.service.links.values()):
            link.client.close()
            if link.process is not None:
                try:
                    link.process.wait(timeout=60)
                except Exception:
                    link.process.kill()
        super().tearDown()
        self.state.close()
        self.tmp.cleanup()

    # Helpers --------------------------------------------------------------
    def cookies(self, response):
        jar = {}
        for header in response.headers.get_list("Set-Cookie"):
            name, value = header.split(";", 1)[0].split("=", 1)
            jar[name] = value
        return jar

    def login(self, password="correct"):
        page = self.fetch("/login")
        self.assertEqual(page.code, 200)
        self.jar = self.cookies(page)
        response = self.post("/api/login", {"username": ME, "password": password})
        self.jar.update(self.cookies(response))
        return response

    def headers(self, xsrf=True):
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in self.jar.items())}
        if xsrf:
            headers["X-XSRFToken"] = self.jar.get("_xsrf", "")
        return headers

    def post(self, path, data, xsrf=True):
        return self.fetch(
            path,
            method="POST",
            headers={**self.headers(xsrf), "Content-Type": "application/json"},
            body=json.dumps(data),
        )

    def get(self, path):
        return self.fetch(path, headers=self.headers(False), follow_redirects=False)

    def wait_for(self, predicate, timeout=240):
        async def loop():
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                await self.service.tick()
                result = await predicate()
                if result:
                    return result
                await asyncio.sleep(0.25)
            raise AssertionError("Condition not reached")

        return self.io_loop.run_sync(loop, timeout=timeout + 10)

    async def job(self, job_id):
        link = self.service.links[ME]
        return await self.service.call(link, "get", id=job_id)

    # Tests ----------------------------------------------------------------
    def test_pages_require_session_and_csrf(self):
        self.assertEqual(self.fetch("/", follow_redirects=False).code, 302)
        self.assertEqual(self.fetch("/api/me").code, 401)
        self.assertEqual(self.fetch("/health").code, 200)
        self.assertEqual(self.fetch("/no-such-page").code, 404)
        self.jar = self.cookies(self.fetch("/login"))
        self.assertEqual(self.post("/api/login", {"username": ME, "password": "correct"}, xsrf=False).code, 403)
        failed = self.login("wrong")
        self.assertEqual((failed.code, json.loads(failed.body)["error"]), (401, "Incorrect username or password"))
        self.assertEqual(self.login().code, 200)
        self.assertEqual(json.loads(self.get("/api/me").body)["username"], ME)
        self.assertEqual(self.post("/api/personal/clear", {}, xsrf=False).code, 403)
        forged = self.fetch(
            "/api/me", headers={**self.headers(False), "X-Forwarded-For": "8.8.8.8", "X-Remote-User": "admin"}
        )
        self.assertFalse(json.loads(forged.body)["admin"])
        self.assertEqual(self.post("/api/admin/users", {"username": ME, "enabled": True}).code, 403)

    def test_shared_job_end_to_end_through_gateway(self):
        self.service.gateway_url = f"http://127.0.0.1:{self.get_http_port()}/gateway/v1"
        self.assertEqual(self.login().code, 200)
        response = self.post(
            "/api/jobs", {"server": "local", "provider": "shared", "model": "allowed", "prompt": "Say done"}
        )
        self.assertEqual(response.code, 200, response.body)
        job_id = json.loads(response.body)["job_id"]

        async def finished():
            record = await self.job(job_id)
            return record if record["status"] in {"succeeded", "failed", "cancelled", "interrupted"} else None

        record = self.wait_for(finished)
        self.assertEqual(record["status"], "succeeded", record)
        self.assertTrue(self.transport.calls, "worker did not reach the gateway")
        self.assertEqual(self.transport.calls[0][0]["api_key"], "shared-secret")
        events = json.loads(self.get(f"/api/jobs/{job_id}/events").body)["events"]
        self.assertIn("fixture complete", json.dumps([e for e in events if e["type"] == "progress"]))
        self.wait_for(lambda: asyncio.sleep(0, result=not self.state.leases()))
        artifacts = json.loads(self.get(f"/api/jobs/{job_id}/artifacts").body)["artifacts"]
        self.assertIn("run-manifest.json", [a["relative_path"] for a in artifacts])
        download = self.get(f"/download/{job_id}/run-manifest.json")
        self.assertEqual(download.code, 200)
        self.assertEqual(json.loads(download.body)["job_id"], job_id)
        self.assertEqual(self.get(f"/download/{job_id}/{quote('../job.json', safe='')}").code, 404)
        for path in Path(record["job_directory"]).rglob("*"):
            if path.is_file():
                self.assertNotIn(b"shared-secret", path.read_bytes(), path)

    def test_logout_cancels_only_personal_jobs(self):
        self.assertEqual(self.login().code, 200)
        self.assertEqual(
            self.post("/api/personal", {"url": "https://personal.example/v1", "api_key": "personal-secret"}).code, 200
        )
        self.service.ticking = True  # Hold admission so both jobs stay queued.
        personal = json.loads(
            self.post("/api/jobs", {"server": "local", "provider": "personal", "model": "m", "prompt": "p"}).body
        )
        shared = json.loads(
            self.post("/api/jobs", {"server": "local", "provider": "shared", "model": "allowed", "prompt": "s"}).body
        )
        self.assertEqual(self.post("/api/logout", {}).code, 200)
        self.assertEqual(self.get("/api/me").code, 401)
        statuses = self.io_loop.run_sync(
            lambda: asyncio.gather(self.job(personal["job_id"]), self.job(shared["job_id"]))
        )
        self.assertEqual([s["status"] for s in statuses], ["cancelled", "queued"])
        self.assertFalse(self.service.sessions.personal)
        self.assertEqual(self.post("/api/jobs/" + shared["job_id"] + "/cancel", {}).code, 401)

    def test_gateway_never_relays_transport_error_text(self):
        self.assertEqual(self.login().code, 200)

        async def failing(*args, **kwargs):
            raise ValueError("Illegal characters in header: Authorization: Bearer shared-secret")

        self.transport.fetch = failing
        token, _ = self.service.sessions.issue(
            username=ME,
            session="",
            job_id="c" * 32,
            server="local",
            cpus=1,
            memory_gb=1,
            provider="shared",
            model="allowed",
            profile=self.service.profile,
        )
        response = self.fetch(
            "/gateway/v1/chat/completions",
            method="POST",
            body=json.dumps({"model": "allowed", "messages": []}),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        self.assertEqual(response.code, 502)
        self.assertNotIn(b"shared-secret", response.body)

    def test_locked_account_is_signed_out_on_recheck(self):
        self.assertEqual(self.login().code, 200)
        self.get("/api/jobs")  # Connect the dispatcher.
        self.service.accounts.account_valid = lambda username: False
        self.io_loop.run_sync(self.service.tick)
        self.assertEqual(self.get("/api/me").code, 401)

    def test_lease_owner_dispatcher_is_relaunched_for_reconciliation(self):
        with self.state.transaction() as db:
            db.execute("INSERT INTO leases VALUES (?,?,?,?,?,?)", ("d" * 32, ME, "local", 1, 1.0, time.time()))
        self.assertNotIn(ME, self.service.links)
        self.wait_for(lambda: asyncio.sleep(0, result=ME in self.service.links), timeout=60)

    def test_unapproved_and_disabled_users(self):
        self.state.access("admin", ME, False)
        self.assertEqual(self.login().code, 403)
        self.state.access("admin", ME, True)
        self.assertEqual(self.login().code, 200)
        self.state.access("admin", ME, False)
        self.assertEqual(self.get("/api/me").code, 403)


class DefaultIngressTests(WebTests):
    cidrs = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

    def test_loopback_is_outside_the_agreed_ranges(self):
        from tornado.simple_httpclient import HTTPStreamClosedError

        with self.assertRaises(HTTPStreamClosedError):  # Closed before any HTTP response.
            self.fetch("/health", raise_error=False)

    # The inherited tests need loopback access.
    test_pages_require_session_and_csrf = test_shared_job_end_to_end_through_gateway = None
    test_logout_cancels_only_personal_jobs = test_unapproved_and_disabled_users = None
    test_gateway_never_relays_transport_error_text = test_locked_account_is_signed_out_on_recheck = None
    test_lease_owner_dispatcher_is_relaunched_for_reconciliation = None


if __name__ == "__main__":
    unittest.main()
