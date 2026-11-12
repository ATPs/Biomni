"""Biomni web service: one Tornado listener for login, UI, APIs, downloads and the model gateway.

Runs as root on server2 so it can authenticate system accounts through PAM and launch each
user's dispatcher under that user's UID. It never executes analysis code itself: jobs,
files and cancellation go through the user-owned dispatcher over a private socketpair.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import pwd
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from tornado import web
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.iostream import StreamClosedError

from .accounts import Accounts, LoginFailed, launch_dispatcher, pam_authenticator
from .ipc import RemoteError, RPCClient
from .providers import ProviderTransport, valid_key
from .security import PRIVATE_CIDRS, AccessDenied, allowed_client
from .state import Sessions, State

log = logging.getLogger("biomni.web")
STATIC = Path(__file__).parent / "static"
TERMINAL = {"succeeded", "failed", "cancelled", "interrupted"}
ACTIVE = {"running", "cancelling"}
COOKIE = "biomni_session"
ERROR_STATUS = {"not_found": 404, "denied": 403, "invalid": 400, "busy": 409, "failed": 502}
USER_TICK_TIMEOUT = 20  # One stalled dispatcher must not delay other users' scheduling.
RECHECK_SECONDS = 60


@dataclass
class WebSession:
    id: str  # Digest of the cookie value; the raw cookie is never stored.
    username: str
    uid: int
    expires: float


@dataclass
class UserLink:
    username: str
    uid: int
    client: RPCClient
    process: object = None
    personal_jobs: dict = field(default_factory=dict)  # job_id -> browser session ID
    admitting: str | None = None
    checked: float = 0.0  # Last PAM account (lock/expiry) recheck.
    creating: int = 0  # Submissions in flight; admission waits so personal jobs get their session first.


class Service:
    def __init__(
        self,
        *,
        state,
        profile,
        accounts,
        gateway_url,
        launcher,
        transport=None,
        session_ttl=86400,
        cidrs=PRIVATE_CIDRS,
        catalog=None,
    ):
        self.state, self.profile, self.accounts = state, profile, accounts
        self.gateway_url, self.launcher = gateway_url, launcher
        self.transport = transport or ProviderTransport()
        self.sessions = Sessions(state, ttl=session_ttl)
        self.session_ttl, self.cidrs, self.catalog = session_ttl, tuple(cidrs), catalog
        self.browser, self.links = {}, {}
        self.link_locks = {}
        self.relaunch_attempts = {}
        self.ticking = False

    # Browser sessions -------------------------------------------------------
    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def session(self, cookie):
        if not cookie or len(cookie) > 256:
            return None
        current = self.browser.get(self.digest(cookie))
        if current is None or current.expires <= time.time():
            return None
        return current

    def create_session(self, user):
        cookie = secrets.token_urlsafe(32)
        session = WebSession(self.digest(cookie), user.pw_name, user.pw_uid, time.time() + self.session_ttl)
        self.browser[session.id] = session
        return cookie, session

    async def end_session(self, session, *, logout=True):
        """Logout, expiry or Clear Personal Settings: erase personal credentials and cancel
        only this session's personal-provider jobs. Shared jobs and other sessions continue."""
        if logout:
            self.browser.pop(session.id, None)
        self.sessions.clear(session.username, session.id)
        link = self.links.get(session.username)
        if link is None:
            return
        for job_id, owner_session in list(link.personal_jobs.items()):
            if owner_session == session.id:
                link.personal_jobs.pop(job_id, None)
                try:
                    await self.call(link, "cancel", timeout=60, id=job_id)
                except Exception:
                    log.warning("personal job cancellation not confirmed user=%s job=%s", session.username, job_id)

    async def disable_user(self, username):
        for session in [s for s in self.browser.values() if s.username == username]:
            self.browser.pop(session.id, None)
        self.sessions.clear(username)
        link = self.links.get(username)
        if link is not None:
            await self.cancel_all(link)

    async def cancel_all(self, link):
        try:
            records = await self.call(link, "list")
        except Exception:
            return
        for record in records:
            if record["status"] not in TERMINAL:
                try:
                    await self.call(link, "cancel", timeout=60, id=record["job_id"])
                except Exception:
                    log.warning("cancellation not confirmed user=%s job=%s", link.username, record["job_id"])

    # Dispatchers ------------------------------------------------------------
    async def call(self, link, op, *, timeout=30, **arguments):
        future = link.client.call(op, **arguments)
        try:
            result, fds = await asyncio.wait_for(asyncio.wrap_future(future), timeout)
        except TimeoutError:
            link.client.forget(future)
            raise
        if op != "open_artifact":
            for fd in fds:
                os.close(fd)
            return result
        return result, fds

    async def link(self, username, uid, *, launch=True):
        link = self.links.get(username)
        if link is not None and not link.client.closed.is_set():
            return link
        if not launch:
            raise ConnectionError("No dispatcher is connected for this user")
        lock = self.link_locks.setdefault(username, asyncio.Lock())
        async with lock:
            link = self.links.get(username)
            if link is not None and not link.client.closed.is_set():
                return link
            user = pwd.getpwnam(username)
            if user.pw_uid != uid:
                raise PermissionError("Account UID changed; sign in again")
            process, sock = await asyncio.to_thread(self.launcher, user)
            link = UserLink(username, uid, RPCClient(sock, name=username), process)
            try:
                hello = await self.call(link, "hello", timeout=90)
            except BaseException:
                link.client.close()
                raise
            if hello.get("uid") != uid or hello.get("owner") != username:
                link.client.close()
                raise PermissionError("Dispatcher identity mismatch")
            self.links[username] = link
            log.info(
                "dispatcher connected user=%s pid=%s reconciled=%s",
                username,
                hello.get("pid"),
                len(hello.get("reconcile", [])),
            )
            return link

    async def tick(self):
        if self.ticking:
            return
        self.ticking = True
        try:
            now = time.time()
            for session in [s for s in self.browser.values() if s.expires <= now]:
                self.browser.pop(session.id, None)
                asyncio.ensure_future(self.end_session(session))  # Cancellations must not block the tick.
            self.sessions.prune()
            await self.relaunch_for_leases()
            await asyncio.gather(*(self.tick_user_safely(link) for link in list(self.links.values())))
        finally:
            self.ticking = False

    async def tick_user_safely(self, link):
        try:
            await asyncio.wait_for(self.tick_user(link), USER_TICK_TIMEOUT)
        except Exception as exc:
            log.warning("scheduler error user=%s: %s", link.username, type(exc).__name__)

    async def relaunch_for_leases(self):
        """After a restart or dispatcher exit, reconnect lease owners so their jobs are reconciled."""
        owners = {lease["owner"] for lease in self.state.leases()} - set(self.links)
        now = time.monotonic()
        for owner in owners:
            if now - self.relaunch_attempts.get(owner, -1e9) < 60:
                continue
            self.relaunch_attempts[owner] = now
            try:
                user = self.accounts.login_user(owner)
            except LoginFailed:
                log.warning(
                    "lease owner %s is not a login account; an administrator must release its reservations", owner
                )
                continue
            asyncio.ensure_future(self._relaunch(user))

    async def _relaunch(self, user):
        try:
            await self.link(user.pw_name, user.pw_uid)
        except Exception as exc:
            log.warning("reconciliation launch failed user=%s: %s", user.pw_name, type(exc).__name__)

    async def tick_user(self, link):
        if link.client.closed.is_set():
            # Leases stay until the next dispatcher reconciles these jobs.
            self.links.pop(link.username, None)
            return
        records = await self.call(link, "list")
        leases = {lease["job_id"] for lease in self.state.leases() if lease["owner"] == link.username}
        for record in records:
            job_id, status = record["job_id"], record["status"]
            if status in TERMINAL:
                link.personal_jobs.pop(job_id, None)
                if job_id in leases and (status != "interrupted" or record.get("termination_confirmed")):
                    self.sessions.finish(link.username, job_id)
                    leases.discard(job_id)
        try:
            self.state.check(link.username)
            if time.monotonic() - link.checked > RECHECK_SECONDS:
                link.checked = time.monotonic()
                if not await asyncio.to_thread(self.accounts.still_valid, link.username, link.uid):
                    raise AccessDenied("System account locked, expired or changed")
        except AccessDenied:
            await self.disable_user(link.username)
            return
        open_jobs = [r for r in records if r["status"] not in TERMINAL]
        if not open_jobs and not leases and not any(s.username == link.username for s in self.browser.values()):
            self.links.pop(link.username, None)
            link.client.close()  # Idle: the dispatcher exits when its connection closes.
            return
        if link.admitting or link.creating or leases or any(r["status"] in ACTIVE for r in records):
            return
        queued = sorted((r for r in records if r["status"] == "queued"), key=lambda r: r["created_at"])
        if queued:
            link.admitting = queued[0]["job_id"]
            asyncio.ensure_future(self.admit(link, queued[0]))

    async def admit(self, link, record):
        job_id, spec = record["job_id"], record["spec"]
        try:
            session = None
            if spec["provider"] == "personal":
                session = link.personal_jobs.get(job_id)
                if session is None:
                    await self.call(
                        link,
                        "reject",
                        id=job_id,
                        message="Personal connection unavailable (signed out or service restarted); resubmit",
                    )
                    return
            try:
                evidence = await self.call(link, "preflight", timeout=120, id=job_id)
            except RemoteError as exc:
                if exc.code == "busy":
                    return  # Target lacks headroom now; stay queued.
                raise
            try:
                token, protocol = self.sessions.issue(
                    username=link.username,
                    session=session or "",
                    job_id=job_id,
                    server=spec["server"],
                    cpus=spec["cpu_threads"],
                    memory_gb=spec["memory_gb"],
                    provider=spec["provider"],
                    model=spec["model"],
                    gpu=spec["gpu"],
                    profile=self.profile,
                )
            except BlockingIOError:
                return
            except (AccessDenied, ValueError) as exc:
                await self.call(link, "reject", id=job_id, message=str(exc))
                return
            credentials = {"token": token, "gateway_url": self.gateway_url, "protocol": protocol}
            try:
                await self.call(link, "start", id=job_id, credentials=credentials, evidence=evidence)
            except RemoteError:
                self.sessions.finish(link.username, job_id)  # Not started (e.g. cancelled meanwhile).
        except Exception as exc:
            log.warning("admission failed user=%s job=%s: %s", link.username, job_id, type(exc).__name__)
        finally:
            link.admitting = None


# Handlers -------------------------------------------------------------------


class Base(web.RequestHandler):
    auth = "session"

    @property
    def service(self):
        return self.application.settings["service"]

    def set_default_headers(self):
        self.set_header("Cache-Control", "no-store")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Referrer-Policy", "same-origin")
        self.set_header(
            "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )

    def check_xsrf_cookie(self):
        # Ingress first (also enforced per connection), then CSRF for browser routes.
        if not allowed_client(self.request.remote_ip, self.service.cidrs):
            raise web.HTTPError(403, "Client network is not allowed")
        if self.auth != "token":
            super().check_xsrf_cookie()

    def prepare(self):
        if not allowed_client(self.request.remote_ip, self.service.cidrs):
            raise web.HTTPError(403, "Client network is not allowed")
        self.web_session = None
        if self.auth == "session":
            self.web_session = self.service.session(self.get_cookie(COOKIE))
            if self.web_session is None:
                if self.request.method == "GET" and not self.request.path.startswith(("/api/", "/download/")):
                    self.redirect("/login")
                    return
                raise web.HTTPError(401, "Sign in required")
            try:
                self.admin = self.service.state.check(self.web_session.username)
            except AccessDenied as exc:
                raise web.HTTPError(403, str(exc)) from exc

    @property
    def username(self):
        return self.web_session.username

    def body(self):
        try:
            value = json.loads(self.request.body or b"{}")
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, TypeError):
            raise web.HTTPError(400, "A JSON object is required") from None

    def write_error(self, status_code, **kwargs):
        error = kwargs.get("exc_info", (None, None, None))[1]
        # Our HTTPError messages are written for users and never contain submitted values.
        message = (error.log_message or error.reason) if isinstance(error, web.HTTPError) else None
        message = message or self._reason
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps({"error": message, "status": status_code}))

    def log_exception(self, typ, value, tb):
        if not isinstance(value, web.HTTPError):
            log.error("request failed path=%s error=%s", self.request.path, typ.__name__)


class NotFound(Base):
    auth = "none"

    def prepare(self):
        super().prepare()
        raise web.HTTPError(404)


class Health(Base):
    auth = "none"

    def get(self):
        self.write({"ok": True, "protocol_version": 1})


class Page(Base):
    def get(self):
        _ = self.xsrf_token
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.write((STATIC / "index.html").read_bytes())


class LoginPage(Base):
    auth = "none"

    def get(self):
        if self.service.session(self.get_cookie(COOKIE)):
            self.redirect("/")
            return
        _ = self.xsrf_token
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.write((STATIC / "login.html").read_bytes())


class Static(Base):
    auth = "none"
    TYPES = {"app.js": "application/javascript", "login.js": "application/javascript", "style.css": "text/css"}

    def get(self, name):
        if name not in self.TYPES:
            raise web.HTTPError(404)
        self.set_header("Content-Type", self.TYPES[name] + "; charset=utf-8")
        self.write((STATIC / name).read_bytes())


class Login(Base):
    auth = "none"
    slots = asyncio.Semaphore(4)

    async def post(self):
        body = self.body()
        service = self.service
        try:
            async with self.slots:
                user = await asyncio.to_thread(
                    service.accounts.authenticate, body.get("username"), body.get("password"), self.request.remote_ip
                )
        except LoginFailed as exc:
            raise web.HTTPError(401 if not str(exc) else 429, str(exc) or "Incorrect username or password") from None
        try:
            service.state.check(user.pw_name)
        except AccessDenied as exc:
            raise web.HTTPError(403, str(exc)) from None
        cookie, session = service.create_session(user)
        self.set_cookie(
            COOKIE, cookie, httponly=True, samesite="Strict", path="/", expires=time.time() + service.session_ttl
        )
        log.info("login user=%s ip=%s", user.pw_name, self.request.remote_ip)
        try:
            await service.link(user.pw_name, user.pw_uid)
        except Exception as exc:
            log.warning("dispatcher launch failed user=%s: %s", user.pw_name, type(exc).__name__)
        self.write({"ok": True, "username": user.pw_name})


class API(Base):
    async def dispatcher(self):
        try:
            return await self.service.link(self.username, self.web_session.uid)
        except Exception:
            raise web.HTTPError(503, "Your job dispatcher is unavailable; sign out and in again") from None

    async def relay(self, op, **arguments):
        link = await self.dispatcher()
        try:
            return await self.service.call(link, op, timeout=60, **arguments)
        except RemoteError as exc:
            raise web.HTTPError(ERROR_STATUS.get(exc.code, 502), str(exc)) from None
        except (TimeoutError, ConnectionError):
            raise web.HTTPError(503, "Job dispatcher did not respond") from None

    async def get(self, action):
        state, service = self.service.state, self.service
        try:
            if action == "me":
                self.write({"username": self.username, "admin": self.admin})
            elif action == "models":
                self.write({"models": state.allowed_models(self.username)})
            elif action == "servers":
                self.write({"servers": service.profile.get("servers", {})})
            elif action == "catalog":
                found = service.catalog.search(self.get_query_argument("q", "")) if service.catalog else []
                self.write({"capabilities": [c.to_dict() for c in found[:200]], "total": len(found)})
            elif action == "jobs":
                self.write({"jobs": await self.relay("list")})
            elif action.startswith("jobs/"):
                parts = action.split("/")
                if len(parts) == 2:
                    self.write(await self.relay("get", id=parts[1]))
                elif len(parts) == 3 and parts[2] == "events":
                    after = self.get_query_argument("after", "0")
                    self.write(
                        {"events": await self.relay("events", id=parts[1], after=int(after) if after.isdigit() else 0)}
                    )
                elif len(parts) == 3 and parts[2] == "artifacts":
                    self.write({"artifacts": await self.relay("artifacts", id=parts[1])})
                else:
                    raise web.HTTPError(404)
            elif action == "admin/users":
                self.write({"users": state.users(self.username)})
            elif action == "admin/providers":
                self.write({"providers": state.providers(self.username)})
            elif action == "admin/grants":
                self.write({"grants": state.grants(self.username)})
            elif action == "admin/leases":
                state.check(self.username, admin=True)
                self.write({"leases": state.leases()})
            else:
                raise web.HTTPError(404)
        except AccessDenied as exc:
            raise web.HTTPError(403, str(exc)) from None

    async def post(self, action):
        body = self.body()
        state, service, transport = self.service.state, self.service, self.service.transport
        try:
            if action == "logout":
                await service.end_session(self.web_session)
                self.clear_cookie(COOKIE, path="/")
                self.write({"ok": True})
            elif action == "jobs":
                fields = {
                    k: body[k]
                    for k in (
                        "server",
                        "prompt",
                        "model",
                        "provider",
                        "cpu_threads",
                        "memory_gb",
                        "gpu",
                        "input_paths",
                        "parent_job",
                    )
                    if k in body and body[k] is not None
                }
                if fields.get("provider") == "personal":
                    self.service.sessions.get_personal(self.username, self.web_session.id)  # Fails if not configured.
                elif fields.get("provider"):
                    state.authorize_model(self.username, fields["provider"], fields.get("model"))
                link = await self.dispatcher()
                link.creating += 1
                try:
                    record = await self.relay("create", **fields)
                    if fields.get("provider") == "personal":
                        link.personal_jobs[record["job_id"]] = self.web_session.id
                finally:
                    link.creating -= 1
                self.write(record)
            elif action.startswith("jobs/") and action.endswith("/cancel") and action.count("/") == 2:
                self.write(await self.relay("cancel", id=action.split("/")[1]))
            elif action == "personal/clear":
                await service.end_session(self.web_session, logout=False)
                self.write({"ok": True})
            elif action in {"personal", "personal/discover"}:
                settings = {
                    "url": await asyncio.to_thread(transport.normalize, body["url"]),
                    "api_key": str(body.get("api_key", "")).strip(),
                    "protocol": body.get("protocol", "chat_completions"),
                }
                if not valid_key(settings["api_key"]):
                    raise ValueError("The API key must be printable ASCII without spaces")
                if settings["protocol"] not in {"chat_completions", "responses"}:
                    raise ValueError("Invalid protocol")
                if "api_key" not in body:  # Keep the session's existing key for the same endpoint.
                    try:
                        previous = service.sessions.get_personal(self.username, self.web_session.id)
                        if previous["url"] == settings["url"]:
                            settings["api_key"] = previous["api_key"]
                    except AccessDenied:
                        pass
                if action == "personal/discover":
                    try:
                        models = await transport.discover(settings)
                    except Exception:
                        raise web.HTTPError(502, "Discovery failed; a manual model ID can still be used") from None
                    service.sessions.set_personal(self.username, self.web_session.id, settings)
                    self.write({"models": models})
                else:
                    service.sessions.set_personal(self.username, self.web_session.id, settings)
                    self.write({"ok": True})
            elif action == "admin/users":
                if not isinstance(body.get("enabled"), bool):
                    raise ValueError("enabled must be a boolean")
                state.access(self.username, body["username"], body["enabled"])
                if not body["enabled"]:
                    await service.disable_user(body["username"])
                self.write({"ok": True})
            elif action == "admin/providers":
                state.check(self.username, admin=True)
                body["url"] = await asyncio.to_thread(transport.normalize, body["url"])
                permitted = {"id", "name", "url", "protocol", "enabled", "api_key", "models"}
                self.write(state.save_provider(self.username, **{k: v for k, v in body.items() if k in permitted}))
                service.sessions.prune()
            elif action == "admin/refresh":
                state.check(self.username, admin=True)
                provider = state.provider(body["provider"])
                if not provider:
                    raise ValueError("Unknown provider")
                try:
                    models = await transport.discover({**provider, "api_key": state.key(provider)})
                except Exception:
                    state.set_catalog(self.username, provider["id"], error=True)
                    raise web.HTTPError(502, "Discovery failed; previous models retained as stale") from None
                self.write(state.set_catalog(self.username, provider["id"], models))
            elif action == "admin/grants":
                if not isinstance(body.get("enabled"), bool):
                    raise ValueError("enabled must be a boolean")
                state.grant(self.username, body["username"], body["provider"], body["model"], body["enabled"])
                service.sessions.prune()
                self.write({"ok": True})
            elif action == "admin/leases/release":
                state.release_lease(self.username, body["job_id"])
                self.write({"ok": True})
            else:
                raise web.HTTPError(404)
        except AccessDenied as exc:
            raise web.HTTPError(403, str(exc)) from None
        except (ValueError, KeyError, TypeError) as exc:
            # Never echo submitted objects: they may contain API keys.
            message = str(exc) if type(exc) is ValueError and len(str(exc)) < 200 else "Invalid request"
            raise web.HTTPError(400, message) from None


class Download(API):
    SUPPORTED_METHODS = ("GET",)

    async def get(self, job_id, relative):
        result, fds = await self._open(job_id, relative)
        try:
            # The dispatcher runs as the user and is untrusted: accept one regular file only.
            if len(fds) != 1 or not stat.S_ISREG(os.fstat(fds[0]).st_mode) or not isinstance(result.get("name"), str):
                raise web.HTTPError(404, "Artifact not found")
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise
        self.set_header("Content-Type", "application/octet-stream")
        self.set_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(result["name"][:255], safe=""))
        with os.fdopen(fds[0], "rb") as stream:
            while chunk := await asyncio.to_thread(stream.read, 256 * 1024):
                self.write(chunk)
                await self.flush()

    async def _open(self, job_id, relative):
        link = await self.dispatcher()
        try:
            return await self.service.call(link, "open_artifact", timeout=60, id=job_id, path=relative)
        except (TimeoutError, RemoteError, ConnectionError):
            raise web.HTTPError(404, "Artifact not found") from None


class Gateway(Base):
    auth = "token"

    def on_connection_close(self):
        future = getattr(self, "upstream", None)
        if future is not None:
            future.cancel()

    async def post(self, path):
        start, task = time.monotonic(), None
        service = self.service
        try:
            auth = self.request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or len(auth) > 512:
                raise AccessDenied("Task authentication required")
            task = service.sessions.lookup(auth[7:])
            expected = "responses" if task.protocol == "responses" else "chat/completions"
            if path != expected:
                raise AccessDenied("Task protocol does not match this endpoint")
            body = self.body()
            if body.get("model") != task.model:
                raise AccessDenied("Task model cannot be changed")
            if any(key in body for key in ("previous_response_id", "conversation", "background")):
                raise web.HTTPError(400, "Cross-request provider state is disabled; send task context explicitly")
            if path == "responses":
                body["store"] = False
            if task.personal is not None:
                provider = task.personal
            else:
                p = service.state.authorize_model(task.owner, task.provider, task.model)
                provider = {**p, "api_key": service.state.key(p)}
            stream = bool(body.get("stream", False))
            if stream:
                self.set_header("Content-Type", "text/event-stream")
            self.upstream = asyncio.ensure_future(
                service.transport.fetch(provider, path, body, stream=self.stream_chunk if stream else None)
            )
            response = await self.upstream
            if not 200 <= response.code < 300:
                if not self._headers_written:
                    raise web.HTTPError(502, f"Provider request failed (HTTP {response.code})")
            elif not stream:
                self.set_header("Content-Type", "application/json")
                self.write(response.body)
            self.finish()
        except AccessDenied as exc:
            raise web.HTTPError(403, str(exc)) from None
        except (asyncio.CancelledError, StreamClosedError):
            return
        except web.HTTPError:
            raise
        except Exception:
            # Never relay transport error text: it can quote request headers (the API key).
            raise web.HTTPError(502, "Provider unavailable") from None
        finally:
            self.audit = (task.owner if task else "unauthorized", task.job_id if task else "none", path, start)

    def on_finish(self):
        owner, job, path, start = getattr(self, "audit", ("unauthorized", "none", "?", time.monotonic()))
        log.info(
            "gateway owner=%s job=%s protocol=%s duration=%.3f status=%s",
            owner,
            job,
            path,
            time.monotonic() - start,
            self.get_status(),
        )

    def stream_chunk(self, chunk):
        if self.request.connection.stream.closed():
            raise StreamClosedError()
        self.write(chunk)
        self.flush()


def create_app(service):
    return web.Application(
        [
            (r"/", Page),
            (r"/login", LoginPage),
            (r"/health", Health),
            (r"/static/([a-z.]+)", Static),
            (r"/api/login", Login),
            (r"/api/(.+)", API),
            (r"/download/([0-9a-f]{32})/(.+)", Download),
            (r"/gateway/v1/(chat/completions|responses)", Gateway),
        ],
        service=service,
        xsrf_cookies=True,
        xsrf_cookie_kwargs={"samesite": "Strict", "path": "/"},
        default_handler_class=NotFound,
        debug=False,
    )


class IngressHTTPServer(HTTPServer):
    """Drop connections from outside the agreed CIDRs before reading any request bytes."""

    def initialize(self, *args, cidrs=PRIVATE_CIDRS, **kwargs):
        self.cidrs = tuple(cidrs)
        super().initialize(*args, **kwargs)

    def handle_stream(self, stream, address):
        if not allowed_client(address[0], self.cidrs):
            stream.close()
            return
        super().handle_stream(stream, address)


DEFAULTS = {
    "bind": "0.0.0.0",
    "port": 8765,
    "state_dir": "/var/lib/biomni",
    "key_file": "/etc/biomni/master.key",
    "pam_service": "biomni",
    "session_hours": 24,
    "min_uid": 1000,
    "allowed_cidrs": list(PRIVATE_CIDRS),
}


def load_config(path):
    config = {**DEFAULTS, **json.loads(Path(path).read_text())}
    for key in ("profile", "local_server", "gateway_url"):
        if not config.get(key):
            raise ValueError(f"Configuration requires {key}")
    return config


def build_service(config):
    from biomni.localenv import Catalog, RuntimeProfile

    profile = RuntimeProfile.from_file(config["profile"])
    key_file = Path(config["key_file"])
    if not key_file.is_file() or key_file.stat().st_mode & 0o077:
        raise SystemExit(f"Create the master key first (mode 0600): python -m biomni.server.app init-key {key_file}")
    state_dir = Path(config["state_dir"])
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = State(state_dir / "policy.sqlite3", key_file.read_bytes().strip())
    python = config.get("dispatcher_python") or profile.python()
    repository = config.get("repository") or profile.repository or str(Path(__file__).resolve().parents[2])
    command = [
        python,
        "-s",
        "-P",
        "-m",
        "biomni.execution.dispatcher",
        "--profile",
        str(Path(config["profile"]).resolve()),
        "--local-server",
        config["local_server"],
    ]
    environment = {"PYTHONPATH": repository, "PYTHONNOUSERSITE": "1"}
    authenticate, account_valid = pam_authenticator(config["pam_service"])
    catalog = Catalog.from_file(profile.catalog_file) if profile.catalog_file else Catalog(profile.capabilities)
    transport = ProviderTransport(forbidden_ports=(int(config["port"]),))
    return Service(
        state=state,
        profile=profile.to_dict(),
        catalog=catalog,
        transport=transport,
        accounts=Accounts(authenticate=authenticate, account_valid=account_valid, min_uid=int(config["min_uid"])),
        gateway_url=config["gateway_url"],
        session_ttl=float(config["session_hours"]) * 3600,
        cidrs=config["allowed_cidrs"],
        launcher=lambda user: launch_dispatcher(user, command, extra_env=environment),
    )


def init_key(path):
    from cryptography.fernet import Fernet

    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(Fernet.generate_key())
    print(f"Created {path}; back it up separately from {DEFAULTS['state_dir']}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--config", required=True)
    key = commands.add_parser("init-key")
    key.add_argument("path")
    args = parser.parse_args(argv)
    if args.command == "init-key":
        init_key(args.path)
        return 0
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load_config(args.config)
    if os.getuid() != 0:
        log.warning("Not running as root: only the service account itself can sign in and run jobs")
    os.umask(0o077)
    service = build_service(config)
    server = IngressHTTPServer(
        create_app(service), xheaders=False, max_body_size=8 * 1024 * 1024, cidrs=config["allowed_cidrs"]
    )
    try:
        server.listen(int(config["port"]), address=config["bind"], family=__import__("socket").AF_INET)
    except OSError as exc:
        raise SystemExit(f"Cannot listen on {config['bind']}:{config['port']}: {exc.strerror}") from None
    log.info("listening on http://%s:%s", config["bind"], config["port"])
    PeriodicCallback(service.tick, 2000).start()
    IOLoop.current().start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
