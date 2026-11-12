"""Protected policy/provider state and session-only task credentials."""

import hashlib
import json
import math
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from .security import AccessDenied, is_admin, system_user


class State:
    def __init__(self, path, encryption_key, *, admin_check=is_admin, user_check=system_user):
        from cryptography.fernet import Fernet

        self.cipher = Fernet(encryption_key)
        self.admin_check, self.user_check = admin_check, user_check
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
            CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS providers (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL,
                protocol TEXT NOT NULL, enabled INTEGER NOT NULL, secret BLOB NOT NULL,
                models TEXT NOT NULL, discovery TEXT NOT NULL, updated REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS grants (username TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
                PRIMARY KEY(username, provider, model), FOREIGN KEY(provider) REFERENCES providers(id) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS audit (at REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS leases (job_id TEXT PRIMARY KEY, owner TEXT NOT NULL, server TEXT NOT NULL,
                cpus INTEGER NOT NULL, memory_gb REAL NOT NULL, created REAL NOT NULL);
        """)
        if self.db.execute("SELECT version FROM schema_version").fetchone()[0] != 1:
            raise ValueError("Unsupported policy database schema")
        self.db.commit()
        if str(path) != ":memory:":
            os.chmod(path, 0o600)

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        with self.lock, self.db:
            yield self.db

    def check(self, username, *, admin=False):
        self.user_check(username)
        wheel = self.admin_check(username)
        with self.lock:
            row = self.db.execute("SELECT enabled FROM users WHERE name=?", (username,)).fetchone()
        if row is not None and not row[0]:
            raise AccessDenied("Application access disabled")
        if not wheel and (admin or row is None):
            raise AccessDenied("Administrator approval required")
        return wheel

    def access(self, actor, username, enabled):
        self.check(actor, admin=True)
        self.user_check(username)
        if actor == username and not enabled:
            raise ValueError("Administrators cannot disable themselves")
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO users VALUES (?,?)", (username, bool(enabled)))
            db.execute("INSERT INTO audit VALUES (?,?,?,?)", (time.time(), actor, "access", username))

    def users(self, actor):
        self.check(actor, admin=True)
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT name,enabled FROM users ORDER BY name")]

    def save_provider(
        self, actor, *, id, name, url, protocol="chat_completions", enabled=True, api_key=None, models=None
    ):
        self.check(actor, admin=True)
        if protocol not in {"chat_completions", "responses"} or not id or len(id) > 100:
            raise ValueError("Invalid provider ID or protocol")
        previous = self.provider(id)
        if api_key is None and previous is None:
            raise ValueError("Provide an API key; use an empty value for a keyless provider")
        if api_key is not None:
            api_key = api_key.strip() if isinstance(api_key, str) else api_key
            from .providers import valid_key

            if not valid_key(api_key):
                raise ValueError("The API key must be printable ASCII without spaces")
        secret = self.cipher.encrypt(api_key.encode()) if api_key is not None else previous["secret"]
        catalog = previous["models"] if previous and models is None else sorted(set(models or []))
        if any(not isinstance(m, str) or not m or len(m) > 512 for m in catalog):
            raise ValueError("Invalid model ID")
        with self.transaction() as db:
            db.execute(
                """INSERT INTO providers VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,url=excluded.url,protocol=excluded.protocol,enabled=excluded.enabled,
                secret=excluded.secret,models=excluded.models,discovery=excluded.discovery,updated=excluded.updated""",
                (id, name, url, protocol, bool(enabled), secret, json.dumps(catalog), "manual", time.time()),
            )
            db.execute("INSERT INTO audit VALUES (?,?,?,?)", (time.time(), actor, "provider_save", id))
        return self.provider(id, public=True)

    def provider(self, id, *, public=False):
        with self.lock:
            row = self.db.execute("SELECT * FROM providers WHERE id=?", (id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["models"] = json.loads(result["models"])
        if public:
            result.pop("secret")
        return result

    def providers(self, actor):
        self.check(actor, admin=True)
        with self.lock:
            ids = [row[0] for row in self.db.execute("SELECT id FROM providers ORDER BY id")]
        return [self.provider(id, public=True) for id in ids]

    def set_catalog(self, actor, id, models=None, *, error=False):
        self.check(actor, admin=True)
        if self.provider(id) is None:
            raise ValueError("Unknown provider")
        with self.transaction() as db:
            if error:
                db.execute("UPDATE providers SET discovery='stale' WHERE id=?", (id,))
            else:
                db.execute(
                    "UPDATE providers SET models=?,discovery='fresh',updated=? WHERE id=?",
                    (json.dumps(sorted(set(models))), time.time(), id),
                )
        return self.provider(id, public=True)

    def grant(self, actor, username, provider, model, enabled):
        self.check(actor, admin=True)
        self.user_check(username)
        p = self.provider(provider)
        if p is None or model not in p["models"]:
            raise ValueError("Unknown provider/model pair")
        with self.transaction() as db:
            if enabled:
                db.execute("INSERT OR IGNORE INTO grants VALUES (?,?,?)", (username, provider, model))
            else:
                db.execute(
                    "DELETE FROM grants WHERE username=? AND provider=? AND model=?", (username, provider, model)
                )
            db.execute("INSERT INTO audit VALUES (?,?,?,?)", (time.time(), actor, "model_grant", username))

    def grants(self, actor):
        self.check(actor, admin=True)
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT * FROM grants ORDER BY username,provider,model")]

    def authorize_model(self, username, provider, model):
        self.check(username)
        p = self.provider(provider)
        with self.lock:
            granted = self.db.execute(
                "SELECT 1 FROM grants WHERE username=? AND provider=? AND model=?", (username, provider, model)
            ).fetchone()
        if not p or not p["enabled"] or model not in p["models"] or not granted:
            raise AccessDenied("This shared provider/model is not granted")
        return p

    def allowed_models(self, username):
        self.check(username)
        with self.lock:
            rows = list(self.db.execute("SELECT provider,model FROM grants WHERE username=?", (username,)))
        result = []
        for provider, model in rows:
            try:
                p = self.authorize_model(username, provider, model)
                result.append({"provider": provider, "name": p["name"], "model": model, "protocol": p["protocol"]})
            except AccessDenied:
                pass
        return result

    def key(self, provider):
        return self.cipher.decrypt(provider["secret"]).decode()

    def leases(self):
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT * FROM leases ORDER BY created")]

    def release_lease(self, actor, job_id):
        """Administrator release after the worker has been inspected and confirmed stopped."""
        self.check(actor, admin=True)
        with self.transaction() as db:
            if db.execute("DELETE FROM leases WHERE job_id=?", (job_id,)).rowcount != 1:
                raise ValueError("Unknown reservation")
            db.execute("INSERT INTO audit VALUES (?,?,?,?)", (time.time(), actor, "lease_release", job_id))


@dataclass(repr=False)
class TaskCredential:
    owner: str
    job_id: str
    server: str
    cpus: int
    memory_gb: float
    provider: str
    model: str
    protocol: str
    expires: float
    personal: dict | None = field(default=None, repr=False)
    session: str = ""  # Digest of the browser session that supplied a personal connection.


class Sessions:
    """All raw personal secrets and gateway credentials die with the service."""

    def __init__(self, state, *, ttl=86400):
        self.state, self.ttl = state, ttl
        self.personal, self.tokens = {}, {}
        self.lock = threading.RLock()

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def set_personal(self, username, session, settings):
        self.state.check(username)
        with self.lock:
            self.personal[(username, self.digest(session))] = (time.time() + self.ttl, dict(settings))

    def get_personal(self, username, session):
        with self.lock:
            record = self.personal.get((username, self.digest(session)))
        if not record or record[0] <= time.time():
            raise AccessDenied("Personal connection expired; enter it again")
        return record[1]

    def clear(self, username, session=None):
        """Erase personal settings and revoke tokens: one session's personal tokens, or all of a user's."""
        digest = None if session is None else self.digest(session)
        revoked = []
        with self.lock:
            for key in list(self.personal):
                if key[0] == username and (digest is None or key[1] == digest):
                    del self.personal[key]
            for token, task in list(self.tokens.items()):
                if task.owner == username and (
                    digest is None or (task.personal is not None and task.session == digest)
                ):
                    revoked.append(task.job_id)
                    del self.tokens[token]
        return revoked

    def issue(self, *, username, session, job_id, server, cpus, memory_gb, provider, model, profile, gpu=False):
        with self.lock:
            self.prune()
            self.state.check(username)
            active = self.state.leases()
            if any(task["owner"] == username for task in active):
                raise BlockingIOError("User already has an active analysis")
            node = profile["servers"].get(server)
            if not node:
                raise ValueError("Unknown server")
            if (
                type(cpus) is not int
                or cpus < 1
                or isinstance(memory_gb, bool)
                or not math.isfinite(memory_gb)
                or memory_gb <= 0
            ):
                raise ValueError("Positive CPU and memory requests are required")
            on_host = [task for task in active if task["server"] == server]
            if len(on_host) >= node.get("max_jobs", 1):
                raise BlockingIOError("Server concurrency limit reached")
            if cpus + sum(task["cpus"] for task in on_host) > int(node["cpu_threads"] * 0.85):
                raise BlockingIOError("Insufficient configured CPU capacity")
            if memory_gb + sum(task["memory_gb"] for task in on_host) > node["memory_gb"] * 0.90:
                raise BlockingIOError("Insufficient configured memory capacity")
            if gpu and not node.get("gpu", False):
                raise ValueError("Selected server has no validated GPU profile")
            personal = None
            if provider == "personal":
                personal = dict(self.get_personal(username, session))
                protocol = personal["protocol"]
            else:
                protocol = self.state.authorize_model(username, provider, model)["protocol"]
            token = secrets.token_urlsafe(48)
            with self.state.transaction() as db:
                db.execute(
                    "INSERT INTO leases VALUES (?,?,?,?,?,?)", (job_id, username, server, cpus, memory_gb, time.time())
                )
            self.tokens[self.digest(token)] = TaskCredential(
                username,
                job_id,
                server,
                cpus,
                memory_gb,
                provider,
                model,
                protocol,
                time.time() + self.ttl,
                personal,
                self.digest(session) if personal is not None else "",
            )
            return token, protocol

    def lookup(self, token):
        with self.lock:
            task = self.tokens.get(self.digest(token))
        if not task or task.expires <= time.time():
            raise AccessDenied("Task credential expired or revoked")
        self.state.check(task.owner)
        if task.personal is None:
            self.state.authorize_model(task.owner, task.provider, task.model)
        return task

    def finish(self, username, job_id):
        with self.lock:
            with self.state.transaction() as db:
                db.execute("DELETE FROM leases WHERE owner=? AND job_id=?", (username, job_id))
            for key, task in list(self.tokens.items()):
                if task.owner == username and task.job_id == job_id:
                    del self.tokens[key]

    def prune(self):
        now = time.time()
        with self.lock:
            for key, task in list(self.tokens.items()):
                try:
                    self.lookup_key(task)
                    valid = task.expires > now
                except AccessDenied:
                    valid = False
                if not valid:
                    del self.tokens[key]
            for key, record in list(self.personal.items()):
                if record[0] <= now:
                    del self.personal[key]

    def lookup_key(self, task):
        self.state.check(task.owner)
        if task.personal is None:
            self.state.authorize_model(task.owner, task.provider, task.model)
