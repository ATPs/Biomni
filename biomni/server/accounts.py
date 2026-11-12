"""System-account login (PAM) and launching each user's dispatcher as that Unix user.

Runs inside the root web service. Passwords are passed to PAM only and are never stored
or logged. Dispatchers start with supplementary groups, GID and UID set in C by
``subprocess`` before exec, so no analysis code runs with root privileges.
"""

import os
import pwd
import socket
import subprocess
import threading
import time

NOLOGIN_SHELLS = {
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/sbin/shutdown",
    "/sbin/halt",
    "/bin/sync",
}


class LoginFailed(Exception):
    pass


def pam_authenticator(service="biomni"):
    """Return ``(authenticate, account_valid)`` backed by the pamela PAM wrapper."""
    import pamela

    def authenticate(username, password):
        try:
            # check=True (pamela default) also runs PAM account management (expiry/lock).
            pamela.authenticate(username, password, service=service, resetcred=0)
            return True
        except pamela.PAMError:
            return False

    def account_valid(username):
        try:
            pamela.check_account(username, service=service)
            return True
        except pamela.PAMError:
            return False

    return authenticate, account_valid


class Accounts:
    def __init__(self, *, authenticate, account_valid, min_uid=1000, max_failures=5, window=300):
        self.authenticate_password, self.account_valid = authenticate, account_valid
        self.min_uid, self.max_failures, self.window = min_uid, max_failures, window
        self.failures = {}
        self.lock = threading.Lock()

    def login_user(self, username):
        """Resolve a canonical login account; reject root, system and nologin identities."""
        if not isinstance(username, str) or not 0 < len(username) <= 64 or "\x00" in username:
            raise LoginFailed()
        try:
            user = pwd.getpwnam(username)
        except KeyError:
            raise LoginFailed() from None
        if user.pw_uid == 0 or user.pw_uid < self.min_uid or (user.pw_shell or "").strip() in NOLOGIN_SHELLS:
            raise LoginFailed()
        return user

    def throttled(self, key):
        now = time.monotonic()
        with self.lock:
            recent = [t for t in self.failures.get(key, ()) if now - t < self.window]
            self.failures[key] = recent
            return len(recent) >= self.max_failures

    def fail(self, *keys):
        with self.lock:
            for key in keys:
                self.failures.setdefault(key, []).append(time.monotonic())

    def authenticate(self, username, password, client_ip):
        """Blocking; call from a worker thread. Returns the canonical pwd entry."""
        keys = ("user:" + str(username)[:64], "ip:" + client_ip)
        if any(self.throttled(k) for k in keys):
            raise LoginFailed("Too many failed attempts; wait a few minutes")
        try:
            if not isinstance(password, str) or not 0 < len(password) <= 4096:
                raise LoginFailed()
            user = self.login_user(username)
            if not self.authenticate_password(user.pw_name, password):
                raise LoginFailed()
            return user
        except LoginFailed:
            self.fail(*keys)
            time.sleep(1)
            raise

    def still_valid(self, username, uid):
        try:
            user = self.login_user(username)
        except LoginFailed:
            return False
        return user.pw_uid == uid and self.account_valid(username)


def launch_dispatcher(user, command, *, extra_env=None):
    """Start the fixed dispatcher as ``user``; return ``(process, connected_socket)``."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        env = {
            "HOME": user.pw_dir,
            "USER": user.pw_name,
            "LOGNAME": user.pw_name,
            "SHELL": user.pw_shell,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            **(extra_env or {}),
            "BIOMNI_DISPATCHER_FD": str(child.fileno()),
        }
        if os.getuid() == 0:
            options = {
                "user": user.pw_uid,
                "group": user.pw_gid,
                "extra_groups": os.getgrouplist(user.pw_name, user.pw_gid),
            }
        elif os.getuid() == user.pw_uid:
            options = {}  # Development: an unprivileged service may launch only its own account.
        else:
            raise PermissionError("Only a root service can launch another user's dispatcher")
        # cwd "/" because chdir happens before the UID change (root-squashed NFS homes); the
        # dispatcher changes to its own state directory after it starts.
        process = subprocess.Popen(
            list(command),
            env=env,
            cwd="/",
            pass_fds=(child.fileno(),),
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            umask=0o077,
            **options,
        )
    except BaseException:
        parent.close()
        raise
    finally:
        child.close()
    return process, parent
