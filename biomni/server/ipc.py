"""Bounded local IPC between the web service and user-owned dispatchers.

Frames are a 4-byte big-endian length followed by one JSON object. A frame may carry
file descriptors (for example an artifact opened by its owner); the sender attaches them
to the frame's first bytes and declares their count in ``_fds``. Received descriptors are
close-on-exec and queued in arrival order, so each frame takes exactly its own.
"""

import itertools
import json
import os
import queue
import socket
import struct
import threading
from collections import deque
from concurrent.futures import Future

PROTOCOL_VERSION = 1
MAX_FRAME = 16 * 1024 * 1024
MAX_FDS = 4
_HEADER = struct.Struct("!I")


class ProtocolError(ConnectionError):
    pass


class RemoteError(Exception):
    """An error reported by the peer; ``code`` is a short machine-readable category."""

    def __init__(self, message, code="failed"):
        super().__init__(message)
        self.code = code


class Channel:
    def __init__(self, sock, *, max_frame=MAX_FRAME):
        self.sock = sock
        self.max_frame = max_frame
        self.buffer = bytearray()
        self.fds = deque()
        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()

    def send(self, message, fds=()):
        fds = list(fds)
        if len(fds) > MAX_FDS:
            raise ValueError("Too many descriptors in one frame")
        payload = json.dumps({**message, "_fds": len(fds)}, allow_nan=False, separators=(",", ":")).encode()
        if len(payload) > self.max_frame:
            raise ValueError("IPC frame exceeds the configured limit")
        data = _HEADER.pack(len(payload)) + payload
        with self.send_lock:
            if fds:
                ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack(f"{len(fds)}i", *fds))]
                sent = self.sock.sendmsg([data], ancillary)
                data = data[sent:]
            if data:
                self.sock.sendall(data)

    def _fill(self):
        space = socket.CMSG_SPACE(MAX_FDS * struct.calcsize("i"))
        data, ancillary, flags, _ = self.sock.recvmsg(65536, space, socket.MSG_CMSG_CLOEXEC)
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                count = len(value) // struct.calcsize("i")
                self.fds.extend(struct.unpack(f"{count}i", value[: count * struct.calcsize("i")]))
        if flags & socket.MSG_CTRUNC:
            self.close_pending_fds()
            raise ProtocolError("Descriptor message truncated")
        if not data:
            raise EOFError("Peer closed the channel")
        self.buffer.extend(data)

    def recv(self):
        """Return ``(message, fds)``; the caller owns and must close ``fds``."""
        with self.recv_lock:
            while len(self.buffer) < _HEADER.size:
                self._fill()
            (size,) = _HEADER.unpack_from(self.buffer)
            if size > self.max_frame:
                raise ProtocolError("IPC frame exceeds the configured limit")
            while len(self.buffer) < _HEADER.size + size:
                self._fill()
            payload = bytes(self.buffer[_HEADER.size : _HEADER.size + size])
            del self.buffer[: _HEADER.size + size]
            try:
                message = json.loads(payload)
                count = message.pop("_fds")
                if not isinstance(message, dict) or type(count) is not int or not 0 <= count <= MAX_FDS:
                    raise ValueError()
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise ProtocolError("Malformed IPC frame") from exc
            if count > len(self.fds):
                raise ProtocolError("Frame declared descriptors that did not arrive")
            taken = [self.fds.popleft() for _ in range(count)]
            if not self.buffer or len(self.fds) > MAX_FDS:
                self.close_pending_fds()  # Undeclared descriptors are never kept.
            return message, taken

    def close_pending_fds(self):
        while self.fds:
            try:
                os.close(self.fds.popleft())
            except OSError:
                pass

    def close(self):
        self.close_pending_fds()
        try:
            self.sock.close()
        except OSError:
            pass


class RPCClient:
    """Multiplexed request/response client.

    A reader thread resolves futures by ID and a writer thread drains a bounded queue, so a
    stalled peer can never block the caller (the web service's event loop).
    """

    def __init__(self, sock, *, name="dispatcher", max_queued=64):
        self.channel = Channel(sock)
        self.pending = {}
        self.ids = itertools.count(1)
        self.lock = threading.Lock()
        self.closed = threading.Event()
        self.outgoing = queue.Queue(maxsize=max_queued)
        self.reader = threading.Thread(target=self._read, daemon=True, name="biomni-ipc-" + name)
        self.writer = threading.Thread(target=self._write, daemon=True, name="biomni-ipc-w-" + name)
        self.reader.start()
        self.writer.start()

    def _write(self):
        while not self.closed.is_set():
            try:
                item = self.outgoing.get(timeout=1)
            except queue.Empty:
                continue
            request_id, message = item
            try:
                self.channel.send(message)
            except (OSError, ValueError) as exc:
                with self.lock:
                    future = self.pending.pop(request_id, None)
                if future is not None and not future.done():
                    future.set_exception(
                        exc if isinstance(exc, ValueError) else ConnectionError("Dispatcher connection failed")
                    )
                if isinstance(exc, OSError):
                    self.close()
                    return

    def forget(self, future):
        """Drop a request whose caller gave up (timeout), so pending entries cannot accumulate."""
        with self.lock:
            self.pending.pop(getattr(future, "request_id", None), None)

    def _read(self):
        try:
            while True:
                message, fds = self.channel.recv()
                with self.lock:
                    future = self.pending.pop(message.get("id"), None)
                if future is None or future.done():
                    for fd in fds:
                        os.close(fd)
                    continue
                if message.get("ok"):
                    future.set_result((message.get("result"), fds))
                else:
                    for fd in fds:
                        os.close(fd)
                    future.set_exception(
                        RemoteError(
                            str(message.get("error", "Dispatcher request failed")), str(message.get("code", "failed"))
                        )
                    )
        except (EOFError, OSError, ProtocolError):
            pass
        finally:
            self.closed.set()
            with self.lock:
                pending, self.pending = self.pending, {}
            for future in pending.values():
                if not future.done():
                    future.set_exception(ConnectionError("Dispatcher connection closed"))
            self.channel.close()

    def call(self, op, **arguments):
        """Return a Future resolving to ``(result, fds)``."""
        future = Future()
        if self.closed.is_set():
            future.set_exception(ConnectionError("Dispatcher connection closed"))
            return future
        with self.lock:
            request_id = next(self.ids)
            future.request_id = request_id
            self.pending[request_id] = future
        try:
            self.outgoing.put_nowait(
                (request_id, {"v": PROTOCOL_VERSION, "id": request_id, "op": op, "args": arguments})
            )
        except queue.Full:
            # The peer is not reading: treat the link as dead rather than queueing without bound.
            self.close()
            with self.lock:
                self.pending.pop(request_id, None)
            if not future.done():
                future.set_exception(ConnectionError("Dispatcher is not responding"))
        return future

    def close(self):
        try:
            self.channel.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if threading.current_thread() is not self.reader:
            self.reader.join(timeout=5)


def serve(channel, handlers, *, max_workers=8, on_eof=None):
    """Serve requests until EOF. Handlers return ``result`` or ``(result, fds)``."""
    from concurrent.futures import ThreadPoolExecutor

    def respond(request_id, op, arguments):
        fds = []
        try:
            handler = handlers.get(op)
            if handler is None:
                raise RemoteError("Unknown operation", "invalid")
            result = handler(**arguments)
            if isinstance(result, tuple):
                result, fds = result
            reply = {"id": request_id, "ok": True, "result": result}
        except RemoteError as exc:
            reply = {"id": request_id, "ok": False, "error": str(exc), "code": exc.code}
        except BlockingIOError as exc:
            reply = {"id": request_id, "ok": False, "error": str(exc), "code": "busy"}
        except (FileNotFoundError, KeyError):
            reply = {"id": request_id, "ok": False, "error": "Task or resource not found", "code": "not_found"}
        except PermissionError as exc:
            reply = {"id": request_id, "ok": False, "error": str(exc) or "Permission denied", "code": "denied"}
        except (ValueError, TypeError) as exc:
            reply = {"id": request_id, "ok": False, "error": str(exc) or "Invalid request", "code": "invalid"}
        except Exception as exc:  # Keep serving; report a bounded message only.
            reply = {"id": request_id, "ok": False, "error": str(exc)[:500] or "Request failed", "code": "failed"}
        try:
            channel.send(reply, fds)
        except ValueError:  # Too large: tell the caller instead of leaving it waiting.
            try:
                channel.send({"id": request_id, "ok": False, "error": "Reply too large", "code": "failed"})
            except (OSError, ValueError):
                pass
        except OSError:
            pass
        finally:
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="biomni-dispatch") as pool:
        try:
            while True:
                message, fds = channel.recv()
                for fd in fds:  # Requests never carry descriptors.
                    os.close(fd)
                if message.get("v") != PROTOCOL_VERSION or not isinstance(message.get("args"), dict):
                    channel.send(
                        {"id": message.get("id"), "ok": False, "error": "Unsupported protocol", "code": "invalid"}
                    )
                    continue
                pool.submit(respond, message.get("id"), message.get("op"), message["args"])
        except (EOFError, OSError, ProtocolError):
            pass
        finally:
            if on_eof is not None:
                on_eof()
