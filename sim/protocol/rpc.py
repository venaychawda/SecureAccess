"""
JSON-RPC 2.0 over newline-delimited TCP.

Server: RpcServer  — register(name, fn), serve_forever(), shutdown()
Client: RpcClient  — connect(), call(method, **params), disconnect()

Connection identity is tracked via thread-local storage so handlers can
identify which TCP connection is making a request without changing the
RPC wire protocol.  Call get_current_conn_id() from any registered handler.
"""
import json
import socket
import socketserver
import threading

# Thread-local storage: populated by _Handler before each dispatch.
_conn_context = threading.local()


def get_current_conn_id() -> int | None:
    """Return a unique integer identifying the current TCP connection."""
    return getattr(_conn_context, "conn_id", None)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        _conn_context.conn_id = id(conn)  # stable for the lifetime of this connection
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                resp = self.server._dispatch(line)
                conn.sendall(json.dumps(resp).encode() + b"\n")


class RpcServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int):
        self._methods: dict = {}
        super().__init__((host, port), _Handler)

    def register(self, name: str, fn) -> None:
        self._methods[name] = fn

    def _dispatch(self, raw: bytes) -> dict:
        rpc_id = None
        try:
            req = json.loads(raw.decode())
            rpc_id = req.get("id")
            method = req.get("method")
            params = req.get("params") or {}
            if method not in self._methods:
                raise KeyError(f"unknown method: {method}")
            result = self._methods[method](**params)
            return {"jsonrpc": "2.0", "result": result, "id": rpc_id}
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": str(exc)},
                "id": rpc_id,
            }


class RpcClient:
    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None
        self._fh = None
        self._next_id = 0
        self._lock = threading.Lock()

    def connect(self) -> None:
        self._sock = socket.create_connection((self._host, self._port), timeout=5)
        self._fh = self._sock.makefile("rb")

    def disconnect(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except OSError:
                pass
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def call(self, method: str, **params) -> dict:
        with self._lock:
            self._next_id += 1
            req = {"jsonrpc": "2.0", "method": method, "params": params, "id": self._next_id}
            self._sock.sendall(json.dumps(req).encode() + b"\n")
            line = self._fh.readline()
            resp = json.loads(line.decode())
        if "error" in resp:
            raise RuntimeError(f"RPC error from ECU: {resp['error']['message']}")
        return resp["result"]
