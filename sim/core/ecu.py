"""
VirtualECU — JSON-RPC server wrapping the UDS session state machine.

Starts a TCP server on a dynamically-assigned port.  All security decisions
live here (Process 2); the DiagnosticClient (Process 1) communicates only
through the RPC protocol — never touching ECU internals directly.

session_timeout_seconds constructor parameter overrides the policy value so
tests can drive timer-dependent behaviour without waiting 300 seconds.
"""
import json
import pathlib
import threading

from sim.core.audit_logger import AuditLogger
from sim.core.authentication import AuthenticationHandler
from sim.core.security_access import SecurityAccessHandler
from sim.core.session import SessionStateMachine
from sim.protocol.rpc import RpcServer, get_current_conn_id

_POLICY_PATH = pathlib.Path(__file__).parent.parent / "config" / "ecu_policy.json"


def _load_policy() -> dict:
    with open(_POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


class VirtualECU:
    def __init__(
        self,
        session_timeout_seconds: float | None = None,
        cert_store=None,
        required_delay_seconds: float | None = None,
        lockout_duration_seconds: float | None = None,
    ):
        self._policy = _load_policy()
        self._session_timeout = session_timeout_seconds
        self._cert_store = cert_store
        self._required_delay = required_delay_seconds
        self._lockout_duration = lockout_duration_seconds
        self._session_sm: SessionStateMachine | None = None
        self._security_access: SecurityAccessHandler | None = None
        self._authentication: AuthenticationHandler | None = None
        self._session_owner: int | None = None
        # REQ-045: track which auth mechanism was first invoked this session
        # ("0x27" | "0x29" | None) — set on first successful seed/cert request
        self._auth_mechanism: str | None = None
        self._lock = threading.Lock()
        self._server: RpcServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("VirtualECU has not been started")
        return self._server.server_address[1]

    def start(self) -> None:
        self._session_sm = SessionStateMachine(self._policy, self._session_timeout)
        self._security_access = SecurityAccessHandler(
            self._policy, self._session_sm,
            required_delay_seconds=self._required_delay,
            lockout_duration_seconds=self._lockout_duration,
        )
        self._authentication = AuthenticationHandler(self._policy, self._session_sm, self._cert_store)
        self._audit = AuditLogger(
            genesis_hash=self._policy["audit_log"]["genesis_hash"]
        )
        self._session_owner = None
        self._auth_mechanism = None
        self._server = RpcServer("127.0.0.1", 0)
        self._server.register("diagnostic_session_control", self._rpc_session_control)
        self._server.register("get_session_state", self._rpc_get_session_state)
        self._server.register("inject_tamper", self._rpc_inject_tamper)
        self._server.register("security_access_request_seed", self._rpc_request_seed)
        self._server.register("security_access_send_key", self._rpc_send_key)
        self._server.register("get_access_level", self._rpc_get_access_level)
        self._server.register("get_attempt_counter", self._rpc_get_attempt_counter)
        self._server.register("authenticate_communicate_certificate", self._rpc_communicate_certificate)
        self._server.register("check_access", self._rpc_check_access)
        self._server.register("send_uds_pdu", self._rpc_send_uds_pdu)
        self._server.register("authenticate_verify_proof", self._rpc_verify_proof)
        self._server.register("authenticate_deauthenticate", self._rpc_deauthenticate)
        self._server.register("get_auth_access_level", self._rpc_get_auth_access_level)
        self._server.register("inject_replay_nonce", self._rpc_inject_replay_nonce)
        self._server.register("get_audit_log", self._rpc_get_audit_log)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="VirtualECU-RPC"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        self._session_sm = None

    # ------------------------------------------------------------------
    # RPC handlers — the ONLY entry points from Process 1
    # ------------------------------------------------------------------

    def _clear_access_levels(self) -> None:
        """Clear all granted access levels, ownership, and mechanism lock (REQ-035, REQ-045)."""
        if self._security_access:
            self._security_access.clear_access()
        if self._authentication:
            self._authentication.clear_access()
        self._session_owner = None
        self._auth_mechanism = None

    def _is_access_granted(self, access_level: str, session_id: int) -> bool:
        sa  = self._security_access.granted_access_level() if self._security_access else None
        auth = self._authentication.granted_access_level() if self._authentication else None
        if access_level == "READ_ONLY":
            return True
        if access_level == "CALIBRATION":
            return session_id == SessionStateMachine.EXTENDED and sa == "CALIBRATION"
        if access_level == "ECU_PROGRAMMING":
            return session_id == SessionStateMachine.PROGRAMMING and sa == "ECU_PROGRAMMING"
        if access_level == "ENGINEERING":
            return session_id == SessionStateMachine.EXTENDED and auth == "ENGINEERING"
        if access_level == "FULL_ACCESS":
            return session_id == SessionStateMachine.PROGRAMMING and auth == "FULL_ACCESS"
        return False

    def _rpc_session_control(self, session_id: int) -> dict:
        conn_id = get_current_conn_id()
        with self._lock:
            current = self._session_sm.current()
            # REQ-007: reject requests from a different connection while a session
            # is elevated (owned by another client)
            if current != SessionStateMachine.DEFAULT and self._session_owner != conn_id:
                return {"positive": False, "nrc": 0x22}

            ok, nrc = self._session_sm.transition(session_id)
            if ok:
                new_session = self._session_sm.current()
                if new_session != SessionStateMachine.DEFAULT:
                    self._session_owner = conn_id
                    self._audit.emit("SESSION_START", service_id=0x10,
                                     client_id=conn_id, result="success")
                else:
                    self._clear_access_levels()  # REQ-035
                    self._audit.emit("SESSION_END", service_id=0x10,
                                     client_id=conn_id, result="success")
                return {"positive": True, "session_id": session_id}
            return {"positive": False, "nrc": nrc}

    def _rpc_get_session_state(self) -> dict:
        conn_id = get_current_conn_id()
        with self._lock:
            current = self._session_sm.current()  # triggers timeout check
            # Reset timer only for the session owner (REQ-006)
            if current != SessionStateMachine.DEFAULT and self._session_owner == conn_id:
                self._session_sm.touch()
            # If timeout fired, clear ownership
            if current == SessionStateMachine.DEFAULT:
                self._session_owner = None
            return {"session_id": current}

    def _rpc_inject_tamper(self) -> dict:
        """Simulation-only: force an immediate tamper-triggered session reset (REQ-008)."""
        conn_id = get_current_conn_id()
        with self._lock:
            self._session_sm.reset()
            self._clear_access_levels()  # REQ-035 + REQ-008
            self._audit.emit("SESSION_TAMPER_RESET", service_id=0x10,
                             client_id=conn_id, result="tamper")
            return {"ok": True}

    def _rpc_request_seed(self, subfunction: int) -> dict:
        conn_id = get_current_conn_id()
        with self._lock:
            current = self._session_sm.current()
            if current != SessionStateMachine.DEFAULT and self._session_owner != conn_id:
                return {"positive": False, "nrc": 0x22}
            # REQ-045: block 0x27 if 0x29 was already invoked this session
            if self._auth_mechanism == "0x29":
                return {"positive": False, "nrc": 0x24}
            ok, seed, nrc = self._security_access.request_seed(subfunction)
            if ok:
                self._auth_mechanism = "0x27"
                return {"positive": True, "seed": list(seed)}
            return {"positive": False, "nrc": nrc}

    def _rpc_send_key(self, subfunction: int, key: list) -> dict:
        conn_id = get_current_conn_id()
        with self._lock:
            current = self._session_sm.current()
            if current != SessionStateMachine.DEFAULT and self._session_owner != conn_id:
                return {"positive": False, "nrc": 0x22}
            ok, access_level, nrc = self._security_access.send_key(subfunction, bytes(key))
            if ok:
                self._audit.emit("AUTH_SUCCESS", service_id=0x27,
                                 access_level=access_level, client_id=conn_id, result="success")
                return {"positive": True, "access_level": access_level}
            if nrc == 0x35:
                self._audit.emit("AUTH_FAILURE", service_id=0x27,
                                 client_id=conn_id, result="failure", nrc_code=nrc)
            return {"positive": False, "nrc": nrc}

    def _rpc_get_access_level(self) -> dict:
        with self._lock:
            return {"access_level": self._security_access.granted_access_level()}

    def _rpc_get_attempt_counter(self, access_level: str) -> dict:
        with self._lock:
            return {"count": self._security_access.attempt_counter(access_level)}

    def _rpc_communicate_certificate(self, cert_pem: str) -> dict:
        conn_id = get_current_conn_id()
        with self._lock:
            current = self._session_sm.current()
            if current != SessionStateMachine.DEFAULT and self._session_owner != conn_id:
                return {"positive": False, "nrc": 0x22}
            if current == SessionStateMachine.DEFAULT:
                return {"positive": False, "nrc": 0x22}
            # REQ-045: block 0x29 if 0x27 was already invoked this session
            if self._auth_mechanism == "0x27":
                return {"positive": False, "nrc": 0x24}
            ok, data, nrc = self._authentication.communicate_certificate(cert_pem, current)
            if ok:
                self._auth_mechanism = "0x29"
                return {"positive": True, **data}
            return {"positive": False, "nrc": nrc}

    def _rpc_verify_proof(self, proof: list) -> dict:
        conn_id = get_current_conn_id()
        with self._lock:
            current = self._session_sm.current()
            if current != SessionStateMachine.DEFAULT and self._session_owner != conn_id:
                return {"positive": False, "nrc": 0x22}
            if current == SessionStateMachine.DEFAULT:
                return {"positive": False, "nrc": 0x22}
            ok, access_level, nrc = self._authentication.verify_proof(bytes(proof), current)
            if ok:
                self._audit.emit("AUTH_SUCCESS", service_id=0x29,
                                 access_level=access_level, client_id=conn_id, result="success")
                return {"positive": True, "access_level": access_level}
            self._audit.emit("AUTH_FAILURE", service_id=0x29,
                             client_id=conn_id, result="failure", nrc_code=nrc)
            return {"positive": False, "nrc": nrc}

    def _rpc_deauthenticate(self) -> dict:
        conn_id = get_current_conn_id()
        with self._lock:
            current = self._session_sm.current()
            if current != SessionStateMachine.DEFAULT and self._session_owner != conn_id:
                return {"positive": False, "nrc": 0x22}
            return self._authentication.deauthenticate()

    def _rpc_get_auth_access_level(self) -> dict:
        with self._lock:
            return {"access_level": self._authentication.granted_access_level()}

    def _rpc_get_audit_log(self) -> dict:
        with self._lock:
            return {"entries": self._audit.entries()}

    def _rpc_inject_replay_nonce(self, nonce: list) -> dict:
        """Simulation-only: overwrite the pending 0x29 challenge to test replay detection."""
        with self._lock:
            self._authentication.inject_pending_nonce_for_test(bytes(nonce))
            return {"ok": True}

    def _rpc_send_uds_pdu(self, service_id: int, payload: list) -> dict:
        """
        Generic UDS PDU entry point for format-level validation (REQ-047).
        Returns NRC 0x13 for unknown service IDs or incorrect payload lengths.
        Valid messages are forwarded to the appropriate typed handler.

        Supported services and expected payload sizes:
          0x10 DiagnosticSessionControl — exactly 1 byte (session ID)
          0x27 SecurityAccess requestSeed — at least 1 byte (subfunction)
        """
        if service_id == 0x10:
            if len(payload) != 1:
                return {"positive": False, "nrc": 0x13}
            return self._rpc_session_control(session_id=int(payload[0]))
        elif service_id == 0x27:
            if len(payload) < 1:
                return {"positive": False, "nrc": 0x13}
            return self._rpc_request_seed(subfunction=int(payload[0]))
        else:
            return {"positive": False, "nrc": 0x13}

    def _rpc_check_access(self, access_level: str) -> dict:
        with self._lock:
            current = self._session_sm.current()  # triggers timeout check
            if current == SessionStateMachine.DEFAULT:
                self._clear_access_levels()        # lazy cleanup after timeout (REQ-035)
            return {"granted": self._is_access_granted(access_level, current)}
