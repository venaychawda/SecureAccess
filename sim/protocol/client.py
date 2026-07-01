"""
DiagnosticClient — Process 1 side of the two-process trust boundary.

Communicates with VirtualECU exclusively via JSON-RPC over TCP.
No ECU internals (session state, key material, counters) are accessible here.
"""
from sim.protocol.rpc import RpcClient


class DiagnosticClient:
    def __init__(self, host: str, port: int):
        self._rpc = RpcClient(host, port)

    def connect(self) -> None:
        self._rpc.connect()

    def disconnect(self) -> None:
        self._rpc.disconnect()

    def send_diagnostic_session_control(self, session_id: int) -> dict:
        """Send UDS 0x10 DiagnosticSessionControl. Returns positive or NRC response dict."""
        return self._rpc.call("diagnostic_session_control", session_id=session_id)

    def get_session_state(self) -> dict:
        """Query current session state via RPC (test helper). Returns {"session_id": int}."""
        return self._rpc.call("get_session_state")

    def inject_tamper_event(self) -> dict:
        """Simulation-only: trigger an immediate tamper-driven session reset (REQ-008)."""
        return self._rpc.call("inject_tamper")

    def request_seed(self, subfunction: int) -> dict:
        """Send 0x27 requestSeed. Returns {"positive": True, "seed": bytes} or NRC dict."""
        result = self._rpc.call("security_access_request_seed", subfunction=subfunction)
        if result.get("positive"):
            result["seed"] = bytes(result["seed"])
        return result

    def send_key(self, subfunction: int, key: bytes) -> dict:
        """Send 0x27 sendKey. Returns {"positive": True, "access_level": str} or NRC dict."""
        return self._rpc.call("security_access_send_key", subfunction=subfunction, key=list(key))

    def get_access_level(self) -> dict:
        """Query the ECU's currently granted 0x27 access level. Returns {"access_level": str|None}."""
        return self._rpc.call("get_access_level")

    def get_attempt_counter(self, access_level: str) -> dict:
        """Query failed sendKey attempt count for an access level. Returns {"count": int}."""
        return self._rpc.call("get_attempt_counter", access_level=access_level)

    def inject_replay_nonce(self, nonce: bytes) -> dict:
        """Simulation-only: overwrite the ECU's pending 0x29 challenge for replay testing."""
        return self._rpc.call("inject_replay_nonce", nonce=list(nonce))

    def communicate_certificate(self, cert_pem: str) -> dict:
        """Send 0x29 communicateCertificate. Returns {"positive": True, "challenge": list, "ecu_cert": str|None} or NRC dict."""
        return self._rpc.call("authenticate_communicate_certificate", cert_pem=cert_pem)

    def verify_proof(self, proof: bytes) -> dict:
        """Send 0x29 proof-of-possession (signed challenge). Returns {"positive": True, "access_level": str} or NRC dict."""
        return self._rpc.call("authenticate_verify_proof", proof=list(proof))

    def deauthenticate(self) -> dict:
        """Send 0x29 deAuthenticate. Revokes 0x29-granted access level."""
        return self._rpc.call("authenticate_deauthenticate")

    def get_auth_access_level(self) -> dict:
        """Query the ECU's currently granted 0x29 access level. Returns {"access_level": str|None}."""
        return self._rpc.call("get_auth_access_level")

    def get_audit_log(self) -> dict:
        """Retrieve all audit log entries from the ECU. Returns {"entries": list[dict]}."""
        return self._rpc.call("get_audit_log")

    def send_uds_pdu(self, service_id: int, payload: list[int]) -> dict:
        """Send a raw UDS PDU. Returns NRC 0x13 if the format is invalid (REQ-047)."""
        return self._rpc.call("send_uds_pdu", service_id=service_id, payload=list(payload))

    def check_access(self, access_level: str) -> dict:
        """Check whether the current session+auth state grants the requested access level. Returns {"granted": bool}."""
        return self._rpc.call("check_access", access_level=access_level)
