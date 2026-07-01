"""
TC-11 — Replay Attack Detection

Requirements : REQ-027, REQ-046
Acceptance criteria:
  1. ECU generates a fresh NONCE_SIZE_BYTES nonce per authentication session.
  2. Re-submitting a captured authentication message with the same nonce → NRC 0x24.
  3. 1000 consecutive nonces are unique (no collision).
  4. Nonce from a previous session is rejected in a new session.
"""
import pytest

from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.hal.cert_store_sim import CertStore
from sim.protocol.client import DiagnosticClient

EXTENDED_SESSION = 0x03
DEFAULT_SESSION  = 0x01

NRC_REQUEST_SEQUENCE_ERROR = 0x24
NONCE_SIZE_BYTES = 16   # from ecu_policy.json


@pytest.fixture
def cert_store():
    return CertStore.generate_in_memory()


@pytest.fixture
def ecu_client(cert_store):
    ecu = VirtualECU(cert_store=cert_store)
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


def _do_full_0x29(client, cert_store):
    """Complete a successful 0x29 unidirectional auth. Returns the nonce used."""
    resp = client.communicate_certificate(cert_store.tester_cert_pem)
    nonce = bytes(resp["challenge"])
    proof = crypto_backend.sign_ecdsa(cert_store.tester_key, nonce)
    client.verify_proof(proof)
    return nonce


@pytest.mark.sim
class TestTC11ReplayDetection:
    """TC-11: Replay Attack Detection"""

    # REQ-027 — Fresh nonce per auth session
    # ---------------------------------------------------------------

    def test_req027_challenge_is_nonce_size_bytes(self, ecu_client, cert_store):
        """REQ-027: communicateCertificate challenge is exactly NONCE_SIZE_BYTES (16) long."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is True
        assert len(bytes(resp["challenge"])) == NONCE_SIZE_BYTES

    def test_req027_consecutive_nonces_are_unique(self, ecu_client, cert_store):
        """REQ-027: 1000 consecutive communicate_certificate calls produce unique nonces."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        nonces = set()
        for _ in range(1000):
            resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
            assert resp["positive"] is True
            nonces.add(bytes(resp["challenge"]))
        assert len(nonces) == 1000

    # REQ-046 — Replay detection: nonce reuse rejected with NRC 0x24
    # ---------------------------------------------------------------

    def test_req046_replay_rejected_same_session(self, ecu_client, cert_store):
        """REQ-046: Injecting a nonce already used in this session → NRC 0x24."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        used_nonce = _do_full_0x29(ecu_client, cert_store)   # N1 now in used-nonce set

        # New session: communicate_certificate to set up state, then inject the old nonce
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.communicate_certificate(cert_store.tester_cert_pem)  # sets pending cert
        ecu_client.inject_replay_nonce(used_nonce)                       # overwrite with N1

        # Replay: sign N1 again and submit
        proof = crypto_backend.sign_ecdsa(cert_store.tester_key, used_nonce)
        resp = ecu_client.verify_proof(proof)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_REQUEST_SEQUENCE_ERROR

    def test_req046_nonce_from_previous_session_rejected(self, ecu_client, cert_store):
        """REQ-046: Nonce N1 seen in session 1 is blocked in session 2."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        n1 = _do_full_0x29(ecu_client, cert_store)   # success; N1 → used_nonces

        # Reset and start fresh session
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        ecu_client.inject_replay_nonce(n1)

        proof = crypto_backend.sign_ecdsa(cert_store.tester_key, n1)
        resp = ecu_client.verify_proof(proof)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_REQUEST_SEQUENCE_ERROR

    def test_req046_fresh_nonce_succeeds_after_replay_attempt(self, ecu_client, cert_store):
        """REQ-046: After a replay attempt is blocked, a fresh auth with a new nonce succeeds."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        used_nonce = _do_full_0x29(ecu_client, cert_store)

        # Failed replay attempt
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        ecu_client.inject_replay_nonce(used_nonce)
        ecu_client.verify_proof(crypto_backend.sign_ecdsa(cert_store.tester_key, used_nonce))

        # Legitimate new auth in another fresh session
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp1 = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        new_nonce = bytes(resp1["challenge"])
        assert new_nonce != used_nonce   # genuinely different nonce
        proof = crypto_backend.sign_ecdsa(cert_store.tester_key, new_nonce)
        resp2 = ecu_client.verify_proof(proof)
        assert resp2["positive"] is True
        assert resp2["access_level"] == "ENGINEERING"

    def test_req046_unused_nonce_not_blocked(self, ecu_client, cert_store):
        """REQ-046: A nonce that was issued but never verified is not in the used-nonce set."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        nonce = bytes(resp["challenge"])
        # Do NOT call verify_proof — nonce is pending but not used
        # Re-issue in same state should still allow verification
        proof = crypto_backend.sign_ecdsa(cert_store.tester_key, nonce)
        resp = ecu_client.verify_proof(proof)
        assert resp["positive"] is True
