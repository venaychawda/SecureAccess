"""
TC-08 — Access Level Gating: RBAC Enforcement

Requirements : REQ-030, REQ-031, REQ-032, REQ-033, REQ-034, REQ-035
Acceptance criteria:
  1. READ_ONLY succeeds in Default Session without auth.
  2. CALIBRATION rejected without 0x27 CALIBRATION auth.
  3. CALIBRATION granted after 0x27 CALIBRATION auth in Extended Session.
  4. ECU_PROGRAMMING requires Programming Session + 0x27 level 0x03/0x04.
  5. ENGINEERING requires Extended Session + 0x29 unidirectional.
  6. FULL_ACCESS requires Programming Session + 0x29 bidirectional.
  7. Access revoked on session revert to Default.
"""
import pytest

from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.hal.cert_store_sim import CertStore
from sim.protocol.client import DiagnosticClient

DEFAULT_SESSION     = 0x01
EXTENDED_SESSION    = 0x03
PROGRAMMING_SESSION = 0x02

SF_CALIBRATION_REQUEST_SEED = 0x01
SF_CALIBRATION_SEND_KEY     = 0x02
SF_PROGRAMMING_REQUEST_SEED = 0x03
SF_PROGRAMMING_SEND_KEY     = 0x04

SECRET_CALIBRATION = "sim-calibration-secret-dev-only"
SECRET_PROGRAMMING = "sim-programming-secret-dev-only"


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------

def _do_0x27_calibration(client):
    resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
    key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_CALIBRATION)
    client.send_key(SF_CALIBRATION_SEND_KEY, key)


def _do_0x27_programming(client):
    resp = client.request_seed(SF_PROGRAMMING_REQUEST_SEED)
    key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_PROGRAMMING)
    client.send_key(SF_PROGRAMMING_SEND_KEY, key)


def _do_0x29_engineering(client, cert_store):
    r = client.communicate_certificate(cert_store.tester_cert_pem)
    proof = crypto_backend.sign_ecdsa(cert_store.tester_key, bytes(r["challenge"]))
    client.verify_proof(proof)


def _do_0x29_full_access(client, cert_store):
    r = client.communicate_certificate(cert_store.tester_cert_pem)
    proof = crypto_backend.sign_ecdsa(cert_store.tester_key, bytes(r["challenge"]))
    client.verify_proof(proof)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.sim
class TestTC08AccessLevelGating:
    """TC-08: Access Level Gating — RBAC Enforcement"""

    # REQ-030 — READ_ONLY: no auth required
    # ---------------------------------------------------------------

    def test_req030_read_only_granted_in_default_session(self, ecu_client):
        """REQ-030: READ_ONLY access is granted in Default Session without any auth."""
        resp = ecu_client.check_access("READ_ONLY")
        assert resp["granted"] is True

    def test_req030_read_only_granted_in_elevated_session(self, ecu_client):
        """REQ-030: READ_ONLY is still granted after session escalation."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.check_access("READ_ONLY")
        assert resp["granted"] is True

    # REQ-031 — CALIBRATION: Extended + 0x27 CALIBRATION
    # ---------------------------------------------------------------

    def test_req031_calibration_rejected_without_auth(self, ecu_client):
        """REQ-031: CALIBRATION denied in Extended Session without 0x27 auth."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        assert ecu_client.check_access("CALIBRATION")["granted"] is False

    def test_req031_calibration_rejected_in_default_session(self, ecu_client):
        """REQ-031: CALIBRATION denied in Default Session even conceptually."""
        assert ecu_client.check_access("CALIBRATION")["granted"] is False

    def test_req031_calibration_granted_after_0x27_auth(self, ecu_client):
        """REQ-031: CALIBRATION granted after Extended Session + 0x27 CALIBRATION auth."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x27_calibration(ecu_client)
        assert ecu_client.check_access("CALIBRATION")["granted"] is True

    # REQ-032 — ECU_PROGRAMMING: Programming + 0x27 level 0x03/0x04
    # ---------------------------------------------------------------

    def test_req032_ecu_programming_rejected_without_auth(self, ecu_client):
        """REQ-032: ECU_PROGRAMMING denied in Programming Session without 0x27 auth."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        assert ecu_client.check_access("ECU_PROGRAMMING")["granted"] is False

    def test_req032_ecu_programming_granted_after_0x27_auth(self, ecu_client):
        """REQ-032: ECU_PROGRAMMING granted after Programming Session + 0x27 high-level auth."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        _do_0x27_programming(ecu_client)
        assert ecu_client.check_access("ECU_PROGRAMMING")["granted"] is True

    # REQ-033 — ENGINEERING: Extended + 0x29 unidirectional
    # ---------------------------------------------------------------

    def test_req033_engineering_rejected_without_0x29(self, ecu_client):
        """REQ-033: ENGINEERING denied in Extended Session without 0x29 auth."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        assert ecu_client.check_access("ENGINEERING")["granted"] is False

    def test_req033_engineering_granted_after_0x29_unidirectional(self, ecu_client, cert_store):
        """REQ-033: ENGINEERING granted after Extended Session + 0x29 unidirectional auth."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x29_engineering(ecu_client, cert_store)
        assert ecu_client.check_access("ENGINEERING")["granted"] is True

    # REQ-034 — FULL_ACCESS: Programming + 0x29 bidirectional
    # ---------------------------------------------------------------

    def test_req034_full_access_granted_after_0x29_bidirectional(self, ecu_client, cert_store):
        """REQ-034: FULL_ACCESS granted after Programming Session + 0x29 bidirectional auth."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        _do_0x29_full_access(ecu_client, cert_store)
        assert ecu_client.check_access("FULL_ACCESS")["granted"] is True

    def test_req034_full_access_rejected_in_extended_session(self, ecu_client, cert_store):
        """REQ-034: FULL_ACCESS denied even after 0x29 if session is Extended (not Programming)."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x29_engineering(ecu_client, cert_store)  # only ENGINEERING in Extended
        assert ecu_client.check_access("FULL_ACCESS")["granted"] is False

    # REQ-035 — Access revoked on session downgrade to Default
    # ---------------------------------------------------------------

    def test_req035_calibration_revoked_on_session_downgrade(self, ecu_client):
        """REQ-035: CALIBRATION access is revoked when session reverts to Default."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x27_calibration(ecu_client)
        assert ecu_client.check_access("CALIBRATION")["granted"] is True
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        assert ecu_client.check_access("CALIBRATION")["granted"] is False

    def test_req035_access_not_carried_into_new_session(self, ecu_client):
        """REQ-035: Access from session S1 does not persist into a new Extended session."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x27_calibration(ecu_client)
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)  # revert + clear
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)  # new session
        assert ecu_client.check_access("CALIBRATION")["granted"] is False
