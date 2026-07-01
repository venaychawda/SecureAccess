"""
TC-10 — Session Token Binding and Re-authentication

Requirements : REQ-042, REQ-043, REQ-044, REQ-045
Acceptance criteria:
  1. Access granted with session token T is rejected with token T2 from different session.
  2. Access level from session S1 cannot be reused in session S2.
  3. After session timeout client must re-authenticate from Default Session.
  4. Invoking 0x29 after 0x27 for the same session returns NRC 0x24.
  5. Invoking 0x27 after 0x29 for the same session returns NRC 0x24.
"""
import time

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

SECRET_CALIBRATION = "sim-calibration-secret-dev-only"

NRC_CONDITIONS_NOT_CORRECT  = 0x22
NRC_REQUEST_SEQUENCE_ERROR  = 0x24

SHORT_TIMEOUT = 2   # seconds — for @slow timeout tests


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def cert_store():
    return CertStore.generate_in_memory()


@pytest.fixture
def ecu_client(cert_store):
    ecu = VirtualECU(cert_store=cert_store, required_delay_seconds=0)
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


@pytest.fixture
def timeout_ecu_client(cert_store):
    """Short session timeout for REQ-044 timer tests."""
    ecu = VirtualECU(
        cert_store=cert_store,
        session_timeout_seconds=SHORT_TIMEOUT,
        required_delay_seconds=0,
    )
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


def _do_0x29_engineering(client, cert_store):
    resp = client.communicate_certificate(cert_store.tester_cert_pem)
    proof = crypto_backend.sign_ecdsa(cert_store.tester_key, bytes(resp["challenge"]))
    client.verify_proof(proof)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.sim
class TestTC10SessionBinding:
    """TC-10: Session Token Binding and Re-authentication"""

    # REQ-042 — Session token binds access to a specific session instance
    # ---------------------------------------------------------------

    def test_req042_access_bound_to_session_instance(self, ecu_client):
        """REQ-042: Access granted in session S1 is not present in a newly started session."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x27_calibration(ecu_client)
        assert ecu_client.check_access("CALIBRATION")["granted"] is True

        # Revert to Default (ends session S1)
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        # Start session S2
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        assert ecu_client.check_access("CALIBRATION")["granted"] is False

    def test_req042_access_requires_reauthentication_in_new_session(self, ecu_client):
        """REQ-042: Client must re-authenticate in each new session to regain access."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x27_calibration(ecu_client)
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        # Verify requestSeed is needed (no cached access)
        assert ecu_client.check_access("CALIBRATION")["granted"] is False
        _do_0x27_calibration(ecu_client)
        assert ecu_client.check_access("CALIBRATION")["granted"] is True

    # REQ-043 — Access level not transferable between sessions
    # ---------------------------------------------------------------

    def test_req043_access_not_transferred_across_session_boundary(self, ecu_client):
        """REQ-043: CALIBRATION access from S1 is unavailable in S2 — same connection."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x27_calibration(ecu_client)
        # Drop to Default then immediately re-escalate (same TCP connection)
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        assert ecu_client.check_access("CALIBRATION")["granted"] is False

    def test_req043_0x29_access_not_transferred_across_session_boundary(
        self, ecu_client, cert_store
    ):
        """REQ-043: ENGINEERING access from S1 is unavailable in S2 — same connection."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x29_engineering(ecu_client, cert_store)
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        assert ecu_client.check_access("ENGINEERING")["granted"] is False

    # REQ-044 — Re-authentication required after session timeout
    # ---------------------------------------------------------------

    @pytest.mark.slow
    def test_req044_access_cleared_after_session_timeout(self, timeout_ecu_client):
        """REQ-044: After session timeout, access level is revoked."""
        timeout_ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_0x27_calibration(timeout_ecu_client)
        assert timeout_ecu_client.check_access("CALIBRATION")["granted"] is True
        time.sleep(SHORT_TIMEOUT + 1)
        assert timeout_ecu_client.check_access("CALIBRATION")["granted"] is False

    @pytest.mark.slow
    def test_req044_requestseed_requires_session_escalation_after_timeout(
        self, timeout_ecu_client
    ):
        """REQ-044: After timeout, requestSeed returns NRC 0x22 — must re-escalate first."""
        timeout_ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        time.sleep(SHORT_TIMEOUT + 1)
        resp = timeout_ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    # REQ-045 — 0x27 and 0x29 mutually exclusive in same session
    # ---------------------------------------------------------------

    def test_req045_0x29_rejected_after_0x27_in_same_session(
        self, ecu_client, cert_store
    ):
        """REQ-045: communicateCertificate (0x29) returns NRC 0x24 after 0x27 is invoked."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)  # 0x27 invoked
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_REQUEST_SEQUENCE_ERROR

    def test_req045_0x27_rejected_after_0x29_in_same_session(
        self, ecu_client, cert_store
    ):
        """REQ-045: requestSeed (0x27) returns NRC 0x24 after 0x29 is invoked."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.communicate_certificate(cert_store.tester_cert_pem)  # 0x29 invoked
        resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_REQUEST_SEQUENCE_ERROR

    def test_req045_mechanism_usable_again_after_session_reset(
        self, ecu_client, cert_store
    ):
        """REQ-045: After session downgrade, mechanism exclusion is cleared."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)  # sets 0x27 mode
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)  # clears mode
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        # 0x29 should now be usable in the fresh session
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is True
