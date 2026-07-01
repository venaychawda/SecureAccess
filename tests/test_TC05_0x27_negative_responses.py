"""
TC-05 — 0x27 SecurityAccess: Negative Responses — Wrong Key / Sequence Errors

Requirements : REQ-015, REQ-017, REQ-018
Acceptance criteria:
  1. Incorrect key returns NRC 0x35.
  2. Attempt counter increments on each NRC 0x35.
  3. sendKey without prior requestSeed returns NRC 0x24.
  4. sendKey after successful sendKey (same seed) returns NRC 0x24.
  5. New requestSeed is required before a second sendKey attempt.
"""
import pytest

from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.protocol.client import DiagnosticClient

EXTENDED_SESSION    = 0x03
PROGRAMMING_SESSION = 0x02

SF_CALIBRATION_REQUEST_SEED = 0x01
SF_CALIBRATION_SEND_KEY     = 0x02
SF_PROGRAMMING_REQUEST_SEED = 0x03
SF_PROGRAMMING_SEND_KEY     = 0x04

SECRET_CALIBRATION = "sim-calibration-secret-dev-only"

NRC_INVALID_KEY             = 0x35
NRC_REQUEST_SEQUENCE_ERROR  = 0x24

WRONG_KEY = bytes(32)  # 32 zero-bytes — never a valid HMAC-SHA256 output for our seeds


@pytest.fixture
def ecu_client():
    # required_delay_seconds=0: TC-05 tests rapid sequential attempts and does not
    # test the delay timer (that is TC-09's responsibility).
    ecu = VirtualECU(required_delay_seconds=0)
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


@pytest.mark.sim
class TestTC05NegativeResponses:
    """TC-05: 0x27 SecurityAccess — Negative Responses"""

    # ------------------------------------------------------------------
    # REQ-015 — Incorrect key → NRC 0x35 + attempt counter increments
    # ------------------------------------------------------------------

    def test_req015_wrong_key_returns_nrc_0x35(self, ecu_client):
        """REQ-015: Sending a wrong key returns NRC 0x35 (invalidKey)."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        resp = ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_INVALID_KEY

    def test_req015_attempt_counter_increments_on_each_wrong_key(self, ecu_client):
        """REQ-015: Attempt counter increments by 1 for each NRC 0x35 response."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        # Send 2 wrong keys — stays below MAX_AUTH_ATTEMPTS (3) so no lockout yet
        for expected_count in range(1, 3):
            ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
            ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
            result = ecu_client.get_attempt_counter("CALIBRATION")
            assert result["count"] == expected_count

    def test_req015_counter_independent_per_access_level(self, ecu_client):
        """REQ-015: Wrong key on CALIBRATION does not affect ECU_PROGRAMMING counter."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
        result = ecu_client.get_attempt_counter("ECU_PROGRAMMING")
        assert result["count"] == 0

    # ------------------------------------------------------------------
    # REQ-017 — sendKey without prior requestSeed → NRC 0x24
    # ------------------------------------------------------------------

    def test_req017_send_key_without_request_seed_returns_nrc_0x24(self, ecu_client):
        """REQ-017: sendKey with no preceding requestSeed returns NRC 0x24."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_REQUEST_SEQUENCE_ERROR

    def test_req017_send_key_in_wrong_session_not_sequence_error(self, ecu_client):
        """REQ-017: sendKey in Default Session (before any requestSeed) returns NRC 0x22, not 0x24."""
        # Default session → session gating fires before sequence check
        resp = ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
        assert resp["positive"] is False
        assert resp["nrc"] == 0x22

    # ------------------------------------------------------------------
    # REQ-018 — Seed invalidated after any sendKey attempt
    # ------------------------------------------------------------------

    def test_req018_seed_invalidated_after_failed_send_key(self, ecu_client):
        """REQ-018: After a failed sendKey, the seed is consumed — next sendKey returns NRC 0x24."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)          # fails, seed consumed
        resp = ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)   # no seed → NRC 0x24
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_REQUEST_SEQUENCE_ERROR

    def test_req018_seed_invalidated_after_successful_send_key(self, ecu_client):
        """REQ-018: After a successful sendKey the seed is consumed — next sendKey returns NRC 0x24."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_CALIBRATION)
        ecu_client.send_key(SF_CALIBRATION_SEND_KEY, key)                # success, seed consumed
        resp = ecu_client.send_key(SF_CALIBRATION_SEND_KEY, key)         # no seed → NRC 0x24
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_REQUEST_SEQUENCE_ERROR

    def test_req018_new_request_seed_enables_retry_after_failure(self, ecu_client):
        """REQ-018: A fresh requestSeed allows a subsequent sendKey after a failed attempt."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)          # fail, seed gone
        # Fresh seed + correct key should succeed
        resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_CALIBRATION)
        resp = ecu_client.send_key(SF_CALIBRATION_SEND_KEY, key)
        assert resp["positive"] is True
