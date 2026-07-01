"""
TC-04 — 0x27 SecurityAccess: Key Validation — Positive Path

Requirements : REQ-013, REQ-014, REQ-016, REQ-019
Acceptance criteria:
  1. HMAC-SHA256(seed, shared_secret) produces the accepted key.
  2. Correct key grants CALIBRATION access (subfunction 0x01/0x02).
  3. Correct key grants ECU_PROGRAMMING access (subfunction 0x03/0x04).
  4. Key comparison uses hmac.compare_digest (constant-time — code gate).
  5. Access level flag is set in ECU state after a successful sendKey.
"""
import pytest

from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.protocol.client import DiagnosticClient

DEFAULT_SESSION = 0x01
EXTENDED_SESSION = 0x03
PROGRAMMING_SESSION = 0x02

# 0x27 subfunction bytes (REQ-019: odd = requestSeed, even = sendKey)
SF_CALIBRATION_REQUEST_SEED = 0x01
SF_CALIBRATION_SEND_KEY     = 0x02
SF_PROGRAMMING_REQUEST_SEED = 0x03
SF_PROGRAMMING_SEND_KEY     = 0x04

# Sim-only shared secrets (labeled dev-only in ecu_policy.json)
SECRET_CALIBRATION = "sim-calibration-secret-dev-only"
SECRET_PROGRAMMING = "sim-programming-secret-dev-only"

NRC_CONDITIONS_NOT_CORRECT = 0x22


@pytest.fixture
def ecu_client():
    ecu = VirtualECU()
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


def _do_calibration_auth(client):
    """Helper: complete the full CALIBRATION 0x27 positive path."""
    client.send_diagnostic_session_control(EXTENDED_SESSION)
    resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
    key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_CALIBRATION)
    return client.send_key(SF_CALIBRATION_SEND_KEY, key)


def _do_programming_auth(client):
    """Helper: complete the full ECU_PROGRAMMING 0x27 positive path."""
    client.send_diagnostic_session_control(EXTENDED_SESSION)
    client.send_diagnostic_session_control(PROGRAMMING_SESSION)
    resp = client.request_seed(SF_PROGRAMMING_REQUEST_SEED)
    key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_PROGRAMMING)
    return client.send_key(SF_PROGRAMMING_SEND_KEY, key)


@pytest.mark.sim
class TestTC04KeyValidation:
    """TC-04: 0x27 SecurityAccess — Key Validation, Positive Path"""

    # ------------------------------------------------------------------
    # REQ-013 — HMAC-SHA256 key derivation produces the accepted key
    # ------------------------------------------------------------------

    def test_req013_hmac_sha256_key_accepted_for_calibration(self, ecu_client):
        """REQ-013: HMAC-SHA256(seed, shared_secret) is the correct key for CALIBRATION."""
        resp = _do_calibration_auth(ecu_client)
        assert resp["positive"] is True

    def test_req013_hmac_sha256_key_accepted_for_programming(self, ecu_client):
        """REQ-013: HMAC-SHA256(seed, shared_secret) is the correct key for ECU_PROGRAMMING."""
        resp = _do_programming_auth(ecu_client)
        assert resp["positive"] is True

    # ------------------------------------------------------------------
    # REQ-014 — Correct key grants the requested access level
    # ------------------------------------------------------------------

    def test_req014_calibration_access_granted(self, ecu_client):
        """REQ-014: Correct key grants CALIBRATION access level."""
        resp = _do_calibration_auth(ecu_client)
        assert resp["positive"] is True
        assert resp["access_level"] == "CALIBRATION"

    def test_req014_ecu_programming_access_granted(self, ecu_client):
        """REQ-014: Correct key grants ECU_PROGRAMMING access level."""
        resp = _do_programming_auth(ecu_client)
        assert resp["positive"] is True
        assert resp["access_level"] == "ECU_PROGRAMMING"

    # ------------------------------------------------------------------
    # REQ-016 — Constant-time key comparison (code gate)
    # ------------------------------------------------------------------

    def test_req016_key_comparison_uses_hmac_compare_digest(self):
        """REQ-016: crypto_backend.constant_time_compare is implemented with hmac.compare_digest."""
        import inspect
        source = inspect.getsource(crypto_backend.constant_time_compare)
        assert "compare_digest" in source

    # ------------------------------------------------------------------
    # REQ-019 — Subfunction byte determines access level mapping
    # ------------------------------------------------------------------

    def test_req019_subfunction_01_02_maps_to_calibration(self, ecu_client):
        """REQ-019: Subfunctions 0x01 (requestSeed) / 0x02 (sendKey) map to CALIBRATION."""
        resp = _do_calibration_auth(ecu_client)
        assert resp["access_level"] == "CALIBRATION"

    def test_req019_subfunction_03_04_maps_to_ecu_programming(self, ecu_client):
        """REQ-019: Subfunctions 0x03 (requestSeed) / 0x04 (sendKey) map to ECU_PROGRAMMING."""
        resp = _do_programming_auth(ecu_client)
        assert resp["access_level"] == "ECU_PROGRAMMING"

    # ------------------------------------------------------------------
    # Acceptance criterion 5 — access level persists in ECU state
    # ------------------------------------------------------------------

    def test_access_level_set_in_ecu_state_after_calibration(self, ecu_client):
        """AC-5: ECU reports CALIBRATION access level after successful sendKey."""
        _do_calibration_auth(ecu_client)
        level = ecu_client.get_access_level()
        assert level["access_level"] == "CALIBRATION"

    def test_access_level_set_in_ecu_state_after_programming(self, ecu_client):
        """AC-5: ECU reports ECU_PROGRAMMING access level after successful sendKey."""
        _do_programming_auth(ecu_client)
        level = ecu_client.get_access_level()
        assert level["access_level"] == "ECU_PROGRAMMING"
