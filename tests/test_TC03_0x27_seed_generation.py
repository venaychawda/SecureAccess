"""
TC-03 — 0x27 SecurityAccess: Seed Generation

Requirements : REQ-010, REQ-011, REQ-012
Acceptance criteria:
  1. Each requestSeed returns a unique CHALLENGE_SIZE_BYTES seed.
  2. Seeds from 1000 consecutive requests are all unique.
  3. requestSeed in Default Session returns NRC 0x22.
  4. requestSeed in Extended Session returns positive response.
"""
import pytest

from sim.core.ecu import VirtualECU
from sim.protocol.client import DiagnosticClient

DEFAULT_SESSION = 0x01
EXTENDED_SESSION = 0x03
PROGRAMMING_SESSION = 0x02

# 0x27 subfunction bytes (odd = requestSeed, even = sendKey)
SF_CALIBRATION_REQUEST_SEED = 0x01    # CALIBRATION level, requires Extended session
SF_PROGRAMMING_REQUEST_SEED = 0x03    # ECU_PROGRAMMING level, requires Programming session

NRC_CONDITIONS_NOT_CORRECT = 0x22

# From ecu_policy.json → crypto.challenge_size_bytes
CHALLENGE_SIZE_BYTES = 32


@pytest.fixture
def ecu_client():
    ecu = VirtualECU()
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


@pytest.mark.sim
class TestTC03SeedGeneration:
    """TC-03: 0x27 SecurityAccess — Seed Generation"""

    # ------------------------------------------------------------------
    # REQ-012 — Session gating
    # ------------------------------------------------------------------

    def test_req012_seed_request_in_default_session_rejected(self, ecu_client):
        """REQ-012: requestSeed in Default Session returns NRC 0x22."""
        resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    def test_req012_calibration_seed_accepted_in_extended_session(self, ecu_client):
        """REQ-012: requestSeed (CALIBRATION) in Extended Session returns positive response."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is True
        assert "seed" in resp

    def test_req012_programming_seed_rejected_in_extended_session(self, ecu_client):
        """REQ-012: requestSeed (ECU_PROGRAMMING) in Extended Session returns NRC 0x22."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.request_seed(SF_PROGRAMMING_REQUEST_SEED)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    def test_req012_programming_seed_accepted_in_programming_session(self, ecu_client):
        """REQ-012: requestSeed (ECU_PROGRAMMING) in Programming Session returns positive response."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        resp = ecu_client.request_seed(SF_PROGRAMMING_REQUEST_SEED)
        assert resp["positive"] is True
        assert "seed" in resp

    # ------------------------------------------------------------------
    # REQ-010 — Seed uniqueness and size
    # ------------------------------------------------------------------

    def test_req010_seed_is_challenge_size_bytes(self, ecu_client):
        """REQ-010: Returned seed is exactly CHALLENGE_SIZE_BYTES (32) bytes."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert len(resp["seed"]) == CHALLENGE_SIZE_BYTES

    def test_req010_consecutive_seeds_are_unique(self, ecu_client):
        """REQ-010: 1000 consecutive requestSeed responses are all unique."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        seeds = set()
        for _ in range(1000):
            resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
            assert resp["positive"] is True
            seeds.add(bytes(resp["seed"]))
        assert len(seeds) == 1000

    # ------------------------------------------------------------------
    # REQ-011 — CSPRNG quality (statistical + implementation gate)
    # ------------------------------------------------------------------

    def test_req011_seed_is_nonzero(self, ecu_client):
        """REQ-011: A seed of all-zero bytes is statistically impossible from os.urandom."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        seed = bytes(resp["seed"])
        assert seed != bytes(CHALLENGE_SIZE_BYTES)

    def test_req011_crypto_backend_uses_os_urandom(self):
        """REQ-011: crypto_backend.generate_seed is implemented with os.urandom (code gate)."""
        import inspect
        from sim.hal import crypto_backend
        source = inspect.getsource(crypto_backend.generate_seed)
        assert "os.urandom" in source or "secrets" in source
        assert "random.random" not in source
