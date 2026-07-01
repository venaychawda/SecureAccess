"""
TC-01 — Session State Machine: Basic Transitions

Requirements : REQ-001, REQ-002, REQ-003, REQ-004, REQ-009
Acceptance criteria:
  1. ECU initialises in Default Session on reset.
  2. Default → Extended transition accepted.
  3. Direct Default → Programming rejected with NRC 0x22.
  4. Extended → Programming accepted.
  5. Invalid session byte rejected with NRC 0x22.
  6. Session state persists correctly across sequential requests.
"""
import pytest

from sim.core.ecu import VirtualECU
from sim.protocol.client import DiagnosticClient

# Session IDs (ecu_policy.json)
DEFAULT_SESSION = 0x01
EXTENDED_SESSION = 0x03
PROGRAMMING_SESSION = 0x02

# UDS Negative Response Codes
NRC_CONDITIONS_NOT_CORRECT = 0x22


@pytest.fixture
def ecu_client():
    """Start VirtualECU, yield a connected DiagnosticClient, then tear down."""
    ecu = VirtualECU()
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


@pytest.mark.sim
class TestTC01SessionTransitions:
    """TC-01: Session State Machine — Basic Transitions"""

    # ------------------------------------------------------------------
    # REQ-001 — Default Session at Power-Up
    # ------------------------------------------------------------------

    def test_req001_power_up_initialises_default_session(self, ecu_client):
        """ECU reports Default Session (0x01) immediately after reset."""
        state = ecu_client.get_session_state()
        assert state["session_id"] == DEFAULT_SESSION

    # ------------------------------------------------------------------
    # REQ-002 — Default → Extended accepted
    # ------------------------------------------------------------------

    def test_req002_default_to_extended_accepted(self, ecu_client):
        """Valid 0x10 0x03 request transitions session from Default to Extended."""
        resp = ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        assert resp["positive"] is True
        assert resp["session_id"] == EXTENDED_SESSION

    # ------------------------------------------------------------------
    # REQ-003 — Default → Programming requires prior Extended or 0x29
    # ------------------------------------------------------------------

    def test_req003_direct_default_to_programming_rejected(self, ecu_client):
        """Direct Default → Programming returns NRC 0x22 (no prior Extended or 0x29)."""
        resp = ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    def test_req003_extended_to_programming_accepted(self, ecu_client):
        """Extended → Programming accepted after valid Default → Extended transition."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        assert resp["positive"] is True
        assert resp["session_id"] == PROGRAMMING_SESSION

    # ------------------------------------------------------------------
    # REQ-004 — Reject out-of-sequence / invalid session escalation
    # ------------------------------------------------------------------

    def test_req004_invalid_session_id_rejected(self, ecu_client):
        """Unknown session byte (0xFF) returns NRC 0x22."""
        resp = ecu_client.send_diagnostic_session_control(0xFF)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    def test_req004_programming_from_default_is_nrc_0x22(self, ecu_client):
        """Programming session from Default Session returns NRC 0x22 (sequence violation)."""
        resp = ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    # ------------------------------------------------------------------
    # REQ-009 — Session state persists across sequential requests
    # ------------------------------------------------------------------

    def test_req009_extended_session_persists_across_multiple_requests(self, ecu_client):
        """Extended session state is maintained across three consecutive state queries."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        for _ in range(3):
            state = ecu_client.get_session_state()
            assert state["session_id"] == EXTENDED_SESSION

    def test_req009_programming_session_persists_after_transition(self, ecu_client):
        """Programming session state persists after Default → Extended → Programming path."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        state = ecu_client.get_session_state()
        assert state["session_id"] == PROGRAMMING_SESSION
