"""
TC-02 — Session Lifecycle: Timeout, Concurrency, Tamper

Requirements : REQ-005, REQ-006, REQ-007, REQ-008
Acceptance criteria:
  1. Session reverts to Default after SESSION_TIMEOUT_SECONDS inactivity.
  2. Valid request resets the inactivity timer.
  3. Second client rejected with NRC 0x22 while a session is already active.
  4. Injected tamper event immediately reverts session to Default.
"""
import time

import pytest

from sim.core.ecu import VirtualECU
from sim.protocol.client import DiagnosticClient

DEFAULT_SESSION = 0x01
EXTENDED_SESSION = 0x03
PROGRAMMING_SESSION = 0x02
NRC_CONDITIONS_NOT_CORRECT = 0x22

# Short timeout injected into the ECU so timer tests complete in seconds.
SHORT_TIMEOUT = 2


@pytest.fixture
def ecu():
    """VirtualECU with an accelerated inactivity timer for timer-dependent tests."""
    _ecu = VirtualECU(session_timeout_seconds=SHORT_TIMEOUT)
    _ecu.start()
    yield _ecu
    _ecu.stop()


@pytest.fixture
def client(ecu):
    """Primary DiagnosticClient connected to the test ECU."""
    c = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    c.connect()
    yield c
    c.disconnect()


@pytest.mark.sim
class TestTC02SessionLifecycle:
    """TC-02: Session Lifecycle — Timeout, Concurrency, Tamper"""

    # ------------------------------------------------------------------
    # REQ-005 — Session Timeout: revert to Default on inactivity
    # ------------------------------------------------------------------

    @pytest.mark.slow
    def test_req005_timeout_reverts_to_default(self, client):
        """REQ-005: Extended session reverts to Default after inactivity timeout."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        time.sleep(SHORT_TIMEOUT + 1)
        state = client.get_session_state()
        assert state["session_id"] == DEFAULT_SESSION

    @pytest.mark.slow
    def test_req005_programming_session_also_reverts(self, client):
        """REQ-005: Programming session also reverts to Default after timeout."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        time.sleep(SHORT_TIMEOUT + 1)
        state = client.get_session_state()
        assert state["session_id"] == DEFAULT_SESSION

    # ------------------------------------------------------------------
    # REQ-006 — Timer reset on activity
    # ------------------------------------------------------------------

    @pytest.mark.slow
    def test_req006_activity_resets_inactivity_timer(self, client):
        """REQ-006: A valid request before timeout resets the inactivity timer."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        time.sleep(SHORT_TIMEOUT - 0.5)        # almost at timeout, not yet
        client.send_diagnostic_session_control(EXTENDED_SESSION)  # reset timer
        time.sleep(SHORT_TIMEOUT - 0.5)        # same interval again from reset
        state = client.get_session_state()
        assert state["session_id"] == EXTENDED_SESSION  # still alive

    # ------------------------------------------------------------------
    # REQ-007 — Concurrent session rejection
    # ------------------------------------------------------------------

    def test_req007_second_client_rejected_while_session_active(self, ecu, client):
        """REQ-007: Second client gets NRC 0x22 while an elevated session is active."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        second = DiagnosticClient(host="127.0.0.1", port=ecu.port)
        second.connect()
        try:
            resp = second.send_diagnostic_session_control(EXTENDED_SESSION)
        finally:
            second.disconnect()
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    def test_req007_default_session_allows_new_client(self, ecu, client):
        """REQ-007: A second client CAN start a session when ECU is in Default (no active session)."""
        second = DiagnosticClient(host="127.0.0.1", port=ecu.port)
        second.connect()
        try:
            resp = second.send_diagnostic_session_control(EXTENDED_SESSION)
        finally:
            second.disconnect()
        assert resp["positive"] is True
        assert resp["session_id"] == EXTENDED_SESSION

    # ------------------------------------------------------------------
    # REQ-008 — Session invalidation on tamper event
    # ------------------------------------------------------------------

    def test_req008_tamper_event_reverts_to_default(self, client):
        """REQ-008: Tamper event immediately reverts Extended session to Default."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        client.inject_tamper_event()
        state = client.get_session_state()
        assert state["session_id"] == DEFAULT_SESSION

    def test_req008_tamper_during_programming_reverts_to_default(self, client):
        """REQ-008: Tamper event reverts Programming session to Default."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        client.inject_tamper_event()
        state = client.get_session_state()
        assert state["session_id"] == DEFAULT_SESSION

    def test_req008_new_session_possible_after_tamper(self, client):
        """REQ-008: After tamper reset, ECU accepts a fresh session escalation."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        client.inject_tamper_event()
        resp = client.send_diagnostic_session_control(EXTENDED_SESSION)
        assert resp["positive"] is True
        assert resp["session_id"] == EXTENDED_SESSION
