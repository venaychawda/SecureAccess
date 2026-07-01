"""
TC-09 — Lockout and Delay Timer

Requirements : REQ-036, REQ-037, REQ-038, REQ-039, REQ-040, REQ-041
Acceptance criteria:
  1. Attempt counter increments independently per access level.
  2. NRC 0x37 if next attempt before REQUIRED_DELAY_SECONDS expires.
  3. NRC 0x36 after MAX_AUTH_ATTEMPTS consecutive failures.
  4. Lockout persists for LOCKOUT_DURATION_SECONDS.
  5. Attempt counter resets to 0 on successful auth.
  6. Lockout on CALIBRATION does not affect ECU_PROGRAMMING.
  7. Lockout state persists across simulated session reset.
"""
import time

import pytest

from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.protocol.client import DiagnosticClient

EXTENDED_SESSION    = 0x03
PROGRAMMING_SESSION = 0x02
DEFAULT_SESSION     = 0x01

SF_CALIBRATION_REQUEST_SEED = 0x01
SF_CALIBRATION_SEND_KEY     = 0x02
SF_PROGRAMMING_REQUEST_SEED = 0x03
SF_PROGRAMMING_SEND_KEY     = 0x04

SECRET_CALIBRATION = "sim-calibration-secret-dev-only"
SECRET_PROGRAMMING = "sim-programming-secret-dev-only"

NRC_INVALID_KEY         = 0x35
NRC_EXCEEDED_ATTEMPTS   = 0x36
NRC_DELAY_NOT_EXPIRED   = 0x37

MAX_ATTEMPTS   = 3    # from ecu_policy.json
SHORT_LOCKOUT  = 3    # seconds — injected for timer tests
SHORT_DELAY    = 1    # seconds — injected for timer tests
WRONG_KEY      = bytes(32)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def ecu():
    """ECU with zero inter-attempt delay (no NRC 0x37) for count/lockout tests."""
    _ecu = VirtualECU(required_delay_seconds=0, lockout_duration_seconds=SHORT_LOCKOUT)
    _ecu.start()
    yield _ecu
    _ecu.stop()


@pytest.fixture
def client(ecu):
    c = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    c.connect()
    yield c
    c.disconnect()


@pytest.fixture
def ecu_with_delay():
    """ECU with short delay and short lockout for @slow timer tests."""
    _ecu = VirtualECU(required_delay_seconds=SHORT_DELAY, lockout_duration_seconds=SHORT_LOCKOUT)
    _ecu.start()
    yield _ecu
    _ecu.stop()


@pytest.fixture
def client_with_delay(ecu_with_delay):
    c = DiagnosticClient(host="127.0.0.1", port=ecu_with_delay.port)
    c.connect()
    yield c
    c.disconnect()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _fail_n(client, n):
    """Make n failed CALIBRATION sendKey attempts (ECU must have delay=0)."""
    for _ in range(n):
        resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        if not resp.get("positive"):
            return resp
        client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
    return None


def _succeed_calibration(client):
    resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
    key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_CALIBRATION)
    return client.send_key(SF_CALIBRATION_SEND_KEY, key)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.sim
class TestTC09LockoutAndDelay:
    """TC-09: Lockout and Delay Timer"""

    # REQ-037 — Lockout after MAX_AUTH_ATTEMPTS
    # ---------------------------------------------------------------

    def test_req037_lockout_triggered_after_max_attempts(self, client):
        """REQ-037: requestSeed returns NRC 0x36 after MAX_AUTH_ATTEMPTS failures."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, MAX_ATTEMPTS)
        resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_EXCEEDED_ATTEMPTS

    def test_req037_nrc_0x36_persists_while_locked(self, client):
        """REQ-037: Repeated requests during lockout all return NRC 0x36."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, MAX_ATTEMPTS)
        for _ in range(3):
            resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
            assert resp["nrc"] == NRC_EXCEEDED_ATTEMPTS

    # REQ-038 — Required delay between attempts
    # ---------------------------------------------------------------

    @pytest.mark.slow
    def test_req038_nrc_0x37_if_retry_before_delay_expires(self, client_with_delay):
        """REQ-038: Immediate retry after failure returns NRC 0x37."""
        client_with_delay.send_diagnostic_session_control(EXTENDED_SESSION)
        client_with_delay.request_seed(SF_CALIBRATION_REQUEST_SEED)
        client_with_delay.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)  # fail #1
        resp = client_with_delay.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_DELAY_NOT_EXPIRED

    @pytest.mark.slow
    def test_req038_retry_allowed_after_delay_expires(self, client_with_delay):
        """REQ-038: requestSeed succeeds once REQUIRED_DELAY_SECONDS has elapsed."""
        client_with_delay.send_diagnostic_session_control(EXTENDED_SESSION)
        client_with_delay.request_seed(SF_CALIBRATION_REQUEST_SEED)
        client_with_delay.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
        time.sleep(SHORT_DELAY + 0.5)
        resp = client_with_delay.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is True  # delay elapsed, seed issued

    # REQ-039 — Lockout duration enforcement
    # ---------------------------------------------------------------

    @pytest.mark.slow
    def test_req039_lockout_expires_after_duration(self, client):
        """REQ-039: Access is restored after LOCKOUT_DURATION_SECONDS elapses."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, MAX_ATTEMPTS)
        assert client.request_seed(SF_CALIBRATION_REQUEST_SEED)["nrc"] == NRC_EXCEEDED_ATTEMPTS
        time.sleep(SHORT_LOCKOUT + 0.5)
        resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is True  # lockout expired

    # REQ-040 — Attempt counter reset on success
    # ---------------------------------------------------------------

    def test_req040_counter_resets_to_zero_on_success(self, client):
        """REQ-040: Attempt counter resets to 0 after a successful sendKey."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, MAX_ATTEMPTS - 1)          # 2 failures
        _succeed_calibration(client)               # success → counter = 0
        assert client.get_attempt_counter("CALIBRATION")["count"] == 0

    def test_req040_max_attempts_resets_after_success(self, client):
        """REQ-040: After counter reset, MAX_ATTEMPTS new failures are needed to re-lock."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, MAX_ATTEMPTS - 1)
        _succeed_calibration(client)               # counter reset
        # Need MAX_ATTEMPTS new failures to lock again
        _fail_n(client, MAX_ATTEMPTS - 1)          # not locked yet
        resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is True

    # REQ-036 — Counters independent per access level
    # ---------------------------------------------------------------

    def test_req036_calibration_lockout_does_not_affect_programming(self, client):
        """REQ-036: Locking CALIBRATION (0x01/0x02) does not block ECU_PROGRAMMING (0x03/0x04)."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, MAX_ATTEMPTS)              # lock CALIBRATION
        # Transition to Programming session; ECU_PROGRAMMING must be unaffected
        client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        resp = client.request_seed(SF_PROGRAMMING_REQUEST_SEED)
        assert resp["positive"] is True

    def test_req036_attempt_counters_are_independent(self, client):
        """REQ-036: CALIBRATION failures do not increment ECU_PROGRAMMING counter."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, 2)
        assert client.get_attempt_counter("ECU_PROGRAMMING")["count"] == 0

    # REQ-041 — Lockout persists across session reset
    # ---------------------------------------------------------------

    def test_req041_lockout_persists_across_session_reset(self, client):
        """REQ-041: Lockout survives a session reset (simulated power-cycle bypass)."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        _fail_n(client, MAX_ATTEMPTS)
        # Simulate session reset: drop to Default then re-escalate
        client.send_diagnostic_session_control(DEFAULT_SESSION)
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_EXCEEDED_ATTEMPTS
