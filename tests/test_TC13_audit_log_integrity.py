"""
TC-13 — Audit Log Integrity

Requirements : REQ-051, REQ-052, REQ-053
Acceptance criteria:
  1. Every auth attempt (success and failure) produces a JSON log entry.
  2. Log entry contains: timestamp, service_id, access_level, client_id, result, nrc_code.
  3. Hash chain verification passes over a log of 100 entries.
  4. Modifying any log entry breaks hash chain verification.
  5. Session start, timeout, explicit-end, and tamper-reset are logged as distinct event types.
  6. Log entries are ordered and non-repudiable.
"""
import copy

import pytest

from sim.core.audit_logger import AuditLogger
from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.hal.cert_store_sim import CertStore
from sim.protocol.client import DiagnosticClient

EXTENDED_SESSION    = 0x03
PROGRAMMING_SESSION = 0x02
DEFAULT_SESSION     = 0x01

SF_CALIBRATION_REQUEST_SEED = 0x01
SF_CALIBRATION_SEND_KEY     = 0x02
SECRET_CALIBRATION = "sim-calibration-secret-dev-only"
WRONG_KEY = bytes(32)

REQUIRED_FIELDS = [
    "timestamp", "event_type", "service_id", "access_level",
    "client_id", "result", "nrc_code", "prev_hash", "entry_hash",
]


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


def _do_calibration_auth(client):
    resp = client.request_seed(SF_CALIBRATION_REQUEST_SEED)
    key = crypto_backend.compute_key_hmac_sha256(resp["seed"], SECRET_CALIBRATION)
    client.send_key(SF_CALIBRATION_SEND_KEY, key)


@pytest.mark.sim
class TestTC13AuditLogIntegrity:
    """TC-13: Audit Log Integrity"""

    # REQ-051 — Structured log per auth event
    # ---------------------------------------------------------------

    def test_req051_auth_success_produces_log_entry(self, ecu_client):
        """REQ-051: Successful 0x27 sendKey produces an AUTH_SUCCESS log entry."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_calibration_auth(ecu_client)
        entries = ecu_client.get_audit_log()["entries"]
        auth_entries = [e for e in entries if e["event_type"] == "AUTH_SUCCESS"]
        assert len(auth_entries) >= 1

    def test_req051_auth_failure_produces_log_entry(self, ecu_client):
        """REQ-051: Failed 0x27 sendKey produces an AUTH_FAILURE log entry."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
        entries = ecu_client.get_audit_log()["entries"]
        fail_entries = [e for e in entries if e["event_type"] == "AUTH_FAILURE"]
        assert len(fail_entries) >= 1
        assert fail_entries[-1]["nrc_code"] == hex(0x35)

    def test_req051_log_entry_contains_all_required_fields(self, ecu_client):
        """REQ-051: Each log entry contains all required fields from the policy."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_calibration_auth(ecu_client)
        entries = ecu_client.get_audit_log()["entries"]
        for entry in entries:
            for field in REQUIRED_FIELDS:
                assert field in entry, f"Missing field '{field}' in entry {entry}"

    def test_req051_auth_failure_nrc_code_recorded(self, ecu_client):
        """REQ-051: Auth failure log entry records the NRC code."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.request_seed(SF_CALIBRATION_REQUEST_SEED)
        ecu_client.send_key(SF_CALIBRATION_SEND_KEY, WRONG_KEY)
        entries = ecu_client.get_audit_log()["entries"]
        failure = next(e for e in entries if e["event_type"] == "AUTH_FAILURE")
        assert failure["nrc_code"] is not None

    # REQ-052 — Hash chain integrity
    # ---------------------------------------------------------------

    def test_req052_chain_verifies_over_100_entries(self, ecu_client):
        """REQ-052: Hash chain verification passes for a log of >= 100 entries."""
        # Generate 100 entries via 50 session round-trips
        for _ in range(50):
            ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
            ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        result = ecu_client.get_audit_log()
        entries = result["entries"]
        assert len(entries) >= 100
        assert AuditLogger.verify_chain(entries) is True

    def test_req052_tampered_entry_breaks_chain(self, ecu_client):
        """REQ-052: Modifying any log entry makes hash chain verification fail."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        _do_calibration_auth(ecu_client)
        entries = ecu_client.get_audit_log()["entries"]
        assert AuditLogger.verify_chain(entries) is True  # pristine chain passes

        # Tamper: alter the result field of the first entry
        tampered = copy.deepcopy(entries)
        tampered[0]["result"] = "TAMPERED"
        assert AuditLogger.verify_chain(tampered) is False

    def test_req052_genesis_hash_is_all_zeros(self, ecu_client):
        """REQ-052: First entry's prev_hash is the all-zeros genesis hash."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        entries = ecu_client.get_audit_log()["entries"]
        assert entries[0]["prev_hash"] == "0" * 64

    # REQ-053 — Session lifecycle events
    # ---------------------------------------------------------------

    def test_req053_session_start_logged_on_escalation(self, ecu_client):
        """REQ-053: Transitioning from Default to Extended logs a SESSION_START event."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        entries = ecu_client.get_audit_log()["entries"]
        starts = [e for e in entries if e["event_type"] == "SESSION_START"]
        assert len(starts) >= 1

    def test_req053_session_end_logged_on_explicit_downgrade(self, ecu_client):
        """REQ-053: Explicit session downgrade to Default logs a SESSION_END event."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        entries = ecu_client.get_audit_log()["entries"]
        ends = [e for e in entries if e["event_type"] == "SESSION_END"]
        assert len(ends) >= 1

    def test_req053_tamper_reset_logged(self, ecu_client):
        """REQ-053: Tamper-triggered session reset logs a SESSION_TAMPER_RESET event."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.inject_tamper_event()
        entries = ecu_client.get_audit_log()["entries"]
        tamper_entries = [e for e in entries if e["event_type"] == "SESSION_TAMPER_RESET"]
        assert len(tamper_entries) >= 1

    def test_req053_session_events_are_distinct_event_types(self, ecu_client):
        """REQ-053: SESSION_START, SESSION_END, and SESSION_TAMPER_RESET are distinct types."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(DEFAULT_SESSION)
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.inject_tamper_event()
        entries = ecu_client.get_audit_log()["entries"]
        event_types = {e["event_type"] for e in entries}
        assert "SESSION_START"        in event_types
        assert "SESSION_END"          in event_types
        assert "SESSION_TAMPER_RESET" in event_types
