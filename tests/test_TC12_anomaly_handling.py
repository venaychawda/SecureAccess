"""
TC-12 — Anomaly and Tamper Handling

Requirements : REQ-047, REQ-048, REQ-049, REQ-050
Acceptance criteria:
  1. Truncated UDS PDU returns NRC 0x13 without crash.
  2. Zero-length payload returns NRC 0x13.
  3. sendKey in Default Session returns NRC 0x22.
  4. requestSeed during active lockout returns NRC 0x36.
  5. Brute-force flag raised after MAX_AUTH_ATTEMPTS across multiple sessions.
  6. Cert with future notBefore rejected.
  7. Cert with invalid/non-EC public key rejected without crash.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from sim.core.ecu import VirtualECU
from sim.hal.cert_store_sim import CertStore
from sim.protocol.client import DiagnosticClient

EXTENDED_SESSION = 0x03
DEFAULT_SESSION  = 0x01

NRC_INCORRECT_FORMAT    = 0x13
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_EXCEEDED_ATTEMPTS   = 0x36
NRC_CERT_EXPIRED        = 0x75

MAX_ATTEMPTS = 3    # from ecu_policy.json
WRONG_KEY    = bytes(32)
_NOW = datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture
def cert_store():
    return CertStore.generate_in_memory()


@pytest.fixture
def client(cert_store):
    ecu = VirtualECU(cert_store=cert_store, required_delay_seconds=0)
    ecu.start()
    c = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    c.connect()
    yield c
    c.disconnect()
    ecu.stop()


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.mark.sim
class TestTC12AnomalyHandling:
    """TC-12: Anomaly and Tamper Handling"""

    # REQ-047 — Malformed request → NRC 0x13
    # ---------------------------------------------------------------

    def test_req047_zero_length_session_control_pdu_returns_nrc_0x13(self, client):
        """REQ-047: 0x10 with zero-length payload returns NRC 0x13."""
        resp = client.send_uds_pdu(0x10, [])
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_INCORRECT_FORMAT

    def test_req047_truncated_security_access_pdu_returns_nrc_0x13(self, client):
        """REQ-047: 0x27 with zero-length payload (no subfunction byte) returns NRC 0x13."""
        resp = client.send_uds_pdu(0x27, [])
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_INCORRECT_FORMAT

    def test_req047_oversized_session_control_pdu_returns_nrc_0x13(self, client):
        """REQ-047: 0x10 with extra bytes beyond the expected single session ID → NRC 0x13."""
        resp = client.send_uds_pdu(0x10, [0x03, 0xFF])  # two bytes instead of one
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_INCORRECT_FORMAT

    def test_req047_unknown_service_id_returns_nrc_0x13(self, client):
        """REQ-047: Unrecognised service ID returns NRC 0x13."""
        resp = client.send_uds_pdu(0xFE, [0x01, 0x02])
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_INCORRECT_FORMAT

    def test_req047_ecu_functional_after_malformed_request(self, client):
        """REQ-047: ECU continues to operate correctly after receiving a malformed PDU."""
        client.send_uds_pdu(0x10, [])          # malformed — no crash
        resp = client.send_uds_pdu(0x10, [0x03])  # valid — Extended session
        assert resp["positive"] is True

    # REQ-048 — Out-of-sequence service call → NRC 0x24 / 0x22
    # ---------------------------------------------------------------

    def test_req048_sendkey_in_default_session_returns_nrc_0x22(self, client):
        """REQ-048: sendKey issued in Default Session (no elevated session) → NRC 0x22."""
        resp = client.send_key(0x02, WRONG_KEY)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    def test_req048_requestseed_during_lockout_returns_nrc_0x36(self, client):
        """REQ-048: requestSeed during active lockout returns NRC 0x36."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        for _ in range(MAX_ATTEMPTS):
            client.request_seed(0x01)
            client.send_key(0x02, WRONG_KEY)
        resp = client.request_seed(0x01)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_EXCEEDED_ATTEMPTS

    # REQ-049 — Brute-force across sessions (SHOULD)
    # ---------------------------------------------------------------

    def test_req049_brute_force_lockout_accumulates_across_sessions(self, client):
        """REQ-049: MAX_ATTEMPTS failures spread across session resets still triggers lockout."""
        for _ in range(MAX_ATTEMPTS):
            client.send_diagnostic_session_control(EXTENDED_SESSION)
            client.request_seed(0x01)
            client.send_key(0x02, WRONG_KEY)        # 1 failure per session
            client.send_diagnostic_session_control(DEFAULT_SESSION)   # session reset
        # Counter should now be at MAX_ATTEMPTS → locked
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = client.request_seed(0x01)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_EXCEEDED_ATTEMPTS

    # REQ-050 — Invalid certificate injection handled without crash
    # ---------------------------------------------------------------

    def test_req050_future_notbefore_cert_rejected(self, client, cert_store):
        """REQ-050: Cert whose notBefore is in the future is rejected with NRC 0x75."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        tester_key = ec.generate_private_key(ec.SECP256R1())
        future_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FutureTester")]))
            .issuer_name(cert_store.root_ca_cert.subject)
            .public_key(tester_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW + datetime.timedelta(days=30))
            .not_valid_after(_NOW + datetime.timedelta(days=395))
            .sign(cert_store.root_ca_key, hashes.SHA256())
        )
        resp = client.communicate_certificate(_pem(future_cert))
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CERT_EXPIRED

    def test_req050_cert_with_rsa_key_rejected_without_crash(self, client, cert_store):
        """REQ-050: Cert using an RSA key (not ECDSA P-256) is rejected without crashing."""
        client.send_diagnostic_session_control(EXTENDED_SESSION)
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSATester")]))
            .issuer_name(cert_store.root_ca_cert.subject)
            .public_key(rsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=365))
            .sign(rsa_key, hashes.SHA256())
        )
        resp = client.communicate_certificate(_pem(rsa_cert))
        # Must not crash; must return a negative response with an appropriate NRC
        assert resp["positive"] is False
        assert resp.get("nrc") in {0x73, 0x76, 0x78}
