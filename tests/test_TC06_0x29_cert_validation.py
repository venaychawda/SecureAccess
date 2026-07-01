"""
TC-06 — 0x29 Authentication: Certificate Validation

Requirements : REQ-020, REQ-022, REQ-023, REQ-024, REQ-029
Acceptance criteria:
  1. Valid tester cert signed by Root CA is accepted.
  2. Cert signed by untrusted CA returns NRC 0x78.
  3. Expired cert returns NRC 0x75.
  4. Malformed cert returns NRC 0x73.
  5. Cert with forged ECDSA signature returns NRC 0x76.
  6. Cert on simulated CRL returns NRC 0x74.
  7. Future notBefore cert returns NRC 0x75.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sim.core.ecu import VirtualECU
from sim.hal.cert_store_sim import CertStore
from sim.protocol.client import DiagnosticClient

EXTENDED_SESSION = 0x03

NRC_CONDITIONS_NOT_CORRECT  = 0x22
NRC_UNSUPPORTED_CERT_FORMAT = 0x73
NRC_CERT_REVOKED            = 0x74
NRC_CERT_EXPIRED            = 0x75
NRC_CERT_SIG_INVALID        = 0x76
NRC_CERT_CHAIN_FAILED       = 0x78

_NOW = datetime.datetime.now(datetime.timezone.utc)


# ------------------------------------------------------------------
# Test helpers — build ad-hoc certificates for negative-path tests
# ------------------------------------------------------------------

def _leaf_cert(cn, signing_key, issuer_cert, subject_key, not_before, not_after):
    """Sign a leaf cert; issuer_cert.subject becomes the issuer field."""
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(signing_key, hashes.SHA256())
    )


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def cert_store():
    """Fresh in-memory PKI for each test (Root CA + ECU + tester certs)."""
    return CertStore.generate_in_memory()


@pytest.fixture
def ecu_client(cert_store):
    """VirtualECU initialised with the test PKI; yields a connected DiagnosticClient."""
    ecu = VirtualECU(cert_store=cert_store)
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.sim
class TestTC06CertValidation:
    """TC-06: 0x29 Certificate Validation"""

    # REQ-020 — Certificate chain validation
    # ---------------------------------------------------------------

    def test_req020_valid_tester_cert_accepted(self, ecu_client, cert_store):
        """REQ-020: Tester cert signed by the ECU's trusted Root CA is accepted."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is True

    def test_req020_untrusted_ca_cert_returns_nrc_0x78(self, ecu_client):
        """REQ-020: Cert signed by an unknown CA returns NRC 0x78 (chain fails)."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        untrusted_key = ec.generate_private_key(ec.SECP256R1())
        fake_ca = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake-CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake-CA")]))
            .public_key(untrusted_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(untrusted_key, hashes.SHA256())
        )
        victim_key = ec.generate_private_key(ec.SECP256R1())
        untrusted_cert = _leaf_cert(
            "FakeTester", untrusted_key, fake_ca, victim_key,
            _NOW - datetime.timedelta(days=1), _NOW + datetime.timedelta(days=365),
        )
        resp = ecu_client.communicate_certificate(_pem(untrusted_cert))
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CERT_CHAIN_FAILED

    # REQ-022 — Tester certificate signature verification
    # ---------------------------------------------------------------

    def test_req022_forged_signature_returns_nrc_0x76(self, ecu_client, cert_store):
        """REQ-022: Cert claiming Root CA issuer but signed with a different key → NRC 0x76."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        forger_key = ec.generate_private_key(ec.SECP256R1())
        victim_key  = ec.generate_private_key(ec.SECP256R1())
        # issuer_name = Root CA subject (passes chain check) but signed by forger_key
        forged = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ForgedTester")]))
            .issuer_name(cert_store.root_ca_cert.subject)
            .public_key(victim_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=365))
            .sign(forger_key, hashes.SHA256())
        )
        resp = ecu_client.communicate_certificate(_pem(forged))
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CERT_SIG_INVALID

    # REQ-023 — Certificate expiry check
    # ---------------------------------------------------------------

    def test_req023_expired_cert_returns_nrc_0x75(self, ecu_client, cert_store):
        """REQ-023: Cert whose notAfter is in the past returns NRC 0x75."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        tester_key = ec.generate_private_key(ec.SECP256R1())
        expired = _leaf_cert(
            "ExpiredTester",
            cert_store.root_ca_key, cert_store.root_ca_cert, tester_key,
            _NOW - datetime.timedelta(days=730),
            _NOW - datetime.timedelta(seconds=1),    # expired 1 second ago
        )
        resp = ecu_client.communicate_certificate(_pem(expired))
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CERT_EXPIRED

    def test_req023_future_notbefore_returns_nrc_0x75(self, ecu_client, cert_store):
        """REQ-023: Cert whose notBefore is in the future returns NRC 0x75."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        tester_key = ec.generate_private_key(ec.SECP256R1())
        future_cert = _leaf_cert(
            "FutureTester",
            cert_store.root_ca_key, cert_store.root_ca_cert, tester_key,
            _NOW + datetime.timedelta(days=30),      # not valid yet
            _NOW + datetime.timedelta(days=395),
        )
        resp = ecu_client.communicate_certificate(_pem(future_cert))
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CERT_EXPIRED

    # REQ-024 — Certificate format validation
    # ---------------------------------------------------------------

    def test_req024_malformed_cert_returns_nrc_0x73(self, ecu_client):
        """REQ-024: Unparseable / malformed certificate data returns NRC 0x73."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        garbage = "-----BEGIN CERTIFICATE-----\nTHISISNOTVALIDB64!!!\n-----END CERTIFICATE-----\n"
        resp = ecu_client.communicate_certificate(garbage)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_UNSUPPORTED_CERT_FORMAT

    # REQ-029 — Simulated CRL check
    # ---------------------------------------------------------------

    def test_req029_revoked_cert_returns_nrc_0x74(self, ecu_client, cert_store):
        """REQ-029: Cert whose SHA-256 thumbprint is on the CRL returns NRC 0x74."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        tester_key = ec.generate_private_key(ec.SECP256R1())
        revoked_cert = _leaf_cert(
            "RevokedTester",
            cert_store.root_ca_key, cert_store.root_ca_cert, tester_key,
            _NOW - datetime.timedelta(days=1), _NOW + datetime.timedelta(days=365),
        )
        thumbprint = revoked_cert.fingerprint(hashes.SHA256()).hex()
        cert_store.add_revoked_thumbprint(thumbprint)
        resp = ecu_client.communicate_certificate(_pem(revoked_cert))
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CERT_REVOKED
