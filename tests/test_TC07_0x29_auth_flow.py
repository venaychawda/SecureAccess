"""
TC-07 — 0x29 Authentication Flow: Unidirectional, Bidirectional, deAuthenticate

Requirements : REQ-021, REQ-025, REQ-026, REQ-028
Acceptance criteria:
  1. Unidirectional flow (tester cert only) grants ENGINEERING access.
  2. Bidirectional flow (tester + ECU cert exchange) grants FULL_ACCESS.
  3. ECU presents valid certificate during bidirectional flow.
  4. deAuthenticate revokes 0x29-granted access level.
  5. Access level returns to pre-auth state after deAuthenticate.
  6. 0x29 in Default Session returns NRC 0x22.
"""
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.hal.cert_store_sim import CertStore
from sim.protocol.client import DiagnosticClient

EXTENDED_SESSION    = 0x03
PROGRAMMING_SESSION = 0x02

NRC_CONDITIONS_NOT_CORRECT = 0x22
NONCE_SIZE_BYTES = 16   # from ecu_policy.json


@pytest.fixture
def cert_store():
    return CertStore.generate_in_memory()


@pytest.fixture
def ecu_client(cert_store):
    ecu = VirtualECU(cert_store=cert_store)
    ecu.start()
    client = DiagnosticClient(host="127.0.0.1", port=ecu.port)
    client.connect()
    yield client
    client.disconnect()
    ecu.stop()


def _do_unidirectional_auth(client, cert_store):
    """Complete the full unidirectional 0x29 flow (Extended session)."""
    client.send_diagnostic_session_control(EXTENDED_SESSION)
    resp1 = client.communicate_certificate(cert_store.tester_cert_pem)
    challenge = bytes(resp1["challenge"])
    proof = crypto_backend.sign_ecdsa(cert_store.tester_key, challenge)
    return client.verify_proof(proof)


def _do_bidirectional_auth(client, cert_store):
    """Complete the full bidirectional 0x29 flow (Programming session)."""
    client.send_diagnostic_session_control(EXTENDED_SESSION)
    client.send_diagnostic_session_control(PROGRAMMING_SESSION)
    resp1 = client.communicate_certificate(cert_store.tester_cert_pem)
    challenge = bytes(resp1["challenge"])
    proof = crypto_backend.sign_ecdsa(cert_store.tester_key, challenge)
    return resp1, client.verify_proof(proof)


@pytest.mark.sim
class TestTC07AuthFlow:
    """TC-07: 0x29 Authentication Flow"""

    # REQ-025 — Unidirectional flow → ENGINEERING
    # ---------------------------------------------------------------

    def test_req025_unidirectional_flow_grants_engineering(self, ecu_client, cert_store):
        """REQ-025: Full unidirectional flow in Extended Session grants ENGINEERING access."""
        resp = _do_unidirectional_auth(ecu_client, cert_store)
        assert resp["positive"] is True
        assert resp["access_level"] == "ENGINEERING"

    def test_req025_communicate_certificate_returns_challenge(self, ecu_client, cert_store):
        """REQ-025: communicateCertificate positive response includes a nonce challenge."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is True
        assert "challenge" in resp
        assert len(bytes(resp["challenge"])) == NONCE_SIZE_BYTES

    def test_req025_default_session_returns_nrc_0x22(self, ecu_client, cert_store):
        """REQ-025: 0x29 communicateCertificate in Default Session returns NRC 0x22."""
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is False
        assert resp["nrc"] == NRC_CONDITIONS_NOT_CORRECT

    # REQ-026 — Bidirectional flow → FULL_ACCESS
    # ---------------------------------------------------------------

    def test_req026_bidirectional_flow_grants_full_access(self, ecu_client, cert_store):
        """REQ-026: Full bidirectional flow in Programming Session grants FULL_ACCESS."""
        _, resp = _do_bidirectional_auth(ecu_client, cert_store)
        assert resp["positive"] is True
        assert resp["access_level"] == "FULL_ACCESS"

    # REQ-021 — ECU certificate issuance
    # ---------------------------------------------------------------

    def test_req021_ecu_presents_cert_in_bidirectional_flow(self, ecu_client, cert_store):
        """REQ-021: ECU includes its certificate in the bidirectional communicateCertificate response."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        ecu_client.send_diagnostic_session_control(PROGRAMMING_SESSION)
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is True
        assert resp.get("ecu_cert") is not None
        ecu_cert = x509.load_pem_x509_certificate(resp["ecu_cert"].encode())
        cn = ecu_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "VirtualECU-SAL-001"

    def test_req021_no_ecu_cert_in_unidirectional_flow(self, ecu_client, cert_store):
        """REQ-021: ECU does NOT send its certificate in unidirectional flow."""
        ecu_client.send_diagnostic_session_control(EXTENDED_SESSION)
        resp = ecu_client.communicate_certificate(cert_store.tester_cert_pem)
        assert resp["positive"] is True
        assert resp.get("ecu_cert") is None

    # REQ-028 — deAuthenticate
    # ---------------------------------------------------------------

    def test_req028_deauthenticate_revokes_access_level(self, ecu_client, cert_store):
        """REQ-028: deAuthenticate clears the 0x29-granted access level."""
        _do_unidirectional_auth(ecu_client, cert_store)
        ecu_client.deauthenticate()
        result = ecu_client.get_auth_access_level()
        assert result["access_level"] is None

    def test_req028_session_preserved_after_deauthenticate(self, ecu_client, cert_store):
        """REQ-028: deAuthenticate revokes access level but keeps the session active."""
        _do_unidirectional_auth(ecu_client, cert_store)
        ecu_client.deauthenticate()
        state = ecu_client.get_session_state()
        assert state["session_id"] == EXTENDED_SESSION
