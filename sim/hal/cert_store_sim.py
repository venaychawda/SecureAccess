"""
cert_store_sim.py — Simulated certificate store for the Virtual ECU.

Holds the Root CA, ECU certificate, and default tester certificate.
Call CertStore.generate_in_memory() to create a fresh PKI for each test
or each ECU start; the files-on-disk path is used in production-like runs.

root_ca_key is exposed so tests can sign ad-hoc tester certs (valid, expired,
forged-issuer, etc.) without touching the ECU internals.
"""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_VALIDITY_ROOT_CA = 3650   # days
_VALIDITY_ECU     = 730
_VALIDITY_TESTER  = 365


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _self_signed_ca(cn: str, key, not_before, not_after) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def _signed_leaf(cn: str, signing_key, issuer_cert, subject_key, not_before, not_after) -> x509.Certificate:
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


class CertStore:
    """In-memory simulated certificate store for Phase 1 testing."""

    def __init__(
        self,
        root_ca_cert: x509.Certificate,
        root_ca_key,
        ecu_cert: x509.Certificate,
        ecu_key,
        tester_cert: x509.Certificate,
        tester_key,
        revoked_thumbprints: list[str] | None = None,
    ):
        self.root_ca_cert = root_ca_cert
        self.root_ca_key  = root_ca_key    # exposed for test cert signing
        self.ecu_cert     = ecu_cert
        self.ecu_key      = ecu_key
        self.tester_cert  = tester_cert
        self.tester_key   = tester_key
        self._revoked: set[str] = set(revoked_thumbprints or [])

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def tester_cert_pem(self) -> str:
        return self.tester_cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def ecu_cert_pem(self) -> str:
        return self.ecu_cert.public_bytes(serialization.Encoding.PEM).decode()

    # ------------------------------------------------------------------
    # CRL management (mutable for test injection)
    # ------------------------------------------------------------------

    def is_revoked(self, thumbprint_hex: str) -> bool:
        return thumbprint_hex in self._revoked

    def add_revoked_thumbprint(self, thumbprint_hex: str) -> None:
        self._revoked.add(thumbprint_hex)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def generate_in_memory(cls, revoked_thumbprints: list[str] | None = None) -> "CertStore":
        """Generate a complete ECDSA P-256 PKI hierarchy in memory."""
        now = _utc_now()

        root_key  = ec.generate_private_key(ec.SECP256R1())
        root_cert = _self_signed_ca(
            "SecureAccess-Lab-Root-CA", root_key,
            now - datetime.timedelta(days=1),
            now + datetime.timedelta(days=_VALIDITY_ROOT_CA),
        )

        ecu_key  = ec.generate_private_key(ec.SECP256R1())
        ecu_cert = _signed_leaf(
            "VirtualECU-SAL-001", root_key, root_cert, ecu_key,
            now - datetime.timedelta(days=1),
            now + datetime.timedelta(days=_VALIDITY_ECU),
        )

        tester_key  = ec.generate_private_key(ec.SECP256R1())
        tester_cert = _signed_leaf(
            "DiagnosticTester-SAL-001", root_key, root_cert, tester_key,
            now - datetime.timedelta(days=1),
            now + datetime.timedelta(days=_VALIDITY_TESTER),
        )

        return cls(root_cert, root_key, ecu_cert, ecu_key, tester_cert, tester_key, revoked_thumbprints)
