"""
crypto_backend.py — HAL gateway for all cryptographic primitives.

sim/core/ MUST NOT call os.urandom, hmac, or cryptography directly.
All crypto goes through this module so the HAL boundary is enforced.
"""
import datetime
import hashlib
import hmac
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def generate_seed(size_bytes: int) -> bytes:
    """Return `size_bytes` of cryptographically random bytes (CSPRNG — os.urandom)."""
    return os.urandom(size_bytes)


def compute_key_hmac_sha256(seed: bytes, shared_secret: str) -> bytes:
    """Derive key = HMAC-SHA256(msg=seed, key=shared_secret) per REQ-013."""
    return hmac.new(shared_secret.encode(), seed, hashlib.sha256).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time bytes equality check using hmac.compare_digest (REQ-016)."""
    return hmac.compare_digest(a, b)


# ------------------------------------------------------------------
# X.509 certificate operations (REQ-020, REQ-022, REQ-023, REQ-024)
# ------------------------------------------------------------------

def parse_certificate(pem: str) -> x509.Certificate | None:
    """Parse a PEM-encoded certificate. Returns None if malformed (→ NRC 0x73)."""
    try:
        return x509.load_pem_x509_certificate(pem.encode())
    except Exception:
        return None


def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    """Return the SHA-256 fingerprint of a certificate as a lowercase hex string."""
    return cert.fingerprint(hashes.SHA256()).hex()


def is_cert_time_valid(cert: x509.Certificate, now: datetime.datetime) -> bool:
    """True if `now` falls within the certificate's [notBefore, notAfter] window."""
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def cert_issuer_matches(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """True if cert.issuer == ca_cert.subject (chain linkage check)."""
    return cert.issuer == ca_cert.subject


def verify_cert_signed_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """True if cert's signature verifies against ca_cert's ECDSA public key."""
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False


def sign_ecdsa(private_key, data: bytes) -> bytes:
    """Sign data with the private key using ECDSA P-256 + SHA-256 (proof of possession)."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_proof_signature(cert: x509.Certificate, signature_bytes: bytes, data: bytes) -> bool:
    """Verify a proof-of-possession signature: cert owner signed data (REQ-026)."""
    try:
        cert.public_key().verify(signature_bytes, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
