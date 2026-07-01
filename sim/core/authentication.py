"""
AuthenticationHandler — UDS Service 0x29 state machine.

Phase 1 (TC-06): validate_tester_cert — format, expiry, chain, signature, CRL.
Phase 2 (TC-07): communicate_certificate — validation + challenge generation;
                 verify_proof — proof-of-possession check → grants access level;
                 deauthenticate — revokes 0x29-granted access.

All cryptographic operations go through sim/hal/crypto_backend.py.
"""
import datetime

from sim.core.session import SessionStateMachine
from sim.hal import crypto_backend


class AuthenticationHandler:
    def __init__(self, policy: dict, session_sm: SessionStateMachine, cert_store):
        self._policy     = policy
        self._session_sm = session_sm
        self._cert_store = cert_store
        self._nonce_size: int = policy["crypto"]["nonce_size_bytes"]
        # In-flight exchange state (cleared per attempt)
        self._pending_challenge: bytes | None = None
        self._pending_tester_cert = None
        self._granted_access_level: str | None = None
        # REQ-046: cross-session nonce history — persists until ECU power cycle
        self._used_nonces: set[bytes] = set()

    # ------------------------------------------------------------------
    # Public API (called under VirtualECU._lock)
    # ------------------------------------------------------------------

    def granted_access_level(self) -> str | None:
        return self._granted_access_level

    def clear_access(self) -> None:
        """Revoke granted access and discard in-flight auth state (REQ-035)."""
        self._granted_access_level = None
        self._pending_challenge = None
        self._pending_tester_cert = None

    def communicate_certificate(
        self, cert_pem: str, session_id: int
    ) -> tuple[bool, dict | None, int | None]:
        """
        Phase 1: validate tester cert, generate nonce challenge, optionally
        include ECU cert (bidirectional / Programming session).

        Returns (True, response_dict, None) or (False, None, nrc).
        response_dict = {"challenge": list[int], "ecu_cert": str | None}
        """
        # Validate cert (same checks as TC-06)
        ok, nrc = self._validate_cert(cert_pem)
        if not ok:
            return False, None, nrc

        # Store validated cert for phase 2
        self._pending_tester_cert = crypto_backend.parse_certificate(cert_pem)
        challenge = crypto_backend.generate_seed(self._nonce_size)
        self._pending_challenge = challenge

        ecu_cert_pem = (
            self._cert_store.ecu_cert_pem
            if session_id == SessionStateMachine.PROGRAMMING
            else None
        )
        self._session_sm.touch()
        return True, {"challenge": list(challenge), "ecu_cert": ecu_cert_pem}, None

    def inject_pending_nonce_for_test(self, nonce: bytes) -> None:
        """Simulation-only: replace the pending challenge to test replay detection (TC-11)."""
        self._pending_challenge = nonce

    def verify_proof(
        self, proof_bytes: bytes, session_id: int
    ) -> tuple[bool, str | None, int | None]:
        """
        Phase 2: verify the tester's proof of possession (ECDSA signature over challenge).
        Returns (True, access_level, None) or (False, None, nrc).
        """
        if self._pending_challenge is None or self._pending_tester_cert is None:
            return False, None, 0x24  # requestSequenceError

        challenge    = self._pending_challenge
        tester_cert  = self._pending_tester_cert

        # REQ-046: reject if this nonce was already used in any previous session
        if challenge in self._used_nonces:
            self._pending_challenge = None
            self._pending_tester_cert = None
            return False, None, 0x24  # requestSequenceError (nonce reuse detected)

        # Consume in-flight state regardless of outcome
        self._pending_challenge = None
        self._pending_tester_cert = None

        if not crypto_backend.verify_proof_signature(tester_cert, proof_bytes, challenge):
            return False, None, 0x76  # certificateSignatureInvalid

        # Record nonce as used only on successful auth
        self._used_nonces.add(challenge)

        access_level = (
            "FULL_ACCESS" if session_id == SessionStateMachine.PROGRAMMING else "ENGINEERING"
        )
        self._granted_access_level = access_level
        self._session_sm.touch()
        return True, access_level, None

    def deauthenticate(self) -> dict:
        """Revoke 0x29-granted access level without tearing down the session (REQ-028)."""
        self._granted_access_level = None
        self._pending_challenge = None
        self._pending_tester_cert = None
        return {"positive": True}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_cert(self, cert_pem: str) -> tuple[bool, int | None]:
        """Five-step cert validation (TC-06 logic)."""
        cert = crypto_backend.parse_certificate(cert_pem)
        if cert is None:
            return False, 0x73

        now = datetime.datetime.now(datetime.timezone.utc)
        if not crypto_backend.is_cert_time_valid(cert, now):
            return False, 0x75

        root_ca = self._cert_store.root_ca_cert
        if not crypto_backend.cert_issuer_matches(cert, root_ca):
            return False, 0x78

        if not crypto_backend.verify_cert_signed_by(cert, root_ca):
            return False, 0x76

        thumbprint = crypto_backend.cert_fingerprint_sha256(cert)
        if self._cert_store.is_revoked(thumbprint):
            return False, 0x74

        return True, None
