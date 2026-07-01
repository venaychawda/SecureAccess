"""
Session state machine for UDS Service 0x10 — DiagnosticSessionControl.

Transition rules (per ecu_policy.json and REQ-001–004):
  Default(0x01)     → Extended(0x03)     allowed
  Default(0x01)     → Programming(0x02)  BLOCKED — requires prior Extended or 0x29 auth
  Extended(0x03)    → Programming(0x02)  allowed
  Extended(0x03)    → Default(0x01)      allowed
  Programming(0x02) → Default(0x01)      allowed
  Programming(0x02) → Extended(0x03)     allowed
  Any unknown session byte               NRC 0x22
  Same-session request (target == current) resets inactivity timer, no state change.

Inactivity timer (REQ-005, REQ-006):
  Elevated sessions (Extended / Programming) revert to Default after
  timeout_seconds of no activity.  Call touch() on every valid request.
  session_timeout_seconds constructor arg overrides the policy value (tests only).
"""
import time


class SessionStateMachine:
    DEFAULT = 0x01
    EXTENDED = 0x03
    PROGRAMMING = 0x02

    _VALID = {DEFAULT, EXTENDED, PROGRAMMING}

    def __init__(self, policy: dict, session_timeout_seconds: float | None = None):
        self._session = self.DEFAULT
        raw = policy["session"]["allowed_transitions"]
        self._allowed: dict[int, set[int]] = {int(k): set(v) for k, v in raw.items()}
        self._timeout: float = (
            session_timeout_seconds
            if session_timeout_seconds is not None
            else float(policy["session"]["timeout_seconds"])
        )
        self._last_activity: float = time.monotonic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def current(self) -> int:
        self._check_timeout()
        return self._session

    def transition(self, target: int) -> tuple[bool, int | None]:
        """Return (True, None) on success or (False, nrc) on rejection."""
        self._check_timeout()

        if target not in self._VALID:
            return False, 0x22

        # Same-session request: reset timer, no state change (valid per UDS)
        if target == self._session:
            self.touch()
            return True, None

        # REQ-003: direct Default → Programming always blocked
        if self._session == self.DEFAULT and target == self.PROGRAMMING:
            return False, 0x22

        allowed = self._allowed.get(self._session, set())
        if target not in allowed:
            return False, 0x22

        self._session = target
        self.touch()
        return True, None

    def touch(self) -> None:
        """Reset the inactivity timer (call on every valid request)."""
        self._last_activity = time.monotonic()

    def reset(self) -> None:
        """Unconditional revert to Default — used for tamper events and power-cycle."""
        self._session = self.DEFAULT
        self.touch()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_timeout(self) -> None:
        if self._session != self.DEFAULT:
            if time.monotonic() - self._last_activity >= self._timeout:
                self._session = self.DEFAULT
