"""
SecurityAccessHandler — UDS Service 0x27 state machine.

Handles requestSeed (odd subfunctions) and sendKey (even subfunctions).
Enforces:
  - Session gating (REQ-012)
  - HMAC-SHA256 key derivation + constant-time compare (REQ-013, REQ-016)
  - Seed invalidation after any sendKey (REQ-018)
  - Per-level attempt counters (REQ-015, REQ-036)
  - Required delay between failed attempts (REQ-038)
  - Lockout after MAX_AUTH_ATTEMPTS failures (REQ-037, REQ-039)
  - Counter/lockout persist across session resets (REQ-041)

Must NOT call crypto primitives directly — all crypto goes through
sim/hal/crypto_backend.py (CLAUDE.md invariant).
"""
import time

from sim.hal import crypto_backend
from sim.core.session import SessionStateMachine

_SESSION_NAME_TO_ID = {
    "default": SessionStateMachine.DEFAULT,
    "extended": SessionStateMachine.EXTENDED,
    "programming": SessionStateMachine.PROGRAMMING,
}


class SecurityAccessHandler:
    def __init__(
        self,
        policy: dict,
        session_sm: SessionStateMachine,
        required_delay_seconds: float | None = None,
        lockout_duration_seconds: float | None = None,
    ):
        self._session_sm = session_sm
        self._challenge_size: int = policy["crypto"]["challenge_size_bytes"]
        self._levels: dict[int, dict] = self._parse_levels(policy)

        lockout_cfg = policy["lockout"]
        self._max_attempts: int = lockout_cfg["max_auth_attempts"]
        self._required_delay: float = (
            required_delay_seconds if required_delay_seconds is not None
            else float(lockout_cfg["required_delay_seconds"])
        )
        self._lockout_duration: float = (
            lockout_duration_seconds if lockout_duration_seconds is not None
            else float(lockout_cfg["lockout_duration_seconds"])
        )

        # Per-access-level state (keyed by access_level string)
        access_levels = {
            cfg["access_level"]
            for cfg in self._levels.values()
            if cfg["type"] == "send_key"
        }
        self._pending_seeds: dict[int, bytes] = {}
        self._granted_access_level: str | None = None
        self._attempt_counters: dict[str, int] = {lv: 0 for lv in access_levels}
        self._lockout_until: dict[str, float | None] = {lv: None for lv in access_levels}
        self._last_fail_at: dict[str, float | None] = {lv: None for lv in access_levels}

    # ------------------------------------------------------------------
    # Public API (called under VirtualECU._lock)
    # ------------------------------------------------------------------

    def granted_access_level(self) -> str | None:
        return self._granted_access_level

    def attempt_counter(self, access_level: str) -> int:
        return self._attempt_counters.get(access_level, 0)

    def clear_access(self) -> None:
        """Revoke granted access and discard pending seeds (REQ-035).
        Intentionally does NOT clear lockout / counters (REQ-041)."""
        self._granted_access_level = None
        self._pending_seeds.clear()

    def request_seed(self, subfunction: int) -> tuple[bool, bytes | None, int | None]:
        """Return (True, seed, None) or (False, None, nrc)."""
        cfg = self._levels.get(subfunction)
        if cfg is None or cfg["type"] != "request_seed":
            return False, None, 0x22

        if self._session_sm.current() != cfg["required_session"]:
            return False, None, 0x22

        blocked, nrc = self._check_rate_limit(cfg["access_level"])
        if blocked:
            return False, None, nrc

        seed = crypto_backend.generate_seed(self._challenge_size)
        self._pending_seeds[subfunction] = seed
        self._session_sm.touch()
        return True, seed, None

    def send_key(self, subfunction: int, key_bytes: bytes) -> tuple[bool, str | None, int | None]:
        """Return (True, access_level, None) or (False, None, nrc)."""
        cfg = self._levels.get(subfunction)
        if cfg is None or cfg["type"] != "send_key":
            return False, None, 0x22

        if self._session_sm.current() != cfg["required_session"]:
            return False, None, 0x22

        req_seed_sf = cfg["request_seed_subfunction"]
        pending_seed = self._pending_seeds.get(req_seed_sf)
        if pending_seed is None:
            return False, None, 0x24  # requestSequenceError

        expected = crypto_backend.compute_key_hmac_sha256(pending_seed, cfg["shared_secret"])
        del self._pending_seeds[req_seed_sf]  # consume seed (REQ-018)

        if not crypto_backend.constant_time_compare(key_bytes, expected):
            return False, None, self._record_failure(cfg["access_level"])

        self._record_success(cfg["access_level"])
        self._granted_access_level = cfg["access_level"]
        self._session_sm.touch()
        return True, cfg["access_level"], None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_rate_limit(self, access_level: str) -> tuple[bool, int | None]:
        """Return (blocked, nrc). Clears expired lockout automatically."""
        now = time.monotonic()
        lockout_until = self._lockout_until.get(access_level)
        if lockout_until is not None:
            if now < lockout_until:
                return True, 0x36               # still locked
            # Lockout expired — reset state
            self._lockout_until[access_level] = None
            self._attempt_counters[access_level] = 0
            self._last_fail_at[access_level] = None

        last_fail = self._last_fail_at.get(access_level)
        if last_fail is not None and (now - last_fail) < self._required_delay:
            return True, 0x37                   # delay not yet elapsed

        return False, None

    def _record_failure(self, access_level: str) -> int:
        """Increment counter; trigger lockout if at max. Returns the NRC to send."""
        self._attempt_counters[access_level] += 1
        self._last_fail_at[access_level] = time.monotonic()
        if self._attempt_counters[access_level] >= self._max_attempts:
            self._lockout_until[access_level] = time.monotonic() + self._lockout_duration
        return 0x35  # invalidKey

    def _record_success(self, access_level: str) -> None:
        self._attempt_counters[access_level] = 0
        self._last_fail_at[access_level] = None
        self._lockout_until[access_level] = None

    def _parse_levels(self, policy: dict) -> dict[int, dict]:
        levels: dict[int, dict] = {}
        for _level_name, cfg in policy["security_access_0x27"]["levels"].items():
            req_sf   = int(cfg["request_seed_subfunction"], 16)
            send_sf  = int(cfg["send_key_subfunction"], 16)
            req_sess = _SESSION_NAME_TO_ID[cfg["required_session"]]
            access   = cfg["grants_access_level"]
            levels[req_sf] = {
                "type": "request_seed",
                "required_session": req_sess,
                "access_level": access,
                "send_key_subfunction": send_sf,
                "algorithm": cfg["algorithm"],
                "shared_secret": cfg["shared_secret_default_sim"],
            }
            levels[send_sf] = {
                "type": "send_key",
                "required_session": req_sess,
                "access_level": access,
                "request_seed_subfunction": req_sf,
                "algorithm": cfg["algorithm"],
                "shared_secret": cfg["shared_secret_default_sim"],
            }
        return levels
