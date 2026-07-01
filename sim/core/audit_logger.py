"""
AuditLogger — append-only structured event log with SHA-256 hash chain.

Every entry is a JSON dict containing all required_fields from ecu_policy.json.
Each entry hashes the previous entry's hash, forming a tamper-evident chain.
"""
import datetime
import hashlib
import json


GENESIS_HASH = "0" * 64


def _hash_entry(entry_without_hash: dict) -> str:
    """SHA-256 of the JSON-serialised entry (sorted keys, no entry_hash field)."""
    return hashlib.sha256(
        json.dumps(entry_without_hash, sort_keys=True).encode()
    ).hexdigest()


class AuditLogger:
    def __init__(self, genesis_hash: str = GENESIS_HASH):
        self._entries: list[dict] = []
        self._prev_hash: str = genesis_hash

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------

    def emit(
        self,
        event_type: str,
        service_id=None,
        access_level=None,
        client_id=None,
        result: str | None = None,
        nrc_code: int | None = None,
    ) -> None:
        entry: dict = {
            "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type":   event_type,
            "service_id":   service_id,
            "access_level": access_level,
            "client_id":    str(client_id) if client_id is not None else None,
            "result":       result,
            "nrc_code":     hex(nrc_code) if nrc_code is not None else None,
            "prev_hash":    self._prev_hash,
        }
        entry_hash = _hash_entry(entry)
        entry["entry_hash"] = entry_hash
        self._prev_hash = entry_hash
        self._entries.append(entry)

    # ------------------------------------------------------------------
    # Read / verify
    # ------------------------------------------------------------------

    def entries(self) -> list[dict]:
        return list(self._entries)

    @staticmethod
    def verify_chain(entries: list[dict], genesis_hash: str = GENESIS_HASH) -> bool:
        """Return True iff every entry's hash is correct and the chain is unbroken."""
        prev = genesis_hash
        for e in entries:
            if e.get("prev_hash") != prev:
                return False
            body = {k: v for k, v in e.items() if k != "entry_hash"}
            if _hash_entry(body) != e.get("entry_hash"):
                return False
            prev = e["entry_hash"]
        return True
