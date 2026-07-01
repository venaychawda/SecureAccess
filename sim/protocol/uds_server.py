"""
uds_server.py — WebSocket bridge between the ECU Monitor dashboard and VirtualECU.

Run:  python -m sim.protocol.uds_server
      (or: python sim/protocol/uds_server.py)

Listens on ws://localhost:8765.
Broadcasts real-time state updates to every connected browser client and
translates dashboard commands into typed VirtualECU RPC calls.
"""
import asyncio
import datetime
import hashlib
import hmac
import json
import logging
import time
import threading
import webbrowser
from pathlib import Path

import websockets
import websockets.exceptions

from sim.core.audit_logger import AuditLogger
from sim.core.ecu import VirtualECU
from sim.hal import crypto_backend
from sim.hal.cert_store_sim import CertStore
from sim.protocol.client import DiagnosticClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [uds_server] %(message)s")
log = logging.getLogger(__name__)

PORT = 8765
HOST = "localhost"

# ECU policy-derived constants (mirrors ecu_policy.json)
_MAX_ATTEMPTS = 3
_SESSION_TIMEOUT = 300

# Subfunction bytes
_SF = {
    "calibration":      {"seed": 0x01, "key": 0x02},
    "ecu_programming":  {"seed": 0x03, "key": 0x04},
}

# ── Shared server state ────────────────────────────────────────────────────

class ServerState:
    def __init__(self):
        self.ecu: VirtualECU | None = None
        self.client: DiagnosticClient | None = None
        self.cert_store: CertStore | None = None
        self.clients: set = set()            # connected WebSocket clients
        self.lock = asyncio.Lock()
        self.last_seed: bytes | None = None
        self.pending_level: str | None = None
        self.session_start_ts: float | None = None

    def boot(self):
        """Start a fresh VirtualECU + DiagnosticClient pair."""
        if self.client:
            try: self.client.disconnect()
            except Exception: pass
        if self.ecu:
            try: self.ecu.stop()
            except Exception: pass
        self.cert_store = CertStore.generate_in_memory()
        self.ecu = VirtualECU(cert_store=self.cert_store, required_delay_seconds=2)
        self.ecu.start()
        self.client = DiagnosticClient(host="127.0.0.1", port=self.ecu.port)
        self.client.connect()
        self.last_seed = None
        self.pending_level = None
        self.session_start_ts = None
        log.info("VirtualECU started on port %d", self.ecu.port)

_state = ServerState()


# ── Broadcast helpers ──────────────────────────────────────────────────────

async def broadcast(msg: dict):
    if not _state.clients:
        return
    data = json.dumps(msg)
    dead = set()
    for ws in list(_state.clients):
        try:
            await ws.send(data)
        except websockets.exceptions.ConnectionClosed:
            dead.add(ws)
    _state.clients -= dead


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


async def push_uds(direction: str, service: str, sub: str, result: str, data: str = ""):
    await broadcast({
        "type": "uds_message",
        "ts": _now_iso(),
        "direction": direction,
        "service": service,
        "sub": sub,
        "result": result,
        "data": data,
    })


async def push_session(session: str, timer: int):
    await broadcast({
        "type": "session_update",
        "session": session,
        "timer_remaining": timer,
    })


async def push_access(level):
    await broadcast({"type": "access_level_update", "level": level})


async def push_auth_level(lv: str, attempts: int, locked: bool,
                          lockout_rem: float = 0, delay_rem: float = 0):
    await broadcast({
        "type": "auth_update",
        "level": lv,
        "attempts": attempts,
        "locked": locked,
        "lockout_remaining": lockout_rem,
        "delay_remaining": delay_rem,
    })


async def push_audit_entries():
    """Send all current audit log entries to newly connected clients."""
    if not _state.ecu:
        return
    try:
        result = _state.client.get_audit_log()
        entries = result.get("entries", [])
        chain_valid = AuditLogger.verify_chain(entries)
        for entry in entries:
            await broadcast({
                "type": "audit_entry",
                "entry": entry,
                "chain_valid": chain_valid,
            })
    except Exception as exc:
        log.warning("push_audit_entries failed: %s", exc)


async def push_snapshot():
    """Push full state snapshot to all clients (called on first connect & power cycle)."""
    if not _state.ecu:
        return
    try:
        sess_resp  = _state.client.get_session_state()
        acc_resp   = _state.client.get_access_level()
        auth_resp  = _state.client.get_auth_access_level()
        audit_resp = _state.client.get_audit_log()

        session_name = {1: "default", 3: "extended", 2: "programming"}.get(
            sess_resp.get("session_id", 1), "default"
        )
        elapsed = (time.monotonic() - _state.session_start_ts) if _state.session_start_ts else 0
        timer   = max(0, _SESSION_TIMEOUT - int(elapsed))

        levels = {}
        for lv in ["CALIBRATION", "ECU_PROGRAMMING", "ENGINEERING", "FULL_ACCESS"]:
            cnt = _state.client.get_attempt_counter(lv).get("count", 0)
            levels[lv] = {"attempts": cnt, "locked": False,
                          "lockout_remaining": 0, "delay_remaining": 0}

        entries = audit_resp.get("entries", [])
        chain_valid = AuditLogger.verify_chain(entries)

        await broadcast({
            "type": "snapshot",
            "session":       session_name,
            "access_level":  acc_resp.get("access_level") or auth_resp.get("access_level"),
            "mechanism":     None,
            "timer":         timer,
            "auth_levels":   levels,
        })

        for entry in entries:
            await broadcast({
                "type": "audit_entry",
                "entry": entry,
                "chain_valid": chain_valid,
            })
    except Exception as exc:
        log.warning("push_snapshot failed: %s", exc)


# ── Command handler ────────────────────────────────────────────────────────

async def handle_cmd(msg: dict):
    cmd = msg.get("cmd")
    c = _state.client

    if cmd == "snapshot":
        await push_snapshot()
        return

    if cmd == "session":
        target = msg.get("target", "default")
        session_id = {"default": 0x01, "extended": 0x03, "programming": 0x02}.get(target, 0x01)
        await push_uds("client→ecu", "0x10", hex(session_id), "request")
        resp = c.send_diagnostic_session_control(session_id)
        if resp.get("positive"):
            if session_id != 0x01:
                _state.session_start_ts = time.monotonic()
            await push_uds("ecu→client", "0x10", hex(session_id), "positive",
                           f"session={target}")
            await push_session(target, _SESSION_TIMEOUT if session_id != 0x01 else 0)
            await push_audit_tail()
        else:
            nrc = resp.get("nrc", 0)
            await push_uds("ecu→client", "0x10", "0x7F", "NRC",
                           f"NRC {hex(nrc)}")
        return

    if cmd == "0x27_seed":
        level = msg.get("level", "calibration")
        sf    = _SF.get(level, _SF["calibration"])["seed"]
        await push_uds("client→ecu", "0x27", hex(sf), "request", "requestSeed")
        resp = c.request_seed(sf)
        if resp.get("positive"):
            seed = resp["seed"]
            _state.last_seed   = seed
            _state.pending_level = level
            secret = ("sim-calibration-secret-dev-only" if level == "calibration"
                      else "sim-programming-secret-dev-only")
            hmac_key = crypto_backend.compute_key_hmac_sha256(seed, secret).hex()
            await push_uds("ecu→client", "0x27", hex(sf), "positive",
                           f"seed={seed.hex()[:16]}…")
            await broadcast({
                "type":     "seed_response",
                "seed":     seed.hex(),
                "level":    level,
                "hmac_key": hmac_key,
            })
            await broadcast({"type": "mechanism_update", "mechanism": "0x27"})
        else:
            nrc = resp.get("nrc", 0)
            await push_uds("ecu→client", "0x27", "0x7F", "NRC", f"NRC {hex(nrc)}")
        return

    if cmd == "0x27_key":
        level  = msg.get("level", "calibration")
        key_hex= msg.get("key", "")
        sf     = _SF.get(level, _SF["calibration"])["key"]
        try:
            key_bytes = bytes.fromhex(key_hex.replace(" ", ""))
        except ValueError:
            await broadcast({"type": "error", "msg": "Invalid hex key"})
            return
        await push_uds("client→ecu", "0x27", hex(sf), "request", "sendKey")
        resp = c.send_key(sf, key_bytes)
        if resp.get("positive"):
            al = resp.get("access_level", "")
            await push_uds("ecu→client", "0x27", hex(sf), "positive",
                           f"GRANTED {al}")
            await push_access(al)
            cnt = c.get_attempt_counter(al.upper()).get("count", 0)
            await push_auth_level(al.upper(), cnt, False)
            await push_audit_tail()
        else:
            nrc = resp.get("nrc", 0)
            await push_uds("ecu→client", "0x27", "0x7F", "NRC", f"NRC {hex(nrc)}")
            for lv in ["CALIBRATION", "ECU_PROGRAMMING"]:
                cnt = c.get_attempt_counter(lv).get("count", 0)
                await push_auth_level(lv, cnt, False)
            await push_audit_tail()
        return

    if cmd == "0x29_auth":
        mode = msg.get("mode", "unidirectional")
        # Set up correct session
        sess_id = _state.client.get_session_state().get("session_id", 1)
        tpem = _state.cert_store.tester_cert_pem
        await push_uds("client→ecu", "0x29", "0x11", "request", "communicateCertificate")
        resp = c.communicate_certificate(tpem)
        if not resp.get("positive"):
            nrc = resp.get("nrc", 0)
            await push_uds("ecu→client", "0x29", "0x7F", "NRC", f"NRC {hex(nrc)}")
            return
        challenge = bytes(resp["challenge"])
        await push_uds("ecu→client", "0x29", "0x11", "positive",
                       f"challenge={challenge.hex()[:16]}…")
        proof = crypto_backend.sign_ecdsa(_state.cert_store.tester_key, challenge)
        await push_uds("client→ecu", "0x29", "0x12", "request", "verifyProof")
        resp2 = c.verify_proof(proof)
        if resp2.get("positive"):
            al = resp2.get("access_level", "")
            await push_uds("ecu→client", "0x29", "0x12", "positive", f"GRANTED {al}")
            await push_access(al)
            await broadcast({"type": "mechanism_update", "mechanism": "0x29"})
            await push_audit_tail()
        else:
            nrc = resp2.get("nrc", 0)
            await push_uds("ecu→client", "0x29", "0x7F", "NRC", f"NRC {hex(nrc)}")
            await push_audit_tail()
        return

    if cmd == "0x29_deauth":
        await push_uds("client→ecu", "0x29", "0x00", "request", "deAuthenticate")
        resp = c.deauthenticate()
        await push_uds("ecu→client", "0x29", "0x00", "positive", "deAuthenticated")
        await push_access(None)
        await push_audit_tail()
        return

    if cmd == "inject_tamper":
        await push_uds("client→ecu", "SIM", "—", "inject", "tamper event")
        c.inject_tamper_event()
        await broadcast({"type": "tamper", "triggered": True})
        await push_session("default", 0)
        await push_access(None)
        await push_audit_tail()
        return

    if cmd == "inject_wrong_key":
        level  = msg.get("level", "calibration")
        sf_seed = _SF.get(level, _SF["calibration"])["seed"]
        sf_key  = _SF.get(level, _SF["calibration"])["key"]
        seed_resp = c.request_seed(sf_seed)
        if seed_resp.get("positive"):
            await push_uds("client→ecu", "0x27", hex(sf_key), "inject", "wrong key")
            resp = c.send_key(sf_key, bytes(32))
            nrc  = resp.get("nrc", 0)
            await push_uds("ecu→client", "0x27", "0x7F", "NRC", f"NRC {hex(nrc)}")
            for lv in ["CALIBRATION","ECU_PROGRAMMING"]:
                cnt = c.get_attempt_counter(lv).get("count", 0)
                await push_auth_level(lv, cnt, False)
            await push_audit_tail()
        return

    if cmd == "inject_expired_cert":
        import datetime as dt
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        now = dt.datetime.now(dt.timezone.utc)
        tkey = ec.generate_private_key(ec.SECP256R1())
        exp_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ExpiredTester")]))
            .issuer_name(_state.cert_store.root_ca_cert.subject)
            .public_key(tkey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=730))
            .not_valid_after(now - dt.timedelta(seconds=1))
            .sign(_state.cert_store.root_ca_key, hashes.SHA256())
        )
        pem = exp_cert.public_bytes(serialization.Encoding.PEM).decode()
        await push_uds("client→ecu", "0x29", "0x11", "inject", "expired cert")
        resp = c.communicate_certificate(pem)
        nrc  = resp.get("nrc", 0)
        await push_uds("ecu→client", "0x29", "0x7F", "NRC", f"NRC {hex(nrc)}")
        return

    if cmd == "inject_replay_nonce":
        if _state.last_seed is None:
            await broadcast({"type": "error", "msg": "No prior seed to replay"})
            return
        # Complete a real auth to get a used nonce, then inject it
        tpem = _state.cert_store.tester_cert_pem
        r = c.communicate_certificate(tpem)
        if r.get("positive"):
            nonce = bytes(r["challenge"])
            proof = crypto_backend.sign_ecdsa(_state.cert_store.tester_key, nonce)
            c.verify_proof(proof)
            # Now inject the same nonce and try again
            c.communicate_certificate(tpem)
            c.inject_replay_nonce(nonce)
            await push_uds("client→ecu", "0x29", "0x12", "inject", "replay nonce")
            resp = c.verify_proof(proof)
            nrc  = resp.get("nrc", 0)
            await push_uds("ecu→client", "0x29", "0x7F", "NRC", f"NRC {hex(nrc)}")
            await push_audit_tail()
        return

    if cmd == "power_cycle":
        log.info("Power cycle requested — rebooting VirtualECU")
        _state.boot()
        await broadcast({"type": "session_update", "session": "default", "timer_remaining": 0})
        await push_access(None)
        await broadcast({"type": "tamper", "triggered": False})
        await push_snapshot()
        return


async def push_audit_tail():
    """Push newest audit log entries (those not yet sent)."""
    if not _state.ecu:
        return
    try:
        result = _state.client.get_audit_log()
        entries = result.get("entries", [])
        if not entries:
            return
        chain_valid = AuditLogger.verify_chain(entries)
        # Only push the last entry (already rendered previous ones)
        await broadcast({
            "type":        "audit_entry",
            "entry":       entries[-1],
            "chain_valid": chain_valid,
        })
    except Exception as exc:
        log.warning("push_audit_tail failed: %s", exc)


# ── WebSocket handler ──────────────────────────────────────────────────────

async def handler(websocket):
    _state.clients.add(websocket)
    log.info("Client connected (total: %d)", len(_state.clients))
    try:
        await push_snapshot()
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            async with _state.lock:
                await handle_cmd(msg)
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        _state.clients.discard(websocket)
        log.info("Client disconnected (total: %d)", len(_state.clients))


# ── Periodic state broadcast (every 2 s) ──────────────────────────────────

async def periodic_push():
    while True:
        await asyncio.sleep(2)
        if not _state.ecu or not _state.clients:
            continue
        try:
            sess_resp = _state.client.get_session_state()
            sess_id   = sess_resp.get("session_id", 1)
            sess_name = {1: "default", 3: "extended", 2: "programming"}.get(sess_id, "default")
            elapsed   = (time.monotonic() - _state.session_start_ts) if _state.session_start_ts else 0
            timer     = max(0, _SESSION_TIMEOUT - int(elapsed))
            await broadcast({"type": "session_update", "session": sess_name, "timer_remaining": timer})

            for lv in ["CALIBRATION", "ECU_PROGRAMMING", "ENGINEERING", "FULL_ACCESS"]:
                cnt = _state.client.get_attempt_counter(lv).get("count", 0)
                await push_auth_level(lv, cnt, False)
        except Exception as exc:
            log.debug("periodic_push: %s", exc)


# ── Main ───────────────────────────────────────────────────────────────────

async def main():
    _state.boot()

    gui_path = Path(__file__).parents[2] / "gui" / "secure_access_monitor.html"
    if gui_path.exists():
        log.info("Dashboard: file://%s", gui_path)
    else:
        log.warning("Dashboard HTML not found at %s", gui_path)

    async with websockets.serve(handler, HOST, PORT):
        log.info("WebSocket server listening on ws://%s:%d", HOST, PORT)
        await asyncio.gather(periodic_push(), asyncio.Future())


if __name__ == "__main__":
    asyncio.run(main())
