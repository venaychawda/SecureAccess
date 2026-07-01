# Secure Access Lab — Dashboard User Guide

This guide explains how to use `gui/secure_access_monitor.html`, the live ECU
Monitor dashboard, once it's connected to a real running server (see
[README.md](README.md) → *Quick Start — Live Demo Dashboard*, or just run
`start_demo.bat`).

Everything shown in the dashboard — session state, seeds, keys, certificates,
NRCs, audit entries — comes from a real `VirtualECU` over `ws://localhost:8765`.
Nothing in this panel is hardcoded or simulated in JavaScript.

---

## 1. Connection status

Top-right badge:

| Badge | Meaning |
|---|---|
| `CONNECTED` (green) | WebSocket open, server reachable |
| `RECONNECTING` (amber) | Attempting to (re)connect |
| `DISCONNECTED` (red) | No server — start it with `start_demo.bat` or `python -m sim.protocol.uds_server` |

The dashboard auto-reconnects every 3 seconds while disconnected — you don't
need to refresh the page once the server comes back up.

---

## 2. Sidebar controls

### Session Control

| Button | Sends | Effect |
|---|---|---|
| **Default** | `DiagnosticSessionControl(0x01)` | Drops to Default session, revokes any granted access level (REQ-035) |
| **Extended** | `DiagnosticSessionControl(0x03)` | Required for CALIBRATION (0x27) and ENGINEERING (0x29 unidirectional) |
| **Programming** | `DiagnosticSessionControl(0x02)` | Required for ECU_PROGRAMMING (0x27) and FULL_ACCESS (0x29 bidirectional) |

The active session button is highlighted blue. **Always set the session
before requesting a seed or authenticating** — the ECU checks the session
first and returns NRC `0x22 conditionsNotCorrect` if it doesn't match what
the access level requires.

### 0x27 SecurityAccess

1. Pick **Access Level** — `CALIBRATION` (subfunctions 0x01/0x02) or
   `ECU_PROGRAMMING` (0x03/0x04).
2. Click **Request Seed** — sends `requestSeed`. On success the ECU returns a
   32-byte seed; the dashboard also computes the expected HMAC-SHA256 key for
   you and pre-fills the **Key** field (this mirrors what a real tester tool
   would compute — the ECU itself never sends the key).
3. Click **Send Key** — sends `sendKey` with the value currently in the Key
   field. You can edit the hex before sending to deliberately trigger a
   negative test (wrong key → NRC `0x35 invalidKey`).

Requirements: correct session for the chosen level (see table below), and no
prior `0x29` authentication already used in this session (see §5).

### 0x29 Authentication

1. Choose **Unidirectional** (tester proves identity to ECU → `ENGINEERING`)
   or **Bidirectional** (mutual auth, ECU also sends its cert → `FULL_ACCESS`).
2. Click **Authenticate** — this drives the full two-step exchange for you:
   `communicateCertificate` (0x11) → ECU validates the tester cert and
   returns a nonce challenge → the dashboard signs it with the tester's
   private key (ECDSA P-256) → `verifyProof` (0x12) → ECU verifies the
   signature and grants access.
3. Click **deAuthenticate** to revoke the granted 0x29 access level without
   dropping the session.

Requirements: Extended session for unidirectional, Programming session for
bidirectional; no prior `0x27` seed/key already used in this session.

### Simulation Injection

These buttons intentionally trigger failure paths, useful for demonstrating
negative-response handling without waiting for a real attacker:

| Button | Effect | Expected NRC |
|---|---|---|
| **Inject Tamper Event** | Simulates a tamper sensor firing — force session reset to Default, revoke all access (REQ-008) | — (session drops) |
| **Inject Wrong Key** | Requests a seed then sends an all-zero key | `0x35 invalidKey` |
| **Inject Expired Cert** | Generates a certificate that's already past `not_valid_after` and submits it | `0x75 certificateExpired` |
| **Inject Replay Nonce** | Completes one real auth exchange, then re-submits the already-used nonce | `0x24 requestSequenceError` |
| **Simulate Power Cycle** | Fully reboots the `VirtualECU` — fresh session, cleared attempt counters, cleared nonce history, new certs | — (full reset) |

---

## 3. Panel: ECU State

| Field | Meaning |
|---|---|
| **Session** | Current UDS session: `DEFAULT` / `EXTENDED` / `PROGRAMMING` |
| **Access Level** | Currently granted level, if any: `CALIBRATION`, `ECU_PROGRAMMING`, `ENGINEERING`, `FULL_ACCESS`, or `NONE` |
| **Auth Mechanism** | Which service granted the current access: `0x27 SecurityAccess` or `0x29 Authentication` |
| **Tamper Flag** | Flashes red briefly after **Inject Tamper Event** fires |
| **Session Timer** | Countdown to automatic session timeout (300 s from `ecu_policy.json`); resets on any activity in the session. Not shown in Default session |

## 4. Panel: Auth Status

One row per access level requiring authentication (`CALIBRATION`,
`ECU_PROGRAMMING`, `ENGINEERING`, `FULL_ACCESS`):

- **Attempt pips** — filled red squares show failed attempts out of the max
  (3, from `ecu_policy.json`). Resets to 0 on a successful auth for that level.
- **LOCKED badge** — appears once the max attempts is reached; shows seconds
  remaining in the 3600 s lockout window (REQ-037/039). Lockout state
  **persists across session resets** (REQ-041) — only expires with time or
  a power cycle.
- **Delay bar** — appears briefly after a failed attempt; the ECU enforces a
  10 s minimum delay between attempts (`0x37 requiredTimeDelayNotExpired`)
  even before lockout kicks in.

Attempt counters are tracked independently per access level — failing
CALIBRATION does not affect the ECU_PROGRAMMING counter.

## 5. Panel: UDS Message Flow

A live, filterable log of every request/response crossing the client↔ECU
boundary — this is the actual wire traffic, in order.

- **Filters**: `ALL`, `0x10`, `0x27`, `0x29`, or `NRC ONLY` (shows only
  negative responses across all services).
- **Columns**: timestamp, direction (`→` client→ecu, `←` ecu→client),
  service ID, subfunction, and result/data.
- Rows with a negative response (NRC) are tinted red; successful positive
  responses are tinted green.

Use this panel to show, in real time, exactly which subfunction was sent and
which NRC came back — it's the fastest way to explain *why* a given action
failed (e.g. confirming a `0x24` came from the `0x11` step vs. the `0x12`
step of a 0x29 exchange).

## 6. Panel: Audit Log

Reflects the ECU's append-only, hash-chained audit trail
(`sim/core/audit_logger.py`), fetched on connect and updated live.

- **Hash chain status bar** — `✓ VALID (N entries)` as long as every entry's
  `prev_hash` correctly chains to the previous entry's hash. Turns
  `✗ CHAIN BROKEN` if you manually tamper with `logs/audit.jsonl` on disk —
  a good way to demonstrate tamper-evidence.
- **Filters**: `ALL`, `AUTH` (success/failure/attempt), `SESSION`
  (start/end/timeout/tamper-reset), `TAMPER`, `LOCKOUT`.
- Each row shows timestamp, event type, access level (if applicable), NRC
  code (if a failure), and a per-entry chain-valid indicator (`✓`/`✗`).

Event types you'll see: `SESSION_START`, `SESSION_END`, `SESSION_TIMEOUT`,
`SESSION_TAMPER_RESET`, `AUTH_SUCCESS`, `AUTH_FAILURE`, `LOCKOUT_TRIGGERED`,
`LOCKOUT_EXPIRED`, `REPLAY_DETECTED`, `DEAUTHENTICATE`.

---

## 7. Guided walkthroughs

### CALIBRATION access (0x27)
1. Session Control → **Extended**
2. 0x27 panel → Access Level `CALIBRATION` → **Request Seed**
3. **Send Key** (auto-filled) → ECU State shows `Access Level: CALIBRATION`, `Auth Mechanism: 0x27`

### ECU_PROGRAMMING access (0x27)
1. Session Control → **Programming**
2. 0x27 panel → Access Level `ECU_PROGRAMMING` → **Request Seed** → **Send Key**

### ENGINEERING access (0x29 unidirectional)
1. Session Control → **Extended**
2. 0x29 panel → **Unidirectional** → **Authenticate**

### FULL_ACCESS (0x29 bidirectional)
1. Session Control → **Programming**
2. 0x29 panel → **Bidirectional** → **Authenticate**

### Demonstrating lockout
1. Session Control → **Extended**
2. 0x27 panel → Access Level `CALIBRATION` → click **Inject Wrong Key** three times (10 s apart, to clear the required-delay window each time)
3. Auth Status panel shows `LOCKED` for CALIBRATION after the 3rd failure — it stays locked for 3600 s, or until **Simulate Power Cycle**

---

## 8. Negative Response Code (NRC) reference

| NRC | Name | Typical cause in this lab |
|---|---|---|
| `0x22` | conditionsNotCorrect | Wrong session for the requested service/level (e.g. requesting a CALIBRATION seed while still in Default) |
| `0x24` | requestSequenceError | `sendKey`/`verifyProof` called without a prior `requestSeed`/`communicateCertificate`; nonce reuse; or `0x27`↔`0x29` mutual-exclusion lock (REQ-045) — one mechanism already used this session |
| `0x35` | invalidKey | Wrong key sent to `sendKey` |
| `0x36` | exceededNumberOfAttempts | Access level is currently locked out |
| `0x37` | requiredTimeDelayNotExpired | Retried before the 10 s inter-attempt delay elapsed |
| `0x73` | unsupportedCertificateFormat | Malformed certificate PEM |
| `0x74` | certificateVerificationFailed | Certificate thumbprint on the (simulated) CRL |
| `0x75` | certificateExpired | Certificate outside its validity window |
| `0x76` | certificateSignatureInvalid | Certificate not signed by the trusted root CA, or proof signature doesn't match the challenge |
| `0x78` | certificateChainVerificationFailed | Certificate issuer doesn't match the expected root CA |

---

## 9. Troubleshooting

**Dashboard stuck on `DISCONNECTED`**
No server is listening on port 8765. Run `start_demo.bat`, or manually:
`python -m sim.protocol.uds_server` (from the project root, with the venv active).

**"Server offline" placeholder text never clears after starting the server**
Check the server's console window for a Python traceback (e.g. port already
in use by another process — see below). If it's clean, refresh the browser
tab; the dashboard requests a fresh `snapshot` on every reconnect.

**Port 8765 already in use / two server windows fighting over the port**
Only one `uds_server.py` instance can bind port 8765 at a time.
`start_demo.ps1` detects an existing listener and reuses it automatically —
if you started one manually as well, close the extra one.

**`0x22` when requesting a seed or authenticating**
You're in the wrong session. Check the *Access Level Map* in
[README.md](README.md) for which session each level requires, then click
the matching Session Control button first.

**`0x24` on `0x29 Authenticate`**
Either you already used `0x27` in this session (mutual-exclusion, REQ-045 —
power-cycle or drop to Default and re-elevate), or `verifyProof` ran without
a fresh `communicateCertificate` (e.g. after **Inject Replay Nonce**).

**Everything is locked and I want a clean slate**
Click **Simulate Power Cycle** — it fully reboots the `VirtualECU`: fresh
session, cleared attempt counters and lockouts, cleared nonce history, and
newly generated certificates.
