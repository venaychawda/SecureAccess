# secure-access-lab

Spec-driven, test-driven simulation of UDS diagnostic access security on a Virtual ECU.

Implements and validates all three UDS access mechanisms defined in ISO 14229-1:

- **Service 0x10** — DiagnosticSessionControl (session state machine)
- **Service 0x27** — SecurityAccess (seed/key, HMAC-SHA256)
- **Service 0x29** — Authentication (PKI/certificate, ECDSA P-256, unidirectional + bidirectional)

**Phase 1 only** — Pure Python simulation. No hardware required.

---

## Prerequisites

- Python 3.11+ on PATH
- Dependencies (installed automatically by the launcher, or manually):

```bash
pip install -r requirements.txt
```

---

## Quick Start — Live Demo Dashboard

The `gui/secure_access_monitor.html` dashboard is a **real** client — it connects
over a live WebSocket to a real `VirtualECU` + `DiagnosticClient` pair and shows
actual UDS traffic, not canned/dummy data. To run it end-to-end:

```powershell
# Option A — double-click
start_demo.bat

# Option B — from PowerShell
.\start_demo.ps1
```

This will:
1. Create/update the `.venv` and install dependencies if needed.
2. Start `sim/protocol/uds_server.py` (boots a real `VirtualECU` on a random
   RPC port, bridges it to `ws://localhost:8765`) in its own console window.
3. Open `gui/secure_access_monitor.html` in your default browser, which
   connects to that live socket.

Leave the server console window open for the duration of the demo — closing
it (or Ctrl+C inside it) stops the Virtual ECU. Re-running the launcher
detects an already-running server on port 8765 and reuses it instead of
starting a second instance.

**For a full walkthrough of every dashboard panel and control (Session
Control, 0x27 SecurityAccess, 0x29 Authentication, ECU State, Auth Status,
UDS Message Flow, Audit Log, Simulation Injection) see [UserHelp.md](UserHelp.md).**

### Manual start (no launcher)

```powershell
.\.venv\Scripts\Activate.ps1
python -m sim.protocol.uds_server
# then open gui/secure_access_monitor.html in a browser
```

> `docs\demo.html` at the repo are static, JS-only
> mockups with fake/hardcoded data (no backend). They are kept for early
> visual reference only — use `gui/secure_access_monitor.html` via the
> launcher for an actual working demonstration.

---

## Project Structure

```
secure-access-lab/
├── README.md
├── UserHelp.md                      ← dashboard user guide (session/0x27/0x29/panels)
├── requirements.txt
├── start_demo.ps1                   ← launches real server + dashboard
├── start_demo.bat                   ← double-click wrapper for start_demo.ps1
├── gui/
│   └── secure_access_monitor.html   ← live dashboard (WebSocket client, real data)
├── specs/
│   ├── requirements.csv             ← 53 requirements (REQ-001 to REQ-053) [added to .gitignore]
│   └── test_cases.csv               ← 13 test cases with REQ traceability [added to .gitignore]
├── sim/
│   ├── hal/
│   │   ├── crypto_backend.py        ← HAL crypto gateway (HMAC-SHA256, ECDSA P-256, X.509)
│   │   └── cert_store_sim.py        ← simulated PKI (Root CA, ECU cert, tester cert)
│   ├── core/
│   │   ├── session.py               ← 0x10 session state machine
│   │   ├── security_access.py       ← 0x27 SecurityAccess handler
│   │   ├── authentication.py        ← 0x29 Authentication handler
│   │   ├── ecu.py                   ← VirtualECU — RPC server, access gating, audit hooks
│   │   └── audit_logger.py          ← structured JSON log + hash chain
│   ├── protocol/
│   │   ├── rpc.py                   ← JSON-RPC over TCP (server + client transport)
│   │   ├── client.py                ← DiagnosticClient — Process 1 (tester) API
│   │   └── uds_server.py            ← WebSocket bridge: dashboard ⇄ VirtualECU
│   └── config/
│       └── ecu_policy.json          ← all policy constants and access level definitions
├── tests/
│   ├── conftest.py
│   ├── test_TC01_session_transitions.py
│   ├── test_TC02_session_lifecycle.py
│   ├── test_TC03_0x27_seed_generation.py
│   ├── test_TC04_0x27_key_validation.py
│   ├── test_TC05_0x27_negative_responses.py
│   ├── test_TC06_0x29_cert_validation.py
│   ├── test_TC07_0x29_auth_flow.py
│   ├── test_TC08_access_level_gating.py
│   ├── test_TC09_lockout_and_delay.py
│   ├── test_TC10_session_binding.py
│   ├── test_TC11_replay_detection.py
│   ├── test_TC12_anomaly_handling.py
│   └── test_TC13_audit_log_integrity.py
├── docs/
│   └── traceability_matrix.md       ← requirement ↔ TC ↔ implementation mapping
└── logs/
    └── audit.jsonl                  ← runtime audit log (created on first run)
```

---

## Running Tests

```bash
# All simulation tests
pytest tests/ -v --tb=short

# Skip slow timer tests
pytest tests/ -v -m "not slow"

# Single test case
pytest tests/test_TC01_session_transitions.py -v

# With coverage
pytest tests/ -v --cov=sim --cov-report=term-missing
```

---

## TDD Workflow

Every implementation follows strict RED → GREEN discipline:

1. Read `specs/requirements.csv` — identify REQ IDs
2. Read `specs/test_cases.csv` — identify TC ID
3. Write test file — run pytest → **must be RED**
4. Implement minimum `sim/` code to pass
5. Run pytest → **must be GREEN**
6. Run full suite — no regressions
7. Update `docs/traceability_matrix.md`

---

## Access Level Map

| Access Level | Session Required | Auth Required | Service |
|---|---|---|---|
| READ_ONLY | Default | None | — |
| CALIBRATION | Extended | 0x27 (subfunction 0x01/0x02) | SecurityAccess |
| ECU_PROGRAMMING | Programming | 0x27 (subfunction 0x03/0x04) | SecurityAccess |
| ENGINEERING | Extended | 0x29 Unidirectional | Authentication |
| FULL_ACCESS | Programming | 0x29 Bidirectional | Authentication |

Note: within a single elevated session, `0x27` and `0x29` are mutually
exclusive (REQ-045) — whichever mechanism is used first locks out the other
until the session resets (power cycle, or transition back to Default).

---

## Standards Reference

- ISO 14229-1:2020 — Unified Diagnostic Services (UDS)
- ISO 14229-1 §10.4 — DiagnosticSessionControl (0x10)
- ISO 14229-1 §10.5 — SecurityAccess (0x27)
- ISO 14229-1 §10.6 — Authentication (0x29)
