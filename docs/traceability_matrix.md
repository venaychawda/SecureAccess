# Traceability Matrix — Secure Access Lab

> **Instructions for Claude CLI:** After each test case reaches GREEN, update the
> Status column for every requirement covered by that TC. Valid values: `PENDING`,
> `IN PROGRESS`, `VERIFIED`, `BLOCKED`.

---

## Summary

| Total Requirements | Verified | In Progress | Pending | Blocked |
|--------------------|----------|-------------|---------|---------|
| 53 | 53 | 0 | 0 | 0 |

*Last updated: TC-13 GREEN — 2026-06-04 — ALL REQUIREMENTS VERIFIED*

---

## Requirements Traceability

| Req ID | Category | Title | Priority | TC ID | Test File | Status |
|--------|----------|-------|----------|-------|-----------|--------|
| REQ-001 | Session | Default Session at Power-Up | MUST | TC-01 | test_TC01_session_transitions.py | VERIFIED |
| REQ-002 | Session | Session Transition — Default to Extended | MUST | TC-01 | test_TC01_session_transitions.py | VERIFIED |
| REQ-003 | Session | Session Transition — Default to Programming | MUST | TC-01 | test_TC01_session_transitions.py | VERIFIED |
| REQ-004 | Session | Reject Out-of-Sequence Session Requests | MUST | TC-01 | test_TC01_session_transitions.py | VERIFIED |
| REQ-005 | Session | Session Timeout — Revert to Default | MUST | TC-02 | test_TC02_session_lifecycle.py | VERIFIED |
| REQ-006 | Session | Session Timeout Reset on Activity | MUST | TC-02 | test_TC02_session_lifecycle.py | VERIFIED |
| REQ-007 | Session | Concurrent Session Rejection | MUST | TC-02 | test_TC02_session_lifecycle.py | VERIFIED |
| REQ-008 | Session | Session Invalidation on Tamper Event | MUST | TC-02 | test_TC02_session_lifecycle.py | VERIFIED |
| REQ-009 | Session | Session State Persistence Across Requests | MUST | TC-01 | test_TC01_session_transitions.py | VERIFIED |
| REQ-010 | SecurityAccess_0x27 | Seed Generation — Uniqueness | MUST | TC-03 | test_TC03_0x27_seed_generation.py | VERIFIED |
| REQ-011 | SecurityAccess_0x27 | Seed Generation — PRNG Quality | MUST | TC-03 | test_TC03_0x27_seed_generation.py | VERIFIED |
| REQ-012 | SecurityAccess_0x27 | Seed Valid Only in Correct Session | MUST | TC-03 | test_TC03_0x27_seed_generation.py | VERIFIED |
| REQ-013 | SecurityAccess_0x27 | Key Derivation — HMAC-SHA256 | MUST | TC-04 | test_TC04_0x27_key_validation.py | VERIFIED |
| REQ-014 | SecurityAccess_0x27 | Key Validation — Correct Key Grants Access | MUST | TC-04 | test_TC04_0x27_key_validation.py | VERIFIED |
| REQ-015 | SecurityAccess_0x27 | Key Validation — Incorrect Key Rejected | MUST | TC-05 | test_TC05_0x27_negative_responses.py | VERIFIED |
| REQ-016 | SecurityAccess_0x27 | Key Validation — Constant-Time Comparison | MUST | TC-04 | test_TC04_0x27_key_validation.py | VERIFIED |
| REQ-017 | SecurityAccess_0x27 | sendKey Without Prior requestSeed Rejected | MUST | TC-05 | test_TC05_0x27_negative_responses.py | VERIFIED |
| REQ-018 | SecurityAccess_0x27 | Seed Invalidation After sendKey Attempt | MUST | TC-05 | test_TC05_0x27_negative_responses.py | VERIFIED |
| REQ-019 | SecurityAccess_0x27 | Access Level Mapping | MUST | TC-04 | test_TC04_0x27_key_validation.py | VERIFIED |
| REQ-020 | Authentication_0x29 | Certificate Chain Validation | MUST | TC-06 | test_TC06_0x29_cert_validation.py | VERIFIED |
| REQ-021 | Authentication_0x29 | ECU Certificate Issuance | MUST | TC-07 | test_TC07_0x29_auth_flow.py | VERIFIED |
| REQ-022 | Authentication_0x29 | Tester Certificate Signature Verification | MUST | TC-06 | test_TC06_0x29_cert_validation.py | VERIFIED |
| REQ-023 | Authentication_0x29 | Certificate Expiry Check | MUST | TC-06 | test_TC06_0x29_cert_validation.py | VERIFIED |
| REQ-024 | Authentication_0x29 | Certificate Format Validation | MUST | TC-06 | test_TC06_0x29_cert_validation.py | VERIFIED |
| REQ-025 | Authentication_0x29 | Unidirectional Authentication Flow | MUST | TC-07 | test_TC07_0x29_auth_flow.py | VERIFIED |
| REQ-026 | Authentication_0x29 | Bidirectional Authentication Flow | MUST | TC-07 | test_TC07_0x29_auth_flow.py | VERIFIED |
| REQ-027 | Authentication_0x29 | Nonce-Based Replay Prevention | MUST | TC-11 | test_TC11_replay_detection.py | VERIFIED |
| REQ-028 | Authentication_0x29 | deAuthenticate Service | MUST | TC-07 | test_TC07_0x29_auth_flow.py | VERIFIED |
| REQ-029 | Authentication_0x29 | Certificate Revocation Check (Simulated CRL) | SHOULD | TC-06 | test_TC06_0x29_cert_validation.py | VERIFIED |
| REQ-030 | AccessControl | READ_ONLY Access — No Auth Required | MUST | TC-08 | test_TC08_access_level_gating.py | VERIFIED |
| REQ-031 | AccessControl | CALIBRATION Access — 0x27 Required | MUST | TC-08 | test_TC08_access_level_gating.py | VERIFIED |
| REQ-032 | AccessControl | ECU_PROGRAMMING Access — 0x27 High Level Required | MUST | TC-08 | test_TC08_access_level_gating.py | VERIFIED |
| REQ-033 | AccessControl | ENGINEERING Access — 0x29 Unidirectional Required | MUST | TC-08 | test_TC08_access_level_gating.py | VERIFIED |
| REQ-034 | AccessControl | FULL_ACCESS — 0x29 Bidirectional Required | MUST | TC-08 | test_TC08_access_level_gating.py | VERIFIED |
| REQ-035 | AccessControl | Access Level Revoked on Session Downgrade | MUST | TC-08 | test_TC08_access_level_gating.py | VERIFIED |
| REQ-036 | Lockout | Attempt Counter per Access Level | MUST | TC-09 | test_TC09_lockout_and_delay.py | VERIFIED |
| REQ-037 | Lockout | Lockout After MAX_AUTH_ATTEMPTS | MUST | TC-09 | test_TC09_lockout_and_delay.py | VERIFIED |
| REQ-038 | Lockout | Required Delay Timer — NRC 0x37 | MUST | TC-09 | test_TC09_lockout_and_delay.py | VERIFIED |
| REQ-039 | Lockout | Lockout Duration Enforcement | MUST | TC-09 | test_TC09_lockout_and_delay.py | VERIFIED |
| REQ-040 | Lockout | Attempt Counter Reset on Successful Auth | MUST | TC-09 | test_TC09_lockout_and_delay.py | VERIFIED |
| REQ-041 | Lockout | Lockout Persists Across Session Reset | MUST | TC-09 | test_TC09_lockout_and_delay.py | VERIFIED |
| REQ-042 | SessionSecurity | Session Token Binding | MUST | TC-10 | test_TC10_session_binding.py | VERIFIED |
| REQ-043 | SessionSecurity | Access Level Not Transferable | MUST | TC-10 | test_TC10_session_binding.py | VERIFIED |
| REQ-044 | SessionSecurity | Session Re-authentication on Timeout | MUST | TC-10 | test_TC10_session_binding.py | VERIFIED |
| REQ-045 | SessionSecurity | Simultaneous 0x27 and 0x29 Auth Rejection | MUST | TC-10 | test_TC10_session_binding.py | VERIFIED |
| REQ-046 | TamperAndAnomaly | Replay Attack Detection — Nonce Reuse | MUST | TC-11 | test_TC11_replay_detection.py | VERIFIED |
| REQ-047 | TamperAndAnomaly | Malformed Request Handling | MUST | TC-12 | test_TC12_anomaly_handling.py | VERIFIED |
| REQ-048 | TamperAndAnomaly | Out-of-Sequence Service Call Rejection | MUST | TC-12 | test_TC12_anomaly_handling.py | VERIFIED |
| REQ-049 | TamperAndAnomaly | Brute-Force Pattern Detection | SHOULD | TC-12 | test_TC12_anomaly_handling.py | VERIFIED |
| REQ-050 | TamperAndAnomaly | Invalid Certificate Injection Handling | MUST | TC-12 | test_TC12_anomaly_handling.py | VERIFIED |
| REQ-051 | AuditLogging | Structured Log per Auth Event | MUST | TC-13 | test_TC13_audit_log_integrity.py | VERIFIED |
| REQ-052 | AuditLogging | Log Integrity — Hash Chain | MUST | TC-13 | test_TC13_audit_log_integrity.py | VERIFIED |
| REQ-053 | AuditLogging | Log Entry for Session Events | MUST | TC-13 | test_TC13_audit_log_integrity.py | VERIFIED |

---

## Test Case Progress

| TC ID | Title | Status | RED Confirmed | GREEN Confirmed | Notes |
|-------|-------|--------|---------------|-----------------|-------|
| TC-01 | Session State Machine — Basic Transitions | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 8/8 passed |
| TC-02 | Session Lifecycle — Timeout / Concurrency / Tamper | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 8/8 passed (3 slow) |
| TC-03 | 0x27 Seed Generation | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 8/8 passed |
| TC-04 | 0x27 Key Validation — Positive Path | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 9/9 passed |
| TC-05 | 0x27 Negative Responses | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 8/8 passed |
| TC-06 | 0x29 Certificate Validation | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 7/7 passed |
| TC-07 | 0x29 Authentication Flow | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 8/8 passed |
| TC-08 | Access Level Gating — RBAC | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 13/13 passed |
| TC-09 | Lockout and Delay Timer | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 10/10 passed (3 slow) |
| TC-10 | Session Token Binding and Re-authentication | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 9/9 passed (2 slow) |
| TC-11 | Replay Attack Detection | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 6/6 passed |
| TC-12 | Anomaly and Tamper Handling | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 10/10 passed |
| TC-13 | Audit Log Integrity | VERIFIED | ✓ 2026-06-04 | ✓ 2026-06-04 | 11/11 passed |

---

## Implementation Coverage by Module

| Module | Implements | TCs Covered | Status |
|--------|-----------|-------------|--------|
| sim/core/session.py | REQ-001–009 (session SM + timer) | TC-01, TC-02 | VERIFIED |
| sim/core/security_access.py | REQ-010–019, REQ-036–041 | TC-03–05, TC-09 | VERIFIED |
| sim/core/authentication.py | REQ-020–029, REQ-046 | TC-06, TC-07, TC-11 | VERIFIED |
| sim/core/audit_logger.py | REQ-051–053 | TC-13 | VERIFIED |
| sim/core/ecu.py | REQ-007, REQ-030–035, REQ-042–045, REQ-047–050 | TC-01–13 | VERIFIED |
| sim/hal/crypto_backend.py | REQ-011, REQ-013, REQ-016, REQ-022, REQ-027 | TC-03–04, TC-06–07, TC-11 | VERIFIED |
| sim/hal/cert_store_sim.py | REQ-020–029 | TC-06, TC-07 | VERIFIED |
| sim/protocol/rpc.py | (JSON-RPC transport) | All | VERIFIED |
| sim/protocol/client.py | (Diagnostic Client — Process 1) | All | VERIFIED |
| sim/protocol/uds_server.py | (WebSocket dashboard bridge) | — | COMPLETE |
| gui/secure_access_monitor.html | (Real-time browser dashboard) | — | COMPLETE |
| sim/protocol/uds_client.py | All | All | PENDING |
