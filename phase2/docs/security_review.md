# Security review report — Merged Phase 2

Version 1.0-rc1. Author: Student 3. Reviewers: Students 1 and 2. Decision-maker for §4: the supervisor.

## 1 Scope and method

This review covers the requirements baseline, the threat catalog, the risk register, the traceability
matrix and the feasibility prototypes in `vehicle/`, `oem_backend/` and `security/`. The method was:

1. Walk every trust boundary ([data_flows.md](data_flows.md)) against the STRIDE worksheets
   ([threat_model.md](threat_model.md)).
2. Check every high or critical risk for prevention, detection, recovery and a negative test.
3. Run `python run_all.py` and inspect the evidence.

## 2 Results (first full run on the reference machine)

| Check | Result | Evidence |
|---|---|---|
| Automated tests | 72 tests (ACC, AT, FT, QT, E2E), all pass | `evidence/unittest.log` |
| Traceability | 53 requirements (51 Must), 35 threats (27 high or critical), 64 matrix rows, 68 test IDs; no missing links | `evidence/trace_check.log` |
| Generated tables | 7 tables match their CSV sources | `evidence/build_docs.log` |
| Secret scan | Repository and evidence: no findings | `evidence/secret_scan.log`, `evidence/evidence_scan.log` |
| Vehicle walkthrough | ACC-06, AT-01, AT-04, FT-05, FT-04 all pass | `evidence/walkthrough/*.json` |
| End-to-end trace | AT-18 passes | `evidence/walkthrough/AT-18.json` |
| Latency (NFR-03) | Median pipeline: 64 KiB ≈ 10 ms, 1 MiB ≈ 14 ms, 16 MiB ≈ 102 ms (Python 3.14, AMD64) | `evidence/latency.csv` |

Re-run `run_all.py` before the review. The numbers above are from the first run and will vary by
machine.

## 3 End-to-end trace of one critical risk (tampered firmware)

This is the scenario for review slot 3:15–4:15. Run `python e2e_trace.py`.

| Link | Value |
|---|---|
| Asset | A-01 Firmware image (integrity High) |
| Threat | B-03 Artifact replaced in backend object storage after signing (Tampering, compromised online service). Same control path as T-01 for a network attacker |
| Risk | 3 × 5 = 15 Critical. Likelihood 3: object storage is online and broadly accessible. Impact 5: malicious firmware offered fleet-wide |
| Requirement | SR-02: the gateway rejects a digest or length mismatch before any byte reaches a slot, and the ECU repeats the check. Supported by SR-01 (digest published at upload) and SR-03 (digest is inside the signed metadata) |
| Control | Prevention: the signed SHA-256 and length are checked at the gateway and again at the ECU. Detection: a `DIGEST_MISMATCH` vehicle event plus a REJECTED backend assignment, sharing one correlation ID. Recovery: nothing is staged, so restore the blob from the release record |
| Component | Gateway verifier + ECU (S1); artifact service (S2); signing service (S3) |
| Test | AT-18 (`tests/test_e2e.py`), plus AT-01 for the network-attacker variant |
| Expected result | `{status: REJECTED, reason: DIGEST_MISMATCH, correlation_id}`; ECU state and both slot files byte-identical; backend assignment `REJECTED` with reason `DIGEST_MISMATCH` |
| Evidence | `evidence/walkthrough/AT-18.json` (vehicle and backend events joined by correlation ID) |

### Why TLS alone is not enough

TLS authenticates a server and protects bytes on one connection. It does not cover these threats:

1. **B-03 / B-04, compromised backend or storage.** TLS faithfully delivers whatever the server holds,
   including a swapped image or an edited offer. Only a signature made over the content, and checked
   on the vehicle, catches this (AT-18, AT-23).
2. **T-03 / T-04, replay and downgrade.** An old, validly signed release served over a perfectly valid
   TLS session is still old. The vehicle needs `metadata_version` and `trusted_min_version` (AT-03,
   AT-04).
3. **T-05, wrong target.** TLS knows nothing about ECU or hardware binding.
4. **K-03, key compromise.** A stolen TLS server key or a mis-issued certificate gives a network
   attacker the server's identity. Firmware trust must not depend on it. The release key and the
   root-signed key set are separate, and are revocable on the vehicle (AT-25).
5. **Evidence.** TLS leaves no lasting proof of what was installed. Signed manifests and the audit
   chain do (SR-13, SR-14, SR-20).

TLS remains useful for confidentiality of credentials and for privacy, but the design treats the
transport as untrusted (ASM-05).

## 4 Residual risks and decisions needed

| ID | Residual risk | Related | Proposed decision | Needs |
|---|---|---|---|---|
| D-04 | Gateway-to-ECU messages are not authenticated (in-process calls). A malicious CAN peer is blocked only by the state machine | V-01 (10 High), ASM-03 | Accept for Phase 2. Phase 3 architecture chooses message authentication for the bus (e.g. SecOC-style MAC) or keeps ECUs as in-process simulation | Supervisor |
| D-06 | The signing service trusts the approval record. Full backend compromise can forge an approval | K-01 (10 High), B-04 | Accept for Phase 2. Phase 3 evaluates approver signatures or an Uptane-style offline image repository | Supervisor |
| D-07 | Event reports are token-authenticated, not signed | B-08 (12 High) | Accept. Signed per-ECU reports decided with metadata design in Phase 3 | S2 + S3 |
| D-08 | Expiry depends on a trusted clock | T-07 (6 Medium), ASM-01 | Accept and state the limitation in all conclusions | S3 |
| D-09 | Revocation does not reach offline vehicles until they connect | K-03 (10 High) | Accept. Record in the claims boundary | S3 |
| D-10 | Simulated tokens have no expiry or rotation; there is no rate limiting | B-01 (12 High), B-06 (8 Medium) | Accept for the prototype. Real identity provider and rate limits are deployment items | S2 |
| D-11 | The audit chain can be rebuilt by an attacker with full write access unless the anchor is stored elsewhere | B-05 (12 High) | Accept. Phase 3 defines where anchors are exported | S2 |
| D-12 | Critical risks need explicit acceptance of their residual risk (guide Section 7) | T-01, F-05, T-02, T-04, F-03, F-04, V-05, B-02, B-03, B-09 | Accept the residual statements in the risk register | Supervisor |

## 5 Reviewer verdict

| Reviewer | Verdict (accepted / accepted with action / rejected) | Comments | Date |
|---|---|---|---|
| Student 1 | | | |
| Student 2 | | | |
| Supervisor | | | |
