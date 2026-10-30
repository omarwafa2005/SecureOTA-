# Five-minute baseline review: script

Follows guide Section 16. Before the review, run `python run_all.py` so the evidence is fresh. Keep a
terminal open in `phase2/`.

**Backup:** record a screen walkthrough of this script (action A-06) in case the live demo fails.

| Time | Part | Show | Say (key points) |
|---|---|---|---|
| 0:00–1:00 | S1 Vehicle | Context and data-flow diagram ([vehicle_spec.md](vehicle_spec.md)); ECU state machine; `python walkthrough.py` | Gateway verifies in 11 ordered steps before anything reaches an ECU. Staging writes only the inactive slot. Activation is gated by speed 0, battery ≥ 12.0 V, ignition, park and no diagnostic session. Health failure, timeout or 3 bad boots cause rollback. 12 power-loss checkpoints all leave a bootable confirmed image (FR-03 to FR-10, SAF-01 to SAF-10) |
| 1:00–2:00 | S2 Backend | [generated/authorization_matrix.md](generated/authorization_matrix.md); API catalog; assignment state diagram | Six roles; every action audited SUCCESS, DENIED or FAILED in a hash chain. Creator ≠ approver. A vehicle acts only for itself. Every request is one transaction. Event reports are idempotent. Errors carry a category and correlation ID only (SR-08, SR-09, SR-11, SR-14, SR-18, FR-12, FR-13) |
| 2:00–3:15 | S3 Security | Attacker model table; [generated/risk_register.md](generated/risk_register.md) top 10; key lifecycle sequence diagram; [generated/standards_matrix.md](generated/standards_matrix.md) | Seven attacker types with explicit limits. 35 risks: 10 critical, 17 high, each with prevention, detection, recovery and a negative test. Root-signed key set gives rotation and revocation. Standards are *informed by* only; ISO texts were not accessed, and we claim no compliance |
| 3:15–4:15 | Integration | `python e2e_trace.py` | Walk A-01 → B-03 → 15 Critical → SR-02 → signed digest checked twice → AT-18 → `evidence/walkthrough/AT-18.json`. One correlation ID joins the vehicle rejection and the backend REJECTED status. Then say why TLS alone is not enough ([security_review.md](security_review.md) §3) |
| 4:15–5:00 | Decisions | [security_review.md](security_review.md) §4; [governance.md](governance.md) §8 | Decisions needed: D-04 bus authentication, D-05 the 17 proposed requirements, D-06 to D-12 residual risks. Phase 3 inputs: metadata roles (Uptane/TUF), signed event reports, bus authentication, audit anchor storage |

## Likely questions and where the answers are

| Question | Answer location |
|---|---|
| What if the clock is wrong? | ASM-01 and D-08: expiry conclusions are limited to a trusted clock. Replay and downgrade protection do not depend on time |
| What if the backend is fully compromised? | Content attacks fail on the vehicle (AT-18, AT-23). Forged approvals are residual D-06 |
| How do you rotate or revoke a key? | ACC-30, AT-25, and the key lifecycle table in [security_spec.md](security_spec.md) §2.3 |
| How do you know nothing was missed? | `tools/check_trace.py`: every Must requirement and every high risk is linked to a passing test |
| Can someone else reproduce this? | `pip install -r requirements.txt && cd phase2 && python run_all.py` (NFR-01, QT-04) |
