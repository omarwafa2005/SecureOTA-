# Governance: review plan, decisions, changes and evidence

Maintained by Student 2 (S2-T4). Every artifact in this phase has an owner, a reviewer, a version and a
status.

> Sections marked **To be filled** record things that only the team and the supervisor can do:
> meetings, approvals and signatures. They are deliberately left blank. Do not fill them in until the
> event has happened.

## 1 Artifact register

| Artifact | Version | Author | Mandatory reviewer | Status |
|---|---|---|---|---|
| Vehicle requirements and state model ([student1_vehicle_spec.md](student1_vehicle_spec.md)) | 0.9 → 1.0-rc1 | S1 | S3 | Review candidate |
| Backend APIs and data concepts ([student2_backend_spec.md](student2_backend_spec.md)) | 1.0-rc1 | S2 | S1 | Review candidate |
| Security requirements and key lifecycle ([student3_security_spec.md](student3_security_spec.md)) | 1.0-rc1 | S3 | S2 | Review candidate |
| Vehicle threats and safety risks (V-, F-, vehicle T- rows) | 1.0-rc1 | S1 | S3 | Draft, awaiting workshop |
| Backend threats and authorization risks (B- rows, T-10, T-12) | 1.0-rc1 | S2 | S3 | Draft, awaiting workshop |
| Traceability matrix (`trace/traceability.csv`) | 1.0-rc1 | S3 | S1 and S2 | Automated checks pass |
| SRS, use cases, data flows, threat model, security review | 1.0-rc1 | All / S3 integrates | All | Review candidate |
| Combined phase package (`run_all.py`) | 1.0-rc1 | S2 | S1 and S3 | Passes on the author's machine; clean reproduction pending (§6) |

## 2 Phase test and review plan (guide Section 14)

| ID | Check | How | Current status |
|---|---|---|---|
| P2-01 | Requirement wording | `check_trace.py` (SHALL, vague words) + human review | Automated part passes; human review **to be done** |
| P2-02 | Identifier integrity | `check_trace.py` | Pass |
| P2-03 | Must coverage | `check_trace.py` | Pass (51/51 Must with owner, reviewer, test) |
| P2-04 | Normal-flow coverage | [use_cases.md](use_cases.md) preconditions and postconditions | Prepared; review **to be done** |
| P2-05 | Failure coverage | FT-01 to FT-05, ACC-15, UC-06/07/09/10 failure flows | Tests pass; review **to be done** |
| P2-06 | Attack coverage | `check_trace.py` | Pass (27/27 high or critical with a negative test) |
| P2-07 | Risk rationale | Rationale columns in `threats.csv`; scoring workshop | Rationale present; workshop **to be done** |
| P2-08 | Control completeness | `check_trace.py` | Pass |
| P2-09 | Standards claim review | `check_trace.py` wording rule + human review | Automated part passes; UN R156 clause check open (A-03) |
| P2-10 | Contract consistency | Field contract in [student2_backend_spec.md](student2_backend_spec.md) §2, E2E-01 | E2E-01 passes; S1 field-by-field review **to be done** |
| P2-11 | Clean reproduction | §6 | **To be done** by S1 and S3 |
| P2-12 | Supervisor baseline review | §7 | **To be done** |

## 3 Review and workshop minutes — **to be filled**

Template, one block per meeting:

```
Meeting:        (daily / integration / weekly evidence / workshop / baseline review)
Date, time:
Participants:
Commit reviewed: (git rev-parse --short HEAD)
Artifacts and versions:
Decisions:      (D-xx)
Score changes:  (threat, old -> new, reason)
Actions:        (A-xx, owner, due)
```

## 4 Decision log

| ID | Decision | Rationale | Status |
|---|---|---|---|
| D-01 | Keep Phase 1 code unchanged; Phase 2 lives in `phase2/` | Phase 1 is the working baseline; Phase 2 prototypes are feasibility evidence only | Proposed by the team |
| D-02 | CSV files in `trace/` are the single source; Markdown tables are generated | Prevents silent divergence (change-control rule) | Proposed |
| D-03 | Use Ed25519 with canonical JSON as a placeholder envelope; full metadata design (Uptane/TUF roles) is Phase 3 | Working rule: no custom crypto; keep the phase about requirements | Proposed |
| D-04 | Gateway-to-ECU message authentication | See [security_review.md](security_review.md) §4 | **Supervisor decision needed** |
| D-05 | Add 17 proposed requirements (FR-11 to FR-15, SR-13 to SR-20, SAF-07 to SAF-10) | Each answers a threat with no baseline requirement | **Supervisor approval needed** for new Musts |
| D-06 to D-12 | Residual risks | See [security_review.md](security_review.md) §4 | **Supervisor decision needed** |
| D-13 | Rejected idea: rely on TLS for firmware integrity | Does not cover B-03, B-04, T-03, T-04, T-05, K-03 | Rejected |
| D-14 | Rejected idea: let operators disable `require_safe_state` per campaign | Would allow remote override of SAF-03 and SAF-04 | Rejected |

No guide baseline Must requirement has been removed.

## 5 Change log

| Version | Date | Change | Author | Reviewer |
|---|---|---|---|---|
| 0.9 | | Student 1 vehicle package (27 requirements, 20 threats, 39 tests) | S1 | |
| 1.0-rc1 | | Merged package: backend and security requirements and threats, assets, standards, full matrix, docs, 72 tests | | |

After baseline approval, every change to a Must requirement, a high-risk score, a public contract or a
security assumption needs a row here plus an issue ID.

## 6 Evidence index and clean reproduction

| Evidence | Produced by | Path |
|---|---|---|
| Test log (all IDs) | `run_all.py` step 1 | `evidence/unittest.log` |
| Trace check | step 2 | `evidence/trace_check.log` |
| Generated-table check | step 3 | `evidence/build_docs.log` |
| Repository secret scan | step 4 | `evidence/secret_scan.log` |
| Vehicle walkthrough (5 scenarios) | step 5 | `evidence/walkthrough/*.json`, `walkthrough.log` |
| Tampered-firmware trace | step 6 | `evidence/walkthrough/AT-18.json`, `e2e_trace.log` |
| Latency | step 7 | `evidence/latency.csv` |
| Evidence secret scan | step 8 | `evidence/evidence_scan.log` |
| Summary | `run_all.py` | `evidence/run_all.log` |

**Clean reproduction record — to be filled:**

| Reproduced by | Date | OS / Python | Commit | Commands | Result |
|---|---|---|---|---|---|
| Student 1 | | | | `git clone …; pip install -r requirements.txt; cd phase2; python run_all.py` | |
| Student 3 | | | | same | |

## 7 Supervisor baseline review — **to be filled**

| Item | Decision | Notes |
|---|---|---|
| Must set (51) approved, including the proposed additions (D-05) | | |
| Prioritized risks approved; critical residual risks accepted (D-12) | | |
| Decisions D-04, D-06 to D-11 | | |
| Baseline version 1.0 approved | | |

## 8 Unresolved action list

| ID | Action | Owner | Due |
|---|---|---|---|
| A-01 | Run the scoring workshop and confirm or change every score; record it in §3 | S3 (all attend) | W5-D3 |
| A-02 | Field-by-field contract review of backend ↔ vehicle (P2-10) | S1 | W6-D1 |
| A-03 | Confirm UN R156 clause references against the public UNECE text before citing them | S3 | W6-D3 |
| A-04 | Clean reproduction from a fresh clone by S1 and S3 (P2-11) | S1, S3 | W6-D4 |
| A-05 | Fill in contribution statements | each student | W6-D4 |
| A-06 | Record the 5-minute presentation backup walkthrough | all | W6-D4 |
| A-07 | Supervisor decisions D-04, D-05, D-06 to D-12 | supervisor | W6-D5 |
