# SecureOTA-V — Merged Phase 2: Requirements, Threat Analysis and Security Traceability

Phase package for weeks 3-6. It holds the requirements specification, threat model, risk register,
traceability matrix and standards mapping, plus feasibility prototypes and tests that make every Must
requirement and every high or critical risk verifiable.

Simulation only. There is no real vehicle, CAN bus, flash driver, cloud deployment or hardware key store.
Phase 1 code (`../backend`, `../gateway`, `../ecu_simulator`) is unchanged.

**Baseline status: version 1.0 review candidate. It is NOT approved yet.** Supervisor approval, the
review meetings and the contribution statement are still to be done (see
[docs/governance.md](docs/governance.md)).

## Run it from a clean checkout

You need Python 3.10 or newer. Run these from the repository root:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cd phase2
python run_all.py
```

`run_all.py` runs every step below, writes its output to `evidence/`, and exits with 0 only if all
steps pass.

| Step | Command (from `phase2/`) | What it proves |
|---|---|---|
| Tests | `python -m unittest discover -s tests -t . -v` | Acceptance (ACC), attack (AT), fault (FT), quality (QT) and end-to-end (E2E) tests |
| Trace check | `python tools/check_trace.py` | No duplicate IDs. Every Must requirement has an owner, a reviewer, a matrix row and a test. Every high or critical risk has controls and a negative test. No standards row claims compliance |
| Tables | `python tools/build_docs.py --check` | The tables in `docs/generated/` match the CSV sources |
| Secret scan | `python tools/scan_secrets.py` | No private key, key file or credential is in the repository (SR-10) |
| Vehicle walkthrough | `python walkthrough.py --evidence evidence/walkthrough` | Five vehicle scenarios, each showing the final slot and version |
| Tampered firmware trace | `python e2e_trace.py --evidence evidence/walkthrough` | Asset → threat → risk → requirement → control → test → evidence for one critical risk |
| Latency | `python tools/bench_verify.py --out evidence/latency.csv` | Verification latency for 64 KiB, 1 MiB and 16 MiB artifacts (NFR-03) |

After you change a CSV in `trace/`, run `python tools/build_docs.py` to regenerate the tables.

## Where each guide deliverable lives (guide Section 15)

| Required package item | Location |
|---|---|
| Software Requirements Specification | [docs/SRS.md](docs/SRS.md) |
| Prioritized requirements catalog | [docs/generated/requirements_catalog.md](docs/generated/requirements_catalog.md), source `trace/requirements.csv` |
| Requirements change log, decision log | [docs/governance.md](docs/governance.md) |
| Actor, asset and data dictionaries | [docs/SRS.md](docs/SRS.md) §2, [docs/generated/asset_inventory.md](docs/generated/asset_inventory.md), `trace/state_fields.csv` |
| Use cases and quality-attribute scenarios | [docs/use_cases.md](docs/use_cases.md) |
| Data-flow diagrams with trust boundaries | [docs/data_flows.md](docs/data_flows.md) |
| Attacker model and security assumptions | [docs/security_spec.md](docs/security_spec.md) §1 |
| STRIDE worksheets, attack trees, threat catalog | [docs/threat_model.md](docs/threat_model.md) |
| Prioritized risk register | [docs/generated/risk_register.md](docs/generated/risk_register.md), source `trace/threats.csv` |
| Standards traceability matrix | [docs/generated/standards_matrix.md](docs/generated/standards_matrix.md), source `trace/standards.csv` |
| Acceptance, attack and fault-test skeletons | `tests/`, listed in [docs/generated/test_catalog.md](docs/generated/test_catalog.md) |
| Master traceability matrix | [docs/generated/traceability_matrix.md](docs/generated/traceability_matrix.md), source `trace/traceability.csv` |
| Review minutes, unresolved actions | [docs/governance.md](docs/governance.md) |
| Security review report | [docs/security_review.md](docs/security_review.md) |
| Contribution statement | [docs/contribution_statements.md](docs/contribution_statements.md) (template, to be filled in) |
| Five-minute review presentation | [docs/presentation.md](docs/presentation.md) |

## Work packages

The work is split into three workstreams, S1 to S3. The owner and reviewer columns in
`trace/` record which workstream an item belongs to and which one it was checked against.

| Workstream | Specification | Prototype and tests |
|---|---|---|
| S1 Vehicle, gateway and ECU | [docs/vehicle_spec.md](docs/vehicle_spec.md) | `vehicle/`, `tests/test_acceptance.py`, `test_attacks.py`, `test_faults.py`, `test_safety.py`, `walkthrough.py` |
| S2 Backend, API and DevSecOps | [docs/backend_spec.md](docs/backend_spec.md) | `oem_backend/`, `tests/test_backend.py`, `run_all.py`, `tools/build_docs.py` |
| S3 Security, research and verification | [docs/security_spec.md](docs/security_spec.md) | `security/`, `tests/test_security.py`, `tools/check_trace.py`, `tools/scan_secrets.py`, `tools/bench_verify.py` |
| All | [docs/threat_model.md](docs/threat_model.md), [docs/security_review.md](docs/security_review.md) | `tests/test_e2e.py`, `tests/fleet.py`, `e2e_trace.py` |

## Layout

```
docs/          written specification, models and review package; generated/ holds tables built from trace/
trace/         CSV source of truth: requirements, threats, assets, state fields, standards, traceability
vehicle/       S1 prototype: gateway verifier, A/B ECU, safety policy, manifest
oem_backend/   S2 prototype: domain service, authorization matrix, hash-chained audit, HTTP API
security/      S3 prototype: key roles, root-signed trusted key set, signing service
tests/         all tests; fleet.py connects backend, signing service and vehicle
tools/         check_trace, build_docs, scan_secrets, bench_verify
evidence/      created by run_all.py (not committed)
```

## Ground rules

- Cryptography comes from the `cryptography` library (Ed25519) and `hashlib` (SHA-256). No custom
  primitives.
- Keys and tokens are generated in memory on every run. Exported keys must be stored outside the
  source tree, encrypted with a passphrase from `SECUREOTA_KEY_PASSPHRASE`.
- The prototypes are feasibility evidence (schedule item W6-D2). They are not the final architecture.
  Architecture and metadata design are Phase 3 decisions.
