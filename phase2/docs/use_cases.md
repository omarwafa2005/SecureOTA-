# Use cases and quality-attribute scenarios

Version 1.0-rc1. Owners follow guide Section 6. Abuse flows are reviewed from the S3 security view. Each use case uses
the guide template: goal, actor, requirements, preconditions, normal flow, alternative, failure and
abuse flows, postconditions with audit and state, and tests.

The vehicle-side use cases UC-05 to UC-10 are also summarized in
[vehicle_spec.md](vehicle_spec.md).

---

## UC-01 Register vehicle and ECUs (owner S2)

- **Goal / actor:** Add a vehicle and its ECU identities to the registry. Actor: registrar.
- **Requirements:** FR-01, PR-01, SR-08, SR-09
- **Preconditions:** The registrar is authenticated, and the vehicle_id is not registered yet.
- **Normal flow:**
  1. The registrar sends `POST /vehicles` with `vehicle_id`, `ecus[{ecu_id, hardware_id}]`,
     `manifest_key_id` and `manifest_public_key`.
  2. The backend checks the identity format, uniqueness and key format.
  3. The backend stores the record and returns 201 with the ECU list.
- **Alternative / failure / abuse:**
  - Duplicate vehicle or ECU → 409 `DUPLICATE_VEHICLE` / `DUPLICATE_ECU`.
  - Invalid ID → 422 `INVALID_IDENTITY`.
  - Extra personal fields such as owner name or GPS → 422 `UNEXPECTED_FIELD`.
  - Non-registrar caller → 403, audited as DENIED.
- **Postconditions:** On success, one vehicle record with only allowed fields. On error, no partial
  record, because the transaction rolls back. One `register_vehicle` audit event either way.
- **Tests / evidence:** ACC-20, ACC-31, AT-10

## UC-02 Upload firmware artifact (owner S2)

- **Goal / actor:** Store an image with its digest. Actor: release creator.
- **Requirements:** SR-01, SR-19, SR-08
- **Preconditions:** The caller has the `release_creator` role.
- **Normal flow:**
  1. The creator sends `POST /artifacts?ecu_id=…&hardware_id=…` with the raw body.
  2. The backend checks the size before storing anything.
  3. The backend computes SHA-256 and length and stores the artifact as `art-<sha256[:16]>`.
  4. The backend returns the ID, digest and length.
- **Alternative / failure / abuse:**
  - Identical upload → same artifact (idempotent).
  - Same ID with different content → 409.
  - Empty body → 422 `EMPTY_ARTIFACT`.
  - Body over 16 MiB → 413 `ARTIFACT_TOO_LARGE`; nothing is stored.
- **Postconditions:** The artifact record and blob are stored, plus one audit event.
- **Tests:** ACC-24, AT-29

## UC-03 Create and approve signed release (owners S2/S3)

- **Goal / actors:** Turn an artifact into a release that may be signed. Actors: creator, then a
  different approver.
- **Requirements:** SR-01, SR-15, SR-18, SR-09
- **Preconditions:** The artifact exists.
- **Normal flow:**
  1. The creator sends `POST /releases {artifact_id, version}` and gets back a DRAFT release, which
     copies the digest and length from the artifact.
  2. The approver sends `POST /releases/{id}/approve`, and the release becomes APPROVED.
  3. Signing happens later, per vehicle, when instructions are built (UC-05). The signing service
     re-checks the approval and that the payload equals the release.
- **Alternative / failure / abuse:**
  - The creator approves their own release → 403 `SEPARATION_OF_DUTIES`; the backend audits DENIED
    and the signing service refuses too.
  - Version already exists for that ECU and hardware → 409 `VERSION_EXISTS`.
  - A signing request for a draft, or with a changed payload or the wrong key role → refused and
    logged in the key usage log.
- **Postconditions:** The release is APPROVED with `approved_by` different from `created_by`.
- **Tests:** ACC-25, AT-26

## UC-04 Create and start campaign (owner S2)

- **Goal / actor:** Offer approved releases to explicit vehicles. Actor: campaign operator.
- **Requirements:** FR-07, FR-14, FR-15, SR-08
- **Preconditions:** The releases are APPROVED and the target vehicles are registered.
- **Normal flow:**
  1. The operator sends `POST /campaigns` with `{release_ids, targets, policy {expires_in_s,
     require_safe_state: true}, dependencies?}`.
  2. The backend checks targets, compatibility and policy, and orders ECUs by their dependencies.
  3. The campaign is created as DRAFT.
  4. The operator sends `POST /campaigns/{id}/start` and the campaign becomes RUNNING.
- **Alternative / failure / abuse:**
  - Empty targets, unknown target or incompatible hardware → 422.
  - `require_safe_state=false` → 422 `INVALID_POLICY`, because the safety gate cannot be disabled
    remotely.
  - Dependency cycle → 422 `DEPENDENCY_CYCLE` with a path such as `ECU-A -> ECU-B -> ECU-A`.
  - Unapproved release → 409.
  - Pause then start again → allowed.
- **Postconditions:** The campaign stores an `ecu_order`. One audit event per call.
- **Tests:** ACC-22, ACC-21 (pause), AT-12

## UC-05 Request vehicle instructions (owners S1/S2)

- **Goal / actor:** The gateway learns what to install. Actor: vehicle gateway.
- **Requirements:** FR-02, FR-15, SR-08, SR-07
- **Preconditions:** The gateway is authenticated as its own vehicle_id.
- **Normal flow:**
  1. The gateway sends `GET /vehicles/{vid}/instructions`.
  2. For each RUNNING campaign that targets the vehicle, the backend picks the eligible ECUs. An ECU
     is eligible when its hardware matches and its reported version is below the release version.
  3. The backend creates an OFFERED assignment and asks the signing service for a per-vehicle target
     with the next `metadata_version`.
  4. The backend returns bundles `{campaign_id, targets[]}`, with targets in dependency order.
  5. The gateway verifies the whole bundle before any download (T-06).
- **Alternative / failure / abuse:**
  - No eligible update → `bundles: []`.
  - Repeated poll → the same signed offer, which the gateway reports as ALREADY_APPLIED if it has
    already staged it.
  - Expired offer → re-signed with a higher `metadata_version`.
  - Another vehicle's ID → 403.
  - Unknown vehicle → 404.
  - Tampered or mixed bundle → the gateway rejects the whole bundle.
- **Postconditions:** Assignments are OFFERED and audited.
- **Tests:** ACC-21, AT-06, AT-23, AT-31

## UC-06 Download and verify artifact (owners S1/S3)

- **Goal / actor:** Get the exact signed bytes. Actor: gateway.
- **Requirements:** FR-03, SR-02, SR-03, SR-12, NFR-04
- **Preconditions:** The target metadata has passed the signature, expiry, target, replay, version and
  length checks.
- **Normal flow:**
  1. The gateway fetches the `artifact_id` named in the signed metadata. The backend serves it only
     because it was offered to this vehicle.
  2. The gateway reads in chunks, capped at `length`, with stall and total timeouts.
  3. The gateway checks the exact length and SHA-256.
- **Alternative / failure / abuse:**
  - Tampered bytes → `DIGEST_MISMATCH`.
  - Truncated → `LENGTH_MISMATCH`.
  - Oversized or endless → `ARTIFACT_TOO_LARGE`.
  - Slow → `DOWNLOAD_TIMEOUT`.
  - Disconnect → `NETWORK_ERROR`, then a clean retry.
  - In every case nothing is staged.
- **Postconditions:** The verified image is in gateway memory only. A `download VERIFIED` or
  `REJECTED` event is recorded.
- **Tests:** ACC-01, AT-01, AT-08, AT-09, AT-18, FT-01

## UC-07 Stage into inactive slot (owner S1)

- **Requirements:** FR-04, FR-05, SAF-01, SAF-02, SAF-06, SAF-08
- **Normal flow:**
  1. The ECU re-checks the target, version, length and digest.
  2. It writes an intent record, then writes a temp file and fsyncs it.
  3. It atomically renames the file into the inactive slot.
  4. It commits STAGED.
- **Failure:** Storage error or power loss at any checkpoint → on restart the partial image is
  discarded, the state returns to IDLE and the active slot is unchanged.
- **Postconditions:** STAGED. The active and confirmed slots are unchanged.
- **Tests:** ACC-02, ACC-03, ACC-10, ACC-11, ACC-15, FT-03

## UC-08 Activate and confirm health (owner S1)

- **Requirements:** FR-09, SAF-03, SAF-04, SAF-05, SAF-07, SAF-09, SAF-10
- **Normal flow:**
  1. The gateway requests activation and the ECU evaluates the safety policy.
  2. The ECU re-checks the staged digest, switches slots and moves to INSTALLED.
  3. On boot the ECU checks the active image digest and counts boot attempts.
  4. A positive health report moves it to CONFIRMED and raises `trusted_min_version`.
- **Failure / abuse:**
  - Unsafe state → POSTPONED; the ECU stays STAGED and the event is kept.
  - Staged image corrupted → REJECTED.
  - Health failed, timed out or the boot limit was reached → ROLLED_BACK.
  - Unsolicited command in the wrong state → `INVALID_STATE`.
- **Tests:** ACC-06, ACC-12, ACC-13, ACC-14, AT-13, AT-14, AT-15, AT-16, FT-05

## UC-09 Rollback after failed health (owner S1)

- **Requirements:** FR-10, SAF-05
- **Normal flow:** The confirmed slot becomes active in one atomic state write, and a ROLLED_BACK event
  records the cause.
- **Failure:** Interrupted rollback → on restart the boot limit completes the rollback.
- **Tests:** ACC-07, FT-03b, FT-04

## UC-10 Resume after disconnect (owners S1/S2)

- **Requirements:** FR-11, FR-13, F-02 recovery
- **Normal flow:**
  1. After a disconnect or a gateway crash, the gateway polls again.
  2. Identical signed metadata gives ALREADY_APPLIED, so nothing is downloaded twice.
  3. Retried event reports with the same `event_id` are applied once.
- **Failure:** Inconsistent partial state is reconciled to ALREADY_APPLIED. A stale event, with an old
  `metadata_version`, gets 409 `STALE_EVENT`.
- **Tests:** ACC-08, FT-01, FT-02, AT-30

## UC-11 Review audit trail (owners S2/S3)

- **Actor:** auditor.
- **Requirements:** SR-09, SR-14, NFR-02, US-01
- **Normal flow:**
  1. The auditor sends `GET /audit?correlation_id=…`.
  2. The backend returns the events plus `chain_intact`.
  3. The auditor joins backend and vehicle events by correlation ID.
  4. The operator status view labels each assignment state distinctly.
- **Abuse:**
  - Non-auditor caller → 403, audited.
  - Modified or deleted events → `chain_intact=false` with `first_bad_seq`.
- **Tests:** ACC-26, ACC-27, ACC-28, ACC-29, AT-22, AT-28

## UC-12 Reject malicious update (owner S3)

- **Requirements:** SR-02 to SR-07, SR-16, SR-17, US-02
- **Normal flow:** For any attack in the catalog, the vehicle returns
  `{status: REJECTED, reason, correlation_id}` and nothing else. The ECU's persistent state and both
  slot files are byte-identical to before.
- **Tests:** AT-01 to AT-09, AT-11, AT-17, AT-18, AT-23 to AT-26

---

## Quality-attribute scenarios

| ID | Source | Stimulus | Environment | Artifact | Response | Measure | Req / test |
|---|---|---|---|---|---|---|---|
| QS-01 | Hostile network peer | Transfer stalls below the progress threshold | Download in progress | Gateway downloader | Abort without staging | Abort within `stall_timeout_s` (10 s); slot B and trusted state unchanged | NFR-04 / AT-09 |
| QS-02 | Fault injector | Power loss at any of the 12 ECU checkpoints | Staging, activation, confirmation or rollback | ECU persistence | Recover on restart | Active slot image matches its recorded digest at every checkpoint | SAF-06 / ACC-15, FT-03 |
| QS-03 | Release engineer | 16 MiB artifact | Normal operation on the reference laptop | Gateway + ECU pipeline | Verify and stage | Median and max latency recorded in `evidence/latency.csv` (first run: about 100 ms median) | NFR-03 / QT-03 |
| QS-04 | Malicious operator | Privileged action outside their role | Backend running | Authorization matrix | Deny and audit | 403; exactly one DENIED event with actor and correlation ID; no state change | SR-08, SR-09 / AT-10 |
| QS-05 | Reviewer | Fresh clone | Python 3.10+ | Phase package | Reproduce all evidence | `python run_all.py` exits 0 and writes every evidence file | NFR-01 / QT-04 |
| QS-06 | Attacker with storage access | Changes one bit of a signed artifact | Campaign running | Gateway verifier | Reject before staging | `DIGEST_MISMATCH`; backend assignment REJECTED with the same correlation ID | SR-02 / AT-18 |
