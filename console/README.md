# SecureOTA-V demo console

A web UI over the Phase 2 prototypes, for demonstrations. It drives the real
OEM backend API (`phase2/oem_backend`) and one simulated vehicle (gateway plus
two A/B ECUs from `phase2/vehicle`), wired the same way as `phase2/tests/fleet.py`.

**Demo only.** The server hands out the per-run bearer tokens so you can switch
roles in the UI, so it listens on `127.0.0.1` only. Nothing in `phase2/` is changed.

## Run it

You need Python 3.10+ (with `requirements.txt` installed) and Node.js 18+.

Development, two terminals from the repository root:

```bash
python console/server.py                 # API on http://127.0.0.1:8000
cd console/web && npm install && npm run dev   # UI on http://localhost:5173
```

Single process, after building the UI once:

```bash
cd console/web && npm install && npm run build && cd ../..
python console/server.py                 # UI and API on http://127.0.0.1:8000
```

Tests: `python -m unittest discover -s console -v`

## What is where

| Path | What it does |
|---|---|
| `/api/*` | The unchanged Phase 2 OEM HTTP API (`create_app`) |
| `GET /demo/session` | Vehicle ID, ECU hardware IDs and the staff identities with their tokens |
| `GET /demo/catalog` | Read-only lists of vehicles, artifacts, releases and campaigns. Any OEM identity, never a vehicle. Audited as `view_catalog` |
| `GET /demo/firmware` | Deterministic fake firmware image for an ECU and version |
| `/demo/vehicle/*` | The simulated vehicle: state, poll (normal, `tamper`, `forge`, `power_loss`), activate, boot, confirm |
| `POST /demo/reset` | New fleet, new keys and new tokens |

## Pages

- **Overview**: the update walkthrough step by step, and who may do what.
- **Fleet**: registered vehicles with their manifest-reported versions, and vehicle registration.
- **Releases**: upload firmware, create a release, approve it. The approver has to be a different person, so try approving as `mallory.creator-approver`.
- **Campaigns**: create, start, pause, and see per-vehicle assignment status.
- **Vehicle simulator**: A/B slots per ECU, the poll scenarios, vehicle conditions, activate, reboot, health check, and the vehicle-side event log.
- **Audit trail**: the hash-chained backend audit log with filters.

The Activity panel lists every request with its outcome and correlation ID.
