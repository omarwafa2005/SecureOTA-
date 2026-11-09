import { useCallback, useEffect, useState } from "react";
import { ApiResult, send } from "../api";
import { Card, Empty, fmtTime, Hash, Id, Pill, useApp } from "../ui";

const SCENARIOS = [
  { id: "", label: "Normal", detail: "Download the offered image as published." },
  { id: "tamper", label: "Tampered in transit", detail: "AT-01: one byte of the image is flipped on the way. Expect DIGEST_MISMATCH." },
  { id: "forge", label: "Forged metadata", detail: "An attacker raises the version in the signed offer without the release key. Expect BAD_SIGNATURE." },
  { id: "power_loss", label: "Power loss mid-write", detail: "Power fails halfway through writing the inactive slot. The ECU recovers on restart; poll again to retry." },
];

type Conditions = { speed_kph: number; gear: string; battery_v: number; ignition: string };

export default function Vehicle() {
  const { call, session } = useApp();
  const [state, setState] = useState<any>(null);
  const [scenario, setScenario] = useState("");
  const [cond, setCond] = useState<Conditions>({ speed_kph: 0, gear: "P", battery_v: 12.6, ignition: "ON" });
  const [last, setLast] = useState<{ title: string; r: ApiResult } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const r = await send("GET", "/demo/vehicle");
    if (r.ok) setState(r.data);
  }, []);
  useEffect(() => { load(); }, [load]);

  const run = async (title: string, path: string, json: unknown) => {
    setBusy(true);
    const r = await call("POST", path, { json, asVehicle: true });
    setLast({ title, r });
    await load();
    setBusy(false);
  };

  const safe = cond.speed_kph === 0 && cond.gear === "P" && cond.battery_v >= 12 && cond.ignition === "ON";

  return (
    <>
      <header className="page-head">
        <h1>Vehicle simulator</h1>
        <p>Gateway and two A/B ECUs of <Id>{session.vehicle_id}</Id>. The vehicle talks to the backend with its own identity; you play the car and, optionally, the attacker.</p>
      </header>

      <div className="grid-2">
        <Card title="1 · Poll for updates">
          <div className="scenarios" role="radiogroup" aria-label="Scenario">
            {SCENARIOS.map((s) => (
              <label key={s.id} className={`scenario ${scenario === s.id ? "on" : ""} ${s.id ? "attack" : ""}`}>
                <input type="radio" name="scenario" checked={scenario === s.id} onChange={() => setScenario(s.id)} />
                <strong>{s.label}</strong>
                <span>{s.detail}</span>
              </label>
            ))}
          </div>
          <button disabled={busy} onClick={() => run(`Poll · ${SCENARIOS.find((s) => s.id === scenario)!.label}`, "/demo/vehicle/poll", { attack: scenario || null })}>
            Poll backend
          </button>
        </Card>

        <Card title="2 · Vehicle conditions" aside={<Pill value={safe ? "safe to activate" : "activation blocked"} tone={safe ? "ok" : "warn"} />}>
          <div className="form">
            <div className="row">
              <label>Speed (km/h)<input type="number" min={0} value={cond.speed_kph} onChange={(e) => setCond({ ...cond, speed_kph: Number(e.target.value) })} /></label>
              <label>Gear
                <select value={cond.gear} onChange={(e) => setCond({ ...cond, gear: e.target.value })}>
                  {["P", "R", "N", "D"].map((g) => <option key={g}>{g}</option>)}
                </select>
              </label>
            </div>
            <div className="row">
              <label>Battery (V)<input type="number" step={0.1} value={cond.battery_v} onChange={(e) => setCond({ ...cond, battery_v: Number(e.target.value) })} /></label>
              <label>Ignition
                <select value={cond.ignition} onChange={(e) => setCond({ ...cond, ignition: e.target.value })}>
                  {["ON", "ACC", "OFF"].map((g) => <option key={g}>{g}</option>)}
                </select>
              </label>
            </div>
            <p className="dim">Used by Activate. The ECU refuses to switch slots unless parked, stopped, ignition on and battery ≥ 12 V (SAF-03, SAF-04).</p>
          </div>
        </Card>
      </div>

      {last && <LastResult title={last.title} r={last.r} />}

      <div className="grid-2">
        {state?.ecus.map((e: any) => (
          <EcuCard key={e.ecu_id} ecu={e} busy={busy}
                   onActivate={() => run(`Activate ${e.ecu_id}`, "/demo/vehicle/activate", { ecu_id: e.ecu_id, conditions: cond })}
                   onBoot={() => run(`Reboot ${e.ecu_id}`, "/demo/vehicle/boot", { ecu_id: e.ecu_id })}
                   onConfirm={(healthy) => run(`Health check ${healthy ? "passes" : "fails"} on ${e.ecu_id}`, "/demo/vehicle/confirm", { ecu_id: e.ecu_id, healthy })} />
        ))}
      </div>

      <Card title="Vehicle event log" aside={<span className="dim">gateway and ECU audit events, newest first</span>}>
        {!state || state.events.length === 0 ? <Empty>Nothing yet.</Empty> : (
          <table className="compact">
            <thead><tr><th>Time</th><th>Component</th><th>Action</th><th>Outcome</th><th>Details</th><th>Correlation</th></tr></thead>
            <tbody>
              {state.events.map((ev: any, i: number) => {
                const { time, component, action, outcome, correlation_id, ...rest } = ev;
                return (
                  <tr key={i}>
                    <td className="dim">{fmtTime(time)}</td>
                    <td>{component}</td>
                    <td>{action}</td>
                    <td><Pill value={outcome} /></td>
                    <td className="details">{Object.entries(rest).map(([k, v]) => <span key={k}>{k}=<b>{Array.isArray(v) ? v.join(",") : String(v)}</b> </span>)}</td>
                    <td><Id>{String(correlation_id).slice(0, 16)}</Id></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

function LastResult({ title, r }: { title: string; r: ApiResult }) {
  const d = r.data ?? {};
  const rows: any[] = d.results ?? (d.status ? [d] : []);
  const bad = !r.ok || rows.some((x) => x.status === "REJECTED" || x.status === "POWER_LOSS");
  return (
    <div className={`last ${bad ? "last-bad" : ""}`}>
      <div className="last-title">{title}</div>
      {!r.ok && <div>{d.error} · {d.code}</div>}
      {r.ok && rows.length === 0 && <div>No updates offered. Is a campaign running for this vehicle, and is it not already at that version?</div>}
      {rows.map((x, i) => (
        <div key={i} className="last-row">
          {x.ecu_id && <strong>{x.ecu_id === "*" ? "bundle" : x.ecu_id}</strong>}
          {x.version && <span>v{x.version}</span>}
          <Pill value={x.status} />
          {x.reason && x.reason !== "OK" && <code>{x.reason}</code>}
          {x.blockers?.length > 0 && <span>blocked by {x.blockers.join(", ")}</span>}
          {x.running_slot && <span>running slot {x.running_slot} · {x.update_state} · boot attempts {x.boot_attempts}</span>}
          {x.backend && !x.backend.skipped && <span className="dim">backend: {x.backend.assignment_state ?? x.backend.code}</span>}
        </div>
      ))}
      {d.backend && !d.backend.skipped && !d.results && <div className="dim">backend assignment: {d.backend.assignment_state ?? d.backend.code}</div>}
      {r.cid && <div className="dim">correlation <Id>{r.cid}</Id></div>}
    </div>
  );
}

function EcuCard({ ecu, busy, onActivate, onBoot, onConfirm }: {
  ecu: any; busy: boolean; onActivate: () => void; onBoot: () => void; onConfirm: (healthy: boolean) => void;
}) {
  const st = ecu.update_state;
  return (
    <Card title={<>{ecu.ecu_id} <code className="dim">{ecu.hardware_id}</code></>} aside={<Pill value={st} />}>
      <div className="slots">
        {(["A", "B"] as const).map((slot) => {
          const rec = ecu.slots[slot];
          const active = ecu.active_slot === slot;
          const confirmed = ecu.confirmed_slot === slot;
          const staged = !active && rec && ecu.staged_version === rec.version;
          return (
            <div key={slot} className={`slot ${active ? "active" : ""} ${rec ? "" : "empty-slot"}`}>
              <div className="slot-name">Slot {slot}</div>
              {rec ? (
                <>
                  <div className="slot-ver">v{rec.version}</div>
                  <Hash value={rec.sha256} n={10} />
                  <div className={rec.valid ? "ok-text" : "bad-text"}>{rec.valid ? "image intact" : "image corrupt"}</div>
                </>
              ) : <div className="dim">empty</div>}
              <div className="tags">
                {active && <Pill value="ACTIVE" tone="info" />}
                {confirmed && <Pill value="CONFIRMED" tone="ok" />}
                {staged && <Pill value="STAGED" tone="info" />}
              </div>
            </div>
          );
        })}
      </div>
      <dl className="facts">
        <div><dt>Running</dt><dd>v{ecu.active_version}</dd></div>
        <div><dt>Anti-rollback floor</dt><dd>v{ecu.trusted_min_version}</dd></div>
        <div><dt>Boot attempts</dt><dd>{ecu.boot_attempts}</dd></div>
        <div><dt>Campaign</dt><dd>{ecu.offer ? <Id>{ecu.offer.campaign_id}</Id> : "—"}</dd></div>
      </dl>
      <div className="actions">
        <button disabled={busy || st !== "STAGED"} onClick={onActivate}>Activate</button>
        <button className="ghost" disabled={busy} onClick={onBoot}>Reboot</button>
        <button className="ghost" disabled={busy || st !== "INSTALLED"} onClick={() => onConfirm(true)}>Health OK</button>
        <button className="ghost danger" disabled={busy || st !== "INSTALLED"} onClick={() => onConfirm(false)}>Health fails</button>
      </div>
    </Card>
  );
}
