import { FormEvent, useState } from "react";
import { ApiResult } from "../api";
import { Card, Empty, Id, Needs, Pill, Result, useApp } from "../ui";

export default function Campaigns() {
  const { catalog, call } = useApp();
  const approved = catalog.releases.filter((r) => r.state === "APPROVED");
  const [releaseIds, setReleaseIds] = useState<string[]>([]);
  const [targets, setTargets] = useState<string[]>([]);
  const [hours, setHours] = useState(24);
  const [create, setCreate] = useState<ApiResult | null>(null);
  const [action, setAction] = useState<ApiResult | null>(null);
  const [status, setStatus] = useState<Record<string, ApiResult>>({});

  const toggle = (list: string[], set: (v: string[]) => void, id: string) =>
    set(list.includes(id) ? list.filter((x) => x !== id) : [...list, id]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setCreate(await call("POST", "/api/campaigns", {
      json: { release_ids: releaseIds, targets, policy: { expires_in_s: Math.round(hours * 3600), require_safe_state: true } },
    }));
  };

  const act = async (id: string, verb: "start" | "pause") => {
    setAction(await call("POST", `/api/campaigns/${id}/${verb}`));
    if (status[id]) loadStatus(id);
  };

  const loadStatus = async (id: string) => {
    const r = await call("GET", `/api/campaigns/${id}/status`);
    setStatus((s) => ({ ...s, [id]: r }));
  };

  return (
    <>
      <header className="page-head">
        <h1>Campaigns</h1>
        <p>A campaign offers approved releases to explicit target vehicles. Vehicles only receive signed, per-vehicle offers while it is running; a paused campaign offers nothing new (FR-16).</p>
      </header>

      <Card title="New campaign" aside={<Needs action="create_campaign" />}>
        <form className="form" onSubmit={submit}>
          <fieldset>
            <legend>Approved releases</legend>
            {approved.length === 0 ? <Empty>No approved releases yet.</Empty> : approved.map((r) => (
              <label key={r.release_id} className="check">
                <input type="checkbox" checked={releaseIds.includes(r.release_id)} onChange={() => toggle(releaseIds, setReleaseIds, r.release_id)} />
                <Id>{r.release_id}</Id> {r.ecu_id} v{r.version}
              </label>
            ))}
          </fieldset>
          <fieldset>
            <legend>Target vehicles</legend>
            {catalog.vehicles.map((v) => (
              <label key={v.vehicle_id} className="check">
                <input type="checkbox" checked={targets.includes(v.vehicle_id)} onChange={() => toggle(targets, setTargets, v.vehicle_id)} />
                <Id>{v.vehicle_id}</Id> <span className="dim">{v.ecus.map((e: any) => e.hardware_id).join(", ")}</span>
              </label>
            ))}
          </fieldset>
          <div className="row">
            <label>Offer expires after (hours)
              <input type="number" min={0.02} max={720} step="any" value={hours} onChange={(e) => setHours(Number(e.target.value))} />
            </label>
            <label className="check locked" title="The backend rejects require_safe_state=false">
              <input type="checkbox" checked readOnly disabled /> Activate only in a safe state (always on)
            </label>
          </div>
          <div><button type="submit">Create campaign</button></div>
          <Result r={create} />
        </form>
      </Card>

      <Card title="Campaigns" aside={<><Needs action="start_campaign" /> <Needs action="view_status" /></>}>
        <Result r={action} />
        {catalog.campaigns.length === 0 ? <Empty>No campaigns yet.</Empty> : catalog.campaigns.map((c) => (
          <div key={c.campaign_id} className="campaign">
            <div className="campaign-head">
              <Id>{c.campaign_id}</Id>
              <Pill value={c.state} />
              <span className="dim">releases {c.release_ids.join(", ")} → {c.targets.join(", ")} · ECU order {c.ecu_order.join(" → ")}</span>
              <span className="spacer" />
              {(c.state === "DRAFT" || c.state === "PAUSED") && <button onClick={() => act(c.campaign_id, "start")}>Start</button>}
              {c.state === "RUNNING" && <button className="ghost" onClick={() => act(c.campaign_id, "pause")}>Pause</button>}
              <button className="ghost" onClick={() => loadStatus(c.campaign_id)}>Status</button>
            </div>
            {status[c.campaign_id] && <StatusTable r={status[c.campaign_id]} />}
          </div>
        ))}
      </Card>
    </>
  );
}

function StatusTable({ r }: { r: ApiResult }) {
  if (!r.ok) return <Result r={r} />;
  const rows: any[] = r.data.assignments;
  if (rows.length === 0) return <Empty>No vehicle has been offered this campaign yet. Poll from the vehicle simulator.</Empty>;
  return (
    <table>
      <thead><tr><th>Vehicle</th><th>ECU</th><th>State</th><th>Meaning</th><th>Reason</th></tr></thead>
      <tbody>
        {rows.map((a) => (
          <tr key={a.vehicle_id + a.ecu_id}>
            <td><Id>{a.vehicle_id}</Id></td>
            <td>{a.ecu_id}</td>
            <td><Pill value={a.state} /></td>
            <td>{a.label}</td>
            <td>{a.reason ? <code>{a.reason}</code> : <span className="dim">—</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
