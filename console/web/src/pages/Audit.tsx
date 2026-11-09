import { FormEvent, useEffect, useState } from "react";
import { ApiResult } from "../api";
import { Card, Empty, fmtTime, Hash, Id, Needs, Pill, Result, useApp } from "../ui";

export default function Audit() {
  const { call, me } = useApp();
  const [filters, setFilters] = useState({ actor: "", action: "", correlation_id: "" });
  const [res, setRes] = useState<ApiResult | null>(null);

  const load = async (e?: FormEvent) => {
    e?.preventDefault();
    const q = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
    setRes(await call("GET", `/api/audit${q ? "?" + q : ""}`));
  };

  // Load once for auditors when the page opens or the identity changes.
  useEffect(() => { if (me.roles.includes("auditor")) load(); }, [me]);

  const events: any[] = res?.ok ? [...res.data.events].reverse() : [];

  return (
    <>
      <header className="page-head">
        <h1>Audit trail</h1>
        <p>Append-only and hash-chained: every event stores the hash of the one before it, so editing or deleting any event breaks the chain (SR-09, SR-14).</p>
      </header>

      <Card title="Query" aside={<Needs action="query_audit" />}>
        <form className="form" onSubmit={load}>
          <div className="row">
            {(["actor", "action", "correlation_id"] as const).map((k) => (
              <label key={k}>{k.replace("_", " ")}
                <input value={filters[k]} onChange={(e) => setFilters({ ...filters, [k]: e.target.value })} placeholder="any" />
              </label>
            ))}
          </div>
          <div><button type="submit">Load events</button></div>
        </form>
      </Card>

      {res && !res.ok && <Result r={res} />}
      {res?.ok && (
        <Card title={`${events.length} events`}
              aside={res.data.chain_intact ? <Pill value="hash chain intact" tone="ok" /> : <Pill value={`chain broken at #${res.data.first_bad_seq}`} tone="bad" />}>
          {events.length === 0 ? <Empty>No events match.</Empty> : (
            <table className="compact">
              <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Outcome</th><th>Code</th><th>Correlation</th><th>Hash</th></tr></thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.seq}>
                    <td className="dim">{e.seq}</td>
                    <td className="dim">{fmtTime(e.time)}</td>
                    <td>{e.actor}</td>
                    <td><code>{e.action}</code></td>
                    <td>{e.object}</td>
                    <td><Pill value={e.outcome} /></td>
                    <td>{e.code ? <code>{e.code}</code> : ""}</td>
                    <td><button className="link" title="Filter by this correlation ID" onClick={() => setFilters({ actor: "", action: "", correlation_id: e.correlation_id })}><Id>{e.correlation_id.slice(0, 16)}</Id></button></td>
                    <td><Hash value={e.hash} n={8} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </>
  );
}
