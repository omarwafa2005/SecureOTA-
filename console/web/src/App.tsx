import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiResult, Identity, send, SendOptions, Session, summarize } from "./api";
import { AppCtx, Catalog, Ctx, Id } from "./ui";
import Overview from "./pages/Overview";
import Fleet from "./pages/Fleet";
import Releases from "./pages/Releases";
import Campaigns from "./pages/Campaigns";
import Vehicle from "./pages/Vehicle";
import Audit from "./pages/Audit";

type PageId = "overview" | "fleet" | "releases" | "campaigns" | "vehicle" | "audit";
export type PageProps = { go: (p: PageId) => void };

const PAGES: { id: PageId; label: string; Page: (props: PageProps) => JSX.Element }[] = [
  { id: "overview", label: "Overview", Page: Overview },
  { id: "fleet", label: "Fleet", Page: Fleet },
  { id: "releases", label: "Releases", Page: Releases },
  { id: "campaigns", label: "Campaigns", Page: Campaigns },
  { id: "vehicle", label: "Vehicle simulator", Page: Vehicle },
  { id: "audit", label: "Audit trail", Page: Audit },
];

type Activity = { n: number; actor: string; method: string; path: string; ok: boolean; status: number; text: string; cid: string | null };

const EMPTY: Catalog = { vehicles: [], artifacts: [], releases: [], campaigns: [] };

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [meKey, setMeKey] = useState("registrar");
  const [page, setPage] = useState<PageId>("overview");
  const [catalog, setCatalog] = useState<Catalog>(EMPTY);
  const [activity, setActivity] = useState<Activity[]>([]);

  const loadSession = useCallback(async () => {
    const r = await send("GET", "/demo/session");
    if (!r.ok) {
      setLoadError(r.data?.message ?? `HTTP ${r.status}`);
      return;
    }
    setLoadError(null);
    setSession(r.data);
  }, []);

  useEffect(() => { loadSession(); }, [loadSession]);

  const me: Identity | undefined = session?.identities.find((i) => i.key === meKey) ?? session?.identities[0];

  const refresh = useCallback(async () => {
    if (!me) return;
    const r = await send("GET", "/demo/catalog", { token: me.token });
    if (r.ok) setCatalog(r.data);
  }, [me]);

  useEffect(() => { refresh(); }, [refresh]);

  const call = useCallback(async (method: string, path: string, opts: SendOptions & { asVehicle?: boolean } = {}): Promise<ApiResult> => {
    const { asVehicle, ...rest } = opts;
    const r = await send(method, path, asVehicle ? rest : { ...rest, token: me?.token });
    const actor = asVehicle ? `gw:${session?.vehicle_id}` : me?.name ?? "?";
    setActivity((a) => [{ n: (a[0]?.n ?? 0) + 1, actor, method, path: path.split("?")[0], ok: r.ok, status: r.status, text: summarize(r), cid: r.cid }, ...a].slice(0, 80));
    if (method !== "GET") refresh();
    return r;
  }, [me, session, refresh]);

  const reset = async () => {
    if (!confirm("Reset the demo? All releases, campaigns, audit events and vehicle state are discarded, and new tokens are issued.")) return;
    await send("POST", "/demo/reset");
    setActivity([]);
    setCatalog(EMPTY);
    await loadSession();
  };

  const ctx: Ctx | null = useMemo(() => (session && me ? { session, me, catalog, refresh, call } : null), [session, me, catalog, refresh, call]);

  if (!ctx) {
    return (
      <div className="boot">
        <h1>SecureOTA-V Console</h1>
        {loadError ? (
          <>
            <p className="result result-bad">Cannot reach the console server: {loadError}</p>
            <p>Start it from the repository root with <code>python console/server.py</code>, then <button onClick={loadSession}>retry</button>.</p>
          </>
        ) : <p>Connecting…</p>}
      </div>
    );
  }

  const Page = PAGES.find((p) => p.id === page)!.Page;

  return (
    <AppCtx.Provider value={ctx}>
      <div className="shell">
        <aside className="side">
          <div className="brand">
            <span className="logo" aria-hidden>◆</span>
            <div>
              <strong>SecureOTA-V</strong>
              <span className="sim-tag">simulation</span>
            </div>
          </div>

          <label className="who">
            <span>Acting as</span>
            <select value={ctx.me.key} onChange={(e) => setMeKey(e.target.value)}>
              {ctx.session.identities.map((i) => (
                <option key={i.key} value={i.key}>{i.name}</option>
              ))}
            </select>
            <span className="roles">{ctx.me.roles.join(" + ")}</span>
          </label>

          <nav>
            {PAGES.map((p) => (
              <button key={p.id} className={p.id === page ? "nav on" : "nav"} onClick={() => setPage(p.id)}>{p.label}</button>
            ))}
          </nav>

          <button className="ghost reset" onClick={reset}>Reset demo</button>
        </aside>

        <main className="main">
          <Page go={setPage} />
        </main>

        <aside className="activity" aria-label="Activity">
          <h2>Activity</h2>
          {activity.length === 0 && <p className="empty">Every request you make shows up here with its correlation ID.</p>}
          <ol>
            {activity.map((a) => (
              <li key={a.n} className={a.ok ? "" : "bad"}>
                <div className="act-line"><span className="method">{a.method}</span> <span className="path">{a.path}</span></div>
                <div className="act-text">{a.status} · {a.text}</div>
                <div className="act-meta">{a.actor}{a.cid && <> · <Id>{a.cid.slice(0, 16)}</Id></>}</div>
              </li>
            ))}
          </ol>
        </aside>
      </div>
    </AppCtx.Provider>
  );
}
