import { createContext, ReactNode, useContext } from "react";
import { ApiResult, Identity, SendOptions, Session } from "./api";

// Mirrors phase2/oem_backend/auth.py AUTHZ_MATRIX. Shown as a hint only: the server decides.
export const ACTION_ROLE = {
  register_vehicle: "registrar",
  upload_artifact: "release_creator",
  create_release: "release_creator",
  approve_release: "release_approver",
  create_campaign: "campaign_operator",
  start_campaign: "campaign_operator",
  pause_campaign: "campaign_operator",
  view_status: "campaign_operator",
  query_audit: "auditor",
} as const;
export type Action = keyof typeof ACTION_ROLE;

export type Catalog = { vehicles: any[]; artifacts: any[]; releases: any[]; campaigns: any[] };

export type Ctx = {
  session: Session;
  me: Identity;
  catalog: Catalog;
  refresh: () => Promise<void>;
  call: (method: string, path: string, opts?: SendOptions & { asVehicle?: boolean }) => Promise<ApiResult>;
};

export const AppCtx = createContext<Ctx | null>(null);
export function useApp(): Ctx {
  const ctx = useContext(AppCtx);
  if (!ctx) throw new Error("AppCtx missing");
  return ctx;
}

export function Card({ title, aside, children }: { title: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      <header className="card-head">
        <h2>{title}</h2>
        {aside && <div className="card-aside">{aside}</div>}
      </header>
      <div className="card-body">{children}</div>
    </section>
  );
}

const TONES: Record<string, string> = {
  OK: "ok", SUCCESS: "ok", APPROVED: "ok", RUNNING: "ok", CONFIRMED: "ok", IDLE: "muted",
  DRAFT: "muted", PAUSED: "warn", OFFERED: "info", STAGED: "info", STAGING: "info",
  INSTALLED: "info", POSTPONED: "warn", ALREADY_APPLIED: "muted",
  REJECTED: "bad", ROLLED_BACK: "warn", DENIED: "bad", FAILED: "bad", UNAUTHENTICATED: "bad",
  POWER_LOSS: "warn",
};

export function Pill({ value, tone }: { value: ReactNode; tone?: string }) {
  const t = tone ?? (typeof value === "string" ? TONES[value] : undefined) ?? "muted";
  return <span className={`pill pill-${t}`}>{value}</span>;
}

/** Which role an action needs, and whether the current identity has it. */
export function Needs({ action }: { action: Action }) {
  const { me } = useApp();
  const role = ACTION_ROLE[action];
  const has = me.roles.includes(role);
  return (
    <span className={`needs ${has ? "needs-ok" : "needs-no"}`}
          title={has ? `${me.name} has ${role}` : `${me.name} lacks ${role}: the server will refuse and audit it`}>
      {has ? "✓" : "✕"} {role}
    </span>
  );
}

export function Hash({ value, n = 12 }: { value?: string | null; n?: number }) {
  if (!value) return <span className="dim">—</span>;
  return <code className="hash" title={value}>{value.slice(0, n)}…</code>;
}

export function Id({ children }: { children: ReactNode }) {
  return <code className="id">{children}</code>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function Result({ r }: { r: ApiResult | null }) {
  if (!r) return null;
  const d = r.data ?? {};
  return (
    <div className={`result ${r.ok ? "result-ok" : "result-bad"}`} role="status">
      {r.ok ? <strong>Done.</strong> : <strong>{d.error ?? `HTTP ${r.status}`}{d.code && d.code !== d.error ? ` · ${d.code}` : ""}</strong>}
      {!r.ok && d.message && <span> {d.message}</span>}
      {d.diagnostic && <span> ({d.diagnostic})</span>}
      {r.cid && <span className="dim"> correlation <Id>{r.cid}</Id></span>}
    </div>
  );
}

export function fmtBytes(n: number): string {
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`;
}

export function fmtTime(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().slice(11, 19);
}
