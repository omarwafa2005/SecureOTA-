// Thin fetch wrapper. Tokens are passed in per call and only ever held in React state.

export type Identity = { key: string; name: string; roles: string[]; token: string };
export type Session = { vehicle_id: string; ecu_hw: Record<string, string>; identities: Identity[] };

export type ApiResult = { ok: boolean; status: number; data: any; cid: string | null };

export type SendOptions = { token?: string; json?: unknown; bytes?: ArrayBuffer };

export async function send(method: string, path: string, opts: SendOptions = {}): Promise<ApiResult> {
  const headers: Record<string, string> = {};
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  let body: BodyInit | undefined;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  } else if (opts.bytes) {
    headers["Content-Type"] = "application/octet-stream";
    body = opts.bytes;
  }
  let res: Response;
  try {
    res = await fetch(path, { method, headers, body });
  } catch {
    return {
      ok: false, status: 0, cid: null,
      data: { error: "NETWORK", code: "SERVER_UNREACHABLE", message: "The console server is not reachable." },
    };
  }
  const isJson = (res.headers.get("content-type") ?? "").includes("json");
  const data = isJson ? await res.json() : await res.arrayBuffer();
  const cid = res.headers.get("X-Correlation-ID") ?? (isJson ? data?.correlation_id ?? null : null);
  return { ok: res.ok, status: res.status, data, cid };
}

/** One-line outcome: HTTP errors use the stable category and code; vehicle results use status and reason. */
export function summarize(r: ApiResult): string {
  const d = r.data;
  if (!r.ok) {
    if (d?.code && d.code !== d.error) return `${d.error} · ${d.code}`;
    return d?.error ?? `HTTP ${r.status}`;
  }
  if (d && typeof d === "object" && "status" in d && "reason" in d) {
    return d.reason === "OK" ? String(d.status) : `${d.status} · ${d.reason}`;
  }
  if (Array.isArray(d?.results)) {
    if (d.results.length === 0) return "No updates offered";
    return d.results.map((x: any) => `${x.ecu_id}: ${x.status}${x.reason && x.reason !== "OK" ? " · " + x.reason : ""}`).join(", ");
  }
  return "OK";
}
