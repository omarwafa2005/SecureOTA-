import { FormEvent, useState } from "react";
import { ApiResult, send } from "../api";
import { Card, Empty, fmtBytes, Hash, Id, Needs, Pill, Result, useApp } from "../ui";

export default function Releases() {
  const { session, catalog, call } = useApp();
  const ecuIds = Object.keys(session.ecu_hw);
  const [ecu, setEcu] = useState(ecuIds[0]);
  const [fwVersion, setFwVersion] = useState(2);
  const [file, setFile] = useState<File | null>(null);
  const [upload, setUpload] = useState<ApiResult | null>(null);
  const [versions, setVersions] = useState<Record<string, number>>({});
  const [action, setAction] = useState<ApiResult | null>(null);

  const doUpload = async (e: FormEvent) => {
    e.preventDefault();
    let bytes: ArrayBuffer;
    if (file) {
      bytes = await file.arrayBuffer();
    } else {
      const fw = await send("GET", `/demo/firmware?ecu_id=${ecu}&version=${fwVersion}`);
      if (!fw.ok) return setUpload(fw);
      bytes = fw.data;
    }
    const q = new URLSearchParams({ ecu_id: ecu, hardware_id: session.ecu_hw[ecu] });
    setUpload(await call("POST", `/api/artifacts?${q}`, { bytes }));
  };

  const createRelease = async (artifactId: string) => {
    setAction(await call("POST", "/api/releases", { json: { artifact_id: artifactId, version: versions[artifactId] ?? 2 } }));
  };

  const approve = async (rid: string) => setAction(await call("POST", `/api/releases/${rid}/approve`));

  return (
    <>
      <header className="page-head">
        <h1>Releases</h1>
        <p>Upload firmware, wrap it in a draft release, then have a different person approve it. Only approved releases can go into a campaign.</p>
      </header>

      <Card title="Upload firmware" aside={<Needs action="upload_artifact" />}>
        <form className="form" onSubmit={doUpload}>
          <div className="row">
            <label>ECU
              <select value={ecu} onChange={(e) => setEcu(e.target.value)}>
                {ecuIds.map((id) => <option key={id} value={id}>{id} ({session.ecu_hw[id]})</option>)}
              </select>
            </label>
            <label>Demo image version
              <input type="number" min={1} value={fwVersion} disabled={!!file} onChange={(e) => setFwVersion(Number(e.target.value))} />
            </label>
          </div>
          <label>Or your own file (up to 16 MiB)
            <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
          <div><button type="submit">Upload</button></div>
          <Result r={upload} />
        </form>
      </Card>

      <Card title="Artifacts" aside={<Needs action="create_release" />}>
        {catalog.artifacts.length === 0 ? <Empty>No artifacts yet.</Empty> : (
          <table>
            <thead><tr><th>Artifact</th><th>ECU / hardware</th><th>Size</th><th>SHA-256</th><th>Uploaded by</th><th>New release</th></tr></thead>
            <tbody>
              {catalog.artifacts.map((a) => (
                <tr key={a.artifact_id}>
                  <td><Id>{a.artifact_id}</Id></td>
                  <td>{a.ecu_id} <code className="dim">{a.hardware_id}</code></td>
                  <td>{fmtBytes(a.length)}</td>
                  <td><Hash value={a.sha256} /></td>
                  <td>{a.uploaded_by}</td>
                  <td>
                    <span className="row tight">
                      <input type="number" min={1} className="narrow" aria-label="Release version"
                             value={versions[a.artifact_id] ?? 2}
                             onChange={(e) => setVersions({ ...versions, [a.artifact_id]: Number(e.target.value) })} />
                      <button onClick={() => createRelease(a.artifact_id)}>Create</button>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Releases" aside={<Needs action="approve_release" />}>
        <Result r={action} />
        {catalog.releases.length === 0 ? <Empty>No releases yet.</Empty> : (
          <table>
            <thead><tr><th>Release</th><th>ECU</th><th>Version</th><th>State</th><th>Created by</th><th>Approved by</th><th></th></tr></thead>
            <tbody>
              {catalog.releases.map((r) => (
                <tr key={r.release_id}>
                  <td><Id>{r.release_id}</Id></td>
                  <td>{r.ecu_id}</td>
                  <td>v{r.version}</td>
                  <td><Pill value={r.state} /></td>
                  <td>{r.created_by}</td>
                  <td>{r.approved_by ?? <span className="dim">—</span>}</td>
                  <td>{r.state === "DRAFT" && <button onClick={() => approve(r.release_id)}>Approve</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
