import { FormEvent, useState } from "react";
import { ApiResult } from "../api";
import { Card, Empty, Id, Needs, Pill, Result, useApp } from "../ui";

function randomHex(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
}

export default function Fleet() {
  const { catalog, call } = useApp();
  const [vid, setVid] = useState("VIN-SIM-0003");
  const [ecus, setEcus] = useState("ECU-A HW-A-REV2\nECU-B HW-B-REV1");
  const [keyHex, setKeyHex] = useState(() => randomHex(32));
  const [result, setResult] = useState<ApiResult | null>(null);

  const register = async (e: FormEvent) => {
    e.preventDefault();
    const list = ecus.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
      const [ecu_id, hardware_id] = l.split(/\s+/);
      return { ecu_id, hardware_id };
    });
    setResult(await call("POST", "/api/vehicles", {
      json: { vehicle_id: vid, ecus: list, manifest_key_id: `vehicle-key-${vid}`, manifest_public_key: keyHex },
    }));
  };

  return (
    <>
      <header className="page-head">
        <h1>Fleet</h1>
        <p>Registered vehicles and the versions their last signed manifest reported. Registration takes identities and hardware IDs only, never personal data (PR-01).</p>
      </header>

      <Card title="Vehicles">
        {catalog.vehicles.length === 0 ? <Empty>No vehicles registered.</Empty> : (
          <table>
            <thead><tr><th>Vehicle</th><th>ECU</th><th>Hardware</th><th>Active</th><th>Confirmed</th><th>State</th></tr></thead>
            <tbody>
              {catalog.vehicles.flatMap((v) => v.ecus.map((e: any, i: number) => (
                <tr key={v.vehicle_id + e.ecu_id}>
                  <td>{i === 0 && <Id>{v.vehicle_id}</Id>}</td>
                  <td>{e.ecu_id}</td>
                  <td><code>{e.hardware_id}</code></td>
                  <td>{e.active_version ?? <span className="dim">unknown</span>}</td>
                  <td>{e.confirmed_version ?? <span className="dim">unknown</span>}</td>
                  <td>{e.update_state ? <Pill value={e.update_state} /> : <span className="dim">no manifest yet</span>}</td>
                </tr>
              )))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Register a vehicle" aside={<Needs action="register_vehicle" />}>
        <form className="form" onSubmit={register}>
          <label>Vehicle ID<input value={vid} onChange={(e) => setVid(e.target.value)} /></label>
          <label>ECUs, one per line: <code>ECU-ID HARDWARE-ID</code>
            <textarea rows={3} value={ecus} onChange={(e) => setEcus(e.target.value)} />
          </label>
          <label>Manifest public key (Ed25519, 64 hex)
            <span className="row">
              <input className="mono" value={keyHex} onChange={(e) => setKeyHex(e.target.value)} />
              <button type="button" className="ghost" onClick={() => setKeyHex(randomHex(32))}>Random</button>
            </span>
          </label>
          <div><button type="submit">Register</button></div>
          <Result r={result} />
        </form>
      </Card>
    </>
  );
}
