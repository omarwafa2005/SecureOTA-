import type { PageProps } from "../App";
import { ACTION_ROLE, Card, useApp } from "../ui";

type Step = { title: string; who: string; page: Parameters<PageProps["go"]>[0]; detail: string; done: boolean };

export default function Overview({ go }: PageProps) {
  const { catalog, session } = useApp();
  const { artifacts, releases, campaigns, vehicles } = catalog;
  const approved = releases.some((r) => r.state === "APPROVED");
  const running = campaigns.some((c) => c.state === "RUNNING");
  const sim = vehicles.find((v) => v.vehicle_id === session.vehicle_id);
  const updated = sim?.ecus.some((e: any) => e.update_state === "CONFIRMED");

  const steps: Step[] = [
    { title: "Upload firmware", who: "bob.creator", page: "releases", done: artifacts.length > 0,
      detail: "The backend stores the image and publishes its SHA-256 and length (SR-01)." },
    { title: "Create a release", who: "bob.creator", page: "releases", done: releases.length > 0,
      detail: "A draft release binds the artifact to an ECU, hardware ID and version." },
    { title: "Approve it", who: "carol.approver", page: "releases", done: approved,
      detail: "A different person must approve (SR-18). Try it as mallory to see the refusal." },
    { title: "Create and start a campaign", who: "dave.operator", page: "campaigns", done: running,
      detail: "Explicit targets and policy. Safe-state activation cannot be turned off." },
    { title: "Vehicle polls, verifies, stages", who: "vehicle simulator", page: "vehicle", done: !!sim?.ecus.some((e: any) => e.staged_version || e.update_state === "CONFIRMED"),
      detail: "Signature, expiry, target, replay, rollback, length and digest checks before the inactive slot is written." },
    { title: "Activate, reboot, confirm", who: "vehicle simulator", page: "vehicle", done: !!updated,
      detail: "Only when parked with enough battery. A failed health check rolls back to the confirmed slot." },
    { title: "Review the audit trail", who: "erin.auditor", page: "audit", done: false,
      detail: "Every privileged action, including denials, is in a hash-chained log." },
  ];
  const next = steps.find((s) => !s.done);

  return (
    <>
      <header className="page-head">
        <h1>Overview</h1>
        <p>Walk one firmware update from upload to a confirmed install on the simulated vehicle <code>{session.vehicle_id}</code>, then try the attacks.</p>
      </header>

      <div className="stats">
        <Stat n={vehicles.length} label="vehicles" />
        <Stat n={artifacts.length} label="artifacts" />
        <Stat n={releases.length} label="releases" />
        <Stat n={campaigns.length} label="campaigns" />
      </div>

      <Card title="Update walkthrough">
        <ol className="steps">
          {steps.map((s, i) => (
            <li key={s.title} className={s.done ? "done" : s === next ? "next" : ""}>
              <span className="step-n">{s.done ? "✓" : i + 1}</span>
              <div>
                <div className="step-title">
                  <button className="link" onClick={() => go(s.page)}>{s.title}</button>
                  <span className="dim"> · as {s.who}</span>
                </div>
                <p>{s.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </Card>

      <Card title="Who may do what">
        <p className="dim">From the backend authorization matrix. Anything not listed is denied, and every attempt is audited.</p>
        <table>
          <thead><tr><th>Action</th><th>Role</th><th>Identity in this demo</th></tr></thead>
          <tbody>
            {Object.entries(ACTION_ROLE).map(([action, role]) => (
              <tr key={action}>
                <td><code>{action}</code></td>
                <td>{role}</td>
                <td>{session.identities.filter((i) => i.roles.includes(role)).map((i) => i.name).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}

function Stat({ n, label }: { n: number; label: string }) {
  return <div className="stat"><strong>{n}</strong><span>{label}</span></div>;
}
