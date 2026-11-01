import { useCallback, useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, session, AccessResult, AuditRow, Decision, Policy, Stats } from "./api";

const COLOR: Record<Decision, string> = { ALLOW: "#1a7f4b", DENY: "#c62828", STEP_UP_AUTHENTICATION: "#b26a00" };
const TABS = ["Overview", "Access monitoring", "Policies", "Simulator"] as const;
type Tab = (typeof TABS)[number];
const USERS = ["aman", "priya", "root", "ravi", "sam", "neha"];
const DEVICES = ["", "d-aman", "d-priya", "d-root", "d-ravi", "d-neha"];
const RESOURCES = ["hr_db", "source_code", "wiki"];

function exportCsv(rows: AuditRow[]) {
  const cols = ["id", "ts", "user_id", "resource", "device_id", "decision", "reason", "policy_id", "policy_version"] as const;
  const cell = (v: unknown) => {
    const t = String(v ?? "");
    return `"${(/^[=+\-@]/.test(t) ? "'" + t : t).replace(/"/g, '""')}"`;   // neutralise spreadsheet formulas
  };
  const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "zeroguard-audit.csv";
  a.click();
  URL.revokeObjectURL(a.href);
}

const Tag = ({ d }: { d: Decision }) => <b style={{ color: COLOR[d] }}>{d}</b>;

export default function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  const [user, setUser] = useState("root");
  const [key, setKey] = useState("");
  const [stats, setStats] = useState<Stats | null>(null);
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [pols, setPols] = useState<Policy[]>([]);
  const [intact, setIntact] = useState<boolean | null>(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    session.user = user; session.key = key; setErr("");
    try {
      const [s, a, p, v] = await Promise.all([api<Stats>("/stats"), api<AuditRow[]>("/audit"), api<Policy[]>("/policies"), api<{ intact: boolean }>("/audit/verify")]);
      setStats(s); setRows(a); setPols(p); setIntact(v.intact);
    } catch (e) {
      setErr((e as Error).message); setStats(null); setRows([]); setPols([]); setIntact(null);
    }
  }, [user, key]);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="wrap">
      <header>
        <h1>ZeroGuard <span className="m">Access Policy Tracker</span></h1>
        <div className="row">
          <label>Viewing as <select value={user} onChange={(e) => setUser(e.target.value)}>{["root", "aman"].map((u) => <option key={u}>{u}</option>)}</select></label>
          <input type="password" placeholder="Admin key (deployed)" defaultValue="" onBlur={(e) => setKey(e.target.value)} />
          <button onClick={() => void load()}>Refresh</button>
        </div>
      </header>
      <nav>{TABS.map((t) => <button key={t} className={t === tab ? "on" : ""} onClick={() => setTab(t)}>{t}</button>)}</nav>
      {err && <p className="err">Could not load admin data ({err}). Admin role{" "}and key are enforced on the server.</p>}
      {tab === "Overview" && <Overview stats={stats} rows={rows} intact={intact} />}
      {tab === "Access monitoring" && <Monitoring rows={rows} />}
      {tab === "Policies" && <Policies pols={pols} />}
      {tab === "Simulator" && <Simulator onDone={() => void load()} />}
    </div>
  );
}

function Overview({ stats, rows, intact }: { stats: Stats | null; rows: AuditRow[]; intact: boolean | null }) {
  const d = stats?.by_decision ?? {};
  const total = Object.values(d).reduce((x, y) => x + y, 0);
  const byDecision = (Object.keys(COLOR) as Decision[]).map((k) => ({ name: k, count: d[k] ?? 0 }));
  const byResource = useMemo(() => {
    const m: Record<string, Record<string, number>> = {};
    rows.forEach((r) => { (m[r.resource] ??= {})[r.decision] = (m[r.resource][r.decision] ?? 0) + 1; });
    return Object.entries(m).map(([resource, v]) => ({ resource, ...v }));
  }, [rows]);
  return (
    <>
      <div className="grid">
        {[["Total events", total], ["Allowed", d.ALLOW ?? 0], ["Denied", d.DENY ?? 0], ["Step-up", d.STEP_UP_AUTHENTICATION ?? 0]].map(([k, n]) =>
          <div className="card" key={k as string}><div className="m">{k}</div><div className="n">{n}</div></div>)}
      </div>
      <div className="grid2">
        <div className="card"><h2>Decisions</h2><div style={{ height: 220 }}><ResponsiveContainer>
          <BarChart data={byDecision}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="name" fontSize={11} /><YAxis allowDecimals={false} /><Tooltip />
            <Bar dataKey="count" fill="#2456d6" /></BarChart></ResponsiveContainer></div></div>
        <div className="card"><h2>Decisions by resource</h2><div style={{ height: 220 }}><ResponsiveContainer>
          <BarChart data={byResource}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="resource" fontSize={11} /><YAxis allowDecimals={false} /><Tooltip /><Legend />
            {(Object.keys(COLOR) as Decision[]).map((k) => <Bar key={k} dataKey={k} stackId="a" fill={COLOR[k]} />)}</BarChart></ResponsiveContainer></div></div>
      </div>
      <div className="grid2">
        <div className="card"><h2>Repeated denials (possible violations)</h2>
          {stats?.repeated_denials.length ? stats.repeated_denials.map((v) => <div key={v.user_id + v.resource}><b>{v.user_id}</b> &rarr; {v.resource}: {v.n} denials</div>) : <span className="m">None</span>}</div>
        <div className="card"><h2>Audit log integrity</h2>
          {intact === null ? <span className="m">Unknown</span> : intact ? <b style={{ color: COLOR.ALLOW }}>Intact &mdash; hash chain verified</b> : <b style={{ color: COLOR.DENY }}>Tampering detected</b>}</div>
      </div>
    </>
  );
}

function Monitoring({ rows }: { rows: AuditRow[] }) {
  const [f, setF] = useState<"ALL" | Decision>("ALL");
  const [q, setQ] = useState("");
  const shown = rows.filter((r) => (f === "ALL" || r.decision === f) && (q === "" || `${r.user_id} ${r.resource} ${r.reason}`.toLowerCase().includes(q.toLowerCase())));
  return (
    <div className="card">
      <div className="row">
        <select value={f} onChange={(e) => setF(e.target.value as "ALL" | Decision)}>{["ALL", ...Object.keys(COLOR)].map((x) => <option key={x}>{x}</option>)}</select>
        <input placeholder="Search user, resource, reason" value={q} onChange={(e) => setQ(e.target.value)} />
        <button onClick={() => exportCsv(shown)}>Export CSV</button><span className="m">{shown.length} of {rows.length}</span>
      </div>
      <div className="w"><table><thead><tr><th>#</th><th>Time (UTC)</th><th>User</th><th>Resource</th><th>Device</th><th>Decision</th><th>Reason</th><th>Policy</th></tr></thead>
        <tbody>{shown.map((r) => <tr key={r.id}><td>{r.id}</td><td>{r.ts.slice(0, 19).replace("T", " ")}</td><td>{r.user_id}</td><td>{r.resource}</td><td>{r.device_id ?? "-"}</td>
          <td><Tag d={r.decision} /></td><td>{r.reason}</td><td>{r.policy_id ?? "-"}{r.policy_version ? ` v${r.policy_version}` : ""}</td></tr>)}</tbody></table></div>
    </div>
  );
}

function Policies({ pols }: { pols: Policy[] }) {
  return (
    <div className="card"><h2>Policies</h2><div className="w"><table><thead><tr><th>ID</th><th>Name</th><th>Effect</th><th>Roles</th><th>Resources</th><th>Status</th><th>v</th></tr></thead>
      <tbody>{pols.map((p) => <tr key={p.id}><td>{p.id}</td><td>{p.name}</td><td><Tag d={p.effect} /></td><td>{p.roles.join(", ") || "any"}</td><td>{p.resources.join(", ") || "any"}</td><td>{p.status}</td><td>{p.version}</td></tr>)}</tbody></table></div></div>
  );
}

function Simulator({ onDone }: { onDone: () => void }) {
  const [u, setU] = useState("priya"); const [dev, setDev] = useState("d-priya"); const [res, setRes] = useState("hr_db");
  const [out, setOut] = useState<AccessResult | null>(null); const [err, setErr] = useState("");
  const run = async () => {
    setErr("");
    try { setOut(await api<AccessResult>(`/access-request?resource=${encodeURIComponent(res)}`, { method: "POST" }, u, dev || undefined)); onDone(); }
    catch (e) { setOut(null); setErr((e as Error).message); }
  };
  return (
    <div className="card"><h2>Request simulator <span className="m">(device posture is simulated)</span></h2>
      <div className="row">
        <select value={u} onChange={(e) => setU(e.target.value)}>{USERS.map((x) => <option key={x}>{x}</option>)}</select>
        <select value={dev} onChange={(e) => setDev(e.target.value)}>{DEVICES.map((x) => <option key={x} value={x}>{x || "(no device)"}</option>)}</select>
        <select value={res} onChange={(e) => setRes(e.target.value)}>{RESOURCES.map((x) => <option key={x}>{x}</option>)}</select>
        <button onClick={() => void run()}>Evaluate</button></div>
      {out && <p><Tag d={out.decision} /> &mdash; {out.reason} ({out.policy_id ?? "default"}{out.policy_version ? ` v${out.policy_version}` : ""})</p>}
      {err && <p className="err">{err}</p>}
    </div>
  );
}
