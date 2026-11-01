import { ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { HeroShield, Icon, IconName, Logo, Wordmark } from "./brand";
import { api, getToken, login, setToken, stepUp, AccessResult, AuditRow, Decision, Me, Policy, Stats } from "./api";

const COLOR: Record<Decision, string> = { ALLOW: "#34d399", DENY: "#fb7185", STEP_UP_AUTHENTICATION: "#fbbf24" };
const LABEL: Record<Decision, string> = { ALLOW: "Allowed", DENY: "Denied", STEP_UP_AUTHENTICATION: "Step-up" };
const KEYS = Object.keys(COLOR) as Decision[];
const TABS = [["Overview", "grid"], ["Access monitoring", "activity"], ["Policies", "shieldcheck"], ["Simulator", "flask"]] as const;
const TIP = { contentStyle: { background: "#0b1330", border: "1px solid #2b3a7a", borderRadius: 10, color: "#e8ecf6" }, cursor: { fill: "rgba(99,179,255,.08)" } };
type Tab = (typeof TABS)[number][0];
const TITLES: Record<Tab, string> = { Overview: "Security overview", "Access monitoring": "Access monitoring", Policies: "Policies", Simulator: "Request simulator" };
const SUBS: Record<Tab, string> = { Overview: "What is happening across your protected resources.", "Access monitoring": "Every decision, with the reason and the policy version. Click a row for details.",
  Policies: "The rules OPA evaluates. Deny always wins.", Simulator: "Try a scenario and watch the decision appear in the audit log." };
const SCENARIOS = [
  { u: "priya", d: "d-priya", r: "hr_db", t: "HR opens the HR database", e: "ALLOW" }, { u: "aman", d: "d-aman", r: "hr_db", t: "Developer opens the HR database", e: "DENY" },
  { u: "neha", d: "d-neha", r: "hr_db", t: "HR user without MFA", e: "STEP_UP_AUTHENTICATION" }, { u: "root", d: "d-root", r: "source_code", t: "Admin on a non-compliant device", e: "DENY" },
  { u: "ravi", d: "d-ravi", r: "source_code", t: "Intern opens source code", e: "DENY" }, { u: "ravi", d: "d-ravi", r: "wiki", t: "Intern reads the wiki", e: "ALLOW" },
  { u: "sam", d: "", r: "wiki", t: "Disabled account", e: "DENY" }, { u: "priya", d: "d-aman", r: "hr_db", t: "Using someone else's device", e: "DENY" },
] as const;

function ago(ts: string) {
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  return s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`;
}
function exportCsv(rows: AuditRow[]) {
  const cols = ["id", "ts", "user_id", "resource", "device_id", "decision", "reason", "policy_id", "policy_version"] as const;
  const cell = (v: unknown) => { const t = String(v ?? ""); return `"${(/^[=+\-@]/.test(t) ? "'" + t : t).replace(/"/g, '""')}"`; };
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([[cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n")], { type: "text/csv" }));
  a.download = "zeroguard-audit.csv"; a.click(); URL.revokeObjectURL(a.href);
}
const Pill = ({ d }: { d: Decision }) => <span className={`pill ${d}`}>{LABEL[d]}</span>;
const Empty = ({ icon, text, children }: { icon: IconName; text: string; children?: ReactNode }) => <div className="empty"><div className="big"><Icon name={icon} size={30} /></div><p>{text}</p>{children}</div>;

export default function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  const [me, setMe] = useState<Me | null>(null); const [booting, setBooting] = useState(!!getToken());
  const [stats, setStats] = useState<Stats | null>(null); const [rows, setRows] = useState<AuditRow[]>([]);
  const [pols, setPols] = useState<Policy[]>([]); const [intact, setIntact] = useState<boolean | null>(null);
  const [err, setErr] = useState(""); const [loading, setLoading] = useState(false); const [auto, setAuto] = useState(false);
  const [sel, setSel] = useState<AuditRow | null>(null); const [otp, setOtp] = useState(""); const [mfaMsg, setMfaMsg] = useState("");
  const isAdmin = me?.role === "admin";

  const signOut = useCallback(() => { setToken(""); setMe(null); setStats(null); setRows([]); setPols([]); setIntact(null); setErr(""); }, []);
  useEffect(() => { if (!getToken()) { setBooting(false); return; } api<Me>("/auth/me").then(setMe).catch(signOut).finally(() => setBooting(false)); }, [signOut]);
  const load = useCallback(async () => {
    if (!isAdmin) return;
    setErr(""); setLoading(true);
    try {
      const [s, a, p, v] = await Promise.all([api<Stats>("/stats"), api<AuditRow[]>("/audit"), api<Policy[]>("/policies"), api<{ intact: boolean }>("/audit/verify")]);
      setStats(s); setRows(a); setPols(p); setIntact(v.intact);
    } catch (e) { const m = (e as Error).message; if (m.startsWith("401")) signOut(); else setErr(m); }
    finally { setLoading(false); }
  }, [isAdmin, signOut]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (!auto) return; const t = setInterval(() => void load(), 10000); return () => clearInterval(t); }, [auto, load]);
  const verify = async () => {
    try { const r = await stepUp(otp); setToken(r.token); setMe(r.user); setOtp(""); setMfaMsg(""); }
    catch (e) { setMfaMsg((e as Error).message.replace(/^\d+: /, "")); }
  };

  if (booting) return <div className="card lock"><Empty icon="clock" text="Loading…" /></div>;
  if (!me) return <Login onDone={(t, u) => { setToken(t); setMe(u); }} />;
  const denies = stats?.by_decision.DENY ?? 0;
  return (
    <div className="app">
      <aside>
        <div className="brand"><Logo size={38} /><Wordmark /></div>
        {TABS.map(([t, i]) => <button key={t} className={`side-btn ${t === tab ? "on" : ""}`} onClick={() => setTab(t)}><Icon name={i} size={18} />{t}
          {t === "Access monitoring" && denies > 0 && <span className="cnt">{denies}</span>}</button>)}
        <div className="note"><div className="pr"><Icon name="shieldcheck" size={14} />Never trust</div><div className="pr"><Icon name="idcard" size={14} />Always verify</div><div className="pr"><Icon name="lock" size={14} />Least privilege</div></div>
      </aside>
      <main>
        <div className="top">
          <div><h1>{TITLES[tab]}</h1><p className="sub">{SUBS[tab]}</p></div>
          <div className="tools">
            <span className="chip" style={{ fontSize: 13, padding: "5px 10px" }}><Icon name="user" size={14} /> {me.name} · {me.role}</span>
            {me.mfa ? <span className="pill ALLOW">MFA verified</span> : <>
              <span className="pill STEP_UP_AUTHENTICATION">MFA not verified</span>
              <input placeholder="6-digit code" aria-label="MFA code" size={9} value={otp} onChange={(e) => setOtp(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void verify(); }} />
              <button className="ghost" onClick={() => void verify()}>Verify</button>{mfaMsg && <span className="m" style={{ color: "var(--no)" }}>{mfaMsg}</span>}</>}
            {isAdmin && <><label className="sw"><input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />Auto-refresh</label>
              <button className="btn" disabled={loading} onClick={() => void load()}>{loading ? "Loading…" : "Refresh"}</button></>}
            <button className="ghost" onClick={signOut}>Sign out</button>
          </div>
        </div>
        {tab === "Simulator" ? <Simulator me={me} onDone={() => void load()} /> : !isAdmin ? (
          <div className="card lock"><div className="ico big-ico"><Icon name="lock" size={30} /></div><h2>Administrators only</h2>
            <p className="m">You are signed in as <b>{me.name}</b> ({me.role}). Dashboards, audit log and policies are for admins. Use the Simulator to check your own access.</p></div>
        ) : err ? <div className="card"><Empty icon="alert" text={`Could not load data (${err}).`} /></div>
          : !stats ? <div className="card"><Empty icon="clock" text="Loading…" /></div>
          : tab === "Overview" ? <Overview stats={stats} rows={rows} intact={intact} go={setTab} />
          : tab === "Access monitoring" ? <Monitoring rows={rows} onPick={setSel} go={setTab} />
          : <PolicyList pols={pols} />}
      </main>
      {sel && <><div className="veil" onClick={() => setSel(null)} /><div className="drawer" role="dialog" aria-label="Decision details">
        <div className="top"><h2>Decision #{sel.id}</h2><button className="ghost" onClick={() => setSel(null)}>Close</button></div>
        <p><Pill d={sel.decision} /></p>
        <dl><dt>Reason</dt><dd>{sel.reason}</dd><dt>User</dt><dd>{sel.user_id}</dd><dt>Resource</dt><dd>{sel.resource}</dd><dt>Device</dt><dd>{sel.device_id ?? "none"}</dd>
          <dt>Policy</dt><dd>{sel.policy_id ?? "default deny"}{sel.policy_version ? ` (v${sel.policy_version})` : ""}</dd><dt>Time (UTC)</dt><dd>{sel.ts.slice(0, 19).replace("T", " ")}</dd></dl></div></>}
    </div>
  );
}

function Login({ onDone }: { onDone: (token: string, user: Me) => void }) {
  const [u, setU] = useState("root"); const [p, setP] = useState(""); const [o, setO] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [hint, setHint] = useState("");
  const submit = async () => {
    setBusy(true); setErr("");
    try { const r = await login(u.trim(), p, o.trim() || undefined); onDone(r.token, r.user); }
    catch (e) { setErr((e as Error).message.replace(/^\d+: /, "")); }
    finally { setBusy(false); }
  };
  const demo = async () => {
    try { const r = await api<{ code: string }>(`/auth/demo-code?username=${encodeURIComponent(u.trim())}`); setHint(`Demo MFA code for ${u}: ${r.code}`); }
    catch { setHint("No demo code: demo mode is off or this user has no MFA enrolled."); }
  };
  return (<div className="login">
    <section className="login-l">
      <div className="hero-brand"><Logo size={64} /><Wordmark size={46} /></div>
      <p className="tag">A Zero Trust Cybersecurity Framework</p><div className="beam" />
      <div className="principles">
        <span><Icon name="shieldcheck" size={22} />Never Trust</span><span><Icon name="idcard" size={22} />Always Verify</span><span><Icon name="lock" size={22} />Least Privilege</span>
      </div>
      <form className="card glass" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
        <h2>Sign in</h2><p className="m" style={{ marginTop: -6 }}>Every request after this is checked against policy.</p>
        <label htmlFor="u">Username</label><input id="u" list="demo-users" autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} />
        <datalist id="demo-users">{["root", "priya", "aman", "ravi", "neha", "sam"].map((x) => <option key={x} value={x} />)}</datalist>
        <label htmlFor="p">Password</label><input id="p" type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} />
        <label htmlFor="o">MFA code <span className="m">(optional now; you can verify later)</span></label><input id="o" inputMode="numeric" maxLength={6} value={o} onChange={(e) => setO(e.target.value)} />
        {err && <p style={{ color: "var(--no)" }}>{err}</p>}
        <button className="btn" style={{ width: "100%", marginTop: 14 }} disabled={busy || !u || !p}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="m" style={{ marginBottom: 0 }}>Demo accounts: root (admin), priya (HR), aman (developer), ravi (intern), neha (HR, no MFA). Password: your <b>DEMO_PASSWORD</b> (Render → Environment).
          {" "}<button type="button" className="ghost" style={{ padding: "2px 8px" }} onClick={() => void demo()}>Show demo MFA code</button></p>
        {hint && <p className="m"><b>{hint}</b></p>}
      </form>
    </section>
    <section className="login-r"><HeroShield /></section>
  </div>);
}

function Overview({ stats, rows, intact, go }: { stats: Stats; rows: AuditRow[]; intact: boolean | null; go: (t: Tab) => void }) {
  const d = stats.by_decision; const total = Object.values(d).reduce((x, y) => x + y, 0);
  const byDecision = KEYS.map((k) => ({ name: LABEL[k], key: k, count: d[k] ?? 0 }));
  const byResource = useMemo(() => {
    const m: Record<string, Record<string, number>> = {};
    rows.forEach((r) => { (m[r.resource] ??= {})[r.decision] = (m[r.resource][r.decision] ?? 0) + 1; });
    return Object.entries(m).map(([resource, v]) => ({ resource, ...v }));
  }, [rows]);
  const cards: [string, number, IconName, string][] = [["Total requests", total, "chart", "#60a5fa"], ["Allowed", d.ALLOW ?? 0, "check", COLOR.ALLOW], ["Denied", d.DENY ?? 0, "ban", COLOR.DENY], ["Step-up needed", d.STEP_UP_AUTHENTICATION ?? 0, "key", COLOR.STEP_UP_AUTHENTICATION]];
  return (<>
    <div className="grid">{cards.map(([k, n, i, c]) => <div className="card stat" key={k}><div className="ico" style={{ color: c, borderColor: c + "88", boxShadow: `0 0 18px ${c}55, inset 0 0 12px ${c}22` }}><Icon name={i} size={22} /></div><div><div className="num">{n}</div><div className="m">{k}</div></div></div>)}</div>
    {total === 0 ? <div className="card"><Empty icon="flask" text="No activity yet. Run a few scenarios to see the dashboard come alive."><button className="btn" onClick={() => go("Simulator")}>Open the simulator</button></Empty></div> : <>
      <div className="grid2">
        <div className="card"><h2>Decisions</h2><div style={{ height: 230 }}><ResponsiveContainer><BarChart data={byDecision}><CartesianGrid strokeDasharray="3 3" vertical={false} /><XAxis dataKey="name" fontSize={12} /><YAxis allowDecimals={false} /><Tooltip {...TIP} />
          <Bar dataKey="count" radius={[8, 8, 0, 0]}>{byDecision.map((x) => <Cell key={x.key} fill={COLOR[x.key]} />)}</Bar></BarChart></ResponsiveContainer></div></div>
        <div className="card"><h2>Decisions by resource</h2><div style={{ height: 230 }}><ResponsiveContainer><BarChart data={byResource}><CartesianGrid strokeDasharray="3 3" vertical={false} /><XAxis dataKey="resource" fontSize={12} /><YAxis allowDecimals={false} /><Tooltip {...TIP} /><Legend />
          {KEYS.map((k) => <Bar key={k} name={LABEL[k]} dataKey={k} stackId="a" fill={COLOR[k]} />)}</BarChart></ResponsiveContainer></div></div>
      </div>
      <div className="grid2">
        <div className="card"><h2><span className="h2i"><Icon name="alert" size={16} /></span> Repeated denials</h2>{stats.repeated_denials.length ? stats.repeated_denials.map((v) => <div className="alert" key={v.user_id + v.resource}><b>{v.user_id}</b> keeps trying <b>{v.resource}</b><span className="pill DENY" style={{ marginLeft: "auto" }}>{v.n} denials</span></div>) : <p className="m">No repeated denials. Nothing suspicious so far.</p>}</div>
        <div className="card"><h2><span className="h2i" style={{ color: "var(--cy)" }}><Icon name="shieldcheck" size={16} /></span> Audit log integrity</h2>{intact === null ? <p className="m">Unknown</p> : intact ? <p><span className="pill ALLOW">Intact</span> <span className="m">Hash chain verified: no record has been edited.</span></p> : <p><span className="pill DENY">Tampering detected</span></p>}</div>
      </div></>}
  </>);
}

function Monitoring({ rows, onPick, go }: { rows: AuditRow[]; onPick: (r: AuditRow) => void; go: (t: Tab) => void }) {
  const [f, setF] = useState<"ALL" | Decision>("ALL"); const [q, setQ] = useState("");
  const count = (k: Decision) => rows.filter((r) => r.decision === k).length;
  const shown = rows.filter((r) => (f === "ALL" || r.decision === f) && `${r.user_id} ${r.resource} ${r.reason}`.toLowerCase().includes(q.toLowerCase()));
  return (<div className="card">
    <div className="top" style={{ marginBottom: 10 }}>
      <div className="chips" style={{ margin: 0 }}>{(["ALL", ...KEYS] as const).map((k) => <button key={k} className={f === k ? "on" : ""} onClick={() => setF(k)}>{k === "ALL" ? `All (${rows.length})` : `${LABEL[k]} (${count(k)})`}</button>)}</div>
      <div className="tools"><input placeholder="Search user, resource or reason" value={q} onChange={(e) => setQ(e.target.value)} /><button className="ghost" disabled={!shown.length} onClick={() => exportCsv(shown)}>Export CSV</button></div></div>
    {shown.length === 0 ? <Empty icon="search" text={rows.length ? "Nothing matches your filters." : "No events yet."}>{!rows.length && <button className="btn" onClick={() => go("Simulator")}>Run a scenario</button>}</Empty> :
      <div className="w"><table><thead><tr><th>When</th><th>User</th><th>Resource</th><th>Decision</th><th>Reason</th><th>Policy</th></tr></thead>
        <tbody>{shown.map((r) => <tr key={r.id} onClick={() => onPick(r)}><td title={r.ts}>{ago(r.ts)}</td><td><b>{r.user_id}</b></td><td>{r.resource}</td><td><Pill d={r.decision} /></td><td>{r.reason}</td><td>{r.policy_id ?? "-"}{r.policy_version ? ` v${r.policy_version}` : ""}</td></tr>)}</tbody></table></div>}
  </div>);
}

function PolicyList({ pols }: { pols: Policy[] }) {
  if (!pols.length) return <div className="card"><Empty icon="shield" text="No policies loaded." /></div>;
  return <div className="grid2">{pols.map((p) => <div className="card" key={p.id}>
    <div className="top" style={{ marginBottom: 6 }}><b>{p.id}</b><Pill d={p.effect} /></div><p style={{ margin: "0 0 10px", fontWeight: 600 }}>{p.name}</p>
    <div className="m">Roles</div>{(p.roles.length ? p.roles : ["any"]).map((x) => <span className="chip" key={x}>{x}</span>)}
    <div className="m">Resources</div>{(p.resources.length ? p.resources : ["any"]).map((x) => <span className="chip" key={x}>{x}</span>)}
    <p className="m" style={{ marginBottom: 0 }}>Status: {p.status} · version {p.version}</p></div>)}</div>;
}

type Run = { u: string; d: string; r: string; t?: string; out?: AccessResult; err?: string };
function Simulator({ me, onDone }: { me: Me; onDone: () => void }) {
  const [runs, setRuns] = useState<Run[]>([]); const [busy, setBusy] = useState(false);
  const [dev, setDev] = useState(`d-${me.id}`); const [res, setRes] = useState("hr_db");
  const isAdmin = me.role === "admin";
  const run = async (x: Run, asOther: boolean) => {
    setBusy(true); let out: Run;
    const path = asOther ? `/simulate?user=${encodeURIComponent(x.u)}&resource=${encodeURIComponent(x.r)}` : `/access-request?resource=${encodeURIComponent(x.r)}`;
    try { out = { ...x, out: await api<AccessResult>(path, { method: "POST" }, x.d || undefined) }; }
    catch (e) { out = { ...x, err: (e as Error).message }; }
    setRuns((p) => [out, ...p].slice(0, 6)); setBusy(false); if (isAdmin) onDone();
  };
  const last = runs[0];
  return (<>
    {last && <div className={`card result ${last.out?.decision ?? ""}`} style={{ marginBottom: 14 }}>
      {last.out ? <><div className="ico" style={{ color: COLOR[last.out.decision], borderColor: COLOR[last.out.decision] + "88", boxShadow: `0 0 22px ${COLOR[last.out.decision]}66` }}><Icon name={last.out.decision === "ALLOW" ? "check" : last.out.decision === "DENY" ? "ban" : "key"} size={26} /></div>
        <div><div><Pill d={last.out.decision} /> <b>{last.t ?? `${last.u} → ${last.r}`}</b></div><div className="m">{last.out.reason} · policy {last.out.policy_id ?? "default"}{last.out.policy_version ? ` v${last.out.policy_version}` : ""}</div></div></> : <span>{last.err}</span>}</div>}
    {isAdmin && <div className="card" style={{ marginBottom: 14 }}><h2>Admin scenarios <span className="m">(evaluated as the named user; device posture is simulated)</span></h2>
      <div className="scen">{SCENARIOS.map((s) => <button key={s.t} className="sc" disabled={busy} onClick={() => void run({ u: s.u, d: s.d, r: s.r, t: s.t }, true)}>
        <b>{s.t}</b><div className="m">{s.u} · {s.d || "no device"} · {s.r}</div><div style={{ marginTop: 8 }}><span className="m">Expect: </span><Pill d={s.e} /></div></button>)}</div></div>}
    <div className="card" style={{ marginBottom: 14 }}><h2>Check my own access <span className="m">(as {me.name}, {me.mfa ? "MFA verified" : "MFA not verified"})</span></h2>
      <div className="tools">
        <select value={dev} onChange={(e) => setDev(e.target.value)} aria-label="Device">{["", "d-aman", "d-priya", "d-root", "d-ravi", "d-neha"].map((x) => <option key={x} value={x}>{x || "(no device)"}</option>)}</select>
        <select value={res} onChange={(e) => setRes(e.target.value)} aria-label="Resource">{["hr_db", "source_code", "wiki"].map((x) => <option key={x}>{x}</option>)}</select>
        <button className="btn" disabled={busy} onClick={() => void run({ u: me.id, d: dev, r: res }, false)}>Request access</button></div></div>
    {runs.length > 1 && <div className="card"><h2>Recent runs</h2>{runs.slice(1).map((x, i) => <div key={i} style={{ padding: "6px 0", borderTop: "1px solid var(--bd)" }}>{x.out ? <Pill d={x.out.decision} /> : "error"} {x.t ?? `${x.u} → ${x.r}`} <span className="m">{x.out?.reason}</span></div>)}</div>}
  </>);
}
