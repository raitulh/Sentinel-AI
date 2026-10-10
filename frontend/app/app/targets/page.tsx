"use client";
import { useEffect, useState } from "react";
import { ArrowRight, Check, Copy, Globe, Plus, ShieldCheck } from "lucide-react";
import { api, Project, Target } from "@/lib/api";

type Challenge = { target_id: string; record_type: string; record_name: string; record_value: string };

export default function TargetsPage() {
  const [items, setItems] = useState<Target[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [note, setNote] = useState("");
  const [ack, setAck] = useState(false);
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [challenge, setChallenge] = useState<Challenge | null>(null);

  async function load(preferredId?: string | null) {
    try {
      const [targets, projectList] = await Promise.all([api<Target[]>("targets"), api<Project[]>("projects")]);
      setItems(targets);
      setProjects(projectList);
      const preferredValid = preferredId && projectList.some(project => project.id === preferredId);
      const currentValid = projectId && projectList.some(project => project.id === projectId);
      if (preferredValid) setProjectId(preferredId);
      else if (!currentValid && projectList.length) setProjectId(projectList[0].id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load targets");
    }
  }

  useEffect(() => {
    const initial = new URLSearchParams(window.location.search).get("project");
    void load(initial);
  }, []);

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setSuccess("");
    try {
      await api("targets", { method: "POST", body: JSON.stringify({
        project_id: projectId, name, url, authorization_acknowledged: ack, authorization_note: note,
      }) });
      setName(""); setUrl(""); setNote(""); setAck(false); setShow(false);
      setSuccess("Target registered. The verification method and current scope status are shown below.");
      await load(projectId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Target registration failed");
    } finally { setBusy(false); }
  }

  async function requestChallenge(targetId: string) {
    setError(""); setSuccess("");
    try {
      const result = await api<Challenge>(`targets/${targetId}/verification-challenge`, { method: "POST", body: "{}" });
      setChallenge(result);
      setSuccess("Add the TXT record shown below, wait for DNS propagation, then verify it.");
    } catch (err) { setError(err instanceof Error ? err.message : "Could not create verification challenge"); }
  }

  async function verifyDns(targetId: string) {
    setError(""); setSuccess(""); setBusy(true);
    try {
      await api(`targets/${targetId}/verify`, { method: "POST", body: "{}" });
      setChallenge(null);
      setSuccess("DNS ownership verification succeeded.");
      await load(projectId);
    } catch (err) { setError(err instanceof Error ? err.message : "DNS verification failed"); }
    finally { setBusy(false); }
  }

  async function disable(targetId: string) {
    setError("");
    try { await api(`targets/${targetId}/disable`, { method: "PATCH", body: "{}" }); await load(projectId); }
    catch (err) { setError(err instanceof Error ? err.message : "Could not disable target"); }
  }

  async function copyChallenge() {
    if (!challenge) return;
    try { await navigator.clipboard.writeText(`${challenge.record_name}\t${challenge.record_type}\t${challenge.record_value}`); setSuccess("TXT record copied."); }
    catch { setError("Clipboard access was unavailable. Select and copy the TXT record manually."); }
  }

  return <>
    <div className="page-heading">
      <div><div className="overline">Scope management</div><h1>Authorized targets</h1><p>Register only applications and APIs you own or have explicit permission to assess.</p></div>
      <button className="btn btn-primary" onClick={() => setShow(value => !value)}><Plus size={14}/>{show ? "Close form" : "Register target"}</button>
    </div>
    {error && <div className="form-error" style={{ marginBottom: 13 }} role="alert">{error}</div>}
    {success && <div className="form-success" style={{ marginBottom: 13 }} role="status">{success}</div>}
    <div className="info-banner" style={{ marginTop: 0, marginBottom: 16 }}><ShieldCheck size={16}/><div><b>Scope enforcement is intentional</b><p>The scanner revalidates the target when a job starts. Hosted mode requires DNS ownership verification; self-hosted mode records an operator attestation but does not independently prove ownership. Network egress controls remain required.</p></div></div>
    {challenge && <div className="form-card" style={{ marginBottom: 18 }}>
      <div className="overline">DNS ownership challenge</div><h2 className="panel-title" style={{ marginTop: 8, marginBottom: 8 }}>Publish this TXT record</h2>
      <p className="small muted" style={{ lineHeight: 1.7 }}>Create the TXT record at your DNS provider. Do not change other scope settings to bypass this check.</p>
      <div className="field" style={{ marginBottom: 11 }}><label>Record name</label><input className="input" readOnly value={challenge.record_name}/></div>
      <div className="field" style={{ marginBottom: 15 }}><label>Record type / value</label><div style={{ display: "flex", gap: 8 }}><input className="input" readOnly value={`${challenge.record_type}  ${challenge.record_value}`}/><button className="btn btn-secondary" type="button" onClick={copyChallenge} aria-label="Copy DNS record"><Copy size={14}/></button></div></div>
      <div className="form-actions"><button className="btn btn-secondary" onClick={() => setChallenge(null)}>Dismiss</button><button className="btn btn-primary" disabled={busy} onClick={() => verifyDns(challenge.target_id)}><Check size={14}/> Verify DNS</button></div>
    </div>}
    {show && <form className="form-card" onSubmit={create} style={{ marginBottom: 18 }}>
      <div className="form-grid">
        <div className="field form-field-wide"><label htmlFor="target-project">Project</label><select className="select" id="target-project" required value={projectId} onChange={event => setProjectId(event.target.value)}><option value="">Select a project</option>{projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></div>
        <div className="field"><label htmlFor="target-name">Display name</label><input className="input" id="target-name" required minLength={2} maxLength={180} value={name} onChange={event => setName(event.target.value)} placeholder="Staging API"/></div>
        <div className="field"><label htmlFor="target-url">Base URL</label><input className="input" id="target-url" type="url" required value={url} onChange={event => setUrl(event.target.value)} placeholder="https://staging.example.com"/></div>
        <div className="field form-field-wide"><label htmlFor="target-note">Authorization details</label><textarea className="textarea" id="target-note" required minLength={10} maxLength={2000} value={note} onChange={event => setNote(event.target.value)} placeholder="Ownership, written authorization reference, environment and allowed scope…"/></div>
        <label className="form-field-wide" style={{ display: "flex", alignItems: "flex-start", gap: 10, fontSize: 11, lineHeight: 1.7, color: "#696357" }}><input type="checkbox" required checked={ack} onChange={event => setAck(event.target.checked)} style={{ marginTop: 3 }}/> I confirm that I own this target or have explicit authorization to run the configured non-destructive checks against it. This authorization does not extend to other hosts or paths.</label>
      </div>
      <div className="form-actions"><button className="btn btn-secondary" type="button" onClick={() => setShow(false)}>Cancel</button><button className="btn btn-primary" disabled={busy || !projects.length}>{busy ? "Registering…" : "Register authorized target"}</button></div>
    </form>}
    <div className="table-panel"><div className="table-toolbar"><strong style={{ fontSize: 11 }}>Registered scope</strong><span className="muted small">{items.length} targets</span></div>
      {items.length === 0 ? <div className="empty-state"><div className="empty-icon"><Globe size={19}/></div><h3>Make scope explicit.</h3><p>Create a project before registering a target. Private hosts require an explicitly configured self-hosted environment and appropriate network isolation.</p><button className="btn btn-primary" onClick={() => projects.length ? setShow(true) : window.location.assign("/app/projects")}>{projects.length ? "Register a target" : "Create a project first"}<ArrowRight size={14}/></button></div> :
      <div className="table-wrap"><table><thead><tr><th>Target</th><th>Project</th><th>Authorization</th><th>Status</th><th>Added</th><th>Actions</th></tr></thead><tbody>{items.map(target => {
        const method = target.verification_method || "pending";
        const label = method === "dns_txt" ? "DNS verified" : method === "operator_attestation" ? "Operator attestation" : "Needs DNS proof";
        return <tr key={target.id}><td><span className="table-primary">{target.name}</span><span className="table-secondary">{target.canonical_url}</span></td><td>{projects.find(project => project.id === target.project_id)?.name || target.project_id.slice(0, 8)}</td><td><span className={`state-badge ${method === "dns_txt" ? "confirmed" : method === "operator_attestation" ? "likely" : "unverified"}`}>{label}</span></td><td><span className={`state-badge ${target.is_active ? "confirmed" : "cancelled"}`}>{target.is_active ? "Active" : "Disabled"}</span></td><td>{new Date(target.created_at).toLocaleDateString()}</td><td><div style={{ display: "flex", gap: 6 }}>{method === "pending" && target.is_active && <button className="btn btn-secondary" style={{ minHeight: 29, padding: "0 8px" }} onClick={() => requestChallenge(target.id)}>Verify DNS</button>}{target.is_active && <button className="btn btn-quiet" style={{ minHeight: 29, padding: "0 8px" }} onClick={() => disable(target.id)}>Disable</button>}</div></td></tr>;
      })}</tbody></table></div>}
    </div>
  </>;
}
