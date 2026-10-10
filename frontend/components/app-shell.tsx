"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Activity, ArrowUpRight, Bell, BookOpen, Bug, ChevronDown, FileText, FolderKanban, Gauge, Globe, LogOut, ScanLine, Settings2, Shield, ShieldCheck, Users } from "lucide-react";
import { api } from "@/lib/api";

const primary = [
  { href: "/app/dashboard", label: "Overview", icon: Gauge },
  { href: "/app/projects", label: "Projects", icon: FolderKanban },
  { href: "/app/targets", label: "Authorized targets", icon: Globe },
  { href: "/app/scans", label: "Scan activity", icon: ScanLine },
  { href: "/app/retests", label: "Retests", icon: Activity },
  { href: "/app/findings", label: "Findings", icon: Bug },
  { href: "/app/reports", label: "Reports", icon: FileText },
];

type UserView = { full_name: string; email: string };
type OrgView = { name: string; role: string };
type SystemView = { deployment_mode: string; ai_enabled: boolean; zap_enabled: boolean };

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<UserView | null>(null);
  const [org, setOrg] = useState<OrgView | null>(null);
  const [system, setSystem] = useState<SystemView | null>(null);
  useEffect(() => {
    Promise.all([api<UserView>("auth/me"), api<OrgView>("organization"), api<SystemView>("system/info")])
      .then(([u, o, s]) => { setUser(u); setOrg(o); setSystem(s); }).catch(() => undefined);
  }, []);
  const initials = (user?.full_name || "S").split(/\s+/).slice(0, 2).map(part => part[0]?.toUpperCase()).join("");
  async function logout() {
    try { await api("logout", { method: "POST", body: "{}" }); } finally { router.replace("/"); router.refresh(); }
  }
  return <div className="app-frame">
    <aside className="sidebar">
      <Link className="brand-lockup" href="/app/dashboard"><span className="brand-mark"><ShieldCheck size={19}/></span><span><b>sentinel</b><em>security workspace</em></span></Link>
      <div className="org-switch"><div className="org-avatar">{(org?.name || "S").slice(0,1).toUpperCase()}</div><div className="org-copy"><b>{org?.name || "My workspace"}</b><span>{org?.role || "Workspace"}</span></div><ChevronDown size={15}/></div>
      <div className="nav-label">WORKSPACE</div>
      <nav className="side-nav">{primary.map(item => { const Icon = item.icon; const active = path === item.href || (item.href !== "/app/dashboard" && path.startsWith(item.href)); return <Link key={item.href} href={item.href} className={`nav-item ${active ? "active" : ""}`}><Icon size={17}/><span>{item.label}</span>{item.href === "/app/findings" && <span className="nav-dot"/>}</Link>; })}</nav>
      <div className="nav-label nav-label-spaced">MANAGE</div>
      <nav className="side-nav">
        <Link href="/app/settings" className={`nav-item ${path.startsWith("/app/settings") ? "active" : ""}`}><Settings2 size={17}/><span>Settings</span></Link>
        <Link href="/app/settings#team" className="nav-item"><Users size={17}/><span>Team access</span></Link>
        <a href="/docs" className="nav-item"><BookOpen size={17}/><span>Documentation</span><ArrowUpRight size={13} className="nav-external"/></a>
      </nav>
      <div className="sidebar-spacer"/>
      <div className="sidebar-status"><span className="status-pulse"/><span>Security engine ready</span><span className="status-version">v1.0</span></div>
      <button className="profile-row" onClick={logout}><div className="profile-avatar">{initials || "S"}</div><div className="profile-details"><b>{user?.full_name || "Workspace member"}</b><span>{user?.email || "Signed in securely"}</span></div><LogOut size={16}/></button>
    </aside>
    <main className="app-main">
      <header className="topbar"><div className="breadcrumb"><span>Workspace</span><span className="crumb-slash">/</span><b>{primary.find(item => path === item.href || (item.href !== "/app/dashboard" && path.startsWith(item.href)))?.label || "Settings"}</b></div><div className="topbar-actions"><span className="environment-chip"><span/> {(system?.deployment_mode || "self_hosted").replaceAll("_", " ")}</span><button className="icon-button" aria-label="Notifications"><Bell size={17}/></button><div className="topbar-divider"/><div className="mini-avatar">{initials || "S"}</div></div></header>
      <div className="page-content">{children}</div>
      <footer className="app-footer"><span>SentinelAI <b>·</b> Evidence-first security</span><span><Shield size={12}/> Authorized assessments only</span></footer>
    </main>
  </div>;
}
