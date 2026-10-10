import Link from "next/link";
import { ArrowRight, BookOpen, ShieldCheck } from "lucide-react";

const guides = [
  { title: "First workspace", detail: "Create the initial owner account, then create a project for an application you control." },
  { title: "Register a target", detail: "Record the exact URL and written authorization. Hosted mode requires a DNS TXT proof before scans can run." },
  { title: "Run a safe baseline", detail: "Review the scan profile and scope. The baseline performs bounded GET-only response checks; the optional ZAP integration uses a scoped spider and passive rules." },
  { title: "Review evidence", detail: "Use the verification state, evidence summary and limitations together. A finding is not a complete security assessment." },
  { title: "Propose and retest a fix", detail: "Review the remediation guidance, approve the proposal decision, implement changes through your normal engineering process, then run a retest." },
];

export default function DocsPage() {
  return <main className="marketing-page">
    <nav className="marketing-nav"><Link href="/" className="marketing-brand"><span className="brand-mark"><ShieldCheck size={19}/></span><span>sentinel<span style={{color:"var(--forest)"}}>ai</span></span></Link><div className="marketing-links"><Link href="/platform">Platform</Link><Link href="/security">Security</Link><Link href="/pricing">Deployment</Link></div><div className="marketing-actions"><Link href="/login" className="text-link">Sign in</Link><Link href="/register" className="btn btn-primary">Open workspace <ArrowRight size={14}/></Link></div></nav>
    <section className="marketing-subhero"><div className="eyebrow" style={{justifyContent:"center"}}><BookOpen size={14}/> Documentation</div><h1>Build a more accountable security workflow.</h1><p>Start here for the safe baseline profile, target authorization model, evidence states and supported remediation lifecycle.</p></section>
    <section className="section" style={{paddingTop:0}}><div className="section-head"><div className="eyebrow">Quick start</div><h2>From workspace to retest.</h2></div><div className="feature-grid">{guides.map((g,i)=><article className="feature-card" key={g.title}><div className="feature-icon">0{i+1}</div><h3>{g.title}</h3><p>{g.detail}</p></article>)}</div><div className="workflow-band" style={{marginTop:32,borderRadius:22}}><div className="workflow-inner"><div className="eyebrow">Read before scanning</div><h2>Keep the scope explicit.</h2><p>Only scan systems you own or have documented authorization to assess. Restrict network egress at the runner boundary, keep the scanner API private, and do not treat an absence of findings as evidence that an application is secure.</p><div className="hero-actions"><Link href="/security" className="btn btn-secondary">Security model <ArrowRight size={14}/></Link><Link href="/app/dashboard" className="btn btn-primary">Open dashboard <ArrowRight size={14}/></Link></div></div></div></section>
    <footer className="marketing-footer"><span>SentinelAI · Documentation</span><div className="footer-links"><Link href="/privacy">Privacy</Link><Link href="/terms">Terms</Link><Link href="/changelog">Changelog</Link></div></footer>
  </main>;
}
