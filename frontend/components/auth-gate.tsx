"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  useEffect(() => {
    let alive = true;
    api("auth/me").then(() => { if (alive) setReady(true); }).catch(() => { if (alive) router.replace("/login?next=/app/dashboard"); });
    return () => { alive = false; };
  }, [router]);
  if (!ready) return <main className="auth-loading"><div className="loading-mark">S</div><p>Checking your secure session…</p></main>;
  return <>{children}</>;
}
