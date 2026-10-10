import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "SentinelAI — Security, with evidence.", template: "%s · SentinelAI" },
  description: "Evidence-first security assessments for applications you own or are authorized to test.",
  applicationName: "SentinelAI",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
