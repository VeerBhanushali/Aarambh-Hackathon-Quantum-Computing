import type { Metadata } from "next";
import Script from "next/script";

export const metadata: Metadata = {
  title: "Quantum Guard — Post-Quantum Cryptography Assessment & Migration Platform",
  description:
    "Full-Stack Next.js SaaS & Enterprise PQC Assessment, CycloneDX 1.6 CBOM, Mosca HNDL Risk Scoring, and NIST FIPS 203/204/205 Migration Platform (quantumguard-lab.veerbhanushali.in).",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="stylesheet" href="/static/style.css?v=12" />
        <style
          dangerouslySetInnerHTML={{
            __html: `
              .tab-section { display: none !important; }
              .tab-section.active { display: block !important; }
              .sub-pane { display: none !important; }
              .sub-pane.active { display: block !important; }
              .saas-stage { display: none !important; }
              .saas-stage.active-stage { display: block !important; }
              .app-layout.saas-stage.active-stage { display: flex !important; }
              .mkt-shell { height: 100vh; overflow-y: auto; scroll-behavior: smooth; padding: 24px 32px 60px; max-width: 1280px; margin: 0 auto; }
              .mkt-nav { display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.88); backdrop-filter: blur(16px); border: 1.5px solid #e2e8f0; border-radius: 16px; padding: 12px 22px; position: sticky; top: 0; z-index: 100; box-shadow: 0 8px 24px rgba(15,23,42,0.05); }
              .mkt-hero { text-align: center; padding: 44px 24px 36px; background: rgba(255,255,255,0.86); border: 1.5px solid #e2e8f0; border-radius: 24px; margin-top: 22px; box-shadow: 0 18px 44px rgba(15,23,42,0.06); position: relative; overflow: hidden; }
              .mkt-grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 22px; }
              .mkt-card { background: #ffffff; border: 1.5px solid #e2e8f0; border-radius: 18px; padding: 20px; transition: all 0.2s ease; box-shadow: 0 6px 18px rgba(15,23,42,0.04); }
              .mkt-card:hover { transform: translateY(-3px); border-color: var(--purple); box-shadow: 0 14px 30px rgba(124,58,237,0.1); }
              .locked-gate-box { background: linear-gradient(180deg, rgba(255,255,255,0.92), #f8fafc); border: 2px dashed var(--purple); border-radius: 18px; padding: 24px; margin-top: 18px; text-align: center; }
            `,
          }}
        />
        <Script
          src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"
          strategy="beforeInteractive"
        />
      </head>
      <body>
        {children}
        <Script src="/static/app.js?v=12" strategy="afterInteractive" />
      </body>
    </html>
  );
}
