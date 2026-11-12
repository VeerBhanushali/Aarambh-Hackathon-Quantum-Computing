import type { Metadata } from "next";
import Script from "next/script";

export const metadata: Metadata = {
  title: "Quantum Guard — Post-Quantum Cryptography Assessment & Migration Platform",
  description:
    "Full-Stack Next.js SaaS & Enterprise PQC Assessment, CycloneDX 1.6 CBOM, Mosca HNDL Risk Scoring, and NIST FIPS 203/204/205 Migration Platform (quantumguard-lab.veerbhanushali.in).",
  icons: {
    icon: [{ url: "/favicon.svg", type: "image/svg+xml" }, { url: "/brand/icon-512.png", sizes: "512x512", type: "image/png" }],
    apple: "/brand/apple-touch-icon.png",
  },
  openGraph: { images: ["/brand/icon-512.png"] },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="stylesheet" href="/static/style.css?v=11" />
        <style
          dangerouslySetInnerHTML={{
            __html: `
              .tab-section { display: none !important; }
              .tab-section.active { display: block !important; }
              .sub-pane { display: none !important; }
              .sub-pane.active { display: block !important; }
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
        <Script src="/static/app.js?v=11" strategy="afterInteractive" />
      </body>
    </html>
  );
}
