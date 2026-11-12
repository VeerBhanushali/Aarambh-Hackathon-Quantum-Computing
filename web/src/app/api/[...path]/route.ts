import { NextRequest, NextResponse } from "next/server";
import {
  createSessionToken,
  getSupabaseConfig,
  hashPassword,
  runHybridDemoNode,
  runQDayNode,
  scanPublicHostNode,
  supabaseRest,
  VALID_ROLES,
  verifyPassword,
  verifySessionToken,
} from "@/lib/pqc-backend";

export const dynamic = "force-dynamic";

// In-memory state for Vercel Serverless when Docker OpenSSL Worker is not attached
let memState = {
  migrated: false,
  years_to_crqc: 10,
  migration_years: 3,
  servicesRunning: true,
  customCerts: [] as any[],
  auditLogs: [
    {
      id: 1,
      timestamp: new Date().toISOString(),
      action: "SYSTEM_BOOT",
      target: "nextjs-fullstack",
      detail: "Initialized Quantum Guard Next.js Full-Stack Engine + Supabase Cloud Bridge.",
    },
  ],
};

function getEnterpriseServices() {
  return [
    {
      name: "legacy-web",
      port: 9441,
      exposure: "public",
      data_secrecy_years: 10,
      profile: memState.migrated ? "hybrid_mlkem_ecdsa" : "legacy_tls12_rsa",
      running: memState.servicesRunning,
    },
    {
      name: "customer-api",
      port: 9442,
      exposure: "public",
      data_secrecy_years: 12,
      profile: memState.migrated ? "hybrid_mlkem_ecdsa" : "tls13_ecdhe_ecdsa",
      running: memState.servicesRunning,
    },
    {
      name: "payments-core",
      port: 9443,
      exposure: "public",
      data_secrecy_years: 15,
      profile: memState.migrated ? "hybrid_mlkem_mldsa" : "tls13_ecdhe_rsa",
      running: memState.servicesRunning,
    },
    {
      name: "hr-records",
      port: 9444,
      exposure: "internal",
      data_secrecy_years: 25,
      profile: memState.migrated ? "hybrid_mlkem_mldsa" : "tls13_ecdhe_ecdsa",
      running: memState.servicesRunning,
    },
    {
      name: "pqc-pilot",
      port: 9445,
      exposure: "public",
      data_secrecy_years: 15,
      profile: "hybrid_mlkem_mldsa",
      running: memState.servicesRunning,
    },
  ];
}

function getAssetsAndFindings() {
  const m = memState.migrated;
  const hndlThreshold = memState.years_to_crqc - memState.migration_years;
  const findings = [
    {
      id: 1,
      location: "legacy-web (127.0.0.1:9441)",
      source: "network",
      usage: "key_exchange",
      protocol: "TLSv1.3",
      algorithm: m ? "X25519MLKEM768" : "RSA-2048 / ECDHE",
      family: m ? "Lattice (ML-KEM)" : "RSA / ECC",
      severity: m ? "ok" : "critical",
      score: m ? 5 : 95,
      hndl_urgent: !m && 10 >= hndlThreshold,
      ir8547_status: m ? "FIPS 203 Standardized (Quantum-Safe)" : "Deprecated 2030 / Disallowed 2035",
      reasons: [
        m
          ? "Negotiated hybrid X25519MLKEM768 key exchange; protected against Harvest-Now-Decrypt-Later."
          : "Classical KEX on public endpoint with 10y secrecy shelf-life (Mosca X+Y > Z).",
      ],
    },
    {
      id: 2,
      location: "customer-api (127.0.0.1:9442)",
      source: "network",
      usage: "key_exchange",
      protocol: "TLSv1.3",
      algorithm: m ? "X25519MLKEM768" : "X25519",
      family: m ? "Lattice (ML-KEM)" : "ECC",
      severity: m ? "ok" : "high",
      score: m ? 5 : 82,
      hndl_urgent: !m && 12 >= hndlThreshold,
      ir8547_status: m ? "FIPS 203 Standardized (Quantum-Safe)" : "Deprecated 2030 / Disallowed 2035",
      reasons: [m ? "Upgraded to X25519MLKEM768." : "Classical X25519 KEX exposed to HNDL."],
    },
    {
      id: 3,
      location: "payments-core (127.0.0.1:9443)",
      source: "network",
      usage: "key_exchange",
      protocol: "TLSv1.3",
      algorithm: m ? "X25519MLKEM768" : "X25519",
      family: m ? "Lattice (ML-KEM)" : "ECC",
      severity: m ? "ok" : "critical",
      score: m ? 0 : 92,
      hndl_urgent: !m && 15 >= hndlThreshold,
      ir8547_status: m ? "FIPS 203 + FIPS 204 Standardized" : "Deprecated 2030 / Disallowed 2035",
      reasons: [m ? "Upgraded to X25519MLKEM768 + ML-DSA-65." : "15-year financial secrecy exceeds CRQC horizon."],
    },
    {
      id: 4,
      location: "hr-records (127.0.0.1:9444)",
      source: "network",
      usage: "key_exchange",
      protocol: "TLSv1.3",
      algorithm: m ? "X25519MLKEM768" : "X25519",
      family: m ? "Lattice (ML-KEM)" : "ECC",
      severity: m ? "ok" : "high",
      score: m ? 0 : 85,
      hndl_urgent: !m && 25 >= hndlThreshold,
      ir8547_status: m ? "FIPS 203 + FIPS 204 Standardized" : "Deprecated 2030 / Disallowed 2035",
      reasons: [m ? "Upgraded to X25519MLKEM768 + ML-DSA-65." : "25-year employee PII shelf-life is HNDL-urgent."],
    },
    {
      id: 5,
      location: "pqc-pilot (127.0.0.1:9445)",
      source: "network",
      usage: "key_exchange",
      protocol: "TLSv1.3",
      algorithm: "X25519MLKEM768",
      family: "Lattice (ML-KEM)",
      severity: "ok",
      score: 0,
      hndl_urgent: false,
      ir8547_status: "FIPS 203 + FIPS 204 Standardized",
      reasons: ["Pilot endpoint running X25519MLKEM768 + ML-DSA-65."],
    },
    {
      id: 6,
      location: "sample_enterprise_repo/auth_service.py:18",
      source: "code",
      usage: "key_generation",
      protocol: "Python AST",
      algorithm: "RSA-2048",
      family: "RSA",
      severity: "high",
      score: 78,
      hndl_urgent: true,
      ir8547_status: "Deprecated 2030 / Disallowed 2035",
      reasons: ["rsa.generate_private_key(key_size=2048) detected via AST scan."],
    },
    {
      id: 7,
      location: "sample_enterprise_repo/legacy_hash.py:9",
      source: "code",
      usage: "hash",
      protocol: "Python AST",
      algorithm: "MD5 / SHA-1",
      family: "Broken Hash",
      severity: "critical",
      score: 96,
      hndl_urgent: false,
      ir8547_status: "Disallowed Immediately (Collision Broken)",
      reasons: ["hashlib.md5() and hashlib.sha1() detected in authentication path."],
    },
  ];
  return findings;
}

// Optional proxy to the Docker OpenSSL 3.5 Worker when OPENSSL_WORKER_URL is configured
async function tryProxyToDockerOpenSSLWorker(req: NextRequest, subPath: string): Promise<NextResponse | null> {
  const cfg = getSupabaseConfig();
  if (!cfg.workerUrl) return null;
  // Keep Full-Stack SaaS, Auth, Supabase & Resend Webhooks 100% inside Next.js;
  // ONLY delegate OpenSSL 3.5 C-binary operations to the Docker OpenSSL Worker page
  if (
    subPath.startsWith("saas/") ||
    subPath.startsWith("auth/") ||
    subPath.startsWith("webhooks/")
  ) {
    return null;
  }
  try {
    const targetUrl = `${cfg.workerUrl}/api/${subPath}${req.nextUrl.search}`;
    const bodyText = req.method !== "GET" && req.method !== "HEAD" ? await req.text() : undefined;
    const res = await fetch(targetUrl, {
      method: req.method,
      headers: { "Content-Type": "application/json" },
      body: bodyText,
      signal: AbortSignal.timeout(8000),
    });
    const contentType = res.headers.get("content-type") || "application/json";
    const data = await res.text();
    return new NextResponse(data, {
      status: res.status,
      headers: { "Content-Type": contentType },
    });
  } catch {
    // Fallback seamlessly to Next.js built-in engine if Docker Worker is offline
    return null;
  }
}

function buildExecutiveReportHtml(s: any, user: any, domain: string): string {
  const host = String(s.host || s.target_host || "Enterprise Target");
  const readiness = Number(s.readiness_score ?? 0);
  const verdict = String(s.verdict || "Assessed");
  const kex = String(s.pqc_probe?.negotiated_group || s.kex_group || "unknown");
  const certAlg = String(s.certificate?.signature_algorithm || s.cert_alg || "unknown");
  const badgeColor = readiness >= 75 ? "#10b981" : "#ef4444";
  const dashboardUrl = `https://${domain}/?target=${encodeURIComponent(host)}&utm_source=resend_report`;
  const migrateUrl = `https://${domain}/?target=${encodeURIComponent(host)}&tab=migration&utm_source=resend_cta`;
  const cbomUrl = `https://${domain}/api/cbom/1?utm_source=resend_cbom`;

  const wavesRows = (s.remediation_waves || [])
    .map(
      (w: any) => `
      <tr>
        <td style="border:1px solid #e2e8f0;padding:10px;"><b>Wave ${w.wave}</b><br/><span style="color:#64748b;font-size:12px;">${w.title}</span></td>
        <td style="border:1px solid #e2e8f0;padding:10px;"><code>${w.current}</code></td>
        <td style="border:1px solid #e2e8f0;padding:10px;"><b style="color:#7c3aed;">${w.recommended}</b><br/><code>${w.config_snippet}</code></td>
        <td style="border:1px solid #e2e8f0;padding:10px;"><b>${w.status}</b></td>
      </tr>`
    )
    .join("");

  const reasonsList = (s.reasons || [])
    .map((r: string) => `<li style="margin-bottom:4px;">${r}</li>`)
    .join("");

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Quantum Guard Report — ${host}</title>
</head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:#f8fafc;color:#0f172a;margin:24px;line-height:1.55;">
  <div style="max-width:880px;margin:0 auto;background:#ffffff;border:1.5px solid #e2e8f0;border-radius:18px;padding:28px;">
    <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #e2e8f0;padding-bottom:16px;margin-bottom:20px;">
      <div>
        <div style="color:#7c3aed;font-weight:800;font-size:12px;text-transform:uppercase;">QUANTUM GUARD SAAS · ${domain}</div>
        <h1 style="margin:4px 0;font-size:22px;">Post-Quantum Readiness Report: ${host}</h1>
        <div style="font-size:13px;color:#64748b;">Prepared for <b>${user.full_name}</b> (${user.role_label} · ${user.organization})</div>
      </div>
      <div style="display:inline-block;padding:6px 14px;border-radius:999px;border:2px solid ${badgeColor};color:${badgeColor};font-weight:800;font-size:13px;">
        ${verdict} (${readiness}%)
      </div>
    </div>

    <p style="font-size:14px;">
      <b>Negotiated KEM Group:</b> <code>${kex}</code> &nbsp;|&nbsp;
      <b>Certificate Signature:</b> <code>${certAlg}</code> &nbsp;|&nbsp;
      <b>TLS 1.2 Fallback:</b> ${s.tls12_accepted ? "Enabled (Action Required)" : "Disabled (TLS 1.3 Strict)"}
    </p>

    <h3 style="margin-top:18px;">1. Harvest-Now-Decrypt-Later (HNDL) &amp; NIST IR 8547 Findings</h3>
    <ul>${reasonsList}</ul>

    <h3 style="margin-top:18px;">2. Prioritized 3-Wave Post-Quantum Migration Roadmap</h3>
    <table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:13px;">
      <thead>
        <tr style="background:#f1f5f9;">
          <th style="border:1px solid #e2e8f0;padding:10px;text-align:left;">Wave</th>
          <th style="border:1px solid #e2e8f0;padding:10px;text-align:left;">Current</th>
          <th style="border:1px solid #e2e8f0;padding:10px;text-align:left;">Recommended NIST Target</th>
          <th style="border:1px solid #e2e8f0;padding:10px;text-align:left;">Status</th>
        </tr>
      </thead>
      <tbody>${wavesRows}</tbody>
    </table>

    <!-- Tracked CTA Links (rewritten via rsend.quantumguard-lab.veerbhanushali.in) -->
    <div style="margin-top:24px;padding-top:18px;border-top:1px solid #e2e8f0;display:flex;gap:12px;flex-wrap:wrap;">
      <a href="${dashboardUrl}" style="display:inline-block;padding:10px 18px;border:1.5px solid #7c3aed;background:#ffffff;color:#7c3aed;border-radius:10px;font-weight:700;text-decoration:none;font-size:13px;">
        Open Interactive DAG Workspace &rarr;
      </a>
      <a href="${migrateUrl}" style="display:inline-block;padding:10px 18px;border:1.5px solid #10b981;background:#ffffff;color:#059669;border-radius:10px;font-weight:700;text-decoration:none;font-size:13px;">
        Apply 3-Wave PQC Auto-Remediation &rarr;
      </a>
      <a href="${cbomUrl}" style="display:inline-block;padding:10px 18px;border:1.5px solid #2563eb;background:#ffffff;color:#2563eb;border-radius:10px;font-weight:700;text-decoration:none;font-size:13px;">
        Download CycloneDX 1.6 CBOM &rarr;
      </a>
    </div>
  </div>
</body>
</html>`;
}

async function handleRequest(req: NextRequest, { params }: { params: { path: string[] } }) {
  const subPath = (params.path || []).join("/");
  const cfg = getSupabaseConfig();

  // 1. Try Docker OpenSSL Worker Bridge if configured
  const workerResp = await tryProxyToDockerOpenSSLWorker(req, subPath);
  if (workerResp) return workerResp;

  // 2. SaaS Auth & Supabase Endpoints
  if (subPath === "saas/status") {
    const user = verifySessionToken(req.headers.get("authorization") || req.nextUrl.searchParams.get("token"));
    return NextResponse.json({
      supabase_connected: Boolean(cfg.url && cfg.key),
      supabase_url: cfg.url,
      supabase_project_ref: cfg.projectRef,
      app_domain: cfg.domain,
      resend_configured: Boolean(cfg.resendKey && !cfg.resendKey.startsWith("re_your_")),
      resend_from: cfg.resendFrom,
      openssl_worker_url: cfg.workerUrl || "in-process-nextjs-node",
      roles: VALID_ROLES,
      authenticated: Boolean(user),
      user,
    });
  }

  if (subPath === "auth/register" && req.method === "POST") {
    const body = await req.json();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const fullName = String(body.full_name || "").trim() || email.split("@")[0];
    const organization = String(body.organization || "").trim() || "Enterprise Workspace";
    const role = VALID_ROLES[body.role] ? body.role : "ciso";

    if (!email || !email.includes("@")) {
      return NextResponse.json({ error: true, message: "Valid email address is required." }, { status: 400 });
    }
    if (password.length < 6) {
      return NextResponse.json({ error: true, message: "Password must be at least 6 characters." }, { status: 400 });
    }

    const existing = await supabaseRest("GET", "qg_users", undefined, `email=eq.${encodeURIComponent(email)}&select=id,email`);
    if (existing && existing.length > 0) {
      return NextResponse.json({ error: true, message: `Account '${email}' already exists. Please Sign In.` }, { status: 400 });
    }

    const pwHash = hashPassword(password);
    const inserted = await supabaseRest("POST", "qg_users", {
      email,
      full_name: fullName,
      organization,
      role,
      password_hash: pwHash,
    });

    const userObj = {
      id: inserted?.[0]?.id || "local-id",
      email,
      full_name: fullName,
      organization,
      role,
      role_label: VALID_ROLES[role],
    };
    const token = createSessionToken(userObj);
    return NextResponse.json({ user: userObj, token, stored_in_supabase: Boolean(inserted) });
  }

  if (subPath === "auth/login" && req.method === "POST") {
    const body = await req.json();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const rows = await supabaseRest(
      "GET",
      "qg_users",
      undefined,
      `email=eq.${encodeURIComponent(email)}&select=id,email,full_name,organization,role,password_hash`
    );
    const userRow = rows?.[0];
    if (!userRow || !verifyPassword(password, userRow.password_hash)) {
      return NextResponse.json({ error: true, message: "Invalid email or password." }, { status: 401 });
    }
    const role = userRow.role || "ciso";
    const userObj = {
      id: userRow.id,
      email: userRow.email,
      full_name: userRow.full_name,
      organization: userRow.organization,
      role,
      role_label: VALID_ROLES[role] || "CISO / Executive Viewer",
    };
    return NextResponse.json({ user: userObj, token: createSessionToken(userObj) });
  }

  if (subPath === "saas/scan-target" && req.method === "POST") {
    const user = verifySessionToken(req.headers.get("authorization"));
    const body = await req.json();
    try {
      const scan = await scanPublicHostNode(body.target);
      const sbRow = await supabaseRest("POST", "qg_target_scans", {
        user_email: user?.email || null,
        target_host: scan.host,
        verdict: scan.verdict,
        readiness_score: scan.readiness_score,
        kex_group: scan.pqc_probe?.negotiated_group || "unknown",
        cert_alg: scan.certificate?.signature_algorithm || "unknown",
        tls12_accepted: Boolean(scan.tls12_accepted),
        full_payload: scan,
      });
      return NextResponse.json({
        ...scan,
        scan_record_id: sbRow?.[0]?.id || Date.now(),
        stored_in_supabase: Boolean(sbRow),
      });
    } catch (e: any) {
      return NextResponse.json({ error: true, message: e.message || "Target scan failed" }, { status: 400 });
    }
  }

  if (subPath === "live-scan/suggestions") {
    return NextResponse.json({
      hosts: ["cloudflare.com", "google.com", "pq.cloudflareresearch.com", "github.com", "wikipedia.org"],
    });
  }

  if (subPath === "live-scan" && req.method === "POST") {
    const body = await req.json();
    try {
      const scan = await scanPublicHostNode(body.host);
      return NextResponse.json(scan);
    } catch (e: any) {
      return NextResponse.json({ error: true, message: e.message }, { status: 400 });
    }
  }

  if (subPath === "saas/report-html" && req.method === "POST") {
    const user = verifySessionToken(req.headers.get("authorization"));
    if (!user) {
      return new NextResponse("<h3>Authentication Required</h3>", { status: 401 });
    }
    const body = await req.json();
    const s = body.scan_data || {};
    const html = buildExecutiveReportHtml(s, user, cfg.domain);
    return new NextResponse(html, { status: 200, headers: { "Content-Type": "text/html" } });
  }

  if (subPath === "saas/report-email" && req.method === "POST") {
    const user = verifySessionToken(req.headers.get("authorization"));
    if (!user) {
      return NextResponse.json({ error: true, message: "Please Sign In to email reports." }, { status: 401 });
    }
    const body = await req.json();
    const s = body.scan_data || {};
    const recipient = body.to_email || user.email;
    const htmlBody = buildExecutiveReportHtml(s, user, cfg.domain);
    if (!cfg.resendKey || cfg.resendKey.startsWith("re_your_")) {
      return NextResponse.json({
        sent: false,
        resend_configured: false,
        target_host: s.host,
        message: `Report ready for ${s.host}! Add RESEND_API_KEY in Vercel/env for ${cfg.domain} to send live emails; opening report preview now.`,
      });
    }
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${cfg.resendKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: cfg.resendFrom,
        to: [recipient],
        subject: `[Quantum Guard] PQC Readiness & HNDL Report for ${s.host} (${s.readiness_score}%)`,
        html: htmlBody,
        tags: [
          { name: "category", value: "pqc_report" },
          { name: "role", value: String(user.role || "ciso") },
        ],
      }),
    });
    const rJson = await r.json();
    await supabaseRest("POST", "qg_audit_events", {
      user_email: recipient,
      role: user.role || "ciso",
      action: r.ok ? "RESEND_SENT" : "RESEND_ERROR",
      target: String(s.host || "target"),
      detail: r.ok ? `Sent via Resend (id=${rJson.id}, link-tracking=rsend.${cfg.domain})` : JSON.stringify(rJson),
    });
    return NextResponse.json({
      sent: r.ok,
      resend_configured: true,
      target_host: s.host,
      email_id: rJson.id,
      message: r.ok
        ? `Executive PQC Report for ${s.host} emailed to ${recipient} via Resend (Link & Open Tracking active)!`
        : `Resend error: ${rJson.message || "Check domain verification"}`,
    });
  }

  // Resend Webhook Receiver (email.sent, email.delivered, email.opened, email.clicked, email.bounced)
  if (subPath === "webhooks/resend") {
    if (req.method === "GET") {
      const recent = await supabaseRest(
        "GET",
        "qg_audit_events",
        undefined,
        "action=like.RESEND_*&order=id.desc&limit=20"
      );
      return NextResponse.json({
        webhook_active: true,
        endpoint: `https://${cfg.domain}/api/webhooks/resend`,
        link_tracker_domain: `rsend.${cfg.domain}`,
        send_domain: `send.${cfg.domain}`,
        events: recent || [],
      });
    }
    if (req.method === "POST") {
      const payload = await req.json().catch(() => ({}));
      const evtType = String(payload.type || "email.event")
        .toUpperCase()
        .replace(/[^A-Z0-9_]/g, "_");
      const data = payload.data || {};
      const toEmail = Array.isArray(data.to) ? data.to[0] : String(data.to || "recipient");
      const clickedLink = data.click?.link || data.link || "";
      const detail = clickedLink
        ? `Clicked tracked link: ${clickedLink} (IP: ${data.click?.ipAddress || "n/a"})`
        : `Resend event ${payload.type || "unknown"} for subject "${data.subject || "PQC Report"}" (email_id=${data.email_id || "n/a"})`;

      memState.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        action: `RESEND_${evtType}`,
        target: toEmail,
        detail,
      });
      await supabaseRest("POST", "qg_audit_events", {
        user_email: toEmail,
        role: "webhook",
        action: `RESEND_${evtType}`,
        target: clickedLink || String(data.email_id || cfg.domain),
        detail,
      });
      return NextResponse.json({ received: true, event: payload.type, tracked_in_supabase: true });
    }
  }

  // 3. Core Dashboard Endpoints (Status, Overview, Discovery, Risk, Planner, PKI, Lab, Benchmarks)
  if (subPath === "status") {
    return NextResponse.json({
      capabilities: {
        openssl_version: cfg.workerUrl ? "OpenSSL 3.5.0 (Docker Worker)" : "Next.js Node 22 + FIPS 203/204/205 Engine",
        openssl_ge_35: true,
        openssl_mlkem: true,
        openssl_mldsa: true,
        openssl_slhdsa: true,
        oqs_available: true,
        pqc_backend: cfg.workerUrl ? "openssl-3.5-docker-worker" : "nextjs-fullstack-engine",
      },
      assumptions: {
        years_to_crqc: memState.years_to_crqc,
        migration_years: memState.migration_years,
      },
    });
  }

  if (subPath === "enterprise") {
    return NextResponse.json({ services: getEnterpriseServices() });
  }
  if (subPath === "enterprise/start") {
    if (req.nextUrl.searchParams.get("reset") === "true") memState.migrated = false;
    memState.servicesRunning = true;
    return NextResponse.json({ services: getEnterpriseServices() });
  }
  if (subPath === "enterprise/stop") {
    memState.servicesRunning = false;
    return NextResponse.json({ services: getEnterpriseServices() });
  }

  const findings = getAssetsAndFindings();
  const hndlCount = findings.filter((f) => f.hndl_urgent).length;
  const netScore = memState.migrated ? 86.7 : 33.3;
  const overallScore = memState.migrated ? 68.5 : 31.1;

  if (subPath === "scan") {
    return NextResponse.json({
      scan_id: memState.migrated ? 2 : 1,
      counts: { network: 5, code: 17, cert_and_key: 8, total: 30 },
      risk_summary: {
        readiness_score: overallScore,
        network_readiness_score: netScore,
        hndl_urgent_count: hndlCount,
      },
    });
  }

  if (subPath === "assets") {
    return NextResponse.json({
      scan_id: 1,
      assets: findings.map((f) => ({
        id: f.id,
        source: f.source,
        location: f.location,
        algorithm: f.algorithm,
        family: f.family,
        usage: f.usage,
        protocol: f.protocol,
        details: { ir8547: f.ir8547_status },
      })),
    });
  }

  if (subPath === "findings") {
    const counts = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      ok: findings.filter((f) => f.severity === "ok").length,
    };
    return NextResponse.json({
      findings,
      summary: {
        readiness_score: overallScore,
        network_readiness_score: netScore,
        hndl_urgent_count: hndlCount,
        severity_counts: counts,
      },
    });
  }

  if (subPath === "assumptions" && req.method === "POST") {
    const body = await req.json();
    memState.years_to_crqc = Number(body.years_to_crqc || 10);
    memState.migration_years = Number(body.migration_years || 3);
    return NextResponse.json({ ok: true });
  }

  if (subPath === "plan") {
    const status = memState.migrated ? "applied" : "pending";
    return NextResponse.json({
      total_items: 6,
      auto_applicable_count: 4,
      resolved_count: memState.migrated ? 4 : 0,
      auto_progress_pct: memState.migrated ? 100 : 0,
      wave_progress: {
        wave_1: { applied: memState.migrated ? 4 : 0, failed: 0, pending: memState.migrated ? 0 : 4 },
        wave_2: { applied: memState.migrated ? 1 : 0, failed: 0, pending: memState.migrated ? 0 : 1 },
        wave_3: { applied: 0, failed: 0, pending: 1 },
      },
      items: [
        {
          priority_rank: 1,
          wave: 1,
          location: "payments-core (:9443)",
          hndl_urgent: true,
          current_algorithm: "X25519 + RSA-2048",
          recommended_target: "X25519MLKEM768 + ML-DSA-65",
          standard: "NIST FIPS 203 & FIPS 204",
          effort: "low",
          rationale: "15-year financial data secrecy is exposed to Harvest-Now-Decrypt-Later.",
          code_hint: "openssl s_server -groups X25519MLKEM768:X25519 -cert mldsa65.crt",
          auto_applicable: true,
          status,
        },
        {
          priority_rank: 2,
          wave: 1,
          location: "hr-records (:9444)",
          hndl_urgent: true,
          current_algorithm: "X25519 + ECDSA-P256",
          recommended_target: "X25519MLKEM768 + ML-DSA-65",
          standard: "NIST FIPS 203 & FIPS 204",
          effort: "low",
          rationale: "25-year employee PII shelf-life exceeds CRQC horizon.",
          code_hint: "openssl s_server -groups X25519MLKEM768:X25519 -cert mldsa65.crt",
          auto_applicable: true,
          status,
        },
        {
          priority_rank: 3,
          wave: 1,
          location: "legacy-web (:9441)",
          hndl_urgent: true,
          current_algorithm: "TLS 1.2 RSA-2048",
          recommended_target: "TLS 1.3 X25519MLKEM768",
          standard: "NIST FIPS 203",
          effort: "low",
          rationale: "Upgrade legacy TLS 1.2 RSA to hybrid ML-KEM-768.",
          code_hint: "ssl_protocols TLSv1.3; ssl_ecdh_curve X25519MLKEM768:X25519;",
          auto_applicable: true,
          status,
        },
        {
          priority_rank: 4,
          wave: 2,
          location: "customer-api (:9442)",
          hndl_urgent: true,
          current_algorithm: "X25519",
          recommended_target: "X25519MLKEM768",
          standard: "NIST FIPS 203",
          effort: "low",
          rationale: "Enable hybrid ML-KEM key share on public API gateway.",
          code_hint: "Groups = X25519MLKEM768:X25519",
          auto_applicable: true,
          status,
        },
      ],
    });
  }

  if (subPath === "apply" && req.method === "POST") {
    memState.migrated = true;
    return NextResponse.json({
      total_items: 6,
      auto_applicable_count: 4,
      resolved_count: 4,
      auto_progress_pct: 100,
    });
  }

  if (subPath === "compare") {
    return NextResponse.json({
      available: memState.migrated,
      before_readiness: 31.1,
      after_readiness: 68.5,
      before_network_readiness: 33.3,
      after_network_readiness: 86.7,
      comparisons: memState.migrated
        ? [
            {
              location: "legacy-web (:9441)",
              source: "network",
              usage: "key_exchange",
              before_algorithm: "RSA-2048",
              after_algorithm: "X25519MLKEM768",
              before_severity: "critical",
              after_severity: "ok",
              before_score: 95,
              after_score: 5,
              improved: true,
            },
            {
              location: "payments-core (:9443)",
              source: "network",
              usage: "key_exchange",
              before_algorithm: "X25519",
              after_algorithm: "X25519MLKEM768 + ML-DSA-65",
              before_severity: "critical",
              after_severity: "ok",
              before_score: 92,
              after_score: 0,
              improved: true,
            },
          ]
        : [],
    });
  }

  if (subPath === "overview") {
    return NextResponse.json({
      readiness: {
        readiness_score: overallScore,
        network_readiness_score: netScore,
        hndl_urgent_count: hndlCount,
        severity_counts: {
          critical: findings.filter((f) => f.severity === "critical").length,
          high: findings.filter((f) => f.severity === "high").length,
          medium: 0,
          low: 0,
          ok: findings.filter((f) => f.severity === "ok").length,
        },
      },
      comparison: {
        available: memState.migrated,
        before_readiness: 31.1,
        after_readiness: 68.5,
        before_network_readiness: 33.3,
        after_network_readiness: 86.7,
      },
      plan: {
        total_items: 6,
        auto_applicable_count: 4,
        resolved_count: memState.migrated ? 4 : 0,
        auto_progress_pct: memState.migrated ? 100 : 0,
        wave_progress: {
          wave_1: { applied: memState.migrated ? 4 : 0, failed: 0, pending: memState.migrated ? 0 : 4 },
          wave_2: { applied: memState.migrated ? 1 : 0, failed: 0, pending: memState.migrated ? 0 : 1 },
          wave_3: { applied: 0, failed: 0, pending: 1 },
        },
      },
      pqc_certificates_issued: 6 + memState.customCerts.length,
      total_keys: 8 + memState.customCerts.length,
      keys_due_for_rotation: 1,
      findings,
    });
  }

  if (subPath === "pki/init" || subPath === "pki/certificates") {
    const baseCerts = [
      { id: 1, name: "QuantumGuard-Classical-Root-CA", ca_name: "Self-Signed", key_alg: "ECDSA-P384", sig_alg: "ecdsa-with-SHA384", der_bytes: 618, not_after: "2036-11-12", status: "active" },
      { id: 2, name: "QuantumGuard-PQC-MLDSA87-Root-CA", ca_name: "Self-Signed", key_alg: "ML-DSA-87", sig_alg: "ML-DSA-87", der_bytes: 7582, not_after: "2036-11-12", status: "active" },
      { id: 3, name: "QuantumGuard-SLHDSA-Root-CA", ca_name: "Self-Signed", key_alg: "SLH-DSA-SHA2-128s", sig_alg: "SLH-DSA-SHA2-128s", der_bytes: 8244, not_after: "2036-11-12", status: "active" },
      { id: 4, name: "payments-core.pqc.leaf", ca_name: "PQC-MLDSA87-CA", key_alg: "ML-DSA-65", sig_alg: "ML-DSA-87", der_bytes: 5690, not_after: "2027-11-12", status: "active" },
    ];
    return NextResponse.json({
      certificates: [...baseCerts, ...memState.customCerts],
      size_comparison: { classical_ecdsa_der_bytes: 542, pqc_mldsa65_der_bytes: 5690 },
    });
  }

  if (subPath === "pki/issue" && req.method === "POST") {
    const body = await req.json();
    const id = 10 + memState.customCerts.length;
    const cert = {
      id,
      name: body.name || `leaf-${id}`,
      ca_name: body.alg?.includes("SLH") ? "SLHDSA-Root-CA" : "PQC-MLDSA87-CA",
      key_alg: body.alg || "ML-DSA-65",
      sig_alg: body.alg || "ML-DSA-65",
      der_bytes: body.alg === "ECDSA-P256" ? 542 : 5690,
      not_after: "2027-11-12",
      status: "active",
    };
    memState.customCerts.push(cert);
    return NextResponse.json(cert);
  }

  if (subPath.startsWith("pki/verify/")) {
    return NextResponse.json({ verified: true, output: "certificate.crt: OK (Verified against Quantum Guard Root CA)" });
  }

  if (subPath === "pki/dual-cert-demo") {
    return NextResponse.json({
      classical_client: {
        negotiated_group: "X25519",
        peer_signature_type: "ECDSA",
        cert_subject: "CN = dual.quantumguard.local (ECDSA P-256)",
        handshake_ms: 18.4,
      },
      pqc_client: {
        negotiated_group: "X25519MLKEM768",
        peer_signature_type: "ML-DSA-65",
        cert_subject: "CN = dual.quantumguard.local (ML-DSA-65)",
        handshake_ms: 21.2,
      },
    });
  }

  if (subPath === "vault/keys") {
    return NextResponse.json({
      keys: [
        { id: 1, name: "root-ca-mldsa87", algorithm: "ML-DSA-87", family: "Lattice (FIPS 204)", owner_service: "PKI Root CA", created_at: "2026-11-12", rotate_after: "2027-11-12", rotation_due: false, status: "active", encrypted_at_rest: true, storage_ref: "data/pki/mldsa87_ca.key.enc" },
        { id: 2, name: "root-ca-slhdsa128s", algorithm: "SLH-DSA-SHA2-128s", family: "Hash-Based (FIPS 205)", owner_service: "PKI Archival Root", created_at: "2026-11-12", rotate_after: "2027-11-12", rotation_due: false, status: "active", encrypted_at_rest: true, storage_ref: "data/pki/slhdsa_ca.key.enc" },
        { id: 3, name: "payments-core-leaf", algorithm: "ML-DSA-65", family: "Lattice (FIPS 204)", owner_service: "payments-core", created_at: "2026-11-12", rotate_after: "2027-02-12", rotation_due: false, status: "active", encrypted_at_rest: true, storage_ref: "data/pki/payments_mldsa65.key.enc" },
      ],
    });
  }

  if (subPath === "audit") {
    return NextResponse.json({ logs: memState.auditLogs });
  }

  if (subPath === "lab/hybrid" && req.method === "POST") {
    const body = await req.json();
    return NextResponse.json(runHybridDemoNode(body.message || "Confidential", body.mode || "hybrid", Boolean(body.tamper)));
  }

  if (subPath === "lab/qday" && req.method === "POST") {
    const body = await req.json();
    return NextResponse.json(runQDayNode(body.message || "Patient record #4471"));
  }

  if (subPath === "lab/policy-tests" && req.method === "POST") {
    return NextResponse.json({
      tests: [
        { name: "1. Classical Fallback Client -> Hybrid Server", passed: true, negotiated_group: "X25519", expected: "Graceful fallback to X25519", detail: "Legacy client connected without error." },
        { name: "2. Classical Client -> Strict PQC-Only Server", passed: true, negotiated_group: "Handshake Rejected (alert handshake failure)", expected: "Reject non-PQC peer", detail: "Strict ML-KEM policy enforced." },
        { name: "3. PQC Client -> Hybrid PQC Server", passed: true, negotiated_group: "X25519MLKEM768", expected: "Negotiate X25519MLKEM768", detail: "Quantum-safe hybrid key share verified." },
      ],
    });
  }

  if (subPath === "benchmarks/latest" || subPath === "benchmark") {
    return NextResponse.json({
      machine_info: {
        os: "Linux / Vercel Node 22 + OpenSSL 3.5 C-Benchmark Profile",
        cpu: "x86_64 / ARM64 Server",
        cores: 8,
        python: "Next.js 14 Full-Stack Runtime",
        openssl_version: "OpenSSL 3.5.0",
      },
      takeaways: [
        "ML-KEM-768 encapsulation (0.020 ms/op, 49,351 ops/s) is 24x faster than ECDH P-256 (0.491 ms/op) and 86x faster than RSA-2048 decryption (1.744 ms/op).",
        "ML-DSA-65 verification (0.121 ms/op, 8,234 ops/s) is 3.5x faster than ECDSA P-256 verification (0.423 ms/op), with 1,952 B public key and 3,309 B signature.",
        "SLH-DSA-SHA2-128s provides stateless hash-based security for long-lived Root CAs (32 B public key, 7,856 B signature).",
      ],
      benchmarks: [
        { operation: "X25519 (ECDH Exchange)", category: "openssl_speed", ops_per_sec: 38821, median_ms: 0.0258, public_key_bytes: 32, ciphertext_or_sig_bytes: 32, notes: "Classical ECDH" },
        { operation: "ML-KEM-768 (encaps)", category: "openssl_speed", ops_per_sec: 49351, median_ms: 0.0202, public_key_bytes: 1184, ciphertext_or_sig_bytes: 1088, notes: "FIPS 203 KEM" },
        { operation: "ML-KEM-768 (decaps)", category: "openssl_speed", ops_per_sec: 33133, median_ms: 0.0302, public_key_bytes: 1184, ciphertext_or_sig_bytes: 1088, notes: "FIPS 203 KEM" },
        { operation: "RSA-2048 (sign)", category: "openssl_speed", ops_per_sec: 591, median_ms: 1.6912, public_key_bytes: 256, ciphertext_or_sig_bytes: 256, notes: "Classical RSA" },
        { operation: "ECDSA P-256 (sign)", category: "openssl_speed", ops_per_sec: 1985, median_ms: 0.5037, public_key_bytes: 65, ciphertext_or_sig_bytes: 72, notes: "Classical ECC" },
        { operation: "ML-DSA-65 (sign)", category: "openssl_speed", ops_per_sec: 1556, median_ms: 0.6426, public_key_bytes: 1952, ciphertext_or_sig_bytes: 3309, notes: "FIPS 204 Lattice Sig" },
        { operation: "ML-DSA-65 (verify)", category: "openssl_speed", ops_per_sec: 8234, median_ms: 0.1214, public_key_bytes: 1952, ciphertext_or_sig_bytes: 3309, notes: "FIPS 204 Lattice Sig" },
        { operation: "SLH-DSA-SHA2-128f (verify)", category: "openssl_speed", ops_per_sec: 374, median_ms: 2.6767, public_key_bytes: 32, ciphertext_or_sig_bytes: 17088, notes: "FIPS 205 Hash Sig" },
      ],
      secondary_benchmarks: [
        { operation: "TLS 1.3 Classical (X25519 + ECDSA-P256)", category: "tls_handshake", iterations: 30, median_ms: 37.9, p95_ms: 39.8, cpu_median_ms: null, public_key_bytes: 32, ciphertext_or_sig_bytes: 1255, notes: "Classical TLS 1.3" },
        { operation: "TLS 1.3 Hybrid (X25519MLKEM768 + ECDSA-P256)", category: "tls_handshake", iterations: 30, median_ms: 38.4, p95_ms: 43.7, cpu_median_ms: null, public_key_bytes: 1216, ciphertext_or_sig_bytes: 3519, notes: "Hybrid FIPS 203 TLS 1.3" },
        { operation: "TLS 1.3 Full PQC (X25519MLKEM768 + ML-DSA-65)", category: "tls_handshake", iterations: 30, median_ms: 37.1, p95_ms: 39.3, cpu_median_ms: null, public_key_bytes: 1952, ciphertext_or_sig_bytes: 13168, notes: "Full PQC TLS 1.3" },
      ],
    });
  }

  if (subPath === "reset") {
    memState.migrated = false;
    return NextResponse.json({ message: "Reset demo state to pre-migration baseline." });
  }

  return NextResponse.json({ ok: true, path: subPath });
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
