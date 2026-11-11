// Quantum Guard Single-Page Dashboard Logic (Vanilla JS + Chart.js)

let chartOverviewWaves = null;
let chartRiskSeverity = null;
let chartBenchLatency = null;
let chartBenchSizes = null;

function showToast(msg, isError = false) {
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.message || `HTTP ${res.status}`);
    }
    return data;
  } catch (err) {
    showToast(`API Error: ${err.message}`, true);
    throw err;
  }
}

// Tab switching
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-section").forEach((s) => s.classList.remove("active"));
    btn.classList.add("active");
    const tabId = "tab-" + btn.getAttribute("data-tab");
    const sec = document.getElementById(tabId);
    if (sec) sec.classList.add("active");
  });
});

function switchTab(tabName) {
  const btn = document.querySelector(`.nav-btn[data-tab="${tabName}"]`);
  if (btn) btn.click();
}

function sevBadge(sev, score = null) {
  const s = (sev || "ok").toLowerCase();
  const label = score !== null ? `${s.toUpperCase()} (${score})` : s.toUpperCase();
  return `<span class="badge sev-${s}">${label}</span>`;
}

// 1. Capabilities Status Check
async function loadStatus() {
  const data = await apiFetch("/api/status");
  const c = data.capabilities;
  const banner = document.getElementById("cap-text");
  const okIcon = c.openssl_ge_35 ? "&#9989;" : "&#9888;&#65039;";
  const deg = document.getElementById("cap-degraded");
  if (deg) {
    const missing = [];
    if (!c.openssl_ge_35) missing.push(`OpenSSL is ${c.openssl_version} (needs 3.5+): hybrid TLS groups, ML-DSA/SLH-DSA CAs, dual-cert serving, policy tests and PQC benchmarks will fail. Set OPENSSL_BIN to an OpenSSL 3.5+ binary or use Docker.`);
    else if (!c.openssl_mlkem || !c.openssl_mldsa) missing.push("This OpenSSL build lacks ML-KEM or ML-DSA; PQC features are degraded.");
    if (!c.oqs_available && !c.openssl_mlkem) missing.push("No ML-KEM backend (liboqs-python or OpenSSL 3.5): Hybrid Lab only works in classical mode.");
    deg.style.display = missing.length ? "block" : "none";
    deg.innerHTML = missing.map((m) => `&#9888;&#65039; ${m}`).join("<br>");
  }
  banner.innerHTML = `${okIcon} <b>Runtime:</b> ${c.openssl_version} | <b>ML-KEM:</b> ${c.openssl_mlkem ? "Enabled" : "No"} | <b>ML-DSA:</b> ${c.openssl_mldsa ? "Enabled" : "No"} | <b>SLH-DSA:</b> ${c.openssl_slhdsa ? "Enabled" : "No"} | <b>Backend:</b> ${c.pqc_backend}`;

  if (data.assumptions) {
    document.getElementById("slider-crqc").value = data.assumptions.years_to_crqc;
    document.getElementById("lbl-crqc").textContent = data.assumptions.years_to_crqc + " years";
    document.getElementById("slider-mig").value = data.assumptions.migration_years;
    document.getElementById("lbl-mig").textContent = data.assumptions.migration_years + " years";
  }
}

// 2. Overview Dashboard & Heatmap
async function loadOverview() {
  const data = await apiFetch("/api/overview");
  const r = data.readiness || {};
  const comp = data.comparison || {};
  const plan = data.plan || {};

  if (comp.available) {
    document.getElementById("kpi-readiness").innerHTML = `${comp.before_readiness}% &rarr; <span style="color:var(--ok)">${comp.after_readiness}%</span>`;
    document.getElementById("kpi-net-readiness").innerHTML = `Network TLS: ${comp.before_network_readiness}% &rarr; <b>${comp.after_network_readiness}%</b>`;
  } else {
    document.getElementById("kpi-readiness").textContent = `${r.readiness_score || 0}%`;
    document.getElementById("kpi-net-readiness").textContent = `Network TLS: ${r.network_readiness_score || 0}%`;
  }

  const counts = r.severity_counts || {};
  document.getElementById("kpi-critical").textContent = counts.critical || 0;
  document.getElementById("kpi-hndl").textContent = r.hndl_urgent_count || 0;
  document.getElementById("kpi-migration").textContent = `${plan.auto_progress_pct || 0}%`;
  document.getElementById("kpi-migration-sub").textContent = `${plan.resolved_count || 0} auto-applied / ${plan.total_items || 0} total items`;
  document.getElementById("kpi-pqc-certs").textContent = data.pqc_certificates_issued || 0;
  document.getElementById("kpi-keys-due").textContent = `${data.total_keys || 0} (${data.keys_due_for_rotation || 0} due)`;

  renderHeatmap(data.findings || []);
  renderOverviewChart(plan.wave_progress || {});
}

function renderHeatmap(findings) {
  const tbody = document.getElementById("heatmap-tbody");
  if (!findings.length) {
    tbody.innerHTML = `<tr><td colspan="5">No scan data yet. Click "Run Guided Demo" or run a Discovery Scan.</td></tr>`;
    return;
  }

  // Group findings by location
  const grouped = {};
  findings.forEach((f) => {
    const loc = f.location;
    if (!grouped[loc]) {
      grouped[loc] = { kex: "-", sig: "-", sym: "-", proto: f.protocol || "-" };
    }
    const badge = `${sevBadge(f.severity, f.score)} <div style="font-size:0.75rem; margin-top:2px;">${f.algorithm}</div>`;
    if (f.usage === "key_exchange") grouped[loc].kex = badge;
    else if (f.usage.includes("auth") || f.usage.includes("sig") || f.usage.includes("cert") || f.usage.includes("jwt") || f.usage.includes("key")) grouped[loc].sig = badge;
    else if (f.usage.includes("symmetric") || f.usage.includes("hash")) grouped[loc].sym = badge;
  });

  tbody.innerHTML = Object.entries(grouped)
    .slice(0, 12)
    .map(
      ([loc, cols]) => `
      <tr>
        <td><b>${loc}</b></td>
        <td>${cols.kex}</td>
        <td>${cols.sig}</td>
        <td>${cols.sym}</td>
        <td><code>${cols.proto}</code></td>
      </tr>`
    )
    .join("");
}

function renderOverviewChart(progress) {
  const ctx = document.getElementById("chart-overview-waves");
  if (!ctx || typeof Chart === "undefined") return;
  if (chartOverviewWaves) chartOverviewWaves.destroy();
  const keys = ["wave_1", "wave_2", "wave_3"];
  const val = (k, f) => (progress[k] ? progress[k][f] : 0);

  chartOverviewWaves = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["Wave 1: HNDL key exchange + broken", "Wave 2: Certificates / PKI", "Wave 3: Code signing / long-lived"],
      datasets: [
        { label: "Applied", data: keys.map((k) => val(k, "applied")), backgroundColor: "#22c55e" },
        { label: "Apply failed", data: keys.map((k) => val(k, "failed")), backgroundColor: "#ef4444" },
        { label: "Pending (manual / not yet applied)", data: keys.map((k) => val(k, "pending")), backgroundColor: "#64748b" },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#f8fafc" } } },
      scales: {
        x: { stacked: true, ticks: { color: "#94a3b8" }, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "#1e293b" } },
      },
    },
  });
}

// 3. Enterprise & Discovery
async function loadEnterprise() {
  const data = await apiFetch("/api/enterprise");
  const tbody = document.getElementById("enterprise-tbody");
  tbody.innerHTML = (data.services || [])
    .map(
      (s) => `
    <tr>
      <td><b>${s.name}</b></td>
      <td><code>127.0.0.1:${s.port}</code></td>
      <td><span class="badge ${s.exposure === "public" ? "sev-high" : "sev-low"}">${s.exposure}</span></td>
      <td>${s.data_secrecy_years} years</td>
      <td><code>${s.profile}</code></td>
      <td>${s.running ? '<span class="badge sev-ok">LISTENING</span>' : '<span class="badge sev-critical">STOPPED</span>'}</td>
    </tr>`
    )
    .join("");
}

async function startEnterprise(reset = false) {
  showToast(reset ? "Resetting & starting 5 enterprise TLS services..." : "Starting enterprise TLS services...");
  await apiFetch(`/api/enterprise/start?reset=${reset}`, { method: "POST" });
  await loadEnterprise();
  showToast("All 5 simulated enterprise TLS services are listening.");
}

async function stopEnterprise() {
  await apiFetch("/api/enterprise/stop", { method: "POST" });
  await loadEnterprise();
  showToast("Stopped enterprise TLS services.");
}

async function triggerScan(kind = "before") {
  showToast(`Running full cryptographic discovery scan (${kind.toUpperCase()})...`);
  const res = await apiFetch(`/api/scan?kind=${kind}`, { method: "POST" });
  document.getElementById("btn-cbom-download").href = `/api/cbom/${res.scan_id}`;
  await refreshAll();
  showToast(`Scan #${res.scan_id} (${kind}) completed: ${res.counts.total} assets discovered.`);
  return res;
}

async function loadAssets() {
  const source = document.getElementById("asset-source-filter").value;
  const data = await apiFetch(`/api/assets?source=${source}`);
  const assets = data.assets || [];
  document.getElementById("assets-count").textContent = assets.length;
  if (data.scan_id) {
    document.getElementById("btn-cbom-download").href = `/api/cbom/${data.scan_id}`;
  }

  const tbody = document.getElementById("assets-tbody");
  tbody.innerHTML = assets
    .map(
      (a) => `
    <tr>
      <td>#${a.id}</td>
      <td><span class="badge sev-low">${a.source}</span></td>
      <td><b>${a.location}</b></td>
      <td><code>${a.algorithm}</code></td>
      <td>${a.family}</td>
      <td>${a.usage}</td>
      <td>${a.protocol || "-"}</td>
      <td style="font-size:0.78rem; color:var(--text-muted);">${escapeHtml(JSON.stringify(a.details).slice(0, 110))}</td>
    </tr>`
    )
    .join("");
}

// 4. Risk & Mosca Assumptions
async function loadFindings() {
  const data = await apiFetch("/api/findings");
  const findings = data.findings || [];
  const tbody = document.getElementById("findings-tbody");

  tbody.innerHTML = findings
    .map(
      (f) => `
    <tr>
      <td><b>${f.location}</b></td>
      <td>${f.source} · <code>${f.usage}</code></td>
      <td><b>${f.algorithm}</b></td>
      <td>${sevBadge(f.severity, f.score)}</td>
      <td>${f.hndl_urgent ? '<span class="badge badge-hndl">HNDL URGENT</span>' : '<span style="color:var(--text-muted)">Not Urgent</span>'}</td>
      <td style="font-size:0.8rem;">${f.ir8547_status}</td>
      <td style="font-size:0.78rem; color:var(--text-muted);">${(f.reasons || []).join(" ")}</td>
    </tr>`
    )
    .join("");

  const counts = (data.summary && data.summary.severity_counts) || {};
  const ctx = document.getElementById("chart-risk-severity");
  if (ctx && typeof Chart !== "undefined") {
    if (chartRiskSeverity) chartRiskSeverity.destroy();
    chartRiskSeverity = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "OK"],
        datasets: [
          {
            data: [counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0, counts.ok || 0],
            backgroundColor: ["#ef4444", "#f97316", "#eab308", "#38bdf8", "#22c55e"],
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "right", labels: { color: "#f8fafc" } } },
      },
    });
  }
}

async function updateAssumptions() {
  const crqc = parseInt(document.getElementById("slider-crqc").value, 10);
  const mig = parseInt(document.getElementById("slider-mig").value, 10);
  await apiFetch("/api/assumptions", {
    method: "POST",
    body: JSON.stringify({ years_to_crqc: crqc, migration_years: mig }),
  });
  await loadFindings();
  await loadOverview();
  showToast(`Updated Mosca shelf-life parameters (CRQC=${crqc}y, Migration=${mig}y).`);
}

// 5. Migration Planner & Compare
async function buildPlan() {
  const plan = await apiFetch("/api/plan", { method: "POST" });
  renderPlan(plan);
  showToast(`Built migration plan with ${plan.total_items} prioritized items.`);
}

async function loadPlan() {
  const plan = await apiFetch("/api/plan");
  renderPlan(plan);
  await loadComparison();
}

function renderPlan(plan) {
  const pct = plan.auto_progress_pct || 0;
  document.getElementById("plan-progress-lbl").textContent = `${pct}% (${plan.resolved_count || 0}/${plan.auto_applicable_count || 0} auto-fixable network items applied)`;
  document.getElementById("plan-progress-bar").style.width = `${pct}%`;

  const tbody = document.getElementById("plan-tbody");
  const items = plan.items || [];
  tbody.innerHTML = items
    .map(
      (it) => `
    <tr>
      <td><b>#${it.priority_rank}</b> · <span class="badge sev-low">Wave ${it.wave}</span></td>
      <td><b>${it.location}</b> ${it.hndl_urgent ? '<span class="badge badge-hndl">HNDL</span>' : ""}</td>
      <td><code>${it.current_algorithm}</code></td>
      <td><b>${it.recommended_target}</b><div style="font-size:0.75rem; color:var(--text-muted);">${it.standard}</div></td>
      <td><span class="badge ${it.effort === "low" ? "sev-ok" : it.effort === "medium" ? "sev-medium" : "sev-high"}">${it.effort}</span></td>
      <td style="font-size:0.8rem;">
        ${it.rationale}
        ${it.code_hint ? `<pre class="code-block">${escapeHtml(it.code_hint)}</pre>` : ""}
      </td>
      <td>
        ${
          it.status === "applied"
            ? '<span class="badge sev-ok">APPLIED</span>'
            : it.status === "failed"
            ? `<span class="badge sev-critical" title="${escapeHtml(it.apply_error || "")}">APPLY FAILED</span>`
            : it.auto_applicable
            ? '<span class="badge sev-medium">AUTO-READY</span>'
            : '<span class="badge sev-low">MANUAL CODE/PKI</span>'
        }
      </td>
    </tr>`
    )
    .join("");
}

async function applyMigrationPlan() {
  showToast("Applying auto-fixable PQC/Hybrid configurations to enterprise services...");
  const res = await apiFetch("/api/apply", { method: "POST" });
  renderPlan(res);
  await loadEnterprise();
  showToast("Applied hybrid ML-KEM & ML-DSA profiles to enterprise services! Now running 'After' scan...");
  await triggerScan("after");
  await loadComparison();
}

async function loadComparison() {
  const comp = await apiFetch("/api/compare");
  const tbody = document.getElementById("compare-tbody");
  if (!comp.available || !comp.comparisons) {
    tbody.innerHTML = `<tr><td colspan="6">${comp.message || "Run Before scan, Apply Plan, and run After scan."}</td></tr>`;
    return;
  }

  tbody.innerHTML = comp.comparisons
    .filter((c) => c.source === "network")
    .map(
      (c) => `
    <tr>
      <td><b>${c.location}</b></td>
      <td><code>${c.usage}</code></td>
      <td><code>${c.before_algorithm}</code></td>
      <td><b style="color:var(--ok)">${c.after_algorithm}</b></td>
      <td>${sevBadge(c.before_severity)} &rarr; ${sevBadge(c.after_severity)}</td>
      <td><b>${c.before_score} &rarr; ${c.after_score}</b> ${c.improved ? '&#9989;' : ''}</td>
    </tr>`
    )
    .join("");
}

// 6. PKI & Dual-Certificate Demo
async function initPKI() {
  showToast("Initializing Classical ECDSA P-384 CA, PQC ML-DSA-87 CA, and SLH-DSA Root CA...");
  await apiFetch("/api/pki/init", { method: "POST" });
  await loadPKI();
  await loadVaultAndAudit();
  showToast("PKI initialized and default leaves issued.");
}

async function loadPKI() {
  const data = await apiFetch("/api/pki/certificates");
  const certs = data.certificates || [];
  const sc = data.size_comparison || {};
  document.getElementById("cert-size-comparison").innerHTML = `
    <b>DER Certificate Size Comparison:</b>
    Classical ECDSA P-256 Leaf: <code>${sc.classical_ecdsa_der_bytes || 0} bytes</code> vs.
    PQC ML-DSA-65 Leaf: <code>${sc.pqc_mldsa65_der_bytes || 0} bytes</code>
  `;

  const tbody = document.getElementById("pki-certs-tbody");
  tbody.innerHTML = certs
    .map(
      (c) => `
    <tr>
      <td>#${c.id}</td>
      <td><b>${c.name}</b></td>
      <td>${c.ca_name}</td>
      <td><code>${c.key_alg}</code></td>
      <td><code>${c.sig_alg}</code></td>
      <td>${c.der_bytes} B</td>
      <td style="font-size:0.78rem;">${c.not_after}</td>
      <td><span class="badge ${c.status === "active" ? "sev-ok" : "sev-low"}">${c.status}</span></td>
      <td><button class="btn btn-outline btn-sm" onclick="verifyCertUI(${c.id})">Verify Chain</button></td>
    </tr>`
    )
    .join("");
}

async function issueCertUI() {
  const name = document.getElementById("pki-issue-name").value || "leaf";
  const alg = document.getElementById("pki-issue-alg").value;
  const res = await apiFetch("/api/pki/issue", {
    method: "POST",
    body: JSON.stringify({ name, alg }),
  });
  await loadPKI();
  await loadVaultAndAudit();
  showToast(`Issued ${res.key_alg} certificate '${res.name}' (${res.der_bytes} B DER).`);
}

async function verifyCertUI(id) {
  const res = await apiFetch(`/api/pki/verify/${id}`, { method: "POST" });
  if (res.verified) {
    showToast(`Chain Verified OK: ${res.output}`);
  } else {
    showToast(`Verification Failed: ${res.output}`, true);
  }
}

async function rotateServiceCert(service) {
  showToast(`Rotating leaf certificate for ${service}...`);
  await apiFetch(`/api/pki/rotate/${service}`, { method: "POST" });
  await loadPKI();
  await loadEnterprise();
  await loadVaultAndAudit();
  showToast(`Rotated certificate and restarted ${service}.`);
}

async function runDualCertDemo() {
  showToast("Running Dual-Certificate TLS 1.3 Server Demo (ECDSA + ML-DSA-65)...");
  const res = await apiFetch("/api/pki/dual-cert-demo", { method: "POST" });
  const cOld = res.classical_client;
  const cNew = res.pqc_client;

  document.getElementById("dc-old-body").innerHTML = `
    <div style="margin-bottom:4px;"><span class="badge sev-medium">CLASSICAL PEER</span></div>
    <div><b>Negotiated Group:</b> <code>${cOld.negotiated_group}</code></div>
    <div><b>Peer Signature Type:</b> <code>${cOld.peer_signature_type}</code></div>
    <div><b>Cert Sig Alg:</b> <code>${cOld.cert_sig_alg}</code></div>
    <div><b>Issuer:</b> ${cOld.issuer}</div>
  `;

  document.getElementById("dc-new-body").innerHTML = `
    <div style="margin-bottom:4px;"><span class="badge sev-ok">PQC ML-DSA PEER</span></div>
    <div><b>Negotiated Group:</b> <code>${cNew.negotiated_group}</code></div>
    <div><b>Peer Signature Type:</b> <b style="color:var(--ok)">${cNew.peer_signature_type}</b></div>
    <div><b>Cert Sig Alg:</b> <code>${cNew.cert_sig_alg}</code></div>
    <div><b>Issuer:</b> ${cNew.issuer}</div>
  `;
  showToast("Dual-Certificate Demo complete: Old client got ECDSA, New client got ML-DSA-65!");
}

// 7. Hybrid Lab & Policy Tests
async function runHybridLab() {
  const message = document.getElementById("hybrid-msg").value;
  const mode = document.getElementById("hybrid-mode").value;
  const tamperEl = document.getElementById("hybrid-tamper");
  const tamper = !!(tamperEl && tamperEl.checked);
  // Called directly (not apiFetch): a tampered run legitimately returns success=false with an error reason.
  const raw = await fetch("/api/lab/hybrid", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, mode, tamper }),
  });
  const res = await raw.json();
  if (!raw.ok || res.error === true) {
    showToast(`Hybrid Lab: ${res.message || "HTTP " + raw.status}`, true);
    return;
  }

  const sb = document.getElementById("hybrid-summary-box");
  sb.innerHTML = `
    <div class="kpi-card" style="border-color: ${res.success ? "var(--ok)" : "var(--critical)"};">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span class="badge ${res.success ? "sev-ok" : "sev-critical"}">
          ${res.success ? "&#10004; DECRYPTED &amp; AUTHENTICATED" : "&#10008; REJECTED: " + escapeHtml(res.error || "FAILED")}
        </span>
        <span style="font-size:0.8rem; color:var(--text-muted);">Backend: <b>${res.backend}</b> | Total: <b>${res.timings_ms.total_ms} ms</b></span>
      </div>
      <div style="margin-top:8px; font-size:0.86rem;">
        <b>Decrypted Message:</b> <code>${escapeHtml(res.decrypted_message || "")}</code>
      </div>
      <div style="margin-top:6px; font-size:0.78rem; color:var(--text-muted);">
        Sizes: X25519 Pub = <b>${res.sizes_bytes.x25519_pub} B</b> |
        ML-KEM-768 CT = <b>${res.sizes_bytes.mlkem768_ciphertext} B</b> |
        Total KEX Overhead = <b>${res.sizes_bytes.total_kex_overhead} B</b> |
        SHA-256 Key FP8 = <code>${res.fingerprints_sha256_8.combined_aes256_key}</code>
      </div>
    </div>
  `;

  document.getElementById("hybrid-steps-list").innerHTML = (res.steps || [])
    .map(
      (s) => `
    <div class="step-item">
      <div class="step-header">
        <span>Step ${s.step} (${s.party}): ${s.title}</span>
        <span>${s.bytes} B · ${s.time_ms} ms</span>
      </div>
      <div class="step-detail">${escapeHtml(s.detail)}</div>
    </div>`
    )
    .join("");

  const h = res.hndl_explanation;
  document.getElementById("hndl-explanation-box").innerHTML = `
    <p style="margin-bottom:8px;"><b>Captured Wire Transcript Size:</b> <code>${h.captured_transcript_bytes} bytes</code></p>
    <p style="margin-bottom:8px; color:#fca5a5;"><b>Classical-Only Risk:</b> ${h.classical_only_risk}</p>
    <p style="color:#86efac;"><b>Hybrid Combiner Protection:</b> ${h.hybrid_protection}</p>
  `;
}

async function runPolicyTestsUI() {
  showToast("Running 3 live TLS 1.3 policy tests via openssl s_client...");
  const res = await apiFetch("/api/lab/policy-tests", { method: "POST" });
  const container = document.getElementById("policy-tests-container");
  container.innerHTML = (res.tests || [])
    .map(
      (t) => `
    <div class="step-item" style="border-left-color: ${t.passed ? "var(--ok)" : "var(--critical)"};">
      <div class="step-header">
        <span>${t.title}</span>
        <span class="badge ${t.passed ? "sev-ok" : "sev-critical"}">${t.passed ? "PASS" : "FAIL"}</span>
      </div>
      <div style="font-size:0.82rem; color:var(--text-muted); margin-top:4px;">${t.description}</div>
      <div style="font-size:0.8rem; margin-top:4px;"><b>Negotiated Group:</b> <code>${t.negotiated_group}</code></div>
      <pre class="code-block">${escapeHtml((t.raw_lines || []).join("\n"))}</pre>
    </div>`
    )
    .join("");
  showToast("All 3 TLS policy verification tests completed!");
}

// 8. Benchmarks
async function loadBenchmarks() {
  const data = await apiFetch("/api/benchmarks/latest");
  renderBenchmarks(data);
}

async function triggerBenchmarks() {
  const n = parseInt(document.getElementById("bench-n").value || "30", 10);
  const btn = document.getElementById("btn-run-bench");
  btn.disabled = true;
  btn.textContent = "Running Benchmarks...";
  showToast(`Running empirical Classical & PQC benchmarks (N=${n})...`);
  try {
    const data = await apiFetch("/api/benchmark", {
      method: "POST",
      body: JSON.stringify({ n }),
    });
    renderBenchmarks(data);
    showToast("Benchmarks completed and saved!");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "&#9201; Run Live Benchmarks";
  }
}

function fmtMs(v) {
  return v === null || v === undefined ? '<span title="not measurable with this method">n/a</span>' : `${v} ms`;
}

function renderBenchmarks(data) {
  const allRows = data.benchmarks || [];
  const primaryRows = data.primary_openssl_speed || allRows;
  const secondaryRows = data.secondary_benchmarks || [];

  if (data.run_id) {
    document.getElementById("btn-bench-csv").href = `/api/benchmarks/${data.run_id}/csv`;
  }

  const mi = data.machine_info || {};
  const ts = data.created_at || mi.measured_at || "N/A";
  document.getElementById("bench-machine-info").innerHTML = mi.os
    ? `<b>Measured At (UTC):</b> <code>${ts}</code> | <b>Run ID:</b> <code>${data.run_id}</code> | <b>Host Specs:</b> ${mi.os} · ${mi.cpu_model || mi.cpu} (${mi.cores} cores) | <b>Python:</b> ${mi.python} | <b>Engine:</b> ${mi.openssl_version}`
    : "No benchmark run stored yet. Click 'Run Live Benchmarks' to measure on this machine.";

  document.getElementById("bench-takeaways").innerHTML = (data.takeaways || [])
    .map((t) => `<li style="margin-bottom:4px;">${t}</li>`)
    .join("");

  document.getElementById("bench-tbody").innerHTML = primaryRows
    .map(
      (r) => `
    <tr>
      <td><b>${r.name}</b></td>
      <td><span class="badge sev-ok">${r.category}</span></td>
      <td><b>${Number(r.n).toLocaleString()} /s</b></td>
      <td><b>${r.median_ms} ms</b></td>
      <td>${fmtMs(r.p95_ms)}</td>
      <td>${fmtMs(r.cpu_ms)}</td>
      <td>${r.pubkey_bytes} B</td>
      <td>${r.ct_or_sig_bytes} B</td>
      <td style="font-size:0.78rem; color:var(--text-muted);">${r.note || ""}</td>
    </tr>`
    )
    .join("");

  const secTbody = document.getElementById("bench-secondary-tbody");
  if (secTbody) {
    secTbody.innerHTML = secondaryRows
      .map(
        (r) => `
      <tr>
        <td><b>${r.name}</b></td>
        <td><span class="badge sev-low">${r.category}</span></td>
        <td>${r.n}</td>
        <td><b>${r.median_ms} ms</b></td>
        <td>${fmtMs(r.p95_ms)}</td>
        <td>${fmtMs(r.cpu_ms)}</td>
        <td>${r.pubkey_bytes} B</td>
        <td>${r.ct_or_sig_bytes} B</td>
        <td style="font-size:0.78rem; color:var(--text-muted);">${r.note || ""}</td>
      </tr>`
      )
      .join("");
  }

  if (!primaryRows.length || typeof Chart === "undefined") return;

  // Exclude outlier SLH-DSA-128s sign (1,650ms) from linear scale distortion by using a logarithmic y-axis
  const chartRows = primaryRows.filter((r) => !r.name.includes("(keygen)") || r.name.includes("ML-"));

  const ctxLat = document.getElementById("chart-bench-latency");
  if (chartBenchLatency) chartBenchLatency.destroy();
  chartBenchLatency = new Chart(ctxLat, {
    type: "bar",
    data: {
      labels: chartRows.map((r) => r.name),
      datasets: [
        {
          label: "In-Process openssl speed Latency (ms/op)",
          data: chartRows.map((r) => Math.max(0.01, r.median_ms)),
          backgroundColor: chartRows.map((r) =>
            r.name.includes("ML-") || r.name.includes("SLH-") ? "#3b82f6" : "#8b5cf6"
          ),
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { type: "logarithmic", ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
        x: { ticks: { color: "#94a3b8", maxRotation: 65, minRotation: 40, font: { size: 10 } } },
      },
      plugins: { legend: { labels: { color: "#f8fafc" } } },
    },
  });

  // Deduplicate algorithms for size chart
  const uniqueSizes = [];
  const seen = new Set();
  primaryRows.forEach((r) => {
    const baseName = r.name.split(" (")[0];
    if (!seen.has(baseName)) {
      seen.add(baseName);
      uniqueSizes.push({ name: baseName, pub: Math.max(1, r.pubkey_bytes), ct: Math.max(1, r.ct_or_sig_bytes) });
    }
  });

  const ctxSz = document.getElementById("chart-bench-sizes");
  if (chartBenchSizes) chartBenchSizes.destroy();
  chartBenchSizes = new Chart(ctxSz, {
    type: "bar",
    data: {
      labels: uniqueSizes.map((u) => u.name),
      datasets: [
        {
          label: "Public Key (Bytes)",
          data: uniqueSizes.map((u) => u.pub),
          backgroundColor: "#22c55e",
        },
        {
          label: "Ciphertext / Signature (Bytes)",
          data: uniqueSizes.map((u) => u.ct),
          backgroundColor: "#f97316",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { type: "logarithmic", ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
        x: { ticks: { color: "#94a3b8", maxRotation: 55, minRotation: 30, font: { size: 10 } } },
      },
      plugins: { legend: { labels: { color: "#f8fafc" } } },
    },
  });
}

// 9. Key Vault & Audit Log
async function loadVaultAndAudit() {
  const vData = await apiFetch("/api/vault/keys");
  const aData = await apiFetch("/api/audit");

  if (vData.production_notice) {
    document.getElementById("vault-notice").textContent = vData.production_notice;
  }

  document.getElementById("vault-keys-tbody").innerHTML = (vData.keys || [])
    .map(
      (k) => `
    <tr>
      <td>#${k.id}</td>
      <td><b>${k.name}</b></td>
      <td><code>${k.alg}</code></td>
      <td>${k.purpose}</td>
      <td style="font-size:0.78rem;">${k.created_at}</td>
      <td style="font-size:0.78rem;">${k.rotate_by}</td>
      <td><span class="badge sev-ok">AES-256-GCM (.enc)</span></td>
      <td><span class="badge ${k.status === "active" ? "sev-ok" : k.status === "due" ? "sev-critical" : "sev-low"}">${k.status}</span></td>
      <td><button class="btn btn-outline btn-sm" onclick="rotateVaultKey(${k.id})">Rotate Key</button></td>
    </tr>`
    )
    .join("");

  document.getElementById("audit-tbody").innerHTML = (aData.audit_log || [])
    .map(
      (a) => `
    <tr>
      <td>#${a.id}</td>
      <td style="font-size:0.78rem;">${a.ts}</td>
      <td><span class="badge sev-low">${a.actor}</span></td>
      <td><b>${a.action}</b></td>
      <td><code>${a.target}</code></td>
      <td style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(a.detail)}</td>
    </tr>`
    )
    .join("");
}

async function rotateVaultKey(keyId) {
  showToast(`Rotating key #${keyId} via PKI CA...`);
  await apiFetch(`/api/vault/rotate/${keyId}`, { method: "POST" });
  await loadVaultAndAudit();
  await loadPKI();
  showToast(`Key #${keyId} rotated and encrypted at rest.`);
}

async function resetDemoUI() {
  showToast("Resetting Demo Database & Stopping Enterprise Services...");
  const res = await apiFetch("/api/reset?keep_benchmarks=true", { method: "POST" });
  document.getElementById("demo-banner").style.display = "none";
  await refreshAll();
  switchTab("overview");
  showToast(res.message);
}

// 10. One-Click Guided Demo Orchestrator (Prompt 6)
async function runGuidedDemo() {
  const banner = document.getElementById("demo-banner");
  const txt = document.getElementById("demo-step-text");
  const pct = document.getElementById("demo-step-pct");
  const btn = document.getElementById("btn-guided-demo");

  banner.style.display = "flex";
  btn.disabled = true;

  const setStep = (msg, p) => {
    txt.innerHTML = `<b>Guided Demo:</b> ${msg}`;
    pct.textContent = `${p}%`;
  };

  try {
    setStep("1/8 Starting 5 simulated enterprise TLS services (reset to initial profiles)...", 12);
    switchTab("discovery");
    await apiFetch("/api/enterprise/start?reset=true", { method: "POST" });
    await loadEnterprise();

    setStep("2/8 Initializing Classical ECDSA P-384 & PQC ML-DSA-87 / SLH-DSA Root CAs...", 25);
    await apiFetch("/api/pki/init", { method: "POST" });
    await loadPKI();

    setStep("3/8 Running 'Before' Cryptographic Discovery Scan (Network, Code, Certs)...", 40);
    await apiFetch("/api/scan?kind=before", { method: "POST" });
    await loadAssets();
    await loadFindings();

    setStep("4/8 Generating 3-Wave Post-Quantum Migration Plan...", 55);
    switchTab("migration");
    await apiFetch("/api/plan", { method: "POST" });
    await loadPlan();

    setStep("5/8 Applying Auto-Fixable PQC Hybrid Profiles & Running 'After' Verification Scan...", 70);
    await apiFetch("/api/apply", { method: "POST" });
    await apiFetch("/api/scan?kind=after", { method: "POST" });
    await loadComparison();
    await loadPlan();

    setStep("6/8 Running Dual-Certificate Demo & TLS 1.3 Policy Tests (Fallback, Strict, Hybrid)...", 82);
    await runDualCertDemo();
    await runPolicyTestsUI();

    setStep("7/8 Running Hybrid X25519 + ML-KEM-768 Encryption Combiner...", 92);
    await runHybridLab();

    setStep("8/8 Checking Empirical Benchmarks & Finalizing Executive Overview...", 98);
    let b = await apiFetch("/api/benchmarks/latest");
    if (!b.benchmarks || !b.benchmarks.length) {
      b = await apiFetch("/api/benchmark", { method: "POST", body: JSON.stringify({ n: 25 }) });
    }
    renderBenchmarks(b);

    await refreshAll();
    switchTab("overview");
    const cmp = await apiFetch("/api/compare");
    setStep(
      `Guided Demo complete. Network TLS readiness ${cmp.before_network_readiness}% &rarr; ${cmp.after_network_readiness}%, overall ${cmp.before_readiness}% &rarr; ${cmp.after_readiness}% (remaining items are code changes, not auto-applicable).`,
      100
    );
    showToast("Guided Demo completed end-to-end!");
  } catch (err) {
    setStep(`Error during Guided Demo: ${err.message}`, 100);
  } finally {
    btn.disabled = false;
  }
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function refreshAll() {
  await Promise.all([
    loadStatus(),
    loadEnterprise(),
    loadAssets(),
    loadFindings(),
    loadPlan(),
    loadPKI(),
    loadBenchmarks(),
    loadVaultAndAudit(),
  ]);
  await loadOverview();
}

window.addEventListener("DOMContentLoaded", async () => {
  await refreshAll();
  await runHybridLab();
});
