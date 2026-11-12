// Quantum Guard — White Glassmorphism & Live Agent Topology Controller

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

// Top-level 5-page Navigation with Smooth Scroll Reset
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-section").forEach((s) => s.classList.remove("active"));
    btn.classList.add("active");
    const tabId = "tab-" + btn.getAttribute("data-tab");
    const sec = document.getElementById(tabId);
    if (sec) sec.classList.add("active");
    const ws = document.querySelector(".workspace");
    if (ws) ws.scrollTo({ top: 0, behavior: "smooth" });
  });
});

function switchTab(tabName) {
  const btn = document.querySelector(`.nav-btn[data-tab="${tabName}"]`);
  if (btn) btn.click();
}

// Sub-tab Switching inside Consolidated Pages
function switchSubTab(sectionPrefix, paneId, btnEl) {
  const section = document.getElementById("tab-" + sectionPrefix);
  if (!section) return;
  section.querySelectorAll(".sub-btn").forEach((b) => b.classList.remove("active"));
  section.querySelectorAll(".sub-pane").forEach((p) => p.classList.remove("active"));
  if (btnEl) btnEl.classList.add("active");
  const pane = document.getElementById(paneId);
  if (pane) pane.classList.add("active");
  const ws = document.querySelector(".workspace");
  if (ws) ws.scrollTo({ top: 0, behavior: "smooth" });
}

function sevBadge(sev, score = null) {
  const s = (sev || "ok").toLowerCase();
  const label = score !== null ? `${s.toUpperCase()} (${score})` : s.toUpperCase();
  return `<span class="badge sev-${s}">${label}</span>`;
}

// ==================== LIVE AGENT 7-NODE DAG & FEEDBACK LOOP ENGINE ====================
const STATE_TO_BADGE = {
  pending: "sev-low",
  active: "sev-low",
  feedback: "sev-medium",
  alert: "sev-critical",
  complete: "sev-ok",
};

const DAG_NODE_INFO = {
  1: {
    name: "01. Scope & Init",
    kind: "AGENT",
    desc: "Initializes the 5 simulated enterprise TLS daemons (ports 9441–9445) and verifies OpenSSL 3.5 PQC providers.",
  },
  2: {
    name: "02. Tool Recon",
    kind: "TOOL",
    desc: "Executes live OpenSSL 3.5 s_client probes across all 5 enterprise endpoints to detect negotiated KEM groups & leaf certificates.",
  },
  3: {
    name: "03. Reflect Gate",
    kind: "DECISION",
    desc: "Self-healing gate: scans 17 AST rules + X.509 store, detects classical handshakes, and loops back to trigger targeted PQC recon.",
  },
  4: {
    name: "04. Observation",
    kind: "AGENT",
    desc: "Aggregates all network, codebase, and certificate discoveries into a standardized CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).",
  },
  5: {
    name: "05. PQC PKI & Intel",
    kind: "PKI CA",
    desc: "Operates Classical ECDSA P-384, PQC ML-DSA-87, and SLH-DSA-128s Root CAs to issue quantum-safe leaf certificates.",
  },
  6: {
    name: "06. Deep Migrate",
    kind: "TOOL",
    desc: "Auto-reconfigures vulnerable enterprise TLS services to hybrid X25519MLKEM768 key exchange and ML-DSA-65 authentication.",
  },
  7: {
    name: "07. Risk Scorer",
    kind: "AGENT",
    desc: "Computes NIST IR 8547 & Mosca (X + Y > Z) HNDL risk scores and verifies before/after quantum readiness.",
  },
};

function selectDagNode(nodeNum) {
  for (let i = 1; i <= 7; i++) {
    const g = document.getElementById(`dag-node-${i}`);
    if (g) g.classList.toggle("selected", i === nodeNum);
  }
  const info = DAG_NODE_INFO[nodeNum];
  if (!info) return;
  const nameEl = document.getElementById("dag-selected-name");
  const descEl = document.getElementById("dag-selected-desc");
  const kindEl = document.getElementById("dag-selected-kind");
  if (nameEl) nameEl.textContent = info.name;
  if (descEl) descEl.textContent = info.desc;
  if (kindEl) kindEl.textContent = `Kind: ${info.kind}`;
}

function setDagNode(nodeNum, state, metaText = null, customDesc = null) {
  const g = document.getElementById(`dag-node-${nodeNum}`);
  if (!g) return;
  g.classList.remove("state-pending", "state-active", "state-feedback", "state-alert", "state-complete");
  g.classList.add(`state-${state}`);
  if (metaText !== null) {
    const m = document.getElementById(`dag-meta-${nodeNum}`);
    if (m) m.textContent = metaText;
  }
  if (customDesc && DAG_NODE_INFO[nodeNum]) {
    DAG_NODE_INFO[nodeNum].desc = customDesc;
    if (g.classList.contains("selected")) {
      selectDagNode(nodeNum);
    }
  }
}

function setDagEdge(edgeId, state) {
  const path = document.getElementById(edgeId);
  if (!path) return;
  path.classList.remove("state-pending", "state-active", "state-feedback", "state-alert", "state-complete");
  path.classList.add(`state-${state}`);
  const markerMap = {
    pending: "url(#arrow-pending)",
    active: "url(#arrow-active)",
    feedback: "url(#arrow-feedback)",
    alert: "url(#arrow-alert)",
    complete: "url(#arrow-complete)",
  };
  path.setAttribute("marker-end", markerMap[state] || "url(#arrow-pending)");
}

function setEndpointCard(name, state, badgeText = null, profText = null) {
  const card = document.getElementById(`ep-card-${name}`);
  if (!card) return;
  card.classList.remove("state-pending", "state-active", "state-complete", "state-alert");
  card.classList.add(`state-${state}`);

  const badge = document.getElementById(`ep-badge-${name}`);
  if (badge && badgeText !== null) {
    badge.textContent = badgeText;
    badge.className = `badge ${STATE_TO_BADGE[state] || "sev-low"}`;
  }
  const prof = document.getElementById(`ep-prof-${name}`);
  if (prof && profText !== null) {
    prof.textContent = profText;
  }
}

function logGraphEvent(tag, text, color = "blue") {
  const feed = document.getElementById("graph-telemetry-feed");
  if (!feed) return;
  const timeStr = new Date().toLocaleTimeString();
  const item = document.createElement("div");
  item.className = `telemetry-item ${color}`;
  item.innerHTML = `<span><b>[${escapeHtml(tag)}]</b> ${text}</span><code>${timeStr}</code>`;
  feed.prepend(item);
}

function setGraphStageBanner(text, dotColor = "purple") {
  const lbl = document.getElementById("graph-stage-label");
  const dot = document.getElementById("graph-pulse-dot");
  if (lbl) lbl.textContent = text;
  if (dot) {
    dot.className = `pulse-dot ${dotColor}`;
  }
}

function syncTopologyFromState(services, findings, plan, comp) {
  if (!services || !services.length) return;
  const hasFindings = findings && findings.length > 0;
  const isMigrated = comp && comp.available && comp.after_network_readiness >= 80;

  // Update 5 endpoint pill cards
  const svcOrder = ["legacy-web", "customer-api", "payments-core", "hr-records", "pqc-pilot"];
  svcOrder.forEach((name) => {
    const s = services.find((x) => x.name === name);
    if (!s || !s.running) {
      setEndpointCard(name, "pending", "STOPPED", s ? s.profile : "offline");
      return;
    }
    const isPqcProfile = s.profile.includes("mlkem") || s.profile.includes("dual");
    if (isPqcProfile) {
      setEndpointCard(name, "complete", "PQC SAFE", s.profile);
    } else if (hasFindings) {
      setEndpointCard(name, "alert", "VULNERABLE", s.profile);
    } else {
      setEndpointCard(name, "pending", "LISTENING", s.profile);
    }
  });

  if (!hasFindings) {
    setDagNode(1, "complete", "3.2s");
    setDagNode(2, "feedback", "4.1s");
    setDagNode(3, "active", "1.8s");
    setDagNode(4, "active", "2.5s");
    setDagNode(5, "pending", "PKI");
    setDagNode(6, "pending", "ML-KEM");
    setDagNode(7, "pending", "--%");
    setDagEdge("dag-edge-1-2", "complete");
    setDagEdge("dag-edge-1-3", "complete");
    setDagEdge("dag-edge-loop", "feedback");
    setDagEdge("dag-edge-2-4", "active");
    setDagEdge("dag-edge-3-4", "active");
    setDagEdge("dag-edge-4-5", "pending");
    setDagEdge("dag-edge-4-6", "pending");
    setDagEdge("dag-edge-5-7", "pending");
    setDagEdge("dag-edge-6-7", "pending");
    return;
  }

  const hndlCount = findings.filter((f) => f.hndl_urgent).length;
  setDagNode(1, "complete", "5 Ports");
  setDagNode(2, "complete", `${findings.length} Hits`);
  setDagNode(3, isMigrated ? "complete" : "feedback", "17 Rules");
  setDagNode(4, "complete", "CBOM OK");

  setDagEdge("dag-edge-1-2", "complete");
  setDagEdge("dag-edge-1-3", "complete");
  setDagEdge("dag-edge-loop", "feedback");
  setDagEdge("dag-edge-2-4", "complete");
  setDagEdge("dag-edge-3-4", "complete");

  if (isMigrated) {
    setDagNode(5, "complete", "ML-DSA");
    setDagNode(6, "complete", "100% Auto");
    setDagNode(
      7,
      "complete",
      `${comp.after_network_readiness}% TLS`,
      `Verified Quantum-Safe! Network TLS Readiness jumped ${comp.before_network_readiness}% -> ${comp.after_network_readiness}%.`
    );
    setDagEdge("dag-edge-4-5", "complete");
    setDagEdge("dag-edge-4-6", "complete");
    setDagEdge("dag-edge-5-7", "complete");
    setDagEdge("dag-edge-6-7", "complete");
  } else {
    setDagNode(5, "active", "3 CAs");
    setDagNode(6, plan && plan.total_items ? "active" : "pending", `${plan ? plan.total_items : 0} Items`);
    setDagNode(
      7,
      "alert",
      `${hndlCount} HNDL`,
      `Detected ${hndlCount} Harvest-Now-Decrypt-Later (X + Y > Z) exposures across classical RSA/ECDHE endpoints.`
    );
    setDagEdge("dag-edge-4-5", "active");
    setDagEdge("dag-edge-4-6", "active");
    setDagEdge("dag-edge-5-7", "alert");
    setDagEdge("dag-edge-6-7", "alert");
  }
}

// 1. Capabilities Status Check
async function loadStatus() {
  const data = await apiFetch("/api/status");
  const c = data.capabilities;
  const banner = document.getElementById("cap-text");
  const deg = document.getElementById("cap-degraded");
  if (deg) {
    const missing = [];
    if (!c.openssl_ge_35)
      missing.push(
        `OpenSSL is ${c.openssl_version} (needs 3.5+): hybrid TLS groups, ML-DSA/SLH-DSA CAs, dual-cert serving, policy tests and PQC benchmarks will fail.`
      );
    else if (!c.openssl_mlkem || !c.openssl_mldsa)
      missing.push("This OpenSSL build lacks ML-KEM or ML-DSA; PQC features are degraded.");
    deg.style.display = missing.length ? "block" : "none";
    deg.innerHTML = missing.join("<br>");
  }
  const shortVer = (c.openssl_version || "OpenSSL 3.5+").split("(")[0].trim();
  banner.title = `Runtime: ${c.openssl_version} | ML-KEM: ${c.openssl_mlkem ? "Enabled" : "No"} | ML-DSA: ${c.openssl_mldsa ? "Enabled" : "No"} | SLH-DSA: ${c.openssl_slhdsa ? "Enabled" : "No"} | Backend: ${c.pqc_backend}`;
  banner.innerHTML = `<span class="runtime-dot"></span><span>${escapeHtml(shortVer)} &middot; FIPS 203/204/205</span>`;

  if (data.assumptions) {
    document.getElementById("slider-crqc").value = data.assumptions.years_to_crqc;
    document.getElementById("lbl-crqc").textContent = data.assumptions.years_to_crqc + " years";
    document.getElementById("slider-mig").value = data.assumptions.migration_years;
    document.getElementById("lbl-mig").textContent = data.assumptions.migration_years + " years";
  }
}

// 2. Overview Dashboard & Heatmap
let _cachedServices = [];

async function loadOverview() {
  const data = await apiFetch("/api/overview");
  const r = data.readiness || {};
  const comp = data.comparison || {};
  const plan = data.plan || {};

  if (comp.available) {
    document.getElementById("kpi-readiness").innerHTML = `${comp.before_readiness}% &rarr; <span style="color:var(--green)">${comp.after_readiness}%</span>`;
    document.getElementById("kpi-net-readiness").innerHTML = `Network TLS: ${comp.before_network_readiness}% &rarr; <b style="color:var(--green)">${comp.after_network_readiness}%</b>`;
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
  syncTopologyFromState(_cachedServices, data.findings || [], plan, comp);
}

function renderHeatmap(findings) {
  const tbody = document.getElementById("heatmap-tbody");
  if (!findings.length) {
    tbody.innerHTML = `<tr><td colspan="5">No scan data yet. Click "Launch Live Agent" or run a Discovery Scan.</td></tr>`;
    return;
  }

  const grouped = {};
  findings.forEach((f) => {
    const loc = f.location;
    if (!grouped[loc]) {
      grouped[loc] = { kex: "-", sig: "-", sym: "-", proto: f.protocol || "-" };
    }
    const badge = `${sevBadge(f.severity, f.score)} <div style="font-size:0.74rem; color:var(--text-secondary); margin-top:2px;">${f.algorithm}</div>`;
    if (f.usage === "key_exchange") grouped[loc].kex = badge;
    else if (
      f.usage.includes("auth") ||
      f.usage.includes("sig") ||
      f.usage.includes("cert") ||
      f.usage.includes("jwt") ||
      f.usage.includes("key")
    )
      grouped[loc].sig = badge;
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
      labels: ["Wave 1: HNDL KEX & Broken", "Wave 2: Certificates / PKI", "Wave 3: Code & SLH-DSA Roots"],
      datasets: [
        { label: "Applied (Quantum-Safe)", data: keys.map((k) => val(k, "applied")), backgroundColor: "#16a34a" },
        { label: "Apply Failed", data: keys.map((k) => val(k, "failed")), backgroundColor: "#dc2626" },
        { label: "Pending (Manual / Code)", data: keys.map((k) => val(k, "pending")), backgroundColor: "#2563eb" },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#334155", font: { weight: "600" } } } },
      scales: {
        x: { stacked: true, ticks: { color: "#475569" }, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { color: "#475569", precision: 0 }, grid: { color: "#e2e8f0" } },
      },
    },
  });
}

// 3. Enterprise & Discovery
async function loadEnterprise() {
  const data = await apiFetch("/api/enterprise");
  _cachedServices = data.services || [];
  const tbody = document.getElementById("enterprise-tbody");
  tbody.innerHTML = _cachedServices
    .map(
      (s) => `
    <tr>
      <td><b>${s.name}</b></td>
      <td><code>127.0.0.1:${s.port}</code></td>
      <td><span class="badge ${s.exposure === "public" ? "sev-medium" : "sev-low"}">${s.exposure}</span></td>
      <td>${s.data_secrecy_years} years</td>
      <td><code>${s.profile}</code></td>
      <td>${
        s.running ? '<span class="badge sev-ok">LISTENING</span>' : '<span class="badge sev-critical">STOPPED</span>'
      }</td>
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
  setGraphStageBanner(`Scanning Enterprise Network, Source Code & Certificates (${kind.toUpperCase()})...`, "purple");
  setDagNode(1, "complete", "5 Ports");
  setDagNode(2, "feedback", "Probing...");
  setDagNode(3, "active", "AST+X509");
  setDagNode(4, "active", "Indexing...");
  setDagEdge("dag-edge-1-2", "complete");
  setDagEdge("dag-edge-1-3", "complete");
  setDagEdge("dag-edge-loop", "feedback");
  setDagEdge("dag-edge-2-4", "active");
  setDagEdge("dag-edge-3-4", "active");
  selectDagNode(2);
  ["legacy-web", "customer-api", "payments-core", "hr-records", "pqc-pilot"].forEach((name) =>
    setEndpointCard(name, "active", "SCANNING")
  );
  logGraphEvent("SCANNER", `Initiated ${kind.toUpperCase()} cryptographic discovery across network, code, and certs.`, "purple");

  showToast(`Running full cryptographic discovery scan (${kind.toUpperCase()})...`);
  const res = await apiFetch(`/api/scan?kind=${kind}`, { method: "POST" });
  document.getElementById("btn-cbom-download").href = `/api/cbom/${res.scan_id}`;
  await refreshAll();

  logGraphEvent(
    "CBOM",
    `Scan #${res.scan_id} complete: ${res.counts.network} network, ${res.counts.code} code, ${res.counts.cert_and_key} cert/key assets.`,
    "green"
  );
  setGraphStageBanner(`Scan #${res.scan_id} (${kind.toUpperCase()}) Completed — ${res.counts.total} Assets Indexed`, "green");
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
      <td style="font-size:0.76rem; color:var(--text-muted);">${escapeHtml(JSON.stringify(a.details).slice(0, 110))}</td>
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
      <td>${
        f.hndl_urgent
          ? '<span class="badge badge-hndl">HNDL URGENT</span>'
          : '<span style="color:var(--text-muted)">Not Urgent</span>'
      }</td>
      <td style="font-size:0.79rem;">${f.ir8547_status}</td>
      <td style="font-size:0.77rem; color:var(--text-secondary);">${(f.reasons || []).join(" ")}</td>
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
        labels: ["Critical (Red)", "High (Red)", "Medium (Purple)", "Low (Blue)", "OK (Green)"],
        datasets: [
          {
            data: [counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0, counts.ok || 0],
            backgroundColor: ["#dc2626", "#ef4444", "#7c3aed", "#2563eb", "#16a34a"],
            borderWidth: 2,
            borderColor: "#ffffff",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "right", labels: { color: "#334155", font: { weight: "600" } } } },
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
  logGraphEvent("MOSCA", `Updated shelf-life assumptions: CRQC=${crqc}y, Migration=${mig}y.`, "purple");
  showToast(`Updated Mosca shelf-life parameters (CRQC=${crqc}y, Migration=${mig}y).`);
}

// 5. Migration Planner & Compare
async function buildPlan() {
  const plan = await apiFetch("/api/plan", { method: "POST" });
  renderPlan(plan);
  logGraphEvent("PLANNER", `Generated 3-wave migration roadmap with ${plan.total_items} items.`, "blue");
  showToast(`Built migration plan with ${plan.total_items} prioritized items.`);
}

async function loadPlan() {
  const plan = await apiFetch("/api/plan");
  renderPlan(plan);
  await loadComparison();
}

function renderPlan(plan) {
  const pct = plan.auto_progress_pct || 0;
  document.getElementById("plan-progress-lbl").textContent = `${pct}% (${plan.resolved_count || 0}/${
    plan.auto_applicable_count || 0
  } auto-fixable network items applied)`;
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
      <td><b>${it.recommended_target}</b><div style="font-size:0.74rem; color:var(--text-muted);">${it.standard}</div></td>
      <td><span class="badge ${
        it.effort === "low" ? "sev-ok" : it.effort === "medium" ? "sev-medium" : "sev-critical"
      }">${it.effort}</span></td>
      <td style="font-size:0.79rem;">
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
  setGraphStageBanner("Applying PQC Hybrid Profiles (X25519MLKEM768 + ML-DSA-65) to Enterprise Services...", "purple");
  setDagNode(5, "active", "ML-DSA");
  setDagNode(6, "active", "Upgrading...");
  setDagEdge("dag-edge-4-5", "active");
  setDagEdge("dag-edge-4-6", "active");
  selectDagNode(6);
  logGraphEvent("MIGRATION", "Reconfiguring live TLS endpoints to X25519MLKEM768 & ML-DSA-65...", "purple");

  showToast("Applying auto-fixable PQC/Hybrid configurations to enterprise services...");
  const res = await apiFetch("/api/apply", { method: "POST" });
  renderPlan(res);
  await loadEnterprise();
  showToast("Applied hybrid ML-KEM & ML-DSA profiles! Running 'After' verification scan...");
  await triggerScan("after");
  await loadComparison();
}

async function loadComparison() {
  const comp = await apiFetch("/api/compare");
  const tbody = document.getElementById("compare-tbody");
  if (!comp.available || !comp.comparisons) {
    tbody.innerHTML = `<tr><td colspan="6">${
      comp.message || "Run Before scan, Apply Plan, and run After scan."
    }</td></tr>`;
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
      <td><b style="color:var(--green)">${c.after_algorithm}</b></td>
      <td>${sevBadge(c.before_severity)} &rarr; ${sevBadge(c.after_severity)}</td>
      <td><b>${c.before_score} &rarr; ${c.after_score}</b> ${c.improved ? "&#9989;" : ""}</td>
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
  logGraphEvent("PKI", "Initialized Classical ECDSA P-384 CA, PQC ML-DSA-87 CA, and SLH-DSA Root CA.", "green");
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
      <td style="font-size:0.76rem;">${c.not_after}</td>
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
    <div style="margin-bottom:4px;"><span class="badge sev-low">CLASSICAL PEER</span></div>
    <div><b>Negotiated Group:</b> <code>${cOld.negotiated_group}</code></div>
    <div><b>Peer Signature Type:</b> <code>${cOld.peer_signature_type}</code></div>
    <div><b>Cert Sig Alg:</b> <code>${cOld.cert_sig_alg}</code></div>
    <div><b>Issuer:</b> ${cOld.issuer}</div>
  `;

  document.getElementById("dc-new-body").innerHTML = `
    <div style="margin-bottom:4px;"><span class="badge sev-ok">PQC ML-DSA PEER</span></div>
    <div><b>Negotiated Group:</b> <code>${cNew.negotiated_group}</code></div>
    <div><b>Peer Signature Type:</b> <b style="color:var(--green)">${cNew.peer_signature_type}</b></div>
    <div><b>Cert Sig Alg:</b> <code>${cNew.cert_sig_alg}</code></div>
    <div><b>Issuer:</b> ${cNew.issuer}</div>
  `;
  logGraphEvent(
    "DUAL-CERT",
    `Legacy client received ${cOld.peer_signature_type}; PQC client received ${cNew.peer_signature_type}.`,
    "green"
  );
  showToast("Dual-Certificate Demo complete: Old client got ECDSA, New client got ML-DSA-65!");
}

// 7. Hybrid Lab & Policy Tests (Plain-English, Human-Readable)
async function runHybridLab() {
  const message = document.getElementById("hybrid-msg").value;
  const mode = document.getElementById("hybrid-mode").value;
  const tamperEl = document.getElementById("hybrid-tamper");
  const tamper = !!(tamperEl && tamperEl.checked);
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

  const isHybrid = mode === "hybrid";
  const sb = document.getElementById("hybrid-summary-box");
  sb.innerHTML = `
    <div class="kpi-card ${res.success ? (isHybrid ? "kpi-green" : "kpi-blue") : "kpi-red"}">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
        <span class="badge ${res.success ? (isHybrid ? "sev-ok" : "sev-medium") : "sev-critical"}">
          ${
            !res.success
              ? "TAMPERING DETECTED — MESSAGE BLOCKED"
              : isHybrid
              ? "QUANTUM-SAFE HYBRID PROTECTION ACTIVE"
              : "LEGACY CLASSICAL ENCRYPTION ONLY (VULNERABLE TO QUANTUM)"
          }
        </span>
        <span style="font-size:0.78rem; color:var(--text-muted);">Completed in <b>${res.timings_ms.total_ms} ms</b></span>
      </div>
      <div style="margin-top:10px; font-size:0.86rem;">
        <b>Verified Message:</b> <span style="color:var(--text-main); font-weight:600;">${escapeHtml(res.decrypted_message || "Blocked due to tampering")}</span>
      </div>
      <div style="margin-top:8px; font-size:0.8rem; color:var(--text-secondary);">
        ${
          !res.success
            ? "AES-256-GCM authentication detected that the message was modified in transit and safely rejected it."
            : isHybrid
            ? "Protected by both Classical (X25519) and NIST Post-Quantum (ML-KEM-768) keys. Even if a future quantum computer breaks X25519, your data remains safe."
            : "Protected only by Classical X25519. An attacker recording this traffic today can decrypt it once a quantum computer arrives."
        }
      </div>
    </div>
  `;

  document.getElementById("hybrid-steps-list").innerHTML = `
    <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:8px; margin-top:8px; font-size:0.78rem;">
      <div style="padding:10px; border:1px solid #e2e8f0; border-radius:10px; background:#fff;">
        <b style="color:var(--purple);">Step 1: Key Exchange</b><br/>
        <span style="color:var(--text-secondary);">${isHybrid ? "Generates X25519 + ML-KEM-768 quantum-safe keys" : "Generates classical X25519 key only"}</span>
      </div>
      <div style="padding:10px; border:1px solid #e2e8f0; border-radius:10px; background:#fff;">
        <b style="color:var(--blue);">Step 2: Key Mixing</b><br/>
        <span style="color:var(--text-secondary);">Combines shared secrets into a 256-bit master key</span>
      </div>
      <div style="padding:10px; border:1px solid #e2e8f0; border-radius:10px; background:#fff;">
        <b style="color:var(--green);">Step 3: Sealed Delivery</b><br/>
        <span style="color:var(--text-secondary);">Encrypts and verifies integrity with AES-256-GCM</span>
      </div>
    </div>
  `;
}

async function runPolicyTestsUI() {
  showToast("Verifying server connection rules...");
  const res = await apiFetch("/api/lab/policy-tests", { method: "POST" });
  const container = document.getElementById("policy-tests-container");
  container.innerHTML = (res.tests || [])
    .map(
      (t) => `
    <div class="step-item" style="border-left-color: ${t.passed ? "var(--green)" : "var(--red)"}; margin-bottom:8px;">
      <div class="step-header">
        <span>${escapeHtml(t.title || t.name)}</span>
        <span class="badge ${t.passed ? "sev-ok" : "sev-critical"}">${t.passed ? "VERIFIED" : "FAILED"}</span>
      </div>
      <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:4px;">${escapeHtml(t.description || t.detail || "")}</div>
      <div style="font-size:0.78rem; margin-top:4px;"><b>Result:</b> <code>${escapeHtml(t.negotiated_group)}</code></div>
    </div>`
    )
    .join("");
  showToast("Connection rules verified!");
}

// 8. Benchmarks (Clean, Human-Readable)
async function loadBenchmarks() {
  const data = await apiFetch("/api/benchmarks/latest");
  renderBenchmarks(data);
}

async function triggerBenchmarks() {
  const n = parseInt(document.getElementById("bench-n").value || "30", 10);
  const btn = document.getElementById("btn-run-bench");
  btn.disabled = true;
  btn.textContent = "Measuring...";
  showToast("Measuring algorithm speed...");
  try {
    const data = await apiFetch("/api/benchmark", {
      method: "POST",
      body: JSON.stringify({ n }),
    });
    renderBenchmarks(data);
    showToast("Speed comparison updated!");
  } finally {
    btn.disabled = false;
    btn.textContent = "Measure Live Speed";
  }
}

function fmtMs(v) {
  return v === null || v === undefined ? "-" : `${v} ms`;
}

function renderBenchmarks(data) {
  const allRows = data.benchmarks || [];
  const primaryRows = data.primary_openssl_speed || allRows;

  if (data.run_id) {
    document.getElementById("btn-bench-csv").href = `/api/benchmarks/${data.run_id}/csv`;
  }

  const mi = data.machine_info || {};
  document.getElementById("bench-machine-info").innerHTML = mi.os
    ? `<b>System:</b> ${escapeHtml(mi.os)} &middot; <b>Engine:</b> ${escapeHtml(mi.openssl_version || "OpenSSL 3.5+")}`
    : "";

  document.getElementById("bench-takeaways").innerHTML = (data.takeaways || [])
    .map((t) => `<li style="margin-bottom:4px;">${escapeHtml(t)}</li>`)
    .join("");

  document.getElementById("bench-tbody").innerHTML = primaryRows
    .map((r) => {
      const name = r.name || r.operation || "";
      const isPqc = name.includes("ML-") || name.includes("SLH-") || name.includes("Hybrid");
      const ops = r.n || r.ops_per_sec || 0;
      const pubB = r.pubkey_bytes ?? r.public_key_bytes ?? 0;
      const ctB = r.ct_or_sig_bytes ?? r.ciphertext_or_sig_bytes ?? 0;
      const summary = isPqc ? "NIST Post-Quantum Standard (Quantum-Safe)" : "Legacy Classical (Deprecated by 2030)";
      return `
    <tr>
      <td><b>${escapeHtml(name)}</b></td>
      <td><span class="badge ${isPqc ? "sev-ok" : "sev-medium"}">${isPqc ? "Post-Quantum" : "Classical"}</span></td>
      <td><b>${Number(ops).toLocaleString()} ops/sec</b></td>
      <td><b>${r.median_ms} ms</b></td>
      <td>${pubB} Bytes</td>
      <td>${ctB} Bytes</td>
      <td style="font-size:0.78rem; color:var(--text-secondary);">${summary}</td>
    </tr>`;
    })
    .join("");

  if (!primaryRows.length || typeof Chart === "undefined") return;

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
            r.name.includes("ML-") || r.name.includes("SLH-") ? "#2563eb" : "#7c3aed"
          ),
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { type: "logarithmic", ticks: { color: "#475569" }, grid: { color: "#e2e8f0" } },
        x: { ticks: { color: "#475569", maxRotation: 65, minRotation: 40, font: { size: 10 } } },
      },
      plugins: { legend: { labels: { color: "#334155", font: { weight: "600" } } } },
    },
  });

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
          backgroundColor: "#16a34a",
          borderRadius: 4,
        },
        {
          label: "Ciphertext / Signature (Bytes)",
          data: uniqueSizes.map((u) => u.ct),
          backgroundColor: "#7c3aed",
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { type: "logarithmic", ticks: { color: "#475569" }, grid: { color: "#e2e8f0" } },
        x: { ticks: { color: "#475569", maxRotation: 55, minRotation: 30, font: { size: 10 } } },
      },
      plugins: { legend: { labels: { color: "#334155", font: { weight: "600" } } } },
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
      <td style="font-size:0.76rem;">${k.created_at}</td>
      <td style="font-size:0.76rem;">${k.rotate_by}</td>
      <td><span class="badge sev-ok">AES-256-GCM (.enc)</span></td>
      <td><span class="badge ${k.status === "active" ? "sev-ok" : k.status === "due" ? "sev-critical" : "sev-low"}">${
        k.status
      }</span></td>
      <td><button class="btn btn-outline btn-sm" onclick="rotateVaultKey(${k.id})">Rotate Key</button></td>
    </tr>`
    )
    .join("");

  document.getElementById("audit-tbody").innerHTML = (aData.audit_log || [])
    .map(
      (a) => `
    <tr>
      <td>#${a.id}</td>
      <td style="font-size:0.76rem;">${a.ts}</td>
      <td><span class="badge sev-low">${a.actor}</span></td>
      <td><b>${a.action}</b></td>
      <td><code>${a.target}</code></td>
      <td style="font-size:0.78rem; color:var(--text-secondary);">${escapeHtml(a.detail)}</td>
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
  setGraphStageBanner("System Reset — DAG Ready. Click 'Launch Live Agent' to start.", "blue");
  setDagNode(1, "complete", "3.2s");
  setDagNode(2, "feedback", "4.1s");
  setDagNode(3, "active", "1.8s");
  setDagNode(4, "active", "2.5s");
  setDagNode(5, "pending", "PKI");
  setDagNode(6, "pending", "ML-KEM");
  setDagNode(7, "pending", "--%");
  setDagEdge("dag-edge-1-2", "complete");
  setDagEdge("dag-edge-1-3", "complete");
  setDagEdge("dag-edge-loop", "feedback");
  setDagEdge("dag-edge-2-4", "active");
  setDagEdge("dag-edge-3-4", "active");
  setDagEdge("dag-edge-4-5", "pending");
  setDagEdge("dag-edge-4-6", "pending");
  setDagEdge("dag-edge-5-7", "pending");
  setDagEdge("dag-edge-6-7", "pending");
  selectDagNode(3);
  ["legacy-web", "customer-api", "payments-core", "hr-records", "pqc-pilot"].forEach((name) =>
    setEndpointCard(name, "pending", "IDLE")
  );
  logGraphEvent("RESET", "Cleared scan database and reset services to initial pre-migration state.", "red");
  await refreshAll();
  showToast(res.message);
}

// 10. Animated Guided Demo Orchestrator on the 7-Node DAG with Feedback Loop
async function runGuidedDemo() {
  const banner = document.getElementById("demo-banner");
  const txt = document.getElementById("demo-step-text");
  const pct = document.getElementById("demo-step-pct");
  const btn = document.getElementById("btn-guided-demo");

  // Switch directly to the Live Agent DAG so the user watches the glowing nodes & feedback loop!
  switchTab("pipeline");

  banner.style.display = "flex";
  btn.disabled = true;

  const setStep = (msg, p, dotColor = "purple") => {
    txt.innerHTML = `<b>Live Agent Pipeline:</b> ${msg}`;
    pct.textContent = `${p}%`;
    setGraphStageBanner(msg, dotColor);
  };

  try {
    // Step 1: Node 01 Scope & Init
    setDagNode(1, "active", "Booting...");
    setDagNode(2, "pending", "5 Ports");
    setDagNode(3, "pending", "17 Rules");
    setDagNode(4, "pending", "CBOM 1.6");
    setDagNode(5, "pending", "PKI");
    setDagNode(6, "pending", "ML-KEM");
    setDagNode(7, "pending", "--%");
    setDagEdge("dag-edge-1-2", "active");
    setDagEdge("dag-edge-1-3", "active");
    selectDagNode(1);
    ["legacy-web", "customer-api", "payments-core", "hr-records", "pqc-pilot"].forEach((name) =>
      setEndpointCard(name, "active", "BOOTING")
    );
    setStep("Step 1/7: Node 01 (Scope & Init) — Starting 5 simulated enterprise TLS services...", 12);
    logGraphEvent("ENTERPRISE", "Spawning 5 openssl s_server processes with initial classical profiles...", "purple");
    await apiFetch("/api/enterprise/start?reset=true", { method: "POST" });
    await loadEnterprise();
    setDagNode(1, "complete", "1.4s");
    setDagEdge("dag-edge-1-2", "complete");
    setDagEdge("dag-edge-1-3", "complete");

    // Step 2: Node 02 (Tool Recon) + Node 03 (Reflect Gate) + Feedback Loop + Node 04 (Observation)
    setStep("Step 2/7: Nodes 02 & 03 (Tool Recon + Reflect Gate Feedback Loop) — Probing TLS & AST...", 30);
    setDagNode(2, "feedback", "Probing...");
    setDagNode(3, "active", "Reflecting...");
    setDagNode(4, "active", "Indexing...");
    setDagEdge("dag-edge-loop", "feedback");
    setDagEdge("dag-edge-2-4", "active");
    setDagEdge("dag-edge-3-4", "active");
    selectDagNode(3);

    const scanBefore = await apiFetch("/api/scan?kind=before", { method: "POST" });
    await loadAssets();
    await loadFindings();
    setDagNode(2, "complete", "2.1s");
    setDagNode(3, "feedback", "17 Rules");
    setDagNode(4, "complete", `${scanBefore.counts.total} Assets`);
    setDagEdge("dag-edge-2-4", "complete");
    setDagEdge("dag-edge-3-4", "complete");
    setDagNode(
      7,
      "alert",
      `${scanBefore.risk_summary.hndl_urgent_count} HNDL`,
      `Before Scan: ${scanBefore.risk_summary.hndl_urgent_count} HNDL-urgent exposures detected (Readiness: ${scanBefore.risk_summary.readiness_score}%).`
    );
    logGraphEvent(
      "RISK-ENGINE",
      `Before Scan: Readiness ${scanBefore.risk_summary.readiness_score}%, ${scanBefore.risk_summary.hndl_urgent_count} HNDL-urgent assets flagged in RED!`,
      "red"
    );

    // Step 3: Node 05 (PQC PKI & Threat Intel)
    setStep("Step 3/7: Node 05 (PQC PKI CA) — Initializing ECDSA P-384, ML-DSA-87 & SLH-DSA Root CAs...", 48);
    setDagNode(5, "active", "Generating...");
    setDagEdge("dag-edge-4-5", "active");
    selectDagNode(5);
    logGraphEvent("PKI-CA", "Generating Classical P-384 Root CA, PQC ML-DSA-87 Root CA & SLH-DSA Root CA...", "purple");
    await apiFetch("/api/pki/init", { method: "POST" });
    await loadPKI();
    setDagNode(5, "complete", "3 CAs OK");
    setDagEdge("dag-edge-4-5", "complete");

    // Step 4: Build 3-Wave Migration Plan & Queue Node 06
    setStep("Step 4/7: Node 06 (Deep Migrate) — Building Prioritized 3-Wave PQC Migration Plan...", 62);
    setDagNode(6, "active", "Planning...");
    setDagEdge("dag-edge-4-6", "active");
    selectDagNode(6);
    const plan = await apiFetch("/api/plan", { method: "POST" });
    await loadPlan();
    logGraphEvent("PLANNER", `Created ${plan.total_items} migration items (${plan.auto_applicable_count} auto-fixable network items).`, "blue");

    // Step 5: Auto-Apply PQC Hybrid Profiles & Rescan ("After")
    setStep("Step 5/7: Node 06 -> Node 02 Feedback Verification — Upgrading to X25519MLKEM768 & ML-DSA-65...", 78);
    setDagNode(6, "feedback", "Applying PQC");
    ["legacy-web", "customer-api", "payments-core", "hr-records", "pqc-pilot"].forEach((name) =>
      setEndpointCard(name, "active", "UPGRADING")
    );
    await apiFetch("/api/apply", { method: "POST" });
    await apiFetch("/api/scan?kind=after", { method: "POST" });
    await loadComparison();
    await loadPlan();
    setDagNode(6, "complete", "100% Auto");
    setDagEdge("dag-edge-4-6", "complete");
    setDagEdge("dag-edge-5-7", "active");
    setDagEdge("dag-edge-6-7", "active");
    logGraphEvent("AUTO-APPLY", "Upgraded all 5 enterprise services to TLS 1.3 X25519MLKEM768 + ML-DSA-65!", "green");

    // Step 6: Node 07 (Risk Scorer & Quantum Verifier)
    setStep("Step 6/7: Node 07 (Risk Scorer & Verifier) — Testing Dual-Cert, 3 TLS Policies & Hybrid KEM...", 90);
    setDagNode(7, "active", "Verifying...");
    selectDagNode(7);
    await runDualCertDemo();
    await runPolicyTestsUI();
    await runHybridLab();
    await runQDay();

    // Step 7: Benchmarks & Final Sync
    setStep("Step 7/7: Loading In-Process openssl speed Benchmarks & Finalizing DAG...", 98);
    let b = await apiFetch("/api/benchmarks/latest");
    if (!b.benchmarks || !b.benchmarks.length) {
      b = await apiFetch("/api/benchmark", { method: "POST", body: JSON.stringify({ n: 25 }) });
    }
    renderBenchmarks(b);

    await refreshAll();
    const cmp = await apiFetch("/api/compare");
    setDagNode(7, "complete", `${cmp.after_network_readiness}% TLS`);
    setDagEdge("dag-edge-5-7", "complete");
    setDagEdge("dag-edge-6-7", "complete");
    const doneMsg = `Pipeline Complete! Network TLS Readiness jumped ${cmp.before_network_readiness}% → ${cmp.after_network_readiness}% (Overall ${cmp.before_readiness}% → ${cmp.after_readiness}%).`;
    setStep(doneMsg, 100, "green");
    logGraphEvent("COMPLETE", doneMsg, "green");
    showToast("Live Agent DAG Pipeline completed! All network services are now Quantum-Safe.");
  } catch (err) {
    setStep(`Pipeline Error: ${err.message}`, 100, "red");
    logGraphEvent("ERROR", err.message, "red");
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

// ---------- Live Internet Scan & Q-Day Replay ----------
const liveHistory = [];

async function loadLiveSuggestions() {
  const box = document.getElementById("live-suggestions");
  if (!box) return;
  try {
    const res = await fetch("/api/live-scan/suggestions").then((r) => r.json());
    box.innerHTML = (res.hosts || [])
      .map(
        (h) =>
          `<button class="btn btn-outline btn-sm" onclick="document.getElementById('live-host').value='${h}';runLiveScan()">${h}</button>`
      )
      .join("");
  } catch (e) {}
}

async function liveScanHost(host) {
  const raw = await fetch("/api/live-scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host }),
  });
  const res = await raw.json();
  if (!raw.ok || res.error === true) throw new Error(res.message || `HTTP ${raw.status}`);
  return res;
}

function renderLiveResult(r) {
  const ready = r.kex_status === "hybrid";
  const unknown = r.score === null || r.score === undefined;
  const color = unknown ? "var(--purple)" : ready ? "var(--green)" : "var(--red)";
  const badge = unknown ? "sev-medium" : ready ? "sev-ok" : "sev-critical";
  const box = document.getElementById("live-result");
  if (!box) return;
  box.innerHTML = `
    <div class="card" style="border-left:5px solid ${color};">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <h3 style="margin:0;">${escapeHtml(r.host)}</h3>
        <span class="badge ${badge}">${escapeHtml(r.verdict)}${unknown ? "" : ` · risk ${r.score}`}</span>
      </div>
      ${r.warning ? `<p style="color:var(--purple); margin-top:8px; font-size:0.8rem;">${escapeHtml(r.warning)}</p>` : ""}
      <ul style="margin-top:8px; padding-left:18px; font-size:0.8rem;">${(r.reasons || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
      <div class="table-wrap" style="margin-top:8px;"><table>
        <thead><tr><th>Probe</th><th>Offered</th><th>Negotiated</th><th>Handshake</th></tr></thead>
        <tbody>
          <tr><td>Post-quantum client</td><td>${r.pqc_probe.offered}</td><td><b>${escapeHtml(r.pqc_probe.negotiated_group)}</b> (${escapeHtml(r.pqc_probe.protocol)})</td><td>${r.pqc_probe.handshake_ms} ms</td></tr>
          <tr><td>Classical client</td><td>${r.classical_probe.offered}</td><td>${escapeHtml(r.classical_probe.negotiated_group)}</td><td>${r.classical_probe.handshake_ms} ms</td></tr>
        </tbody>
      </table></div>
      <p style="font-size:0.74rem; color:var(--text-muted); margin-top:8px;">Certificate: ${escapeHtml(r.certificate.signature_algorithm)} (peer signature ${escapeHtml(r.certificate.peer_signature_type)}) · issuer ${escapeHtml(r.certificate.issuer)} · trust check: ${r.certificate.verified ? "verified" : escapeHtml(r.certificate.verify_message)} · TLS 1.2 accepted: ${r.tls12_accepted ? "yes" : "no"} · ${r.measured_at}</p>
    </div>`;
}

function renderLiveHistory() {
  const tbody = document.getElementById("live-history");
  if (!tbody) return;
  tbody.innerHTML = liveHistory
    .map(
      (r) =>
        `<tr><td><b>${escapeHtml(r.host)}</b></td><td>${escapeHtml(r.verdict)}</td><td><code>${escapeHtml(r.pqc_probe.negotiated_group)}</code></td><td>${escapeHtml(r.certificate.signature_algorithm)}</td><td>${r.tls12_accepted ? "yes" : "no"}</td><td>${r.measured_at}</td></tr>`
    )
    .join("");
}

async function runLiveScan() {
  const host = document.getElementById("live-host").value.trim();
  if (!host) return showToast("Type a website first, e.g. cloudflare.com", true);
  const btn = document.getElementById("btn-live-scan");
  btn.disabled = true;
  btn.textContent = "Scanning...";
  try {
    const r = await liveScanHost(host);
    renderLiveResult(r);
    liveHistory.unshift(r);
    renderLiveHistory();
  } catch (e) {
    showToast(`Live scan: ${e.message}`, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = "Scan Live";
  }
}

async function runLiveScanAll() {
  const res = await fetch("/api/live-scan/suggestions").then((r) => r.json());
  for (const h of res.hosts || []) {
    try {
      const r = await liveScanHost(h);
      liveHistory.unshift(r);
      renderLiveHistory();
    } catch (e) {
      showToast(`${h}: ${e.message}`, true);
    }
  }
  const total = liveHistory.length;
  const ready = liveHistory.filter((r) => r.kex_status === "hybrid").length;
  showToast(`${ready} of ${total} scanned sites negotiate post-quantum key exchange.`);
}

async function runQDay() {
  const msgEl = document.getElementById("qday-msg");
  if (!msgEl) return;
  const message = msgEl.value;
  const raw = await fetch("/api/lab/qday", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  const res = await raw.json();
  if (!raw.ok || res.error === true) return showToast(`Q-Day: ${res.message || raw.status}`, true);
  const card = (title, s) => `
    <div class="kpi-card" style="flex:1; border-color:${s.attacker_decrypted ? "var(--red)" : "var(--green)"};">
      <div class="kpi-label">${title}</div>
      <div style="font-size:0.96rem; font-weight:800; margin:6px 0; color:${s.attacker_decrypted ? "var(--red)" : "var(--green)"};">
        ${s.attacker_decrypted ? "EXPOSED — HACKER READS MESSAGE" : "PROTECTED — MESSAGE STAYS SAFE"}
      </div>
      <div style="font-size:0.8rem; color:var(--text-secondary);">${
        s.attacker_decrypted
          ? `Quantum computer broke X25519 and read: <b>"${escapeHtml(s.attacker_plaintext)}"</b>`
          : `Quantum computer could not break ML-KEM-768. Your confidential message remains 100% unreadable.`
      }</div>
    </div>`;
  const box = document.getElementById("qday-result");
  if (box) {
    box.innerHTML = `
      <div style="display:flex; gap:12px; flex-wrap:wrap;">
        ${card("Legacy Connection (X25519 Only)", res.sessions.classical)}
        ${card("Quantum Guard Hybrid (X25519 + ML-KEM-768)", res.sessions.hybrid)}
      </div>`;
  }
}

// ==================== SAAS AUTH (RBAC), SUPABASE & TARGET SCANNER ====================
let currentUser = null;
let authToken = localStorage.getItem("qg_auth_token") || "";
let latestTargetScan = null;
let pendingPostAuthAction = null;

function authHeaders() {
  const h = { "Content-Type": "application/json" };
  if (authToken) h["Authorization"] = `Bearer ${authToken}`;
  return h;
}

function switchSaaSStage(stage, authTab = "login") {
  if (stage === "workspace" && !currentUser) {
    showToast("Please Sign In or Create a Free Account to access the Full Dashboard.", true);
    stage = "auth";
  }
  const map = {
    marketing: "stage-marketing",
    lite: "stage-lite",
    auth: "stage-auth",
    workspace: "stage-workspace",
  };
  Object.values(map).forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.remove("active-stage");
  });
  const targetEl = document.getElementById(map[stage] || "stage-marketing");
  if (targetEl) targetEl.classList.add("active-stage");

  if (stage === "auth") {
    switchAuthTab(authTab);
  }
  if (stage === "workspace" && latestTargetScan) {
    const wsInput = document.getElementById("saas-target-input");
    if (wsInput) wsInput.value = latestTargetScan.host || "";
    renderSaaSTargetResult(latestTargetScan);
  }
}

function startDomainCheckFromMarketing() {
  const mktInput = document.getElementById("mkt-domain-input");
  const val = (mktInput ? mktInput.value : "").trim();
  switchSaaSStage("lite");
  const liteInput = document.getElementById("lite-domain-input");
  if (liteInput && val) {
    liteInput.value = val;
    runLiteDomainScan();
  } else if (liteInput) {
    liteInput.focus();
  }
}

function quickFillLite(domain) {
  const liteInput = document.getElementById("lite-domain-input");
  if (liteInput) {
    liteInput.value = domain;
    runLiteDomainScan();
  }
}

async function runLiteDomainScan() {
  const liteInput = document.getElementById("lite-domain-input");
  const rawTarget = (liteInput ? liteInput.value : "").trim();
  if (!rawTarget) {
    showToast("Enter a domain name to scan (e.g. cloudflare.com, google.com, veerbhanushali.in).", true);
    if (liteInput) liteInput.focus();
    return;
  }
  const btn = document.getElementById("btn-lite-scan");
  const box = document.getElementById("lite-scan-result-box");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Scanning Domain...";
  }
  if (box) {
    box.style.display = "block";
    box.innerHTML = `<div style="padding:14px; border:1.5px solid var(--purple); border-radius:12px; background:#fff; font-weight:700; color:var(--purple);">Scanning <code>${escapeHtml(rawTarget)}</code> for Post-Quantum TLS 1.3 readiness...</div>`;
  }
  try {
    const raw = await fetch("/api/saas/scan-target", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ target: rawTarget }),
    });
    const res = await raw.json();
    if (!raw.ok || res.error) throw new Error(res.message || "Scan failed");
    latestTargetScan = res;
    const isPqc = res.kex_status === "hybrid";
    const kex = (res.pqc_probe && res.pqc_probe.negotiated_group) || "unknown";
    const certAlg = (res.certificate && res.certificate.signature_algorithm) || "unknown";
    if (box) {
      box.innerHTML = `
        <div style="padding:18px; border:2px solid ${isPqc ? "var(--green)" : "var(--red)"}; border-radius:16px; background:#ffffff; box-shadow:0 10px 26px rgba(15,23,42,0.06);">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
            <div>
              <span class="badge ${isPqc ? "sev-ok" : "sev-critical"}">${escapeHtml(res.verdict)}</span>
              <h3 style="margin:6px 0 2px; font-size:1.15rem;">Target: <code>${escapeHtml(res.host)}</code></h3>
            </div>
            <div style="text-align:right;">
              <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); font-weight:800;">Quantum Readiness Score</div>
              <div style="font-size:1.85rem; font-weight:900; color:${isPqc ? "var(--green)" : "var(--red)"};">${res.readiness_score}%</div>
            </div>
          </div>
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-top:12px; font-size:0.82rem;">
            <div style="padding:10px; border:1px solid #e2e8f0; border-radius:10px;"><b>Key Exchange:</b><br/><code>${escapeHtml(kex)}</code></div>
            <div style="padding:10px; border:1px solid #e2e8f0; border-radius:10px;"><b>Certificate Signature:</b><br/><code>${escapeHtml(certAlg)}</code></div>
            <div style="padding:10px; border:1px solid #e2e8f0; border-radius:10px;"><b>TLS 1.2 Fallback:</b><br/><b>${res.tls12_accepted ? "Accepted (Legacy Risk)" : "Disabled (Strict TLS 1.3)"}</b></div>
          </div>
          <div style="margin-top:12px; padding:10px 12px; background:#f8fafc; border-radius:10px; font-size:0.79rem; color:var(--text-secondary);">
            <b>Full Remediation &amp; Dashboard Locked:</b> Sign in below to unlock the 3-Wave upgrade plan for <b>${escapeHtml(res.host)}</b>, download the Executive PDF Report, email it via Resend, and open the full 5-tab dashboard.
          </div>
        </div>
      `;
    }
    showToast(`Domain check complete for ${res.host} (${res.readiness_score}% Ready).`);
  } catch (err) {
    if (box) {
      box.innerHTML = `<div style="padding:14px; border:1.5px solid var(--red); border-radius:12px; color:var(--red); font-weight:700;">Scan Error: ${escapeHtml(err.message)}</div>`;
    }
    showToast(err.message, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Scan Domain";
    }
  }
}

async function loadSaaSStatus() {
  try {
    const res = await fetch("/api/saas/status", { headers: authHeaders() }).then((r) => r.json());
    const sbBadge = document.getElementById("supabase-badge");
    if (sbBadge) {
      sbBadge.className = `badge ${res.supabase_connected ? "sev-ok" : "sev-medium"}`;
      sbBadge.textContent = res.supabase_connected ? "Supabase Cloud" : "Local DB";
    }
    if (res.authenticated && res.user) {
      currentUser = res.user;
      switchSaaSStage("workspace");
    } else {
      currentUser = null;
      switchSaaSStage("marketing");
    }
    renderAuthTopBar();
  } catch (e) {}
}

function renderAuthTopBar() {
  const area = document.getElementById("auth-bar-area");
  if (!area) return;
  if (currentUser) {
    area.innerHTML = `
      <button class="btn btn-outline btn-sm" onclick="switchSaaSStage('marketing')">Home</button>
      <span class="badge sev-medium" title="${escapeHtml(currentUser.organization)}">${escapeHtml(currentUser.role_label)}</span>
      <span style="font-size:0.76rem; font-weight:700; color:var(--text-main);">${escapeHtml(currentUser.full_name || currentUser.email)}</span>
      <button class="btn btn-outline btn-sm" onclick="logoutSaaS()">Sign Out</button>
    `;
  } else {
    area.innerHTML = `
      <button class="btn btn-purple btn-sm" id="btn-open-auth" onclick="openAuthModal('login')">Sign In</button>
    `;
  }
  if (latestTargetScan) renderSaaSTargetResult(latestTargetScan);
}

function openAuthModal(tab = "login", reasonMsg = null, afterCallback = null) {
  pendingPostAuthAction = afterCallback;
  const reasonEl = document.getElementById("auth-modal-reason");
  if (reasonEl && reasonMsg) {
    reasonEl.textContent = reasonMsg;
  }
  switchSaaSStage("auth", tab);
}

function closeAuthModal() {
  if (currentUser) {
    switchSaaSStage("workspace");
  } else {
    switchSaaSStage("lite");
  }
}

function switchAuthTab(tab) {
  document.getElementById("tab-btn-login").classList.toggle("active", tab === "login");
  document.getElementById("tab-btn-register").classList.toggle("active", tab === "register");
  document.getElementById("auth-form-login").style.display = tab === "login" ? "block" : "none";
  document.getElementById("auth-form-register").style.display = tab === "register" ? "block" : "none";
}

async function submitLogin() {
  const email = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;
  try {
    const raw = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const res = await raw.json();
    if (!raw.ok || res.error) throw new Error(res.message || "Login failed");
    authToken = res.token;
    currentUser = res.user;
    localStorage.setItem("qg_auth_token", authToken);
    renderAuthTopBar();
    switchSaaSStage("workspace");
    showToast(`Welcome back, ${currentUser.full_name}!`);
    if (pendingPostAuthAction) {
      const fn = pendingPostAuthAction;
      pendingPostAuthAction = null;
      fn();
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

async function submitRegister() {
  const full_name = document.getElementById("reg-name").value.trim();
  const organization = document.getElementById("reg-org").value.trim();
  const role = document.getElementById("reg-role").value;
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  try {
    const raw = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, full_name, organization, role }),
    });
    const res = await raw.json();
    if (!raw.ok || res.error) throw new Error(res.message || "Registration failed");
    authToken = res.token;
    currentUser = res.user;
    localStorage.setItem("qg_auth_token", authToken);
    renderAuthTopBar();
    switchSaaSStage("workspace");
    showToast(`Account created as ${currentUser.role_label}!`);
    if (pendingPostAuthAction) {
      const fn = pendingPostAuthAction;
      pendingPostAuthAction = null;
      fn();
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

function logoutSaaS() {
  authToken = "";
  currentUser = null;
  localStorage.removeItem("qg_auth_token");
  renderAuthTopBar();
  switchSaaSStage("marketing");
  showToast("Signed out.");
}

async function runSaaSTargetScan() {
  const inputEl = document.getElementById("saas-target-input");
  const rawTarget = (inputEl ? inputEl.value : "").trim();
  if (!rawTarget) {
    showToast("Enter a target domain first (e.g. cloudflare.com, google.com, or veerbhanushali.in).", true);
    if (inputEl) inputEl.focus();
    return;
  }

  const btn = document.getElementById("btn-saas-scan");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Scanning...";
  }

  try {
    setGraphStageBanner(`Probing '${rawTarget}' via OpenSSL 3.5+ TLS 1.3 Handshakes...`, "purple");
    setDagNode(1, "complete", "Target Set", `Target locked: ${rawTarget}.`);
    setDagNode(2, "feedback", "Probing 443", `Probing ${rawTarget}:443 with X25519MLKEM768 + classical X25519...`);
    setDagNode(3, "active", "Cert Gate", `Inspecting certificate signature & TLS 1.2 fallback on ${rawTarget}...`);
    setDagNode(4, "active", "Indexing...", `Saving scan record for ${rawTarget}...`);
    setDagEdge("dag-edge-1-2", "complete");
    setDagEdge("dag-edge-1-3", "complete");
    setDagEdge("dag-edge-loop", "feedback");
    setDagEdge("dag-edge-2-4", "active");
    setDagEdge("dag-edge-3-4", "active");

    const raw = await fetch("/api/saas/scan-target", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ target: rawTarget }),
    });
    const res = await raw.json();
    if (!raw.ok || res.error) throw new Error(res.message || `Scan failed (${raw.status})`);

    latestTargetScan = res;
    const isPqc = res.kex_status === "hybrid";
    const kexGroup = (res.pqc_probe && res.pqc_probe.negotiated_group) || "unknown";
    const certAlg = (res.certificate && res.certificate.signature_algorithm) || "unknown";

    setDagNode(2, "complete", `${res.pqc_probe.handshake_ms}ms`, `Target ${res.host} negotiated ${kexGroup} in ${res.pqc_probe.handshake_ms}ms.`);
    setDagNode(3, isPqc ? "complete" : "feedback", certAlg, `Certificate uses ${certAlg}; TLS 1.2 accepted: ${res.tls12_accepted ? "Yes" : "No"}.`);
    setDagNode(4, "complete", "Saved", `Saved scan #${res.scan_record_id} for ${res.host} to Supabase.`);
    setDagNode(5, isPqc ? "complete" : "active", "Wave 2 PKI", `Recommended upgrade: ML-DSA-65 Dual-Cert for ${res.host}.`);
    setDagNode(6, isPqc ? "complete" : "alert", kexGroup, isPqc ? `${res.host} supports X25519MLKEM768.` : `Action needed: Enable X25519MLKEM768 on ${res.host}.`);
    setDagNode(7, isPqc ? "complete" : "alert", `${res.readiness_score}% Ready`, `Verdict for ${res.host}: ${res.verdict} (${res.readiness_score}%).`);

    setDagEdge("dag-edge-2-4", "complete");
    setDagEdge("dag-edge-3-4", "complete");
    setDagEdge("dag-edge-4-5", "complete");
    setDagEdge("dag-edge-4-6", isPqc ? "complete" : "alert");
    setDagEdge("dag-edge-5-7", "complete");
    setDagEdge("dag-edge-6-7", isPqc ? "complete" : "alert");

    setGraphStageBanner(`Scan Complete: ${res.host} — ${res.verdict} (${res.readiness_score}%)`, isPqc ? "green" : "red");
    renderSaaSTargetResult(res);
    showToast(`Scan complete for ${res.host} (${res.verdict})!`);
  } catch (err) {
    setGraphStageBanner(`Scan Error: ${err.message}`, "red");
    showToast(`Scan Error: ${err.message}`, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Scan Domain";
    }
  }
}

function renderSaaSTargetResult(scan) {
  const bar = document.getElementById("saas-target-result-bar");
  if (!bar || !scan) return;
  const isPqc = scan.kex_status === "hybrid";
  const kex = (scan.pqc_probe && scan.pqc_probe.negotiated_group) || "unknown";
  const certAlg = (scan.certificate && scan.certificate.signature_algorithm) || "unknown";

  bar.style.display = "block";
  bar.innerHTML = `
    <div style="background:#ffffff; border:1.5px solid ${isPqc ? "var(--green)" : "var(--red)"}; border-radius:14px; padding:12px 16px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; box-shadow:0 8px 24px rgba(15,23,42,0.06);">
      <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
        <span class="badge ${isPqc ? "sev-ok" : "sev-critical"}">${escapeHtml(scan.verdict)}</span>
        <div>
          <div style="font-size:0.9rem; font-weight:800; color:var(--text-main);">
            Target: <code>${escapeHtml(scan.host)}</code> &middot; Quantum Readiness: <span style="color:${isPqc ? "var(--green)" : "var(--red)"};">${scan.readiness_score}%</span>
          </div>
          <div style="font-size:0.75rem; color:var(--text-secondary);">
            Key Exchange: <b>${escapeHtml(kex)}</b> &middot; Certificate: <b>${escapeHtml(certAlg)}</b> &middot; TLS 1.2 Fallback: <b>${scan.tls12_accepted ? "Accepted" : "Disabled"}</b>
          </div>
        </div>
      </div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn btn-blue btn-sm" onclick="openProtectedTargetReport()">
          ${currentUser ? "Open Full PDF Report" : "Sign In for PDF Report"}
        </button>
        <button class="btn btn-purple btn-sm" onclick="emailTargetReportViaResend()">
          ${currentUser ? `Email Report (${escapeHtml(currentUser.email)})` : "Sign In to Email Report"}
        </button>
      </div>
    </div>
  `;
}

async function openProtectedTargetReport() {
  if (!latestTargetScan) {
    return openProtectedEnterpriseReport();
  }
  if (!currentUser || !authToken) {
    return openAuthModal(
      "login",
      `Sign in or create an account to unlock the full Post-Quantum Report for ${latestTargetScan.host}.`,
      () => openProtectedTargetReport()
    );
  }
  try {
    const raw = await fetch("/api/saas/report-html", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ scan_data: latestTargetScan }),
    });
    if (raw.status === 401) {
      logoutSaaS();
      return openAuthModal("login", "Session expired. Please sign in to view your report.");
    }
    const htmlDoc = await raw.text();
    const win = window.open("", "_blank");
    if (win) {
      win.document.open();
      win.document.write(htmlDoc);
      win.document.close();
    }
  } catch (err) {
    showToast(`Report Error: ${err.message}`, true);
  }
}

async function emailTargetReportViaResend() {
  if (!latestTargetScan) {
    showToast("Scan a target domain first so we can email its report!", true);
    return;
  }
  if (!currentUser || !authToken) {
    return openAuthModal(
      "login",
      `Sign in or create an account to email the PQC Report for ${latestTargetScan.host} via Resend.`,
      () => emailTargetReportViaResend()
    );
  }
  try {
    showToast(`Sending PQC Report for ${latestTargetScan.host} to ${currentUser.email}...`);
    const raw = await fetch("/api/saas/report-email", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ to_email: currentUser.email, scan_data: latestTargetScan }),
    });
    const res = await raw.json();
    if (!raw.ok || res.error) throw new Error(res.message || "Email failed");
    showToast(res.message);
    if (!res.resend_configured) {
      await openProtectedTargetReport();
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

function openProtectedEnterpriseReport() {
  if (!currentUser || !authToken) {
    return openAuthModal(
      "login",
      "Sign in or create an account to unlock & download the Executive PDF Compliance Report.",
      () => window.open("/api/report", "_blank")
    );
  }
  window.open("/api/report", "_blank");
}

window.addEventListener("DOMContentLoaded", async () => {
  const tlDate = document.getElementById("tl-today-date");
  if (tlDate) tlDate.textContent = new Date().toLocaleDateString(undefined, { year: "numeric", month: "long" });
  await loadSaaSStatus();
  loadLiveSuggestions();
  await refreshAll();
  // Auto-populate baseline scan if dashboard has 0 findings so Executive Dashboard is never blank
  const rEl = document.getElementById("kpi-readiness");
  if (rEl && rEl.textContent === "0%") {
    try {
      await fetch("/api/enterprise/start", { method: "POST" });
      await fetch("/api/scan?label=before", { method: "POST" });
      await fetch("/api/plan/generate", { method: "POST" });
      await refreshAll();
    } catch (e) {}
  }
  await runHybridLab();
  await runQDay();
});
