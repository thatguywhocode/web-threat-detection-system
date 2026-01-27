// On page load
window.onload = () => {
  renderHistory();
  document.getElementById("downloadBtn").style.display = "none";
};

async function scan() {
  const loading = document.getElementById("loading");
  const scanBtn = document.getElementById("scanBtn");
  const resultDiv = document.getElementById("result");

  const inputField = document.getElementById("inputData");
  const input = inputField.value.trim();

  if (!input) {
    alert("Please enter a URL or HTML content");
    return;
  }

  // Detect input type
  let bodyData = {};
  let targetLabel = "";

  if (input.startsWith("http://") || input.startsWith("https://")) {
    bodyData.url = input;
    targetLabel = input;
  } else if (input.includes("<html") || input.includes("<script")) {
    bodyData.html = input;
    targetLabel = "HTML Input";
  } else {
    alert("Invalid URL or HTML content");
    return;
  }

  // Loading UI
  loading.style.display = "block";
  scanBtn.disabled = true;
  scanBtn.innerText = "Scanning...";
  resultDiv.style.display = "none";

  try {
    const response = await fetch("http://localhost:3000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyData)
    });

    const data = await response.json();

    if (!response.ok || !data.risk || !data.analysis) {
      alert(data.error || "Invalid response from server");
      return;
    }

    // Show result
    resultDiv.style.display = "block";
    document.getElementById("downloadBtn").style.display = "inline-block";

    // Timestamp
    document.getElementById("scanTime").innerText =
      new Date().toLocaleString();

    // Severity
    const severity = data.risk.severity;
    const severityEl = document.getElementById("severity");
    const severityIcon = document.getElementById("severityIcon");

    severityEl.innerText = severity;
    severityEl.className = severity.toLowerCase();

    severityIcon.innerText =
      severity === "LOW" ? "✅" :
      severity === "MEDIUM" ? "⚠️" : "🚨";

    // Risk score
    document.getElementById("riskScore").innerText =
      data.risk.riskScore;

    // Static analysis
    document.getElementById("scripts").innerText =
      data.analysis.totalScripts;
    document.getElementById("iframes").innerText =
      data.analysis.totalIframes;
    document.getElementById("hidden").innerText =
      data.analysis.hiddenElementsDetected ? "Yes" : "No";
    document.getElementById("jsPatterns").innerText =
      data.analysis.suspiciousJSPatterns.join(", ") || "None";
    document.getElementById("keywords").innerText =
      data.analysis.matchedKeywords.join(", ") || "None";

    // Risk explanation
    const explanation = document.getElementById("riskExplanation");
    explanation.innerHTML = "";

    if (data.analysis.totalScripts > 5)
      explanation.innerHTML += "<li>High number of scripts detected</li>";
    if (data.analysis.hiddenElementsDetected)
      explanation.innerHTML += "<li>Hidden HTML elements found</li>";
    if (data.analysis.totalIframes > 0)
      explanation.innerHTML += "<li>Iframe detected</li>";
    if (data.virusTotal?.malicious > 0)
      explanation.innerHTML += "<li>VirusTotal flagged the URL</li>";

    if (explanation.innerHTML === "")
      explanation.innerHTML = "<li>No major risk indicators found</li>";

    // VirusTotal
    document.getElementById("vtMalicious").innerText =
      data.virusTotal?.malicious ?? "N/A";
    document.getElementById("vtSuspicious").innerText =
      data.virusTotal?.suspicious ?? "N/A";

    // Save history
    saveToHistory(targetLabel, severity);
    renderHistory();

  } catch (err) {
    alert("Error connecting to backend");
    console.error(err);
  } finally {
    loading.style.display = "none";
    scanBtn.disabled = false;
    scanBtn.innerText = "Scan Website";
  }
}

// Clear form
function clearForm() {
  document.getElementById("inputData").value = "";
  document.getElementById("result").style.display = "none";
  document.getElementById("downloadBtn").style.display = "none";
  document.getElementById("loading").style.display = "none";
}

// History
function saveToHistory(target, severity) {
  const history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];
  history.unshift({ target, severity, time: new Date().toLocaleString() });
  sessionStorage.setItem("scanHistory", JSON.stringify(history.slice(0, 5)));
}

function toggleSeverityGuide() {
  const content = document.getElementById("severityContent");
  const toggle = document.getElementById("severityToggle");

  if (!content || !toggle) return;

  if (content.style.display === "none") {
    content.style.display = "block";
    toggle.innerText = "➖";
  } else {
    content.style.display = "none";
    toggle.innerText = "➕";
  }
}

function downloadReport() {
  const severity = document.getElementById("severity").innerText;
  const riskScore = document.getElementById("riskScore").innerText;

  if (!severity) {
    alert("No scan result available to download");
    return;
  }

  const reportText = `
Web Threat Detection Report
---------------------------
Scan Time: ${document.getElementById("scanTime").innerText}

Severity: ${severity}
Risk Score: ${riskScore}

Static Analysis Results:
- Scripts: ${document.getElementById("scripts").innerText}
- Iframes: ${document.getElementById("iframes").innerText}
- Hidden Elements: ${document.getElementById("hidden").innerText}
- Keywords Found: ${document.getElementById("keywords").innerText}

VirusTotal Results:
- Malicious: ${document.getElementById("vtMalicious").innerText}
- Suspicious: ${document.getElementById("vtSuspicious").innerText}

Note:
This analysis is based on static HTML inspection and reputation checks only.
No scripts were executed during the scan.

Generated on: ${new Date().toLocaleString()}
`;

  const blob = new Blob([reportText], { type: "text/plain" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "web_threat_scan_report.txt";
  link.click();
}

function renderHistory() {
  const history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];
  const list = document.getElementById("historyList");
  const box = document.querySelector(".history");

  if (!history.length) {
    box.style.display = "none";
    return;
  }

  box.style.display = "block";
  list.innerHTML = "";
  history.forEach(h => {
    const li = document.createElement("li");
    li.innerText = `${h.time} | ${h.target} | ${h.severity}`;
    list.appendChild(li);
  });
}
