require("dotenv").config();

const express = require("express");
const axios = require("axios");
const cors = require("cors");

const staticAnalyze = require("./analyzers/staticAnalyzer");
const calculateRisk = require("./risk/riskEngine");
const checkVirusTotal = require("./analyzers/virusTotalAnalyzer");

const app = express();

/* ================= Middleware ================= */
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* ================= Health Check ================= */
app.get("/", (req, res) => {
  res.send("Web Threat Detection API is running");
});

/* ================= Scan Endpoint ================= */
app.post("/scan", async (req, res) => {
  try {
    let html = "";
    let vtResult = { malicious: 0, suspicious: 0 };

    /* ---------- Input Handling ---------- */
    if (req.body?.html) {
      html = req.body.html;
    } 
    else if (req.body?.url) {
      const url = req.body.url;

      let response;
      try {
        response = await axios.get(url, {
          timeout: 8000,
          maxRedirects: 5,
          headers: { "User-Agent": "WebThreatScanner/1.0" },
          validateStatus: () => true
        });
      } catch (err) {
        return res.status(400).json({
          error: "Failed to fetch URL content"
        });
      }

      html = response.data;

      /* Handle non-HTML responses safely */
      if (typeof html !== "string" || !html.includes("<")) {
        html = `<pre>${String(html).slice(0, 500)}</pre>`;
      }

      /* VirusTotal check (non-blocking) */
      try {
        const vt = await checkVirusTotal(url);
        if (vt && typeof vt.malicious === "number") {
          vtResult = vt;
        }
      } catch (err) {
        vtResult = { malicious: 0, suspicious: 0 };
      }
    } 
    else {
      return res.status(400).json({
        error: "Provide either 'html' or 'url' in request body"
      });
    }

    /* ---------- Static Analysis ---------- */
    const analysisResult = staticAnalyze(html) || {
      totalScripts: 0,
      totalIframes: 0,
      hiddenElementsDetected: false,
      suspiciousJSPatterns: [],
      matchedKeywords: []
    };

    /* ---------- Base Risk Calculation ---------- */
    let riskResult = calculateRisk(analysisResult) || {
      riskScore: 0,
      severity: "LOW"
    };

    if (typeof riskResult.riskScore !== "number") {
      riskResult.riskScore = 0;
    }

    /* ---------- VirusTotal Risk Adjustment ---------- */
    if (vtResult.malicious >= 1 && vtResult.malicious < 3) {
      riskResult.riskScore += 3;
    } else if (vtResult.malicious >= 3 && vtResult.malicious < 6) {
      riskResult.riskScore += 7;
    } else if (vtResult.malicious >= 6) {
      riskResult.riskScore += 12;
    }

    /* ---------- Severity Mapping ---------- */
    if (riskResult.riskScore >= 14) {
      riskResult.severity = "HIGH";
    } else if (riskResult.riskScore >= 7) {
      riskResult.severity = "MEDIUM";
    } else {
      riskResult.severity = "LOW";
    }

    /* ---------- Final Response ---------- */
    return res.json({
      analysis: analysisResult,
      risk: riskResult,
      virusTotal: vtResult
    });

  } catch (error) {
    console.error("Scan error:", error.message);

    return res.status(500).json({
      error: "Internal Server Error"
    });
  }
});

/* ================= Start Server ================= */
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
