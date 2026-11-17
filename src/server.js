require("dotenv").config();

const express = require("express");
const axios = require("axios");
const cors = require("cors");

const staticAnalyze = require("./analyzers/staticAnalyzer");
const calculateRisk = require("./risk/riskEngine");
const checkVirusTotal = require("./analyzers/virusTotalAnalyzer");
const { socEventRouter, recordScanEvent, initDb } = require("./soc/events");

const app = express();

/* ================= Middleware ================= */
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* ================= SOC Event Management API ================= */
app.use("/api/soc/events", socEventRouter);

// Attempt database connection non-blockingly (resilient fallback if offline)
initDb().catch(() => {});

/* ================= Health Check ================= */
app.get("/", (req, res) => {
  res.send("Web Threat Detection API is running");
});

/* ================= Scan Endpoint ================= */
app.post("/scan", async (req, res) => {
  try {
    let html = "";
    let targetUrl = "";
    let vtResult = {
      status: "not_applicable",
      available: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      message: "VirusTotal reputation check not applicable for raw HTML input."
    };

    /* ---------- Input Handling ---------- */
    if (req.body?.html) {
      html = req.body.html;
      targetUrl = "";
    } 
    else if (req.body?.url) {
      targetUrl = req.body.url.trim();

      // Ensure protocol is present
      if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
        targetUrl = "https://" + targetUrl;
      }

      let response;
      try {
        response = await axios.get(targetUrl, {
          timeout: 9000,
          maxRedirects: 5,
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 WebThreatScanner/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
          },
          validateStatus: () => true
        });
        html = response.data;
      } catch (err) {
        return res.status(400).json({
          error: `Failed to fetch target URL: ${err.message || "Network error"}`
        });
      }

      /* Handle non-HTML or binary responses safely */
      if (typeof html !== "string") {
        html = `<pre>${String(html).slice(0, 500)}</pre>`;
      } else if (!html.includes("<")) {
        html = `<pre>${html.slice(0, 500)}</pre>`;
      }

      /* VirusTotal Threat Intelligence check */
      try {
        const vt = await checkVirusTotal(targetUrl);
        if (vt) {
          vtResult = vt;
        }
      } catch (err) {
        vtResult = {
          status: "unavailable",
          available: false,
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 0,
          message: "Reputation check unavailable. No reputation conclusion can be drawn."
        };
      }
    } 
    else {
      return res.status(400).json({
        error: "Provide either 'html' or 'url' in request body"
      });
    }

    /* ---------- Static DOM & Pattern Analysis ---------- */
    const analysisResult = staticAnalyze(html, targetUrl) || {
      totalScripts: 0,
      totalIframes: 0,
      hiddenElementsDetected: false,
      suspiciousJSPatterns: [],
      matchedKeywords: [],
      findings: [],
      suspiciousFindings: []
    };

    /* ---------- Comprehensive Risk & Verdict Calculation ---------- */
    const riskResult = calculateRisk(analysisResult, vtResult);

    /* ---------- SOC Event Recording (Non-blocking adapter) ---------- */
    recordScanEvent(
      { target: targetUrl || "HTML Source", url: targetUrl, html: req.body?.html },
      { analysis: analysisResult, risk: riskResult, virusTotal: vtResult },
      {
        source: targetUrl ? "URL_SCANNER" : "HTML_SCANNER",
        clientIp: req.ip || req.socket?.remoteAddress || "127.0.0.1",
        userAgent: req.headers["user-agent"] || ""
      }
    ).catch(err => {
      console.warn("SOC event logging error:", err.message);
    });

    /* ---------- Final Response (Strictly preserves existing API contract) ---------- */
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
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Web Threat Detection Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
