const axios = require("axios");

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;

async function checkVirusTotal(url) {
  if (!VT_API_KEY) return null;

  try {
    const encodedUrl = Buffer.from(url)
      .toString("base64")
      .replace(/=/g, "");

    const response = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${encodedUrl}`,
      {
        headers: { "x-apikey": VT_API_KEY },
        timeout: 6000
      }
    );

    const stats = response.data.data.attributes.last_analysis_stats;

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0
    };

  } catch (err) {
    // ✅ NEVER crash backend
    console.warn("VirusTotal unavailable:", err.response?.status || err.message);
    return null; // <-- IMPORTANT
  }
}

module.exports = checkVirusTotal;
