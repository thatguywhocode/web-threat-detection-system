const axios = require("axios");

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;

/**
 * VirusTotal Global Threat Intelligence Analyzer
 * Queries VirusTotal v3 URL reputation API and provides categorized detection metrics.
 *
 * @param {string} url - Target URL to query
 * @returns {Promise<Object>} Categorized reputation status and detection counts
 */
async function checkVirusTotal(url) {
  // If no API key configured, explicitly report as unavailable (never pretend it is clean 0)
  if (!VT_API_KEY || VT_API_KEY.trim() === "") {
    return {
      status: "unavailable",
      available: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: 0,
      message: "Reputation check unavailable. No reputation conclusion can be drawn."
    };
  }

  try {
    // VirusTotal v3 requires URL identifier to be base64 without padding '='
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

    const attributes = response.data?.data?.attributes || {};
    const stats = attributes.last_analysis_stats || {};

    const malicious = typeof stats.malicious === "number" ? stats.malicious : 0;
    const suspicious = typeof stats.suspicious === "number" ? stats.suspicious : 0;
    const harmless = typeof stats.harmless === "number" ? stats.harmless : 0;
    const undetected = typeof stats.undetected === "number" ? stats.undetected : 0;
    const reputation = typeof attributes.reputation === "number" ? attributes.reputation : 0;

    return {
      status: "success",
      available: true,
      malicious,
      suspicious,
      harmless,
      undetected,
      reputation,
      message: `Reputation checked: ${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless out of ${malicious + suspicious + harmless + undetected} security engines.`
    };

  } catch (err) {
    const statusCode = err.response?.status;

    // 404 means the URL has never been scanned by VirusTotal yet
    if (statusCode === 404) {
      return {
        status: "not_found",
        available: true,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: 0,
        message: "URL is not yet indexed in VirusTotal's global database (zero prior scans recorded)."
      };
    }

    // 401/403/429 or network timeout
    console.warn("VirusTotal query error:", statusCode || err.message);

    return {
      status: "unavailable",
      available: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: 0,
      message: "Reputation check unavailable. No reputation conclusion can be drawn."
    };
  }
}

module.exports = checkVirusTotal;
