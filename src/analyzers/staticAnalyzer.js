const cheerio = require("cheerio");

function staticAnalyze(html = "") {
  /* ---------- Safety Check ---------- */
  if (!html || typeof html !== "string") {
    return {
      totalScripts: 0,
      totalIframes: 0,
      hiddenElementsDetected: false,
      suspiciousJSPatterns: [],
      matchedKeywords: []
    };
  }

  let $;
  try {
    $ = cheerio.load(html);
  } catch (err) {
    return {
      totalScripts: 0,
      totalIframes: 0,
      hiddenElementsDetected: false,
      suspiciousJSPatterns: [],
      matchedKeywords: []
    };
  }

  /* ---------- Script & Iframe Count ---------- */
  const totalScripts = $("script").length;
  const totalIframes = $("iframe").length;

  /* ---------- Hidden Element Detection ---------- */
  let hiddenElementsDetected = false;

  $("*").each((_, el) => {
    const style = $(el).attr("style");
    if (style && typeof style === "string") {
      const s = style.toLowerCase();
      if (
        s.includes("display:none") ||
        s.includes("opacity:0") ||
        s.includes("visibility:hidden") ||
        s.includes("height:0") ||
        s.includes("width:0")
      ) {
        hiddenElementsDetected = true;
      }
    }
  });

  /* ---------- JavaScript Pattern Analysis ---------- */
  let jsCode = "";

  $("script").each((_, script) => {
    const code = $(script).html();
    if (typeof code === "string") {
      jsCode += code.toLowerCase();
    }
  });

  const suspiciousPatterns = [
    "eval(",
    "document.write",
    "atob(",
    "btoa(",
    "unescape(",
    "fromcharcode",
    "settimeout(",
    "setinterval("
  ];

  const suspiciousJSPatterns = suspiciousPatterns.filter(pattern =>
    jsCode.includes(pattern)
  );

  /* ---------- Keyword-Based Detection ---------- */
  const keywords = [
    "login",
    "password",
    "verify",
    "wallet",
    "crypto",
    "bonus",
    "free",
    "claim",
    "account"
  ];

  const bodyText = $("body").text().toLowerCase();
  const matchedKeywords = keywords.filter(word =>
    bodyText.includes(word)
  );

  /* ---------- Final Result ---------- */
  return {
    totalScripts,
    totalIframes,
    hiddenElementsDetected,
    suspiciousJSPatterns,
    matchedKeywords
  };
}

module.exports = staticAnalyze;
