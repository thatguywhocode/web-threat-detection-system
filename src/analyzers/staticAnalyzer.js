const cheerio = require("cheerio");

/**
 * Enhanced Static HTML & DOM Security Analyzer
 * Distinguishes benign modern web structures from authentic threat indicators.
 *
 * @param {string} html - Raw HTML source code
 * @param {string} [targetUrl=""] - Optional target URL for context-aware validation
 * @returns {Object} Comprehensive analysis results and structured security findings
 */
function staticAnalyze(html = "", targetUrl = "") {
  /* ---------- Safety Check ---------- */
  if (!html || typeof html !== "string") {
    return createEmptyAnalysisResult();
  }

  let $;
  try {
    $ = cheerio.load(html);
  } catch (err) {
    return createEmptyAnalysisResult();
  }

  let parsedTargetHost = "";
  try {
    if (targetUrl && (targetUrl.startsWith("http://") || targetUrl.startsWith("https://"))) {
      parsedTargetHost = new URL(targetUrl).hostname.toLowerCase();
    }
  } catch (_) {
    parsedTargetHost = "";
  }

  const findings = [];

  /* ================= 1. SCRIPT & RESOURCE AUDIT ================= */
  const scripts = $("script");
  const totalScripts = scripts.length;

  // Informational finding for high script count (NO risk points assigned)
  if (totalScripts > 20) {
    findings.push({
      id: "INFO_SCRIPT_COUNT",
      name: "Complex Web Application Structure",
      severity: "INFO",
      explanation: `Target contains ${totalScripts} script tags, typical for modern bundled single-page applications or media-rich portals.`,
      evidence: `Total <script> tags: ${totalScripts}`,
      whyItMatters: "Large script volume increases the surface area for analysis but does not inherently indicate malicious intent.",
      recommendedAction: "Monitor third-party dependencies and maintain a strict Content Security Policy (CSP).",
      isThreat: false
    });
  }

  /* ================= 2. HIDDEN ELEMENTS ANALYSIS ================= */
  let hiddenElementsCount = 0;
  const suspiciousHiddenElements = [];

  // Helper to test if inline style indicates visibility suppression
  function isStyleHidden(styleStr) {
    if (!styleStr || typeof styleStr !== "string") return false;
    const s = styleStr.toLowerCase().replace(/\s+/g, "");
    return (
      s.includes("display:none") ||
      s.includes("visibility:hidden") ||
      s.includes("opacity:0") ||
      s.includes("height:0px") ||
      s.includes("width:0px") ||
      s.includes("height:0;") ||
      s.includes("width:0;") ||
      s.includes("position:absolute;left:-") ||
      s.includes("position:fixed;left:-")
    );
  }

  $("*").each((_, el) => {
    const tagName = el.tagName ? el.tagName.toLowerCase() : "";
    const style = $(el).attr("style");
    const isHiddenAttr = $(el).attr("hidden") !== undefined;
    const isHidden = isHiddenAttr || isStyleHidden(style);

    if (isHidden) {
      hiddenElementsCount++;

      // Check if this hidden element is a common benign component:
      const classAttr = ($(el).attr("class") || "").toLowerCase();
      const idAttr = ($(el).attr("id") || "").toLowerCase();
      const roleAttr = ($(el).attr("role") || "").toLowerCase();
      const ariaHidden = $(el).attr("aria-hidden") === "true";

      const isBenignUI =
        tagName === "svg" ||
        tagName === "path" ||
        tagName === "defs" ||
        tagName === "symbol" ||
        tagName === "template" ||
        tagName === "noscript" ||
        roleAttr === "dialog" ||
        roleAttr === "tooltip" ||
        classAttr.includes("modal") ||
        classAttr.includes("dropdown") ||
        classAttr.includes("menu") ||
        classAttr.includes("collapse") ||
        classAttr.includes("sr-only") ||
        classAttr.includes("visually-hidden") ||
        classAttr.includes("tooltip") ||
        idAttr.includes("modal") ||
        idAttr.includes("dropdown") ||
        ariaHidden;

      // Check for SUSPICIOUS hidden combinations (Avoid duplicate detections on same element):
      // A. Hidden forms collecting user credentials (checks forms first)
      if (tagName === "form" && !isBenignUI) {
        const inputs = $(el).find("input");
        let hasAuthInput = false;
        inputs.each((_, inp) => {
          const type = ($(inp).attr("type") || "").toLowerCase();
          const name = ($(inp).attr("name") || "").toLowerCase();
          // Real credential fields (exclude standard CSRF tokens)
          if (type === "password" || (name.includes("pass") && !name.includes("token")) || name.includes("credit") || name.includes("card")) {
            hasAuthInput = true;
          }
        });

        if (hasAuthInput) {
          suspiciousHiddenElements.push({
            type: "HIDDEN_CREDENTIAL_FORM",
            description: "Form with credential input fields concealed from visible viewport",
            snippet: String($.html(el)).slice(0, 150)
          });
        }
      }
      // B. Hidden standalone password field (outside a form that was already flagged)
      else if (
        !isBenignUI &&
        ((tagName === "input" && $(el).attr("type") === "password") ||
         ($(el).find('input[type="password"]').length > 0 && $(el).closest("form").length === 0))
      ) {
        suspiciousHiddenElements.push({
          type: "HIDDEN_PASSWORD_FIELD",
          description: "Password input styled hidden or inside hidden container without standard modal markup",
          snippet: String($.html(el)).slice(0, 150)
        });
      }

      // C. Hidden external iframe (flagged under iframe analysis to avoid double-counting)
      if (tagName === "iframe") {
        const src = ($(el).attr("src") || "").trim();
        const isExternalOrSuspicious = isExternalSrc(src, parsedTargetHost);
        if (isExternalOrSuspicious) {
          // Handled centrally in Iframe Analysis
        }
      }
    }
  });

  // Evaluate findings for hidden elements
  if (suspiciousHiddenElements.length > 0) {
    suspiciousHiddenElements.forEach(item => {
      findings.push({
        id: `THREAT_${item.type}`,
        name: item.type === "HIDDEN_PASSWORD_FIELD" ? "Concealed Credential Input"
            : item.type === "HIDDEN_EXTERNAL_IFRAME" ? "Hidden Background Iframe"
            : "Hidden Credential Collection Form",
        severity: item.type === "HIDDEN_PASSWORD_FIELD" || item.type === "HIDDEN_CREDENTIAL_FORM" ? "HIGH" : "MEDIUM",
        explanation: `${item.description}. This technique is commonly associated with credential autofill harvesting or stealth clickjacking.`,
        evidence: item.snippet,
        whyItMatters: "Attackers conceal sensitive form elements to trick browser autofill managers or redirect traffic in the background without user awareness.",
        recommendedAction: "Verify whether this element is intentionally hidden for genuine functionality or if it poses an autofill harvesting risk.",
        isThreat: true
      });
    });
  } else if (hiddenElementsCount > 0) {
    // Purely benign informational observation
    findings.push({
      id: "INFO_BENIGN_HIDDEN",
      name: "Standard Hidden UI Elements",
      severity: "INFO",
      explanation: `Observed ${hiddenElementsCount} hidden elements (e.g. navigation drawers, modals, screen-reader utilities) consistent with standard responsive design.`,
      evidence: `Hidden elements count: ${hiddenElementsCount}`,
      whyItMatters: "Modern web applications frequently toggle UI element visibility for accessible navigation, modals, and responsive layouts.",
      recommendedAction: "No action required. All hidden elements matched standard benign UI patterns.",
      isThreat: false
    });
  }

  /* ================= 3. IFRAME ANALYSIS ================= */
  const iframes = $("iframe");
  const totalIframes = iframes.length;
  const suspiciousIframes = [];

  iframes.each((_, iframe) => {
    const src = ($(iframe).attr("src") || "").trim();
    const style = $(iframe).attr("style") || "";
    const width = $(iframe).attr("width");
    const height = $(iframe).attr("height");

    const isZeroDimension =
      width === "0" || height === "0" ||
      width === "1" || height === "1" ||
      isStyleHidden(style);

    const isDataOrJs = src.startsWith("data:") || src.startsWith("javascript:");
    const isSuspiciousExternal = isExternalSrc(src, parsedTargetHost) && (isZeroDimension || isDataOrJs);

    if (isSuspiciousExternal || isDataOrJs) {
      suspiciousIframes.push({
        src: src.slice(0, 100),
        isZeroDimension,
        isDataOrJs
      });
    }
  });

  if (suspiciousIframes.length > 0) {
    findings.push({
      id: "THREAT_SUSPICIOUS_IFRAME",
      name: "Suspicious or Obscured Iframe",
      severity: "HIGH",
      explanation: `Detected ${suspiciousIframes.length} iframe(s) with obscured dimensions or suspicious data/javascript protocols.`,
      evidence: suspiciousIframes.map(i => `src: ${i.src}`).join("; "),
      whyItMatters: "Concealed external iframes are commonly used for clickjacking, background drive-by payloads, and silent tracking beacons.",
      recommendedAction: "Inspect the destination URL of all embedded frames and implement an explicit X-Frame-Options or frame-ancestors CSP directive.",
      isThreat: true
    });
  } else if (totalIframes > 0) {
    findings.push({
      id: "INFO_LEGIT_IFRAMES",
      name: "Standard Embedded Iframes",
      severity: "INFO",
      explanation: `Detected ${totalIframes} standard iframe(s) (e.g. embedded video, widgets, or analytics).`,
      evidence: `Total iframes: ${totalIframes}`,
      whyItMatters: "Standard embedded frames from trusted hosts are common in commercial and media websites.",
      recommendedAction: "Verify frame sources and ensure sandbox attributes are applied where appropriate.",
      isThreat: false
    });
  }

  /* ================= 4. JAVASCRIPT PATTERN & OBFUSCATION ANALYSIS ================= */
  let combinedScriptText = "";
  scripts.each((_, script) => {
    const content = $(script).html();
    if (typeof content === "string") {
      combinedScriptText += content + "\n";
    }
  });

  const jsThreats = analyzeJavaScriptContent(combinedScriptText);
  const matchedJSPatternNames = [];

  jsThreats.forEach(threat => {
    matchedJSPatternNames.push(threat.pattern);
    findings.push({
      id: `THREAT_JS_${threat.pattern.toUpperCase()}`,
      name: threat.name,
      severity: threat.severity,
      explanation: threat.explanation,
      evidence: threat.evidence,
      whyItMatters: threat.whyItMatters,
      recommendedAction: threat.recommendedAction,
      isThreat: true
    });
  });

  /* ================= 5. PHISHING & CREDENTIAL HARVESTING ANALYSIS ================= */
  // Check Meta Refresh tags
  $("meta").each((_, meta) => {
    const equiv = ($(meta).attr("http-equiv") || "").toLowerCase();
    const content = ($(meta).attr("content") || "").toLowerCase();
    if (equiv === "refresh" && content.includes("url=")) {
      const parts = content.split("url=");
      const target = parts[1] ? parts[1].replace(/["']/g, "").trim() : "";
      const isRawIp = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(target);
      const isSuspiciousTld = /\.(tk|xyz|top|pw|cc|cn|work)\b/i.test(target);
      if (isRawIp || isSuspiciousTld) {
        findings.push({
          id: "THREAT_META_REFRESH_REDIRECT",
          name: "Suspicious Meta Refresh Redirection",
          severity: "HIGH",
          explanation: `Page specifies automatic meta refresh redirecting to raw IP or untrusted domain: ${target}`,
          evidence: `meta http-equiv="refresh" content="${content}"`,
          whyItMatters: "Meta refresh tags with 0-second timers are frequently used by phishing kits to quickly bounce victims off landing domains to hostile servers.",
          recommendedAction: "Examine redirect destination and remove automated meta tags.",
          isThreat: true
        });
      }
    }
  });

  const phishingThreats = analyzePhishingAndForms($, parsedTargetHost);

  phishingThreats.forEach(threat => {
    findings.push({
      id: `THREAT_PHISHING_${threat.type}`,
      name: threat.name,
      severity: threat.severity,
      explanation: threat.explanation,
      evidence: threat.evidence,
      whyItMatters: threat.whyItMatters,
      recommendedAction: threat.recommendedAction,
      isThreat: true
    });
  });

  // Backward compatible keyword check (purely for contract compatibility)
  const legacyKeywords = ["login", "password", "verify", "wallet", "crypto", "bonus", "free", "claim", "account"];
  const bodyText = $("body").text().toLowerCase();
  const matchedKeywords = legacyKeywords.filter(w => bodyText.includes(w));

  // If keywords exist without suspicious form or lures, record as informational
  if (matchedKeywords.length > 0 && phishingThreats.length === 0) {
    findings.push({
      id: "INFO_KEYWORDS_BENIGN",
      name: "Common Authentication Terms",
      severity: "INFO",
      explanation: `Detected standard terms (${matchedKeywords.join(", ")}) on the page. These are expected on authentic platforms with sign-in or account management.`,
      evidence: `Matched vocabulary: ${matchedKeywords.join(", ")}`,
      whyItMatters: "Legitimate websites like GitHub, Google, and Amazon routinely contain login and account references. Keywords alone do not indicate phishing.",
      recommendedAction: "No action required unless accompanied by anomalous external form targets.",
      isThreat: false
    });
  }

  /* ================= 6. FINAL COMPILATION ================= */
  const suspiciousFindings = findings.filter(f => f.isThreat);
  const hiddenElementsDetected = suspiciousHiddenElements.length > 0;
  const rawHtmlLength = (html || "").trim().length;
  const bodyTextTrimmed = $("body").text().trim();
  const isEssentiallyEmpty = rawHtmlLength < 25 || (!bodyTextTrimmed && totalScripts === 0 && totalIframes === 0);

  return {
    totalScripts,
    totalIframes,
    hiddenElementsDetected,
    suspiciousJSPatterns: matchedJSPatternNames,
    matchedKeywords,
    isEssentiallyEmpty,

    // Enhanced inspection outputs
    findings,
    suspiciousFindings,
    metrics: {
      hiddenElementsCount,
      suspiciousHiddenCount: suspiciousHiddenElements.length,
      suspiciousIframesCount: suspiciousIframes.length,
      jsThreatsCount: jsThreats.length,
      phishingThreatsCount: phishingThreats.length,
      rawHtmlLength
    }
  };
}

/**
 * Deep inspection of JavaScript source for authentic malicious signatures
 */
function analyzeJavaScriptContent(jsText) {
  if (!jsText || typeof jsText !== "string" || jsText.trim().length === 0) {
    return [];
  }

  const threats = [];
  const lower = jsText.toLowerCase();

  // Pattern 1: Obfuscated eval with dynamic decoding
  // e.g. eval(atob(...)), eval(unescape(...)), eval(String.fromCharCode(...))
  const evalAtobRegex = /eval\s*\(\s*(atob|unescape|decodeuricomponent|string\.fromcharcode)\s*\(/i;
  const evalMatch = jsText.match(evalAtobRegex);
  if (evalMatch) {
    threats.push({
      pattern: "eval_encoded_payload",
      name: "Dynamic Execution of Encoded Payload",
      severity: "HIGH",
      explanation: `Script dynamically executes deobfuscated code via eval(${evalMatch[1]}(...)).`,
      evidence: evalMatch[0],
      whyItMatters: "Executing decoded strings at runtime is a primary evasion technique used by malware loaders to bypass static signature scanners.",
      recommendedAction: "Extract and examine the decoded payload; eliminate runtime eval() usage."
    });
  }

  // Pattern 2: Function constructor execution with encoded string
  // e.g. Function(atob(...))() or []["filter"]["constructor"](...)
  const funcConstructorRegex = /function\s*\(\s*(atob|unescape)\s*\(/i;
  const ctorMatch = jsText.match(funcConstructorRegex);
  if (ctorMatch) {
    threats.push({
      pattern: "function_constructor_evasion",
      name: "Function Constructor Code Execution",
      severity: "HIGH",
      explanation: "Dynamic code generation using Function constructor with decoded payload.",
      evidence: ctorMatch[0],
      whyItMatters: "Commonly employed in polymorphic droppers and packer scripts to bypass eval-based alerts.",
      recommendedAction: "Refactor dynamic execution and inspect the payload."
    });
  }

  // Pattern 3: Excessive hex / unicode string packing with rotation
  // e.g. array of \x65\x76\x61\x6c or \u0065\u0076\u0061\u006c
  const hexDensityRegex = /(?:\\x[0-9a-fA-F]{2}){6,}/g;
  const hexMatches = jsText.match(hexDensityRegex);
  if (hexMatches && hexMatches.length >= 3) {
    threats.push({
      pattern: "hex_packed_obfuscation",
      name: "Hex-Encoded Obfuscation Array",
      severity: "HIGH",
      explanation: `Detected dense clusters of hexadecimal character escape sequences (${hexMatches.length} dense blocks).`,
      evidence: hexMatches[0].slice(0, 60) + "...",
      whyItMatters: "High-density hex sequences are characteristic of JavaScript obfuscators (such as Obfuscator.io) frequently used to conceal malicious exploits.",
      recommendedAction: "Deobfuscate the script and identify the underlying API calls."
    });
  }

  // Pattern 4: Suspicious credential keylogger / form listener
  const keyloggerRegex = /addeventlistener\s*\(\s*["']key(?:down|press|up)["'].*?(?:password|passwd|pwd|creditcard).*?(?:fetch|xmlhttprequest|\.src\s*=)/is;
  if (keyloggerRegex.test(lower)) {
    threats.push({
      pattern: "credential_keylogger",
      name: "Keystroke & Credential Interception Pattern",
      severity: "CRITICAL",
      explanation: "Script attaches keyboard event listeners to password fields and initiates external data transmission.",
      evidence: "Keylistener pattern matching sensitive input and exfiltration primitives",
      whyItMatters: "Indicates an active Magecart or digital skimming attack capturing user credentials or credit card entries as they are typed.",
      recommendedAction: "Immediately audit third-party scripts and isolate the impacted endpoint."
    });
  }

  // Pattern 5: Immediate external redirection in inline script or meta refresh
  const immediateRedirectRegex = /(?:window\.)?location(?:\.replace\s*\(\s*|\.assign\s*\(\s*|\.href\s*=\s*|\s*=\s*)["'](https?:\/\/[^"']+)["']/i;
  const redirectMatch = jsText.match(immediateRedirectRegex);
  if (redirectMatch) {
    const dest = redirectMatch[1];
    // Flag if destination is a raw IP address or suspicious TLD
    const isRawIp = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(dest);
    const isSuspiciousTld = /\.(tk|xyz|top|pw|cc|cn|work)\b/i.test(dest);

    if (isRawIp || isSuspiciousTld) {
      threats.push({
        pattern: "suspicious_immediate_redirect",
        name: "Immediate Redirection to Suspicious Host",
        severity: "HIGH",
        explanation: `Script executes immediate redirection to an untrusted or raw IP host: ${dest}`,
        evidence: redirectMatch[0],
        whyItMatters: "Rapid client-side redirects to raw IPs or high-risk TLDs are common in phishing gates and traffic distribution systems (TDS).",
        recommendedAction: "Verify destination domain reputation and remove unauthorized redirects."
      });
    }
  }

  // Pattern 6: Dynamic script tag creation pointing to suspicious source
  const dynamicScriptRegex = /document\.createelement\s*\(\s*["']script["']\s*\).*?\.src\s*=\s*["'](https?:\/\/[^"']+|data:[^"']+)["']/is;
  const dynScriptMatch = jsText.match(dynamicScriptRegex);
  if (dynScriptMatch) {
    const src = dynScriptMatch[1];
    const isRawIp = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(src);
    const isData = src.startsWith("data:");
    const isPasteSite = /(pastebin|hastebin|ghostbin|discordapp\.com\/attachments)/i.test(src);

    if (isRawIp || isData || isPasteSite) {
      threats.push({
        pattern: "dynamic_untrusted_script_injection",
        name: "Dynamic Script Injection from Untrusted Source",
        severity: "HIGH",
        explanation: `Script dynamically generates and appends an executable script element from an anomalous location: ${src.slice(0, 80)}`,
        evidence: dynScriptMatch[0].slice(0, 100),
        whyItMatters: "Loading scripts from paste sites, raw IPs, or data URIs is a standard technique to bypass initial static inspection filters.",
        recommendedAction: "Restrict script sources via Content Security Policy (CSP) script-src directive."
      });
    }
  }

  return threats;
}

/**
 * Inspection of forms, action endpoints, and phishing lures
 */
function analyzePhishingAndForms($, parsedTargetHost) {
  const threats = [];

  $("form").each((_, form) => {
    const action = ($(form).attr("action") || "").trim();
    const method = ($(form).attr("method") || "GET").toUpperCase();
    const hasPasswordField = $(form).find('input[type="password"]').length > 0;

    if (hasPasswordField) {
      // Check: Form submitting password to an external domain or raw IP or over insecure HTTP
      if (action.startsWith("http://") || action.startsWith("https://")) {
        try {
          const actionHost = new URL(action).hostname.toLowerCase();
          const isRawIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(actionHost);

          if (isRawIp) {
            // Prioritize raw IP submission: highly critical phishing indicator
            threats.push({
              type: "CREDENTIAL_SUBMISSION_RAW_IP",
              name: "Credential Exfiltration to Raw IP Address",
              severity: "CRITICAL",
              explanation: `Login form explicitly posts credentials to a raw IP address (${actionHost}) rather than a registered domain name.`,
              evidence: `form action="${action}"`,
              whyItMatters: "Legitimate enterprise services never post user credentials to raw IP destinations; this is an almost universal indicator of phishing infrastructure.",
              recommendedAction: "Block and investigate the target host immediately."
            });
          } else if (action.startsWith("http://") && parsedTargetHost) {
            // Insecure HTTP password submission
            threats.push({
              type: "INSECURE_PASSWORD_TRANSMISSION",
              name: "Insecure Password Submission (Plain HTTP)",
              severity: "HIGH",
              explanation: `Credential form submits passwords over unencrypted HTTP: ${action}`,
              evidence: `form action="${action}"`,
              whyItMatters: "Plain HTTP submission exposes credentials to interception, eavesdropping, and man-in-the-middle (MitM) attacks.",
              recommendedAction: "Ensure all authentication forms submit exclusively over secure HTTPS."
            });
          } else if (parsedTargetHost && !isSameOrSubdomain(actionHost, parsedTargetHost)) {
            // Target is an entirely different domain
            threats.push({
              type: "EXTERNAL_CREDENTIAL_ACTION",
              name: "External Domain Credential Form Submission",
              severity: "HIGH",
              explanation: `Form containing password fields submits to an external third-party domain (${actionHost}) different from current host (${parsedTargetHost}).`,
              evidence: `Target: ${parsedTargetHost} | Action: ${actionHost}`,
              whyItMatters: "Phishing kits often host fake templates on compromised domains that exfiltrate entered passwords to external collector servers.",
              recommendedAction: "Confirm whether cross-domain authentication (SSO) is intended or if the form is harvesting user credentials."
            });
          }
        } catch (_) {}
      }
    }
  });

  // Check 3: Urgent phishing lure wording combined with credential submission
  const bodyText = $("body").text().toLowerCase();
  const hasUrgentLure =
    (bodyText.includes("account suspended") ||
     bodyText.includes("verify your wallet") ||
     bodyText.includes("unauthorized activity detected") ||
     bodyText.includes("security alert: urgent action required") ||
     bodyText.includes("claim bonus now enter password") ||
     bodyText.includes("enter recovery seed phrase")) &&
    ($('input[type="password"]').length > 0 || bodyText.includes("password"));

  if (hasUrgentLure) {
    threats.push({
      type: "SOCIAL_ENGINEERING_CREDENTIAL_LURE",
      name: "High-Urgency Social Engineering Lure",
      severity: "HIGH",
      explanation: "Page pairs coercive urgency phrasing (e.g. account suspension, security emergency) with credential collection inputs.",
      evidence: "Combination of coercive urgency keywords and password collection inputs",
      whyItMatters: "Social engineering tactics manipulate victims into rapidly surrendering authentication credentials under perceived duress.",
      recommendedAction: "Verify sender domain legitimacy through independent out-of-band communication."
    });
  }

  return threats;
}

/**
 * Helper to identify external destination URLs
 */
function isExternalSrc(src, targetHost) {
  if (!src) return false;
  const s = src.toLowerCase().trim();
  if (s.startsWith("data:") || s.startsWith("javascript:")) return true;
  if (!s.startsWith("http://") && !s.startsWith("https://")) return false;

  try {
    const urlObj = new URL(src);
    const host = urlObj.hostname.toLowerCase();
    if (!targetHost) return true;
    return !isSameOrSubdomain(host, targetHost);
  } catch (_) {
    return false;
  }
}

function isSameOrSubdomain(hostA, hostB) {
  if (hostA === hostB) return true;
  return hostA.endsWith("." + hostB) || hostB.endsWith("." + hostA);
}

function createEmptyAnalysisResult() {
  return {
    totalScripts: 0,
    totalIframes: 0,
    hiddenElementsDetected: false,
    suspiciousJSPatterns: [],
    matchedKeywords: [],
    isEssentiallyEmpty: true,
    findings: [],
    suspiciousFindings: [],
    metrics: {
      hiddenElementsCount: 0,
      suspiciousHiddenCount: 0,
      suspiciousIframesCount: 0,
      jsThreatsCount: 0,
      phishingThreatsCount: 0
    }
  };
}

module.exports = staticAnalyze;
