/**
 * Risk Scoring & Severity Classification Engine
 * @param {Object} analysisResult
 * @returns risk assessment
 */
function calculateRisk(analysisResult) {
  let riskScore = 0;

  // Weight assignments
  if (analysisResult.totalScripts > 3) {
    riskScore += 3;
  }

  if (analysisResult.totalIframes > 0) {
    riskScore += 4;
  }

  if (analysisResult.hiddenElementsDetected) {
    riskScore += 5;
  }

  riskScore += analysisResult.suspiciousJSPatterns.length * 3;
  riskScore += analysisResult.matchedKeywords.length * 2;

  // Severity classification
  let severity = "LOW";

  if (riskScore >= 7 && riskScore < 14) {
    severity = "MEDIUM";
  } else if (riskScore >= 14) {
    severity = "HIGH";
  }

  return {
    riskScore,
    severity
  };
}

module.exports = calculateRisk;
