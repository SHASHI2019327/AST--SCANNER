"use strict";
const { analyse, rank, LEVELS } = require("./risk-classifier");
const SEVERITY = { safe: "INFO", unknown: "INFO", low: "LOW", medium: "MEDIUM", high: "HIGH", critical: "CRITICAL" };

function analyzeFindings(input) {
  const findings = input.map((source) => {
    const assessment = analyse(source);
    const risk = assessment.risk || "unknown";
    return {
      ...source,
      risk,
      severity: SEVERITY[risk] || "INFO",
      quantum: assessment.quantum || "unknown",
      keySize: assessment.keySize || source.keySize || null,
      mode: assessment.mode || source.mode || null,
      reasons: [...new Set([...(source.reasons || []), ...(assessment.reasons || [])])],
      recommendation: [source.recommendation, assessment.recommendation].filter(Boolean).join(" "),
      requiringReview: risk === "unknown" || assessment.quantum === "vulnerable",
    };
  });
  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === "CRITICAL").length,
    high: findings.filter(f => f.severity === "HIGH").length,
    medium: findings.filter(f => f.severity === "MEDIUM").length,
    low: findings.filter(f => f.severity === "LOW").length,
    info: findings.filter(f => f.severity === "INFO").length,
    quantumVulnerable: findings.filter(f => f.quantum === "vulnerable").length,
    requiringReview: findings.filter(f => f.requiringReview).length,
  };
  findings.sort((a,b) => (rank(b.risk) - rank(a.risk)) || String(a.algorithm).localeCompare(String(b.algorithm)));
  return { generatedAt: new Date().toISOString(), summary, findings };
}
module.exports = { analyzeFindings };
