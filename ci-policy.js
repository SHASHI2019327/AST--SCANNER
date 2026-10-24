
"use strict";

const SEVERITY_RANK = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

function enforceRiskThreshold(report, failOn = "none") {
  const threshold = String(failOn).toUpperCase();

  if (!(threshold in SEVERITY_RANK) && threshold !== "NONE") {
    throw new Error(`Invalid risk threshold: ${failOn}`);
  }

  if (!report || !Array.isArray(report.findings)) {
    throw new TypeError("report.findings must be an array");
  }

  const thresholdRank =
    threshold === "NONE" ? Infinity : SEVERITY_RANK[threshold];

  const violations = report.findings.filter((finding) => {
    const severity = String(finding.severity || "").toUpperCase();
    const rank = SEVERITY_RANK[severity];

    return rank !== undefined && rank >= thresholdRank;
  });

  console.log(`Risk threshold: ${threshold}`);
  console.log(`Violating findings: ${violations.length}`);

  for (const finding of violations) {
    console.log(
      `- [${finding.severity}] ${finding.algorithm || "Unknown"}`
    );
  }

  return {
    passed: violations.length === 0,
    violations,
  };
}

module.exports = { enforceRiskThreshold };