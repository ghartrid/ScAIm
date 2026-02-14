/**
 * ScAIm Scoring Aggregator
 * Combines scores from all detectors with paranoid bias.
 * Scores always round UP. Low threshold for triggering warnings.
 */
const ScaimScoring = {
  LEVELS: {
    SAFE: "safe",
    CAUTION: "caution",
    WARNING: "warning",
    DANGER: "danger"
  },

  THRESHOLDS: {
    safe: 15,     // 0-15
    caution: 40,  // 16-40
    warning: 65,  // 41-65
    danger: 100   // 66-100
  },

  WEIGHTS: {
    keywords: 0.18,
    structural: 0.14,
    phishing: 0.14,
    socialEngineering: 0.10,
    fakeEcommerce: 0.10,
    cryptoScam: 0.10,
    techSupport: 0.08,
    romanceFee: 0.08,
    maliciousDownload: 0.08
  },

  // Findings with these categories can jump straight to WARNING
  CRITICAL_ESCALATION_CATEGORIES: [
    "External Form Action",
    "Href Spoofing",
    "Homoglyph Domain",
    "IP Address URL",
    "Obfuscated Code",
    "Seed Phrase Theft",
    "Wallet Impersonation",
    "Remote Access Tool",
    "BSOD Simulation",
    "Dangerous File Download",
    "Disguised File Extension",
    "Advance Fee Fraud",
    "419 Advance Fee Scam"
  ],

  /**
   * Aggregate all detector results into a final threat assessment.
   * @param {Object} results - All detector results, each with { score: number, findings: Array }
   * @returns {{ level: string, score: number, findings: Array, summary: string }}
   */
  aggregate(results) {
    // Weighted score — dynamically computed from WEIGHTS keys
    let weightedScore = 0;
    for (const [key, weight] of Object.entries(this.WEIGHTS)) {
      weightedScore += (results[key]?.score || 0) * weight;
    }

    // Paranoid bias: always round up
    weightedScore = Math.ceil(weightedScore);

    // Collect all findings
    const allFindings = [];
    for (const key of Object.keys(results)) {
      if (results[key]?.findings) {
        allFindings.push(...results[key].findings);
      }
    }

    // Check for critical escalation — any single critical finding bumps to WARNING minimum
    let hasCritical = false;
    for (const finding of allFindings) {
      if (finding.severity === "critical" ||
          this.CRITICAL_ESCALATION_CATEGORIES.includes(finding.category)) {
        hasCritical = true;
        break;
      }
    }

    if (hasCritical && weightedScore < this.THRESHOLDS.caution + 1) {
      weightedScore = this.THRESHOLDS.caution + 1; // Jump to WARNING
    }

    // Clamp
    weightedScore = Math.min(100, Math.max(0, weightedScore));

    // Determine level
    const level = this._getLevel(weightedScore);

    // Sort findings by severity (critical > high > medium > low)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) =>
      (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)
    );

    // Generate summary
    const summary = this._generateSummary(level, weightedScore, allFindings);

    return {
      level,
      score: weightedScore,
      findings: allFindings,
      summary
    };
  },

  _getLevel(score) {
    if (score <= this.THRESHOLDS.safe) return this.LEVELS.SAFE;
    if (score <= this.THRESHOLDS.caution) return this.LEVELS.CAUTION;
    if (score <= this.THRESHOLDS.warning) return this.LEVELS.WARNING;
    return this.LEVELS.DANGER;
  },

  _generateSummary(level, score, findings) {
    const count = findings.length;

    switch (level) {
      case this.LEVELS.SAFE:
        return count > 0
          ? `Page scanned — ${count} minor observation(s) noted, but no major concerns detected.`
          : "Page scanned — no concerns detected.";

      case this.LEVELS.CAUTION:
        return `ScAIm detected ${count} concern(s) on this page. Proceed with caution and avoid sharing sensitive information.`;

      case this.LEVELS.WARNING:
        return `ScAIm found ${count} suspicious element(s) on this page. Be very careful before entering any personal or financial information.`;

      case this.LEVELS.DANGER:
        return `ScAIm strongly advises extreme caution. This page shows ${count} sign(s) of a potential scam. Do not enter any personal or financial information.`;

      default:
        return `ScAIm scan complete — ${count} finding(s).`;
    }
  }
};
