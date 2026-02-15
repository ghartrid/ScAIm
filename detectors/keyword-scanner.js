/**
 * ScAIm Keyword Scanner Engine
 * Scans visible page text for suspicious keywords across all categories.
 * Supports compound scoring — keywords from multiple categories multiply suspicion.
 */
const KeywordScanner = {
  /**
   * Scan the page for keyword matches.
   * @returns {{ score: number, findings: Array, matchedCategories: Set, matches: Array }}
   */
  scan() {
    const rawText = this._extractVisibleText();
    const pageText = typeof TextNormalizer !== "undefined" ? TextNormalizer.normalize(rawText) : rawText;
    const matches = [];
    const categoryScores = {};
    const matchedCategories = new Set();

    for (const [categoryKey, category] of Object.entries(SCAIM_KEYWORDS)) {
      categoryScores[categoryKey] = 0;

      for (const entry of category.keywords) {
        const count = this._countMatches(pageText, entry.term);
        if (count > 0) {
          matchedCategories.add(categoryKey);
          const matchScore = entry.weight * Math.min(count, 5); // cap repeated matches at 5
          categoryScores[categoryKey] += matchScore;
          matches.push({
            term: entry.term,
            category: categoryKey,
            categoryLabel: category.label,
            weight: entry.weight,
            count,
            score: matchScore
          });
        }
      }
    }

    const rawScore = this._calculateRawScore(categoryScores);
    const compoundMultiplier = this._getCompoundMultiplier(matchedCategories);
    const urgencyMultiplier = this._getUrgencyMultiplier(categoryScores, matchedCategories);
    const finalScore = Math.min(100, Math.ceil(rawScore * compoundMultiplier * urgencyMultiplier));

    const findings = this._generateFindings(matches, matchedCategories, finalScore);

    return {
      score: finalScore,
      findings,
      matchedCategories,
      matches
    };
  },

  /**
   * Extract all visible text from the page body.
   */
  _extractVisibleText() {
    if (!document.body) return "";
    // Clone to avoid modifying the actual DOM
    const clone = document.body.cloneNode(true);
    // Extract text from SVG <text> elements before removing SVG containers
    // (scam content can hide in SVG text to evade detection)
    let svgText = "";
    const svgTexts = clone.querySelectorAll("svg text");
    svgTexts.forEach(el => { svgText += " " + (el.textContent || ""); });
    // Remove script, style, and non-visible elements
    const removable = clone.querySelectorAll("script, style, noscript, svg, template");
    removable.forEach(el => el.remove());
    // Use textContent on the cleaned clone (innerText is unreliable on detached nodes)
    return ((clone.textContent || "") + svgText).toLowerCase();
  },

  /**
   * Count case-insensitive, word-boundary-aware matches of a term in text.
   */
  _countMatches(text, term) {
    const escaped = term.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // Use word boundary where possible, but allow partial for short terms
    const pattern = term.length >= 3
      ? new RegExp(`\\b${escaped}\\b`, "gi")
      : new RegExp(escaped, "gi");
    const matches = text.match(pattern);
    return matches ? matches.length : 0;
  },

  /**
   * Sum up category scores into a raw score, normalized to 0-100 range.
   */
  _calculateRawScore(categoryScores) {
    let total = 0;
    for (const score of Object.values(categoryScores)) {
      total += score;
    }
    // Normalize: a raw total of 40+ points maps to ~50 base score
    return Math.min(100, (total / 80) * 100);
  },

  /**
   * Get compound multiplier based on how many categories matched.
   * More categories = exponentially more suspicious.
   */
  _getCompoundMultiplier(matchedCategories) {
    const count = matchedCategories.size;
    if (count <= 1) return 1.0;
    if (count === 2) return 1.5;
    if (count === 3) return 2.0;
    return 2.5; // 4+ categories — very suspicious
  },

  /**
   * If urgency keywords appear alongside other categories, escalate further.
   */
  _getUrgencyMultiplier(categoryScores, matchedCategories) {
    if (!matchedCategories.has("urgency")) return 1.0;
    const hasFinancial = matchedCategories.has("financial") || matchedCategories.has("money");
    const hasData = matchedCategories.has("dataExchange");
    const hasCrypto = matchedCategories.has("crypto");
    if (hasFinancial && hasData) return 1.5; // triple threat
    if (hasCrypto && (hasFinancial || hasData)) return 1.5; // crypto + financial/data + urgency
    if (hasFinancial || hasData || hasCrypto) return 1.3;
    return 1.1;
  },

  /**
   * Generate human-readable, paranoid findings from matches.
   */
  _generateFindings(matches, matchedCategories, _score) {
    const findings = [];

    if (matches.length === 0) return findings;

    // Group matches by category
    const byCategory = {};
    for (const m of matches) {
      if (!byCategory[m.category]) byCategory[m.category] = [];
      byCategory[m.category].push(m);
    }

    // Generate paranoid observations per category
    if (byCategory.financial) {
      const terms = byCategory.financial.map(m => `"${m.term}"`).join(", ");
      findings.push({
        severity: this._severityFromWeight(byCategory.financial),
        category: "Financial",
        message: `This page contains financial terminology (${terms}) — be cautious about any requests for financial information or transactions.`
      });
    }

    if (byCategory.money) {
      const terms = byCategory.money.map(m => `"${m.term}"`).join(", ");
      findings.push({
        severity: this._severityFromWeight(byCategory.money),
        category: "Money/Transaction",
        message: `This page references monetary transactions (${terms}) — verify the legitimacy of any payment requests before proceeding.`
      });
    }

    if (byCategory.dataExchange) {
      const terms = byCategory.dataExchange.map(m => `"${m.term}"`).join(", ");
      findings.push({
        severity: "high",
        category: "Data Exchange",
        message: `This page requests or references personal data (${terms}) — never share sensitive information unless you are certain of the site's legitimacy.`
      });
    }

    if (byCategory.urgency) {
      const terms = byCategory.urgency.map(m => `"${m.term}"`).join(", ");
      findings.push({
        severity: "high",
        category: "Urgency Tactics",
        message: `This page uses pressure language (${terms}) — legitimate organizations rarely demand immediate action. This is a common manipulation technique.`
      });
    }

    if (byCategory.authority) {
      const terms = byCategory.authority.map(m => `"${m.term}"`).join(", ");
      findings.push({
        severity: "high",
        category: "Authority Impersonation",
        message: `This page references authoritative organizations (${terms}) — scammers frequently impersonate authorities to create fear and compliance.`
      });
    }

    if (byCategory.rewardBait) {
      const terms = byCategory.rewardBait.map(m => `"${m.term}"`).join(", ");
      findings.push({
        severity: "medium",
        category: "Reward Bait",
        message: `This page uses reward/prize language (${terms}) — unsolicited prize notifications are almost always scams.`
      });
    }

    if (byCategory.crypto) {
      const terms = byCategory.crypto.map(m => `"${m.term}"`).join(", ");
      findings.push({
        severity: this._severityFromWeight(byCategory.crypto),
        category: "Crypto/Investment",
        message: `This page contains crypto/investment terminology (${terms}) — be extremely cautious of any requests involving seed phrases, private keys, or wallet connections.`
      });
    }

    // Compound warning
    if (matchedCategories.size >= 3) {
      const categoryNames = [...matchedCategories].map(
        c => SCAIM_KEYWORDS[c]?.label || c
      ).join(", ");
      findings.push({
        severity: "critical",
        category: "Compound Risk",
        message: `This page triggers ${matchedCategories.size} different risk categories (${categoryNames}). The combination of these signals significantly increases the likelihood of a scam.`
      });
    }

    return findings;
  },

  /**
   * Determine severity from the max weight of matches in a group.
   */
  _severityFromWeight(matches) {
    const maxWeight = Math.max(...matches.map(m => m.weight));
    if (maxWeight >= 7) return "high";
    if (maxWeight >= 4) return "medium";
    return "low";
  }
};
