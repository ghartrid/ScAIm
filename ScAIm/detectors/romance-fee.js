/**
 * ScAIm Romance & Advance-Fee Scam Detector
 * Detects inheritance scams, advance fee fraud, romance manipulation,
 * platform migration tactics, and Nigerian prince-style patterns.
 */
const RomanceFeeDetector = {
  scan() {
    const findings = [];
    let score = 0;

    score += this._checkAdvanceFeePatterns(findings);
    score += this._checkInheritanceLottery(findings);
    score += this._checkRomanceManipulation(findings);
    score += this._checkPlatformMigration(findings);
    score += this._checkNigerianPrince(findings);
    score += this._checkMilitaryRomance(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Detect advance fee fraud patterns — requests to pay a fee before receiving money.
   */
  _checkAdvanceFeePatterns(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const feePatterns = [
      { pattern: /pay\s+(a\s+)?(small\s+)?(processing|transfer|handling|administrative|customs|clearance|release|delivery)\s+fee/i, label: "processing/transfer fee" },
      { pattern: /(processing|transfer|handling|clearance|release)\s+fee\s+of\s+\$?\d/i, label: "fee with specific amount" },
      { pattern: /fee\s+(is\s+)?(required|needed|necessary)\s+(before|to\s+(release|process|transfer|complete))/i, label: "fee required before release" },
      { pattern: /small\s+(fee|amount|charge|payment)\s+(to\s+)?(unlock|release|process|claim|receive)/i, label: "small fee to unlock funds" },
      { pattern: /tax\s+(clearance|payment|fee)\s+(is\s+)?(required|needed|must\s+be\s+paid)/i, label: "tax clearance fee" },
      { pattern: /insurance\s+fee\s+(for|to|before)/i, label: "insurance fee" },
      { pattern: /pay.*before\s+(you\s+)?(can\s+)?(receive|access|claim|get|withdraw)/i, label: "pay before receiving" }
    ];

    let matchCount = 0;
    const matchedLabels = [];
    for (const fp of feePatterns) {
      if (fp.pattern.test(pageText)) {
        matchCount++;
        matchedLabels.push(fp.label);
      }
    }

    if (matchCount >= 2) {
      findings.push({
        severity: "critical",
        category: "Advance Fee Fraud",
        message: `This page contains ${matchCount} advance fee patterns (${matchedLabels.slice(0, 3).join(", ")}) — this is a textbook advance fee scam. Legitimate transactions NEVER require you to pay fees upfront to receive money.`
      });
      score += 30;
    } else if (matchCount === 1) {
      findings.push({
        severity: "high",
        category: "Advance Fee Pattern",
        message: `This page mentions a ${matchedLabels[0]} — be extremely cautious of any request to pay fees before receiving money or goods. This is the most common pattern in advance fee fraud.`
      });
      score += 15;
    }

    return score;
  },

  /**
   * Detect inheritance and lottery scam patterns.
   */
  _checkInheritanceLottery(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const inheritancePatterns = [
      { pattern: /next\s+of\s+kin/i, weight: 7 },
      { pattern: /beneficiary\s+of\s+(a\s+)?(large\s+)?(sum|amount|fund|estate|inheritance)/i, weight: 8 },
      { pattern: /unclaimed\s+(fund|money|inheritance|estate|deposit|asset)/i, weight: 7 },
      { pattern: /deceased\s+(client|customer|account\s+holder|relative)/i, weight: 7 },
      { pattern: /left\s+(behind\s+)?(a\s+)?(large\s+)?(sum|fortune|inheritance|estate)/i, weight: 5 },
      { pattern: /no\s+(known\s+)?(heir|relative|next\s+of\s+kin)/i, weight: 7 },
      { pattern: /contact\s+(my|our)\s+(lawyer|attorney|barrister|solicitor)/i, weight: 6 },
      { pattern: /will\s+and\s+testament/i, weight: 4 },
      { pattern: /probate\s+(court|process)/i, weight: 4 }
    ];

    let matchCount = 0;
    let maxWeight = 0;
    for (const ip of inheritancePatterns) {
      if (ip.pattern.test(pageText)) {
        matchCount++;
        maxWeight = Math.max(maxWeight, ip.weight);
      }
    }

    if (matchCount >= 3) {
      findings.push({
        severity: "critical",
        category: "Inheritance Scam",
        message: `This page contains ${matchCount} inheritance/estate scam indicators — messages about unclaimed funds, deceased account holders, and beneficiary claims from strangers are virtually always scams.`
      });
      score += 25;
    } else if (matchCount >= 1 && maxWeight >= 7) {
      findings.push({
        severity: "high",
        category: "Inheritance Scam Pattern",
        message: "This page contains language commonly used in inheritance scams — be extremely skeptical of any unsolicited message about unclaimed estates or beneficiary claims."
      });
      score += 12;
    }

    // Lottery scam patterns
    const lotteryPatterns = [
      /you\s+(have\s+)?(been\s+)?selected\s+(as\s+)?(a\s+)?(winner|beneficiary)/i,
      /winning\s+(notification|announcement|claim)/i,
      /lottery\s+(winning|prize|claim|notification|board|commission)/i,
      /your\s+email\s+(was|has\s+been)\s+(randomly\s+)?selected/i,
      /online\s+(raffle|draw|sweepstake)/i,
      /claim\s+your\s+(winning|prize|fund|award)/i
    ];

    let lotteryMatches = 0;
    for (const lp of lotteryPatterns) {
      if (lp.test(pageText)) lotteryMatches++;
    }

    if (lotteryMatches >= 2) {
      findings.push({
        severity: "high",
        category: "Lottery Scam",
        message: `This page contains ${lotteryMatches} lottery/prize scam indicators — you cannot win a lottery you never entered. These scams always lead to advance fee requests.`
      });
      score += 18;
    }

    return Math.min(35, score);
  },

  /**
   * Detect romance manipulation language.
   */
  _checkRomanceManipulation(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const romancePatterns = [
      { pattern: /i('?ve|\s+have)\s+chosen\s+you/i, weight: 7 },
      { pattern: /god\s+(led|brought|sent)\s+me\s+to\s+you/i, weight: 7 },
      { pattern: /i\s+trust\s+you\s+with\s+my\s+(life|everything|heart)/i, weight: 6 },
      { pattern: /you\s+are\s+the\s+only\s+(one|person)\s+i\s+(can\s+)?trust/i, weight: 7 },
      { pattern: /i\s+need\s+your\s+help\s+(urgently|desperately|please)/i, weight: 5 },
      { pattern: /i('?m|\s+am)\s+stranded\s+(in|at|here)/i, weight: 6 },
      { pattern: /send\s+(me\s+)?money\s+(so\s+)?(i\s+)?can\s+(come|visit|travel|fly)/i, weight: 8 },
      { pattern: /i\s+(want|need)\s+to\s+(meet|visit|see)\s+you\s+but/i, weight: 5 },
      { pattern: /my\s+(bank|account)\s+(is|has\s+been)\s+(frozen|blocked|restricted)/i, weight: 6 },
      { pattern: /i\s+can'?t\s+access\s+my\s+(funds?|money|account)\s+(right\s+now|at\s+the\s+moment)/i, weight: 6 }
    ];

    let matchCount = 0;
    let maxWeight = 0;
    for (const rp of romancePatterns) {
      if (rp.pattern.test(pageText)) {
        matchCount++;
        maxWeight = Math.max(maxWeight, rp.weight);
      }
    }

    if (matchCount >= 3) {
      findings.push({
        severity: "high",
        category: "Romance Scam Language",
        message: `This page contains ${matchCount} romance scam manipulation patterns — scammers build emotional connections to exploit trust. Never send money to someone you've only met online.`
      });
      score += 20;
    } else if (matchCount >= 1 && maxWeight >= 7) {
      findings.push({
        severity: "medium",
        category: "Emotional Manipulation",
        message: "This page contains language commonly used in romance scams — be cautious of overly intense emotional appeals from people you don't know well."
      });
      score += 10;
    }

    return score;
  },

  /**
   * Detect requests to move communication to another platform.
   */
  _checkPlatformMigration(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const migrationPatterns = [
      /message\s+me\s+(on|at|via)\s+(whatsapp|telegram|signal|hangouts|viber)/i,
      /add\s+me\s+on\s+(whatsapp|telegram|signal|hangouts|viber|wechat)/i,
      /contact\s+me\s+(on|via|through)\s+(whatsapp|telegram|signal|hangouts)/i,
      /reach\s+me\s+(on|at|via)\s+(whatsapp|telegram|signal)/i,
      /let'?s\s+(move|continue|chat)\s+(on|to|via)\s+(whatsapp|telegram|signal|hangouts)/i,
      /my\s+(whatsapp|telegram)\s+(number|is|:)/i,
      /text\s+me\s+(on|at)\s+\+?\d{10,}/i
    ];

    let matchCount = 0;
    for (const mp of migrationPatterns) {
      if (mp.test(pageText)) matchCount++;
    }

    if (matchCount >= 1) {
      findings.push({
        severity: "medium",
        category: "Platform Migration",
        message: "This page asks you to move communication to WhatsApp, Telegram, or another platform — scammers do this to avoid platform monitoring and reporting. Be cautious of anyone pushing you off the original communication channel."
      });
      score += 10;
    }

    return score;
  },

  /**
   * Detect Nigerian prince / foreign official scam patterns.
   */
  _checkNigerianPrince(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const princePatternsGeneral = [
      { pattern: /foreign\s+government\s+official/i, weight: 7 },
      { pattern: /bank\s+of\s+(nigeria|ghana|south\s+africa|uganda|kenya|senegal)/i, weight: 7 },
      { pattern: /confidential\s+(business|transaction|proposal|matter)/i, weight: 5 },
      { pattern: /business\s+proposal\s+(worth|of)\s+\$?\d/i, weight: 7 },
      { pattern: /over-?invoice/i, weight: 7 },
      { pattern: /diplomatic\s+(bag|courier|channel)/i, weight: 8 },
      { pattern: /consignment\s+(box|trunk|package)/i, weight: 6 },
      { pattern: /your\s+share\s+(will\s+be|is)\s+\d/i, weight: 7 },
      { pattern: /mutual\s+benefit/i, weight: 3 },
      { pattern: /\d+\s*%\s*(of\s+the\s+)?(total\s+)?(fund|sum|amount)\s+(will\s+be\s+)?(for\s+)?you/i, weight: 8 },
      { pattern: /i\s+am\s+(a|the)\s+(director|manager|officer|chairman|prince|minister|governor)/i, weight: 5 }
    ];

    let matchCount = 0;
    let totalWeight = 0;
    for (const pp of princePatternsGeneral) {
      if (pp.pattern.test(pageText)) {
        matchCount++;
        totalWeight += pp.weight;
      }
    }

    if (matchCount >= 3) {
      findings.push({
        severity: "critical",
        category: "419 Advance Fee Scam",
        message: `This page contains ${matchCount} hallmarks of a classic "Nigerian prince" / 419 advance fee scam — foreign officials, confidential business proposals, and percentage splits of large sums are the textbook pattern.`
      });
      score += 30;
    } else if (matchCount >= 2) {
      findings.push({
        severity: "high",
        category: "419 Scam Indicators",
        message: "This page shows multiple indicators of a 419 advance fee scam — be extremely skeptical of unsolicited business proposals involving foreign funds or officials."
      });
      score += 15;
    }

    return Math.min(35, score);
  },

  /**
   * Detect military romance scam patterns.
   */
  _checkMilitaryRomance(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const militaryPatterns = [
      /deployed\s+(overseas|abroad|in\s+(iraq|afghanistan|syria|ukraine))/i,
      /military\s+(leave|papers|discharge)\s+(papers?\s+)?(cost|fee|require)/i,
      /(army|military|navy|marine)\s+(officer|doctor|engineer|general|sergeant)/i,
      /united\s+nations?\s+(mission|peacekeep|deploy)/i,
      /cannot\s+access\s+(my\s+)?(bank|funds?|money)\s+(from|while|during)\s+(here|deployment|overseas)/i
    ];

    let matchCount = 0;
    for (const mp of militaryPatterns) {
      if (mp.test(pageText)) matchCount++;
    }

    // Only flag if military terms appear alongside money/fee patterns
    const hasMoneyRequest = /send\s+money|wire\s+transfer|gift\s+card|western\s+union|moneygram|need\s+(money|fund|help\s+with\s+money)/i.test(pageText);

    if (matchCount >= 2 && hasMoneyRequest) {
      findings.push({
        severity: "high",
        category: "Military Romance Scam",
        message: "This page combines military deployment claims with money requests — military romance scams use fake military identities to build trust before requesting funds for leave papers, travel, or emergencies."
      });
      score += 20;
    } else if (matchCount >= 3) {
      findings.push({
        severity: "medium",
        category: "Military Romance Pattern",
        message: "This page contains multiple military deployment references commonly used in romance scams — verify any military identity independently through official channels."
      });
      score += 10;
    }

    return score;
  }
};
