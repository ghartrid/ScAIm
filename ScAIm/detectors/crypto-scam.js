/**
 * ScAIm Crypto & Investment Scam Detector
 * Detects fake trading platforms, pump-and-dump language, rug pull patterns,
 * unrealistic ROI promises, fake endorsements, and seed phrase theft attempts.
 */
const CryptoScamDetector = {
  // Celebrities commonly impersonated in crypto scams
  FAKE_ENDORSERS: [
    "elon musk", "mark zuckerberg", "jeff bezos", "bill gates",
    "warren buffett", "chamath", "mr beast", "andrew tate",
    "richard branson", "tim cook", "satoshi"
  ],

  scan() {
    const findings = [];
    let score = 0;

    score += this._checkSeedPhraseTheft(findings);
    score += this._checkFakeTradingPlatform(findings);
    score += this._checkPumpAndDump(findings);
    score += this._checkRugPull(findings);
    score += this._checkUnrealisticROI(findings);
    score += this._checkFakeEndorsements(findings);
    score += this._checkWalletConnectScam(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Critical: detect attempts to steal wallet seed/recovery phrases.
   */
  _checkSeedPhraseTheft(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const seedPatterns = [
      { pattern: /enter\s+(your\s+)?(seed|recovery|mnemonic)\s+phrase/i, label: "seed phrase entry" },
      { pattern: /input\s+(your\s+)?(12|24)\s*(-|\s)?word\s+(phrase|seed|recovery)/i, label: "12/24-word phrase request" },
      { pattern: /paste\s+(your\s+)?private\s+key/i, label: "private key paste request" },
      { pattern: /enter\s+(your\s+)?private\s+key/i, label: "private key entry" },
      { pattern: /verify\s+(your\s+)?wallet.*seed/i, label: "wallet seed verification" },
      { pattern: /recover\s+(your\s+)?wallet.*phrase/i, label: "wallet recovery phrase request" },
      { pattern: /import\s+wallet.*seed\s+phrase/i, label: "wallet import via seed" }
    ];

    for (const sp of seedPatterns) {
      if (sp.pattern.test(pageText)) {
        findings.push({
          severity: "critical",
          category: "Seed Phrase Theft",
          message: `This page requests your ${sp.label} — NEVER enter your seed phrase or private key on any website. This is almost certainly an attempt to steal your crypto wallet.`
        });
        score += 35;
        break; // One finding is enough for critical
      }
    }

    // Also check for input fields specifically asking for seed phrases
    const inputs = document.querySelectorAll("input, textarea");
    for (const input of inputs) {
      const attrs = [
        input.getAttribute("name") || "",
        input.getAttribute("id") || "",
        input.getAttribute("placeholder") || "",
        input.getAttribute("aria-label") || ""
      ].join(" ").toLowerCase();

      if (/seed.?phrase|recovery.?phrase|private.?key|mnemonic/i.test(attrs)) {
        if (score === 0) { // Only if not already flagged
          findings.push({
            severity: "critical",
            category: "Seed Phrase Theft",
            message: "This page has an input field requesting a crypto wallet seed phrase or private key — legitimate wallets NEVER ask you to enter these on a website."
          });
          score += 35;
        }
        break;
      }
    }

    return score;
  },

  /**
   * Detect fake trading platform indicators.
   */
  _checkFakeTradingPlatform(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const platformPatterns = [
      { pattern: /connect\s+(your\s+)?wallet/i, weight: 6 },
      { pattern: /trading\s+bot/i, weight: 5 },
      { pattern: /mining\s+contract/i, weight: 6 },
      { pattern: /liquidity\s+pool/i, weight: 4 },
      { pattern: /staking\s+reward/i, weight: 4 },
      { pattern: /yield\s+farm/i, weight: 4 },
      { pattern: /flash\s+loan/i, weight: 5 },
      { pattern: /arbitrage\s+(bot|opportunity|profit)/i, weight: 6 },
      { pattern: /auto.?trading\s+(platform|system|software)/i, weight: 6 }
    ];

    let matchCount = 0;
    let totalWeight = 0;
    for (const pp of platformPatterns) {
      if (pp.pattern.test(pageText)) {
        matchCount++;
        totalWeight += pp.weight;
      }
    }

    if (matchCount >= 3) {
      findings.push({
        severity: "high",
        category: "Fake Trading Platform",
        message: `This page contains ${matchCount} crypto trading buzzwords — scam sites use legitimate-sounding DeFi terminology to appear credible. Verify any platform independently before connecting your wallet.`
      });
      score += Math.min(25, totalWeight);
    } else if (matchCount >= 1) {
      // Single match is just informational in combination with other signals
      score += matchCount * 3;
    }

    return score;
  },

  /**
   * Detect pump-and-dump language.
   */
  _checkPumpAndDump(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const pumpPatterns = [
      /guaranteed\s+(returns?|profits?|gains?|income)/i,
      /passive\s+income\s+(daily|weekly|monthly|guaranteed)/i,
      /get\s+rich\s+(quick|fast|now)/i,
      /financial\s+freedom\s+(today|now|guaranteed)/i,
      /life.?changing\s+(returns?|profits?|money|opportunity)/i,
      /next\s+(100|1000)x/i,
      /moon\s*(shot|ing)|to\s+the\s+moon/i,
      /don'?t\s+miss\s+(this|out|the\s+opportunity)/i
    ];

    let matchCount = 0;
    for (const pattern of pumpPatterns) {
      if (pattern.test(pageText)) matchCount++;
    }

    if (matchCount >= 2) {
      findings.push({
        severity: "high",
        category: "Pump-and-Dump Language",
        message: `This page uses ${matchCount} pump-and-dump phrases promising unrealistic gains — legitimate investments never guarantee returns. This is a hallmark of crypto scams.`
      });
      score += 15 + matchCount * 3;
    }

    return Math.min(30, score);
  },

  /**
   * Detect rug pull patterns.
   */
  _checkRugPull(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const rugPullPatterns = [
      { pattern: /presale|pre-sale|pre\s+sale/i, weight: 4 },
      { pattern: /whitelist\s+spot/i, weight: 5 },
      { pattern: /limited\s+(token\s+)?supply/i, weight: 4 },
      { pattern: /fair\s+launch/i, weight: 3 },
      { pattern: /early\s+(investor|adopter|bird)\s+(bonus|reward|discount)/i, weight: 6 },
      { pattern: /token\s+(burn|burning)/i, weight: 3 },
      { pattern: /send\s+(\w+\s+)?to\s+(this\s+)?(address|wallet)\s+(to\s+)?receive/i, weight: 9 },
      { pattern: /double\s+your\s+(crypto|bitcoin|eth|token|coin)/i, weight: 9 }
    ];

    let matchCount = 0;
    let maxWeight = 0;
    for (const rp of rugPullPatterns) {
      if (rp.pattern.test(pageText)) {
        matchCount++;
        maxWeight = Math.max(maxWeight, rp.weight);
      }
    }

    // "Send to address to receive" is critical on its own
    if (maxWeight >= 9) {
      findings.push({
        severity: "critical",
        category: "Crypto Doubling Scam",
        message: "This page claims you can double your crypto by sending to an address — this is a classic and extremely common crypto scam. Any crypto you send will be stolen."
      });
      score += 30;
    } else if (matchCount >= 2) {
      findings.push({
        severity: "medium",
        category: "Rug Pull Indicators",
        message: `This page shows ${matchCount} rug pull warning signs (presale, limited supply, early investor bonuses) — many fraudulent token projects use these tactics to attract victims before disappearing with funds.`
      });
      score += 10 + matchCount * 3;
    }

    return Math.min(35, score);
  },

  /**
   * Detect unrealistic ROI promises.
   */
  _checkUnrealisticROI(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    // Match patterns like "50% daily return", "1000% APY", "200% monthly profit"
    const roiPattern = /(\d{2,})%\s*(daily|weekly|monthly|annual|apy|apr|roi|return|profit|yield|gain)/gi;
    const matches = pageText.match(roiPattern);

    if (matches) {
      // Check if any of the percentages are unrealistic
      for (const match of matches) {
        const percentMatch = match.match(/(\d+)%/);
        if (percentMatch) {
          const pct = parseInt(percentMatch[1]);
          const isDaily = /daily/i.test(match);
          const isWeekly = /weekly/i.test(match);
          const isMonthly = /monthly/i.test(match);

          // Flag unrealistic rates
          if ((isDaily && pct > 1) || (isWeekly && pct > 10) ||
              (isMonthly && pct > 30) || pct >= 1000) {
            findings.push({
              severity: "high",
              category: "Unrealistic ROI",
              message: `This page promises "${match.trim()}" — no legitimate investment can sustain these returns. This is a classic Ponzi/scam pattern where early investors are paid with new victims' money.`
            });
            score += 20;
            break;
          }
        }
      }
    }

    return score;
  },

  /**
   * Detect fake celebrity endorsements for crypto.
   */
  _checkFakeEndorsements(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();
    const hostname = window.location.hostname.toLowerCase();

    // Skip on legitimate news/social media sites
    const newsSites = ["cnn.com", "bbc.com", "reuters.com", "bloomberg.com",
                       "twitter.com", "x.com", "reddit.com", "youtube.com",
                       "forbes.com", "cnbc.com", "nytimes.com"];
    if (newsSites.some(s => hostname.includes(s))) return 0;

    const cryptoTerms = /crypto|bitcoin|btc|ethereum|eth|token|coin|blockchain|defi|nft|invest/i;
    if (!cryptoTerms.test(pageText)) return 0; // Only check if page is crypto-related

    for (const celebrity of this.FAKE_ENDORSERS) {
      const namePattern = new RegExp(`\\b${celebrity.replace(/\s+/g, "\\s+")}\\b`, "gi");
      const mentions = (pageText.match(namePattern) || []).length;

      if (mentions >= 2) {
        findings.push({
          severity: "medium",
          category: "Fake Celebrity Endorsement",
          message: `This crypto page mentions "${celebrity}" ${mentions} times — scammers frequently use fake celebrity endorsements to create false credibility for fraudulent investments.`
        });
        score += 12;
        break;
      }
    }

    return score;
  },

  /**
   * Detect wallet connect phishing (fake dApp connection pages).
   */
  _checkWalletConnectScam(findings) {
    let score = 0;
    const hostname = window.location.hostname.toLowerCase();

    // Check for wallet brand impersonation in domain
    const walletBrands = ["metamask", "trustwallet", "phantom", "coinbase",
                          "ledger", "trezor", "exodus", "atomic"];

    for (const brand of walletBrands) {
      if (hostname.includes(brand) &&
          !hostname.endsWith(brand + ".io") &&
          !hostname.endsWith(brand + ".com") &&
          !hostname.endsWith(brand + ".app")) {
        findings.push({
          severity: "critical",
          category: "Wallet Impersonation",
          message: `The domain "${hostname}" contains "${brand}" but is NOT the official ${brand} website — this is likely a phishing page designed to steal your wallet credentials.`
        });
        score += 30;
        break;
      }
    }

    // Check for multiple wallet connect buttons (scam sites often show many wallet options)
    const walletButtons = document.querySelectorAll(
      '[class*="wallet"], [id*="wallet"], [class*="connect"], [data-wallet]'
    );
    const walletButtonTexts = Array.from(walletButtons)
      .map(el => (el.textContent || "").toLowerCase())
      .filter(t => /metamask|trust|phantom|coinbase|ledger|walletconnect|connect/i.test(t));

    if (walletButtonTexts.length >= 4) {
      findings.push({
        severity: "high",
        category: "Suspicious Wallet Connect",
        message: `This page displays ${walletButtonTexts.length} wallet connection options — phishing sites often present multiple wallet choices to cast a wide net for victims.`
      });
      score += 15;
    }

    return score;
  }
};
