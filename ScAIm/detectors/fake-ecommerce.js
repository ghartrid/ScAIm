/**
 * ScAIm Fake E-Commerce Detector
 * Detects unrealistic deals, missing trust signals, and suspicious shopping patterns.
 */
const FakeEcommerceDetector = {
  scan() {
    const findings = [];
    let score = 0;

    score += this._checkUnrealisticPricing(findings);
    score += this._checkTrustSignals(findings);
    score += this._checkSuspiciousCheckout(findings);
    score += this._checkFakeReviews(findings);
    score += this._checkPaymentMethods(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Detect unrealistic discounts and pricing.
   */
  _checkUnrealisticPricing(findings) {
    let score = 0;
    const pageText = document.body?.innerText || "";

    // Look for extreme discount patterns
    const discountPatterns = [
      { pattern: /\b(9[0-9]|100)\s*%\s*off\b/gi, label: "90%+ discount" },
      { pattern: /\b(8[0-9])\s*%\s*off\b/gi, label: "80%+ discount" },
      { pattern: /save\s*(9[0-9]|100)\s*%/gi, label: "save 90%+" }
    ];

    for (const dp of discountPatterns) {
      const matches = pageText.match(dp.pattern);
      if (matches && matches.length > 0) {
        findings.push({
          severity: "high",
          category: "Unrealistic Discount",
          message: `This page advertises a ${dp.label} — discounts this extreme are extremely rare from legitimate retailers and are a hallmark of scam shopping sites.`
        });
        score += 15;
        break;
      }
    }

    // Check for suspiciously low prices (e.g., "$1.99" for items that appear expensive)
    const priceElements = document.querySelectorAll(
      '[class*="price"], [class*="cost"], [class*="amount"], [data-price]'
    );

    let veryLowPriceCount = 0;
    priceElements.forEach(el => {
      const text = el.textContent || "";
      const priceMatch = text.match(/\$\s*(\d+\.?\d*)/);
      if (priceMatch) {
        const price = parseFloat(priceMatch[1]);
        if (price > 0 && price < 5) veryLowPriceCount++;
      }
    });

    if (veryLowPriceCount > 3) {
      findings.push({
        severity: "medium",
        category: "Suspiciously Low Prices",
        message: `${veryLowPriceCount} items on this page are priced under $5 — scam sites often list items at impossibly low prices to lure victims.`
      });
      score += 10;
    }

    return score;
  },

  /**
   * Check for missing trust signals that legitimate stores have.
   */
  _checkTrustSignals(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();
    const allLinks = document.querySelectorAll("a");
    const linkTexts = Array.from(allLinks).map(a => (a.textContent || "").toLowerCase());
    const linkHrefs = Array.from(allLinks).map(a => (a.getAttribute("href") || "").toLowerCase());

    // Only run these checks if the page appears to be a shop
    const isShopLike = this._isShopLikePage(pageText);
    if (!isShopLike) return 0;

    // Check for contact information
    const hasContact = linkTexts.some(t => t.includes("contact")) ||
                       linkHrefs.some(h => h.includes("contact")) ||
                       /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/.test(pageText); // phone number

    if (!hasContact) {
      findings.push({
        severity: "high",
        category: "No Contact Information",
        message: "This shopping page has no visible contact information — legitimate online stores always provide a way to reach customer support."
      });
      score += 15;
    }

    // Check for privacy policy
    const hasPrivacy = linkTexts.some(t => t.includes("privacy")) ||
                       linkHrefs.some(h => h.includes("privacy"));
    if (!hasPrivacy) {
      findings.push({
        severity: "medium",
        category: "No Privacy Policy",
        message: "This shopping page has no privacy policy link — legitimate stores are legally required to disclose how they handle your data."
      });
      score += 10;
    }

    // Check for return/refund policy
    const hasReturns = linkTexts.some(t => t.includes("return") || t.includes("refund")) ||
                       linkHrefs.some(h => h.includes("return") || h.includes("refund"));
    if (!hasReturns) {
      findings.push({
        severity: "medium",
        category: "No Return Policy",
        message: "This shopping page has no return or refund policy — scam stores deliberately omit return policies because they don't intend to honor purchases."
      });
      score += 10;
    }

    // Check for about us / company info
    const hasAbout = linkTexts.some(t => t.includes("about")) ||
                     linkHrefs.some(h => h.includes("about"));
    if (!hasAbout) {
      findings.push({
        severity: "low",
        category: "No Company Information",
        message: "This shopping page has no 'About Us' or company information — legitimate businesses want you to know who they are."
      });
      score += 5;
    }

    // Check for physical address
    const hasAddress = /\b\d{1,5}\s+[\w\s]+\b(street|st|avenue|ave|road|rd|blvd|drive|dr|lane|ln|way)\b/i.test(pageText);
    if (!hasAddress && !hasContact) {
      findings.push({
        severity: "medium",
        category: "No Physical Address",
        message: "This shopping page has no physical address — legitimate retailers typically display their business address."
      });
      score += 8;
    }

    return score;
  },

  /**
   * Check for suspicious checkout behavior.
   */
  _checkSuspiciousCheckout(findings) {
    let score = 0;
    const forms = document.querySelectorAll("form");

    forms.forEach(form => {
      const inputs = form.querySelectorAll("input, select, textarea");
      const inputNames = Array.from(inputs).map(i =>
        ((i.getAttribute("name") || "") + " " + (i.getAttribute("placeholder") || "")).toLowerCase()
      ).join(" ");

      // Check if form asks for excessive personal info
      const sensitiveFields = {
        ssn: /ssn|social.?security/i,
        dob: /date.?of.?birth|dob|birthday/i,
        passport: /passport/i,
        license: /driver|license/i,
        mother: /maiden|mother/i
      };

      const foundSensitive = [];
      for (const [key, pattern] of Object.entries(sensitiveFields)) {
        if (pattern.test(inputNames)) {
          foundSensitive.push(key);
        }
      }

      if (foundSensitive.length >= 2) {
        findings.push({
          severity: "critical",
          category: "Excessive Data Collection",
          message: `A form on this page asks for ${foundSensitive.length} types of sensitive personal information (${foundSensitive.join(", ")}) — no legitimate shopping checkout needs this much personal data.`
        });
        score += 25;
      }
    });

    return score;
  },

  /**
   * Detect fake review patterns.
   */
  _checkFakeReviews(findings) {
    let score = 0;

    // Look for review containers
    const reviewElements = document.querySelectorAll(
      '[class*="review"], [class*="testimonial"], [class*="rating"]'
    );

    if (reviewElements.length === 0) return 0;

    // Check for all-5-star patterns
    const starElements = document.querySelectorAll('[class*="star"], [class*="rating"]');
    let fiveStarCount = 0;
    let totalReviews = 0;

    starElements.forEach(el => {
      const text = el.textContent || "";
      if (/5\s*(\/\s*5|stars?|out of)/i.test(text) || /\u2605{5}/.test(text)) {
        fiveStarCount++;
      }
      if (/\d\s*(\/\s*5|stars?|out of)/i.test(text)) {
        totalReviews++;
      }
    });

    if (totalReviews >= 5 && fiveStarCount === totalReviews) {
      findings.push({
        severity: "medium",
        category: "Suspicious Reviews",
        message: `All ${totalReviews} visible reviews appear to be 5-star ratings — a 100% perfect review score is statistically improbable and suggests fabricated reviews.`
      });
      score += 12;
    }

    return score;
  },

  /**
   * Check for unusual payment method requests.
   */
  _checkPaymentMethods(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const suspiciousPayments = [
      { pattern: /pay.*(gift card|itunes|google play card|steam card)/i, label: "gift card payment" },
      { pattern: /pay.*(bitcoin|crypto|ethereum|btc|eth)/i, label: "cryptocurrency payment" },
      { pattern: /pay.*(wire transfer|western union|moneygram)/i, label: "wire transfer payment" },
      { pattern: /pay.*(zelle|venmo|cash\s?app).*only/i, label: "peer-to-peer payment only" }
    ];

    for (const sp of suspiciousPayments) {
      if (sp.pattern.test(pageText)) {
        findings.push({
          severity: "high",
          category: "Suspicious Payment Method",
          message: `This page suggests ${sp.label} — scammers prefer untraceable payment methods. Legitimate stores accept credit cards and offer buyer protection.`
        });
        score += 15;
      }
    }

    return Math.min(30, score);
  },

  /**
   * Heuristic: does this page look like an e-commerce/shopping page?
   */
  _isShopLikePage(pageText) {
    const shopIndicators = [
      /add to cart/i, /buy now/i, /checkout/i, /shopping cart/i,
      /\$\d+\.\d{2}/, /free shipping/i, /add to bag/i,
      /shop now/i, /order now/i, /in stock/i, /out of stock/i
    ];

    let matches = 0;
    for (const pattern of shopIndicators) {
      if (pattern.test(pageText)) matches++;
    }

    return matches >= 2;
  }
};
