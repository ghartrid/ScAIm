/**
 * ScAIm Phishing Detector
 * Paranoid analysis of URLs, domains, and login forms.
 */
const PhishingDetector = {
  // Common homoglyph substitutions
  HOMOGLYPHS: {
    "0": "o", "1": "l", "l": "1", "o": "0",
    "rn": "m", "vv": "w", "cl": "d",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x"
  },

  // Known brands that get impersonated
  TARGET_BRANDS: [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "chase", "wellsfargo",
    "bankofamerica", "citibank", "usbank", "capitalone", "americanexpress",
    "dropbox", "adobe", "spotify", "ebay", "walmart", "target",
    "costco", "bestbuy", "ups", "fedex", "usps", "dhl"
  ],

  SUSPICIOUS_TLDS: [
    ".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".icu", ".cam", ".rest", ".surf"
  ],

  scan() {
    const findings = [];
    let score = 0;

    score += this._checkURL(findings);
    score += this._checkDomain(findings);
    score += this._checkLoginForms(findings);
    score += this._checkBrandImpersonation(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Analyze the current URL for phishing indicators.
   */
  _checkURL(findings) {
    let score = 0;
    const url = window.location.href;
    const hostname = window.location.hostname;

    // IP address URL
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      findings.push({
        severity: "critical",
        category: "IP Address URL",
        message: `This page is served from a raw IP address (${hostname}) instead of a domain name — legitimate websites almost never do this. This is a strong indicator of phishing.`
      });
      score += 30;
    }

    // Excessive subdomains
    const parts = hostname.split(".");
    if (parts.length > 4) {
      findings.push({
        severity: "high",
        category: "Excessive Subdomains",
        message: `The URL has ${parts.length - 2} subdomains (${hostname}) — attackers use excessive subdomains to make URLs look like legitimate sites (e.g., "login.paypal.com.malicious-site.xyz").`
      });
      score += 15;
    }

    // Suspicious TLD
    for (const tld of this.SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) {
        findings.push({
          severity: "medium",
          category: "Suspicious Domain Extension",
          message: `This site uses the "${tld}" domain extension — while not always malicious, this extension is disproportionately used for phishing and scam sites.`
        });
        score += 10;
        break;
      }
    }

    // URL-encoded characters in hostname
    if (/%[0-9a-f]{2}/i.test(url.split("/")[2] || "")) {
      findings.push({
        severity: "high",
        category: "Encoded URL",
        message: "The URL contains encoded characters in the domain — this technique is used to disguise the true destination of a link."
      });
      score += 15;
    }

    // Very long URL (common in phishing)
    if (url.length > 200) {
      findings.push({
        severity: "low",
        category: "Long URL",
        message: `This URL is unusually long (${url.length} characters) — excessively long URLs can be used to hide suspicious parameters or the true domain.`
      });
      score += 5;
    }

    // @ symbol in URL authority (used to mask true domain)
    // Only check the authority portion (before the path) to avoid false positives
    // on URLs with @ in query parameters like ?email=user@gmail.com
    const urlAuthority = url.split("//")[1]?.split("/")[0] || "";
    if (urlAuthority.includes("@")) {
      findings.push({
        severity: "high",
        category: "Deceptive URL",
        message: 'This URL contains an "@" symbol — this is a known technique to make a URL appear to point to one site (before the @) while actually going to another (after the @).'
      });
      score += 20;
    }

    return score;
  },

  /**
   * Check for homoglyph/lookalike domains.
   */
  _checkDomain(findings) {
    let score = 0;
    const hostname = window.location.hostname.toLowerCase();

    for (const brand of this.TARGET_BRANDS) {
      // Exact subdomain match is fine (e.g., login.paypal.com)
      if (hostname === brand + ".com" || hostname.endsWith("." + brand + ".com")) {
        continue;
      }

      // Check for lookalikes
      if (this._isSimilarToBrand(hostname, brand)) {
        findings.push({
          severity: "critical",
          category: "Homoglyph Domain",
          message: `The domain "${hostname}" looks similar to "${brand}" but is NOT the real site — this is a common phishing technique using lookalike characters or misspellings.`
        });
        score += 35;
        break; // One finding is enough
      }
    }

    // Check for brand name in subdomain (e.g., paypal.malicious.com)
    const parts = hostname.split(".");
    if (parts.length >= 3) {
      const subdomains = parts.slice(0, -2).join(".");
      for (const brand of this.TARGET_BRANDS) {
        if (subdomains.includes(brand) && !hostname.endsWith(brand + ".com")) {
          findings.push({
            severity: "high",
            category: "Brand in Subdomain",
            message: `The subdomain contains "${brand}" but this is NOT the real ${brand} website — the actual domain is "${parts.slice(-2).join(".")}". Attackers put brand names in subdomains to trick you.`
          });
          score += 20;
          break;
        }
      }
    }

    return score;
  },

  /**
   * Check if a hostname is suspiciously similar to a known brand.
   */
  _isSimilarToBrand(hostname, brand) {
    // Remove TLD for comparison
    const domainBase = hostname.split(".").slice(0, -1).join(".");

    // Check for the brand name with common substitutions
    const variations = [
      brand,
      brand.replace("a", "4"),
      brand.replace("e", "3"),
      brand.replace("i", "1"),
      brand.replace("o", "0"),
      brand.replace("l", "1"),
      brand + "login",
      brand + "secure",
      brand + "verify",
      brand + "account",
      "secure" + brand,
      "login" + brand,
      brand + "-" + "login",
      brand + "-" + "secure"
    ];

    for (const variant of variations) {
      if (domainBase.includes(variant) && domainBase !== brand) {
        return true;
      }
    }

    // Levenshtein distance check (1-2 character difference)
    if (this._levenshtein(domainBase, brand) <= 2 && domainBase !== brand) {
      return true;
    }

    return false;
  },

  /**
   * Simple Levenshtein distance.
   */
  _levenshtein(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b[i - 1] === a[j - 1]) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    return matrix[b.length][a.length];
  },

  /**
   * Check login forms for phishing indicators.
   */
  _checkLoginForms(findings) {
    let score = 0;
    const forms = document.querySelectorAll("form");
    const pageHost = window.location.hostname;

    forms.forEach(form => {
      const hasPassword = form.querySelector('input[type="password"]');
      const hasEmail = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"], input[name*="login"]');

      if (!hasPassword && !hasEmail) return;

      const isLoginForm = hasPassword || hasEmail;
      if (!isLoginForm) return;

      // Login form on HTTP
      if (window.location.protocol === "http:") {
        findings.push({
          severity: "critical",
          category: "Insecure Login",
          message: "This login form is on an unencrypted (HTTP) page — your credentials will be sent in plain text and can be intercepted by anyone."
        });
        score += 25;
      }

      // Login form posting to external domain
      const action = form.getAttribute("action");
      if (action) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname !== pageHost) {
            findings.push({
              severity: "critical",
              category: "External Login Action",
              message: `This login form sends your credentials to ${actionUrl.hostname}, which is different from the current site — this is a strong phishing indicator.`
            });
            score += 30;
          }
        } catch (e) { /* skip */ }
      }
    });

    return score;
  },

  /**
   * Check if page appears to impersonate a known brand.
   */
  _checkBrandImpersonation(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();
    const hostname = window.location.hostname.toLowerCase();

    for (const brand of this.TARGET_BRANDS) {
      // Skip if we're actually on that brand's domain
      if (hostname.includes(brand + ".com") || hostname.includes(brand + ".org")) continue;

      // Check if the page text heavily references the brand AND has a login form
      const brandMentions = (pageText.match(new RegExp(`\\b${brand}\\b`, "gi")) || []).length;
      const hasLoginForm = document.querySelector('input[type="password"]');

      if (brandMentions >= 3 && hasLoginForm) {
        findings.push({
          severity: "high",
          category: "Brand Impersonation",
          message: `This page mentions "${brand}" ${brandMentions} times and contains a login form, but you are NOT on ${brand}'s official website — this page may be impersonating ${brand} to steal your credentials.`
        });
        score += 25;
        break;
      }
    }

    return score;
  }
};
