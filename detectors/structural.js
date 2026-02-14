/**
 * ScAIm Structural Paranoia Detector
 * The "neurotic expert" core — inspects page DOM and structure
 * for anything remotely suspicious.
 */
const StructuralDetector = {
  scan() {
    const findings = [];
    let score = 0;

    score += this._checkForms(findings);
    score += this._checkExternalScripts(findings);
    score += this._checkIframes(findings);
    score += this._checkLinkSpoofing(findings);
    score += this._checkHTTPS(findings);
    score += this._checkExternalResources(findings);
    score += this._checkObfuscation(findings);
    score += this._checkSensitiveInputs(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Inspect all forms: where they POST, hidden fields, sensitive fields.
   */
  _checkForms(findings) {
    let score = 0;
    const forms = document.querySelectorAll("form");
    if (forms.length === 0) return 0;

    const pageHost = window.location.hostname;

    forms.forEach((form, i) => {
      const action = form.getAttribute("action") || "";
      const method = (form.getAttribute("method") || "get").toLowerCase();

      // Check for external form action
      if (action && method === "post") {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname !== pageHost) {
            findings.push({
              severity: "critical",
              category: "External Form Action",
              message: `Form #${i + 1} submits data to a different domain (${actionUrl.hostname}) — this is a common phishing technique where your data is sent to an attacker-controlled server.`
            });
            score += 30;
          }
        } catch (e) {
          // Malformed URL in action — suspicious
          findings.push({
            severity: "medium",
            category: "Malformed Form",
            message: `Form #${i + 1} has a malformed action URL ("${action.substring(0, 80)}") — this could indicate sloppy development or an attempt to obfuscate the destination.`
          });
          score += 10;
        }
      }

      // Check for hidden inputs
      const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
      if (hiddenInputs.length > 0) {
        findings.push({
          severity: hiddenInputs.length > 3 ? "high" : "medium",
          category: "Hidden Form Fields",
          message: `Form #${i + 1} contains ${hiddenInputs.length} hidden input field(s) — hidden fields can silently collect and transmit data you can't see.`
        });
        score += Math.min(15, hiddenInputs.length * 3);
      }

      // Check for password fields
      const passwordFields = form.querySelectorAll('input[type="password"]');
      if (passwordFields.length > 0 && window.location.protocol !== "https:") {
        findings.push({
          severity: "critical",
          category: "Insecure Password Field",
          message: `Form #${i + 1} has a password field on a non-HTTPS page — your password could be intercepted in transit. Never enter passwords on non-secure pages.`
        });
        score += 25;
      }
    });

    return score;
  },

  /**
   * Flag third-party scripts.
   */
  _checkExternalScripts(findings) {
    let score = 0;
    const scripts = document.querySelectorAll("script[src]");
    const pageHost = window.location.hostname;
    const externalDomains = new Set();

    scripts.forEach(script => {
      try {
        const url = new URL(script.src, window.location.href);
        if (url.hostname !== pageHost) {
          externalDomains.add(url.hostname);
        }
      } catch (e) { /* skip malformed */ }
    });

    if (externalDomains.size > 5) {
      findings.push({
        severity: "medium",
        category: "Excessive External Scripts",
        message: `This page loads scripts from ${externalDomains.size} different external domains — legitimate sites typically load from fewer sources. Each external script is a potential vector for malicious code.`
      });
      score += 10 + (externalDomains.size - 5) * 2;
    }

    return Math.min(25, score);
  },

  /**
   * Flag all iframes, especially hidden/tiny ones.
   */
  _checkIframes(findings) {
    let score = 0;
    const iframes = document.querySelectorAll("iframe");
    if (iframes.length === 0) return 0;

    let hiddenCount = 0;
    const pageHost = window.location.hostname;

    iframes.forEach(iframe => {
      const rect = iframe.getBoundingClientRect();
      const isHidden = rect.width <= 1 || rect.height <= 1 ||
                       iframe.style.display === "none" ||
                       iframe.style.visibility === "hidden" ||
                       iframe.style.opacity === "0";

      if (isHidden) hiddenCount++;

      const src = iframe.getAttribute("src") || "";
      if (src) {
        try {
          const url = new URL(src, window.location.href);
          if (url.hostname !== pageHost && isHidden) {
            findings.push({
              severity: "high",
              category: "Hidden External Iframe",
              message: `A hidden iframe loads content from ${url.hostname} — hidden iframes are commonly used to silently load malicious content, track users, or perform clickjacking attacks.`
            });
            score += 20;
          }
        } catch (e) { /* skip */ }
      }
    });

    if (hiddenCount > 0 && findings.filter(f => f.category === "Hidden External Iframe").length === 0) {
      findings.push({
        severity: "medium",
        category: "Hidden Iframe",
        message: `This page contains ${hiddenCount} hidden iframe(s) — hidden iframes can be used for tracking or loading content without your knowledge.`
      });
      score += hiddenCount * 8;
    }

    if (iframes.length > 3) {
      findings.push({
        severity: "low",
        category: "Multiple Iframes",
        message: `This page embeds ${iframes.length} iframes — while not always malicious, excessive iframes can indicate content injection or ad-heavy sites.`
      });
      score += 5;
    }

    return Math.min(40, score);
  },

  /**
   * Check for links that display one URL but link to another (href spoofing).
   */
  _checkLinkSpoofing(findings) {
    let score = 0;
    const links = document.querySelectorAll("a[href]");
    let spoofCount = 0;

    links.forEach(link => {
      const displayText = (link.textContent || "").trim().toLowerCase();
      const href = (link.getAttribute("href") || "").toLowerCase();

      // Check if display text looks like a URL but doesn't match href
      const urlPattern = /^(https?:\/\/)?[\w.-]+\.\w{2,}/;
      if (urlPattern.test(displayText) && href.startsWith("http")) {
        try {
          const displayDomain = displayText.replace(/^https?:\/\//, "").split("/")[0];
          const hrefDomain = new URL(href, window.location.href).hostname;
          if (displayDomain !== hrefDomain && !hrefDomain.endsWith("." + displayDomain)) {
            spoofCount++;
            if (spoofCount <= 3) { // report first 3 individually
              findings.push({
                severity: "critical",
                category: "Href Spoofing",
                message: `A link displays "${displayText.substring(0, 50)}" but actually points to "${hrefDomain}" — this is a classic phishing technique to trick you into clicking a malicious link.`
              });
            }
            score += 20;
          }
        } catch (e) { /* skip */ }
      }
    });

    if (spoofCount > 3) {
      findings.push({
        severity: "critical",
        category: "Href Spoofing",
        message: `${spoofCount} links on this page show one URL but point to a different domain — this page is systematically deceptive.`
      });
    }

    return Math.min(50, score);
  },

  /**
   * Warn about HTTP pages or mixed content.
   */
  _checkHTTPS(findings) {
    let score = 0;

    if (window.location.protocol === "http:") {
      findings.push({
        severity: "high",
        category: "No HTTPS",
        message: "This page is served over HTTP (not encrypted) — any information you enter can be intercepted by anyone on the same network. Never enter sensitive data on unencrypted pages."
      });
      score += 15;
    }

    return score;
  },

  /**
   * Count how many external domains the page loads resources from.
   */
  _checkExternalResources(findings) {
    const pageHost = window.location.hostname;
    const externalDomains = new Set();

    // Check all elements with src attributes
    const elements = document.querySelectorAll("[src]");
    elements.forEach(el => {
      const src = el.getAttribute("src");
      if (src) {
        try {
          const url = new URL(src, window.location.href);
          if (url.hostname !== pageHost) {
            externalDomains.add(url.hostname);
          }
        } catch (e) { /* skip */ }
      }
    });

    // Check link elements (stylesheets, etc.)
    const linkEls = document.querySelectorAll("link[href]");
    linkEls.forEach(el => {
      try {
        const url = new URL(el.href, window.location.href);
        if (url.hostname !== pageHost) {
          externalDomains.add(url.hostname);
        }
      } catch (e) { /* skip */ }
    });

    if (externalDomains.size > 10) {
      findings.push({
        severity: "medium",
        category: "Excessive External Domains",
        message: `This page loads resources from ${externalDomains.size} different external domains — this increases the attack surface and suggests heavy third-party dependence.`
      });
      return 10;
    }

    return 0;
  },

  /**
   * Detect obfuscated or suspicious inline scripts.
   */
  _checkObfuscation(findings) {
    let score = 0;
    const scripts = document.querySelectorAll("script:not([src])");

    let evalCount = 0;
    let base64Count = 0;
    let docWriteCount = 0;

    scripts.forEach(script => {
      const content = script.textContent || "";
      // Count eval() usage
      const evalMatches = content.match(/\beval\s*\(/g);
      if (evalMatches) evalCount += evalMatches.length;

      // Count base64 patterns
      const b64Matches = content.match(/atob\s*\(|btoa\s*\(|base64/gi);
      if (b64Matches) base64Count += b64Matches.length;

      // Count document.write
      const dwMatches = content.match(/document\.write/g);
      if (dwMatches) docWriteCount += dwMatches.length;
    });

    if (evalCount > 0) {
      findings.push({
        severity: "high",
        category: "Obfuscated Code",
        message: `This page uses eval() ${evalCount} time(s) — eval() executes arbitrary code and is frequently used to hide malicious scripts from inspection.`
      });
      score += evalCount * 8;
    }

    if (base64Count > 2) {
      findings.push({
        severity: "medium",
        category: "Encoded Content",
        message: `This page contains ${base64Count} base64 encoding/decoding operations — while sometimes legitimate, base64 is commonly used to hide malicious payloads from scanners.`
      });
      score += base64Count * 4;
    }

    if (docWriteCount > 0) {
      findings.push({
        severity: "medium",
        category: "Dynamic Content Injection",
        message: `This page uses document.write() ${docWriteCount} time(s) — this can inject content into the page dynamically, potentially altering what you see.`
      });
      score += docWriteCount * 5;
    }

    return Math.min(35, score);
  },

  /**
   * Check for inputs requesting highly sensitive data.
   */
  _checkSensitiveInputs(findings) {
    let score = 0;
    const sensitivePatterns = [
      { pattern: /ssn|social.?security/i, label: "Social Security Number", severity: "critical", points: 25 },
      { pattern: /credit.?card|card.?number/i, label: "Credit Card Number", severity: "high", points: 15 },
      { pattern: /cvv|cvc|security.?code/i, label: "Card Security Code", severity: "high", points: 15 },
      { pattern: /routing.?number/i, label: "Bank Routing Number", severity: "critical", points: 20 },
      { pattern: /passport/i, label: "Passport Number", severity: "high", points: 15 },
      { pattern: /driver.?s?.?licen/i, label: "Driver's License", severity: "high", points: 15 }
    ];

    const inputs = document.querySelectorAll("input, textarea");
    const checkedLabels = new Set();

    inputs.forEach(input => {
      const identifiers = [
        input.getAttribute("name") || "",
        input.getAttribute("id") || "",
        input.getAttribute("placeholder") || "",
        input.getAttribute("aria-label") || ""
      ].join(" ");

      for (const sp of sensitivePatterns) {
        if (sp.pattern.test(identifiers) && !checkedLabels.has(sp.label)) {
          checkedLabels.add(sp.label);
          findings.push({
            severity: sp.severity,
            category: "Sensitive Data Request",
            message: `This page has an input field requesting your ${sp.label} — be absolutely certain you trust this site before providing this information.`
          });
          score += sp.points;
        }
      }
    });

    return Math.min(50, score);
  }
};
