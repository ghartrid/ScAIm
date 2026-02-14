/**
 * ScAIm Tech Support Scam Detector
 * Detects fake error codes, remote access tool references, phone number urgency,
 * fake system scans, browser lock attempts, and scare tactics.
 */
const TechSupportScamDetector = {
  // Remote access tools commonly abused by scammers
  REMOTE_TOOLS: [
    "teamviewer", "anydesk", "logmein", "ultraviewer", "connectwise",
    "supremo", "splashtop", "ammyy", "rustdesk", "getscreen",
    "screenconnect", "bomgar", "zoho assist"
  ],

  scan() {
    const findings = [];
    let score = 0;

    score += this._checkFakeErrorCodes(findings);
    score += this._checkRemoteAccessTools(findings);
    score += this._checkPhoneNumberUrgency(findings);
    score += this._checkFakeSystemScan(findings);
    score += this._checkBrowserLockAttempts(findings);
    score += this._checkBSODSimulation(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Detect fake Windows/Mac error codes and system alerts.
   */
  _checkFakeErrorCodes(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const errorPatterns = [
      { pattern: /error\s*(code\s*)?#?\s*0x[0-9a-f]{4,8}/i, label: "Windows hex error code" },
      { pattern: /error\s*(code\s*)?#?\s*(DW|DT|SL)\d{4,}/i, label: "fabricated error code" },
      { pattern: /threat\s*id\s*:\s*\d+/i, label: "fake threat ID" },
      { pattern: /error\s*#\s*\d{3,}/i, label: "numbered error code" },
      { pattern: /windows\s+(defender|security|firewall)\s+(alert|warning|error|notification)/i, label: "fake Windows security alert" },
      { pattern: /apple\s+security\s+(alert|warning|breach)/i, label: "fake Apple security alert" },
      { pattern: /trojan\s*(spyware|virus|malware)?\s*(detected|found|alert)/i, label: "fake trojan detection" },
      { pattern: /your\s+(firewall|antivirus|windows\s+defender)\s+(has\s+been\s+)?disabled/i, label: "fake security disabled warning" }
    ];

    let matchCount = 0;
    const matchedLabels = [];
    for (const ep of errorPatterns) {
      if (ep.pattern.test(pageText)) {
        matchCount++;
        matchedLabels.push(ep.label);
      }
    }

    if (matchCount >= 2) {
      findings.push({
        severity: "critical",
        category: "Fake Error Codes",
        message: `This page displays ${matchCount} fake system error indicators (${matchedLabels.slice(0, 3).join(", ")}) — real system errors NEVER appear on web pages. This is a tech support scam designed to frighten you into calling a fake support number.`
      });
      score += 30;
    } else if (matchCount === 1) {
      findings.push({
        severity: "high",
        category: "Fake Error Code",
        message: `This page displays a ${matchedLabels[0]} — legitimate system errors are shown by your operating system, not by websites. Be suspicious of any page claiming your system has errors.`
      });
      score += 15;
    }

    return score;
  },

  /**
   * Detect references to remote access tools.
   */
  _checkRemoteAccessTools(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    const foundTools = [];
    for (const tool of this.REMOTE_TOOLS) {
      if (pageText.includes(tool)) {
        foundTools.push(tool);
      }
    }

    // Remote access tool + phone number or "support" = very suspicious
    if (foundTools.length > 0) {
      const hasPhoneNumber = /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(pageText) ||
                             /\b1[-.\s]?8\d{2}[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(pageText);
      const hasSupport = /support|help\s*desk|technician|agent/i.test(pageText);

      if (hasPhoneNumber || hasSupport) {
        findings.push({
          severity: "critical",
          category: "Remote Access Tool",
          message: `This page references remote access software (${foundTools.join(", ")}) alongside ${hasPhoneNumber ? "a phone number" : "support language"} — tech support scammers ask you to install these tools so they can take control of your computer and steal your data or money.`
        });
        score += 30;
      } else {
        findings.push({
          severity: "medium",
          category: "Remote Access Reference",
          message: `This page mentions remote access software (${foundTools.join(", ")}) — while sometimes legitimate, be cautious if asked to install or run these tools by someone you didn't contact first.`
        });
        score += 8;
      }
    }

    return score;
  },

  /**
   * Detect phone numbers presented with urgency.
   */
  _checkPhoneNumberUrgency(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    // Toll-free numbers (1-800, 1-888, 1-877, 1-866, 1-855, 1-844, 1-833)
    const tollFreePattern = /\b1[-.\s]?8[0-9]{2}[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
    const tollFreeMatches = pageText.match(tollFreePattern);

    if (tollFreeMatches) {
      // Check for urgency language near the number
      const urgencyNearPhone = [
        /call\s+(us\s+)?(now|immediately|right\s+away|today|urgently)/i,
        /call\s+(this|the)\s+(number|helpline|hotline)\s+(now|immediately)/i,
        /dial\s+(now|immediately)/i,
        /speak\s+(to|with)\s+(a\s+)?(technician|agent|specialist|expert)\s+(now|immediately)/i,
        /don'?t\s+(hang\s+up|disconnect)/i,
        /toll[- ]?free\s+(number|helpline|support)/i
      ];

      let hasUrgency = false;
      for (const pattern of urgencyNearPhone) {
        if (pattern.test(pageText)) {
          hasUrgency = true;
          break;
        }
      }

      if (hasUrgency) {
        findings.push({
          severity: "high",
          category: "Urgent Phone Scam",
          message: `This page displays a toll-free number (${tollFreeMatches[0]}) with urgent language pressuring you to call — legitimate companies don't pressure you to call through alarming web pages. Never call numbers displayed on suspicious websites.`
        });
        score += 20;
      }
    }

    return score;
  },

  /**
   * Detect fake system scan animations/progress bars.
   */
  _checkFakeSystemScan(findings) {
    let score = 0;

    // Check for scan-related elements
    const scanElements = document.querySelectorAll(
      '[class*="scan"], [id*="scan"], [class*="scanning"], [id*="scanning"]'
    );

    const threatElements = document.querySelectorAll(
      '[class*="threat"], [class*="virus"], [class*="malware"], [class*="infected"]'
    );

    // Check for progress bars near threat language
    const progressElements = document.querySelectorAll(
      'progress, [role="progressbar"], [class*="progress"], [class*="loading-bar"]'
    );

    const pageText = (document.body?.innerText || "").toLowerCase();
    const hasThreatLanguage = /virus|malware|trojan|threat|infected|spyware|adware|ransomware/i.test(pageText);

    if (scanElements.length > 0 && hasThreatLanguage) {
      findings.push({
        severity: "high",
        category: "Fake System Scan",
        message: "This page appears to simulate a system scan for viruses or malware — websites CANNOT scan your computer. This is a scare tactic used by tech support scammers."
      });
      score += 20;
    }

    if (progressElements.length > 0 && threatElements.length > 0) {
      findings.push({
        severity: "high",
        category: "Fake Scan Animation",
        message: "This page displays a progress bar alongside threat/virus elements — this simulates a fake scan to make you believe your computer is infected."
      });
      score += 15;
    }

    return Math.min(25, score);
  },

  /**
   * Detect browser lock/fullscreen attempts.
   */
  _checkBrowserLockAttempts(findings) {
    let score = 0;

    // Check inline scripts for lock patterns
    const scripts = document.querySelectorAll("script:not([src])");
    let hasLockAttempt = false;

    scripts.forEach(script => {
      const content = script.textContent || "";

      // Fullscreen API abuse
      if (/requestFullscreen|webkitRequestFullscreen|mozRequestFullScreen/i.test(content)) {
        hasLockAttempt = true;
      }

      // Repeated alert/confirm to prevent closing
      if (/while\s*\(.*\)\s*\{[^}]*(alert|confirm)\s*\(/i.test(content)) {
        hasLockAttempt = true;
      }

      // History manipulation to prevent back button
      if (/history\s*\.\s*(pushState|replaceState).*setInterval|setInterval.*history\s*\.\s*(pushState|replaceState)/i.test(content)) {
        hasLockAttempt = true;
      }

      // Window.open loops
      if (/while\s*\(.*\)\s*\{[^}]*window\.open/i.test(content)) {
        hasLockAttempt = true;
      }
    });

    if (hasLockAttempt) {
      findings.push({
        severity: "high",
        category: "Browser Lock Attempt",
        message: "This page contains scripts that attempt to lock your browser (fullscreen, alert loops, or navigation prevention) — this is a common tech support scam technique. You can close the tab using Ctrl+W or the Task Manager."
      });
      score += 20;
    }

    return score;
  },

  /**
   * Detect fake Blue Screen of Death (BSOD) simulation.
   */
  _checkBSODSimulation(findings) {
    let score = 0;

    // Check for full-page blue/red/dark backgrounds with error text
    const body = document.body;
    if (!body) return 0;

    const bodyStyle = window.getComputedStyle(body);
    const bgColor = bodyStyle.backgroundColor;

    // Parse RGB values
    const rgbMatch = bgColor.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
    if (rgbMatch) {
      const r = parseInt(rgbMatch[1]);
      const g = parseInt(rgbMatch[2]);
      const b = parseInt(rgbMatch[3]);

      // Blue screen (BSOD-like)
      const isBluish = b > 150 && r < 50 && g < 50;
      // Dark red (critical error style)
      const isDarkRed = r > 150 && g < 50 && b < 50;

      if (isBluish || isDarkRed) {
        const pageText = (document.body?.innerText || "").toLowerCase();
        if (/error|stop\s+code|your\s+pc\s+ran|problem|restart|crash/i.test(pageText)) {
          findings.push({
            severity: "critical",
            category: "BSOD Simulation",
            message: "This page appears to simulate a Blue Screen of Death or critical system error — real system crashes are handled by your operating system, not displayed on websites. This is a tech support scam."
          });
          score += 30;
        }
      }
    }

    return score;
  }
};
