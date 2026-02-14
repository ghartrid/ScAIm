/**
 * ScAIm Social Engineering Detector
 * Detects urgency tactics, fake timers, pressure techniques, and manipulation.
 */
const SocialEngineeringDetector = {
  scan() {
    const findings = [];
    let score = 0;

    score += this._checkCountdownTimers(findings);
    score += this._checkPopupsAndModals(findings);
    score += this._checkFakeNotifications(findings);
    score += this._checkExitIntent(findings);
    score += this._checkUrgencyPatterns(findings);
    score += this._checkFearTactics(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Detect countdown timers in the DOM.
   */
  _checkCountdownTimers(findings) {
    let score = 0;
    const pageText = document.body?.innerText || "";

    // Look for timer-like patterns in text (e.g., "05:23:17", "00:14:59")
    const timerPattern = /\b\d{1,2}:\d{2}:\d{2}\b/g;
    const timerMatches = pageText.match(timerPattern);

    if (timerMatches && timerMatches.length > 0) {
      // Check for elements commonly used as countdown containers
      const timerElements = document.querySelectorAll(
        '[class*="countdown"], [class*="timer"], [id*="countdown"], [id*="timer"], ' +
        '[class*="clock"], [class*="expire"], [class*="hurry"]'
      );

      if (timerElements.length > 0 || timerMatches.length > 0) {
        findings.push({
          severity: "high",
          category: "Countdown Timer",
          message: "This page displays a countdown timer — fake urgency timers are a classic manipulation technique. Legitimate offers don't typically pressure you with ticking clocks."
        });
        score += 15;
      }
    }

    // Also check for CSS animations on timer-like elements
    const animatedTimers = document.querySelectorAll(
      '[class*="countdown"][style*="animation"], [class*="timer"][style*="animation"]'
    );
    if (animatedTimers.length > 0) {
      score += 5;
    }

    return score;
  },

  /**
   * Detect aggressive popups and modals.
   */
  _checkPopupsAndModals(findings) {
    let score = 0;

    // Count visible modals/overlays
    const modals = document.querySelectorAll(
      '[class*="modal"], [class*="popup"], [class*="overlay"], [class*="dialog"], ' +
      '[role="dialog"], [role="alertdialog"]'
    );

    let visibleModals = 0;
    modals.forEach(modal => {
      const style = window.getComputedStyle(modal);
      if (style.display !== "none" && style.visibility !== "hidden") {
        visibleModals++;
      }
    });

    if (visibleModals > 1) {
      findings.push({
        severity: "medium",
        category: "Multiple Popups",
        message: `This page shows ${visibleModals} popup/modal elements simultaneously — aggressive popup usage is a common tactic to disorient users and pressure quick decisions.`
      });
      score += 10 + (visibleModals - 1) * 5;
    }

    // Check for full-screen overlays
    const fullScreenOverlays = document.querySelectorAll('[class*="overlay"], [class*="backdrop"]');
    fullScreenOverlays.forEach(overlay => {
      const style = window.getComputedStyle(overlay);
      if (style.position === "fixed" && style.display !== "none" &&
          parseInt(style.zIndex) > 999) {
        findings.push({
          severity: "medium",
          category: "Full-Screen Overlay",
          message: "This page uses a full-screen overlay — these can be used to block content and force interaction with a specific element."
        });
        score += 8;
      }
    });

    return Math.min(25, score);
  },

  /**
   * Detect fake notification badges and alert styling.
   */
  _checkFakeNotifications(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    // Fake notification patterns
    const fakeAlertPatterns = [
      { pattern: /your (computer|device|system) (is|has been) (infected|compromised|hacked)/i, label: "fake infection alert" },
      { pattern: /virus(es)? (detected|found|alert)/i, label: "fake virus warning" },
      { pattern: /windows (has )?detected/i, label: "fake Windows alert" },
      { pattern: /your (computer|mac|pc) is (at risk|in danger)/i, label: "fake device threat" },
      { pattern: /call (this number|us|now|immediately).*\d{3}/i, label: "tech support scam phone number" },
      { pattern: /do not (close|shut|turn off)/i, label: "scare tactic to prevent closing" }
    ];

    for (const fp of fakeAlertPatterns) {
      if (fp.pattern.test(pageText)) {
        findings.push({
          severity: "critical",
          category: "Fake Security Alert",
          message: `This page displays a ${fp.label} — real security warnings come from your operating system or antivirus software, NEVER from a website. This is almost certainly a scam.`
        });
        score += 25;
      }
    }

    return Math.min(50, score);
  },

  /**
   * Detect exit-intent scripts.
   */
  _checkExitIntent(findings) {
    let score = 0;
    let hasExitTrap = false;

    // Check inline scripts for beforeunload patterns (without serializing entire DOM)
    const scripts = document.querySelectorAll("script:not([src])");
    scripts.forEach(script => {
      if (/beforeunload|onbeforeunload/.test(script.textContent || "")) {
        hasExitTrap = true;
      }
    });

    // Also check for onbeforeunload attribute on body/html
    if (!hasExitTrap) {
      const body = document.body;
      const html = document.documentElement;
      if ((body && body.hasAttribute("onbeforeunload")) ||
          (html && html.hasAttribute("onbeforeunload"))) {
        hasExitTrap = true;
      }
    }

    if (hasExitTrap) {
      findings.push({
        severity: "medium",
        category: "Exit Prevention",
        message: "This page attempts to prevent you from leaving — exit-intent traps are used to keep you on scam pages. You can always close the tab directly."
      });
      score += 10;
    }

    return score;
  },

  /**
   * Check for urgency language patterns beyond keyword matching.
   */
  _checkUrgencyPatterns(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    // Check for specific threatening/urgent sentence patterns
    const urgentPatterns = [
      { pattern: /your account (will be|has been) (suspended|closed|terminated|locked|disabled)/i, msg: "account suspension threat" },
      { pattern: /unauthorized (access|transaction|activity|login|charge)/i, msg: "unauthorized activity claim" },
      { pattern: /(verify|confirm) (your|the) (account|identity|information) (within|before|by)/i, msg: "verification deadline" },
      { pattern: /failure to (respond|verify|confirm|update|comply) (will|may) result/i, msg: "consequence threat" },
      { pattern: /we (will|may) (suspend|close|terminate|restrict|limit) your/i, msg: "service restriction threat" }
    ];

    for (const up of urgentPatterns) {
      if (up.pattern.test(pageText)) {
        findings.push({
          severity: "high",
          category: "Threatening Language",
          message: `This page contains a ${up.msg} — legitimate organizations communicate account issues through secure channels, not through threatening web pages.`
        });
        score += 12;
      }
    }

    return Math.min(30, score);
  },

  /**
   * Check for fear-based manipulation tactics.
   */
  _checkFearTactics(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();

    // Check for emotional manipulation
    const fearPatterns = [
      { pattern: /someone (is|may be) (using|accessing|stealing)/i, msg: "someone is accessing your account" },
      { pattern: /your (data|identity|information) (is|has been|may be) (compromised|stolen|at risk|leaked)/i, msg: "data breach claim" },
      { pattern: /we (noticed|detected) (suspicious|unusual|unauthorized)/i, msg: "suspicious activity claim" },
      { pattern: /(police|authorities|fbi|irs) (will|may) (be contacted|investigate)/i, msg: "law enforcement threat" }
    ];

    for (const fp of fearPatterns) {
      if (fp.pattern.test(pageText)) {
        findings.push({
          severity: "high",
          category: "Fear Manipulation",
          message: `This page claims "${fp.msg}" — scammers use fear to override your critical thinking. Take a breath and verify any claims through official channels.`
        });
        score += 15;
      }
    }

    return Math.min(30, score);
  }
};
