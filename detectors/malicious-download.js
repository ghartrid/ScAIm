/**
 * ScAIm Malicious Download Detector
 * Detects fake download buttons, dangerous file extensions, fake update prompts,
 * auto-download triggers, deceptive download counts, and drive-by download patterns.
 */
const MaliciousDownloadDetector = {
  // File extensions commonly used in malware
  DANGEROUS_EXTENSIONS: [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".ws", ".wsf", ".wsc", ".wsh", ".ps1", ".psc1", ".msi", ".msp",
    ".com", ".pif", ".hta", ".cpl", ".inf", ".reg", ".rgs",
    ".jar", ".apk", ".app", ".dmg", ".iso", ".img"
  ],

  // Legitimate download sites to reduce false positives
  DOWNLOAD_SITES: [
    "github.com", "gitlab.com", "sourceforge.net", "npmjs.com",
    "pypi.org", "maven.org", "nuget.org", "rubygems.org",
    "developer.apple.com", "developer.android.com", "microsoft.com",
    "adobe.com", "java.com", "mozilla.org", "google.com"
  ],

  scan() {
    const findings = [];
    let score = 0;

    score += this._checkDangerousFileLinks(findings);
    score += this._checkFakeUpdatePrompts(findings);
    score += this._checkFakeDownloadButtons(findings);
    score += this._checkAutoDownloadScripts(findings);
    score += this._checkDeceptiveDownloadCounts(findings);
    score += this._checkDisguisedExtensions(findings);

    return {
      score: Math.min(100, score),
      findings
    };
  },

  /**
   * Check for links to dangerous file types.
   */
  _checkDangerousFileLinks(findings) {
    let score = 0;
    const links = document.querySelectorAll("a[href]");
    const hostname = window.location.hostname.toLowerCase();

    // Skip on known legitimate download sites
    if (this.DOWNLOAD_SITES.some(s => hostname.includes(s))) return 0;

    const dangerousLinks = [];

    links.forEach(link => {
      const href = (link.getAttribute("href") || "").toLowerCase();
      for (const ext of this.DANGEROUS_EXTENSIONS) {
        if (href.endsWith(ext) || href.includes(ext + "?") || href.includes(ext + "#")) {
          dangerousLinks.push({ href, ext, text: (link.textContent || "").trim().substring(0, 60) });
          break;
        }
      }
    });

    // Also check elements with download attribute
    const downloadLinks = document.querySelectorAll("a[download]");
    downloadLinks.forEach(link => {
      const downloadName = (link.getAttribute("download") || "").toLowerCase();
      for (const ext of this.DANGEROUS_EXTENSIONS) {
        if (downloadName.endsWith(ext)) {
          dangerousLinks.push({ href: link.href, ext, text: downloadName });
          break;
        }
      }
    });

    if (dangerousLinks.length > 0) {
      const exts = [...new Set(dangerousLinks.map(l => l.ext))].join(", ");
      const severity = dangerousLinks.length >= 3 ? "critical" : "high";
      findings.push({
        severity,
        category: "Dangerous File Download",
        message: `This page contains ${dangerousLinks.length} link(s) to potentially dangerous file types (${exts}) — executable files downloaded from untrusted sites can install malware, ransomware, or spyware on your device.`
      });
      score += 15 + dangerousLinks.length * 5;
    }

    return Math.min(35, score);
  },

  /**
   * Detect fake software update prompts.
   */
  _checkFakeUpdatePrompts(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();
    const hostname = window.location.hostname.toLowerCase();

    // Skip on actual update domains
    const updateDomains = ["adobe.com", "java.com", "microsoft.com", "mozilla.org",
                           "google.com", "apple.com", "chrome.com"];
    if (updateDomains.some(d => hostname.includes(d))) return 0;

    const updatePatterns = [
      { pattern: /flash\s+player\s+(is\s+)?(out\s+of\s+date|update|required|needs?\s+to\s+be\s+updated)/i, label: "Flash Player update (Flash is discontinued)" },
      { pattern: /java\s+(is\s+)?(out\s+of\s+date|update|required|needs?\s+to\s+be\s+updated)/i, label: "Java update" },
      { pattern: /your\s+browser\s+(is\s+)?(out\s+of\s+date|needs?\s+(an?\s+)?update|outdated|not\s+supported)/i, label: "browser update" },
      { pattern: /(video|media)\s+(player|codec)\s+(is\s+)?(required|needed|missing|not\s+found|update)/i, label: "media codec/player" },
      { pattern: /download\s+(the\s+)?(latest|new|required)\s+(version|update|patch)/i, label: "software update" },
      { pattern: /critical\s+(security\s+)?(update|patch)\s+(is\s+)?(available|required|needed)/i, label: "critical security update" },
      { pattern: /font\s+(was\s+)?not\s+found|install\s+(the\s+)?missing\s+font/i, label: "missing font (malware technique)" }
    ];

    for (const up of updatePatterns) {
      if (up.pattern.test(pageText)) {
        // Flash Player is discontinued — any page asking for it is a scam
        const severity = up.label.includes("Flash") ? "critical" : "high";
        findings.push({
          severity,
          category: "Fake Update Prompt",
          message: `This page claims you need a ${up.label} — ${up.label.includes("Flash") ? "Flash Player was discontinued in 2020 and any website requesting it is a scam." : "legitimate updates come from your operating system or the software itself, NEVER from random websites. Downloading updates from untrusted pages installs malware."}`
        });
        score += severity === "critical" ? 25 : 18;
        break; // One finding per category
      }
    }

    return score;
  },

  /**
   * Detect multiple/fake download buttons.
   */
  _checkFakeDownloadButtons(findings) {
    let score = 0;

    // Find all elements that look like download buttons
    const allElements = document.querySelectorAll("a, button, [role='button'], [class*='btn'], [class*='button']");
    let downloadButtonCount = 0;
    const downloadButtons = [];

    allElements.forEach(el => {
      const text = (el.textContent || "").trim().toLowerCase();
      const classes = (typeof el.className === "string" ? el.className : el.getAttribute("class") || "").toLowerCase();
      const href = (el.getAttribute("href") || "").toLowerCase();

      const isDownloadButton =
        /^download(\s+now)?$/i.test(text) ||
        /^(free\s+)?download$/i.test(text) ||
        /^get\s+(it\s+)?now$/i.test(text) ||
        /^install(\s+now)?$/i.test(text) ||
        (classes.includes("download") && (text.length < 30));

      if (isDownloadButton) {
        downloadButtonCount++;
        downloadButtons.push({
          text: text.substring(0, 40),
          tag: el.tagName.toLowerCase(),
          href: href.substring(0, 80)
        });
      }
    });

    if (downloadButtonCount > 3) {
      findings.push({
        severity: "high",
        category: "Multiple Download Buttons",
        message: `This page has ${downloadButtonCount} download buttons — pages with many download buttons often use decoy buttons to trick you into downloading malware instead of the intended file.`
      });
      score += 15;
    }

    // Check for download buttons that are actually ads or lead to different domains
    const pageHost = window.location.hostname;
    let externalDownloads = 0;

    for (const btn of downloadButtons) {
      if (btn.href && btn.href.startsWith("http")) {
        try {
          const url = new URL(btn.href);
          if (url.hostname !== pageHost) {
            externalDownloads++;
          }
        } catch (e) { /* skip */ }
      }
    }

    if (externalDownloads >= 2) {
      findings.push({
        severity: "high",
        category: "Deceptive Download Buttons",
        message: `${externalDownloads} download buttons on this page link to external domains — these are likely ads or malicious downloads disguised as the real download button.`
      });
      score += 12;
    }

    return Math.min(25, score);
  },

  /**
   * Detect scripts that trigger automatic downloads.
   */
  _checkAutoDownloadScripts(findings) {
    let score = 0;
    const scripts = document.querySelectorAll("script:not([src])");

    scripts.forEach(script => {
      const content = script.textContent || "";

      // Check for programmatic download triggers
      const autoDownloadPatterns = [
        /createElement\s*\(\s*['"]a['"]\s*\)[\s\S]{0,200}\.download\s*=/i,
        /window\.location\s*=\s*['"][^'"]*\.(exe|msi|dmg|apk|bat)/i,
        /location\.href\s*=\s*['"][^'"]*\.(exe|msi|dmg|apk|bat)/i,
        /\.click\(\)[\s\S]{0,50}download/i
      ];

      for (const pattern of autoDownloadPatterns) {
        if (pattern.test(content)) {
          findings.push({
            severity: "high",
            category: "Auto-Download Script",
            message: "This page contains a script that automatically triggers a file download — drive-by downloads are a common malware distribution technique. Cancel any unexpected downloads immediately."
          });
          score += 20;
          return; // Exit forEach callback
        }
      }
    });

    return Math.min(20, score);
  },

  /**
   * Detect deceptive download count claims.
   */
  _checkDeceptiveDownloadCounts(findings) {
    let score = 0;
    const pageText = (document.body?.innerText || "").toLowerCase();
    const hostname = window.location.hostname.toLowerCase();

    // Skip on legitimate app stores
    const appStores = ["play.google.com", "apps.apple.com", "microsoft.com",
                       "chrome.google.com", "addons.mozilla.org"];
    if (appStores.some(s => hostname.includes(s))) return 0;

    // Check for inflated download counts
    const countPatterns = [
      /downloaded\s+(over\s+)?\d[\d,]*\s*(million|\+|times)/i,
      /\d[\d,]*\s*\+?\s*downloads/i,
      /trusted\s+by\s+\d[\d,]*\s*(million|\+)?\s*(users|people|customers)/i
    ];

    for (const pattern of countPatterns) {
      const match = pageText.match(pattern);
      if (match) {
        // Extract the number
        const numMatch = match[0].match(/(\d[\d,]*)/);
        if (numMatch) {
          const num = parseInt(numMatch[1].replace(/,/g, ""));
          if (num >= 1000000) {
            findings.push({
              severity: "low",
              category: "Inflated Download Claims",
              message: `This page claims "${match[0].trim()}" — scam download pages often fabricate large numbers to create false trust. Verify download counts on official app stores.`
            });
            score += 5;
            break;
          }
        }
      }
    }

    return score;
  },

  /**
   * Detect disguised file extensions (e.g., "document.pdf.exe").
   */
  _checkDisguisedExtensions(findings) {
    let score = 0;
    const links = document.querySelectorAll("a[href], a[download]");

    links.forEach(link => {
      const href = link.getAttribute("href") || "";
      const download = link.getAttribute("download") || "";
      const filename = download || href.split("/").pop().split("?")[0];

      if (!filename) return;

      // Check for double extensions (e.g., .pdf.exe, .doc.scr)
      const safeExtensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png",
                              ".gif", ".mp3", ".mp4", ".txt", ".csv", ".zip"];
      const dangerousExtensions = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".msi",
                                   ".pif", ".com", ".hta", ".ps1", ".jar"];

      for (const safe of safeExtensions) {
        for (const dangerous of dangerousExtensions) {
          if (filename.toLowerCase().includes(safe + dangerous)) {
            findings.push({
              severity: "critical",
              category: "Disguised File Extension",
              message: `A download on this page has a disguised filename ("${filename.substring(0, 60)}") — it appears to be a ${safe} file but is actually a ${dangerous} executable. This is a classic malware distribution technique.`
            });
            score += 25;
            return; // Exit forEach callback
          }
        }
      }
    });

    return Math.min(25, score);
  }
};
