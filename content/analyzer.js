/**
 * ScAIm Analyzer — Content Script Orchestrator
 * Runs all paranoid detectors, aggregates results, and triggers the banner.
 * Checks domain allowlist/blocklist before running detectors.
 * Handles SPA navigation (pushState/replaceState/popstate) for dynamic sites.
 */
const ScaimAnalyzer = {
  _hasRun: false,
  _results: null,
  _lastUrl: null,
  _debounceTimer: null,
  _navigationPatched: false,
  _bannerCallId: 0,

  /**
   * Run the full paranoid analysis pipeline.
   */
  run() {
    if (this._hasRun) return;
    this._hasRun = true;
    this._lastUrl = window.location.href;

    // Check if extension is enabled before running
    chrome.storage.local.get("enabled", (result) => {
      if (result.enabled === false) return;
      this._analyzeWithDomainCheck();
    });
  },

  /**
   * Check domain lists before running full analysis.
   */
  async _analyzeWithDomainCheck() {
    try {
      // Initialize domain lists from storage
      await DomainLists.init();

      const hostname = window.location.hostname;

      // Check allowlist — skip scanning entirely
      if (DomainLists.isAllowed(hostname)) {
        const assessment = {
          level: "safe",
          score: 0,
          findings: [],
          summary: "This site is on your trusted allowlist — analysis skipped.",
          allowlisted: true
        };
        this._results = assessment;
        this._sendToBackground(assessment);
        return;
      }

      // Check blocklist — auto-flag as danger
      const blockMatch = DomainLists.isBlocked(hostname);
      if (blockMatch) {
        const assessment = {
          level: "danger",
          score: 100,
          findings: [{
            severity: "critical",
            category: "Blocklisted Domain",
            message: `This domain (${hostname}) is on the ${blockMatch.source === "builtin" ? "ScAIm built-in" : "your custom"} blocklist — category: ${blockMatch.category}. This site has been identified as potentially dangerous.`
          }],
          summary: `This domain is blocklisted (${blockMatch.category}). Exercise extreme caution.`,
          blocklisted: true
        };
        this._results = assessment;
        this._sendToBackground(assessment);
        this._showBannerIfAllowed(assessment);
        return;
      }

      // No list match — run full analysis
      this._analyze();

      // On social media sites, also start the post-level scanner
      if (typeof SocialMediaScanner !== "undefined") {
        SocialMediaScanner.init();
      }
    } catch (err) {
      // If domain list check fails, still run analysis
      console.error("[ScAIm] Domain list check error:", err);
      this._analyze();
    }
  },

  /**
   * Internal: perform the actual analysis with all detectors.
   */
  _analyze() {
    try {
      // Preserve social media findings added during re-analysis (race condition fix:
      // addSocialFindings() may write while _analyze() is running asynchronously)
      const existingSocialFindings = this._results
        ? this._results.findings.filter(f => f.category && f.category.startsWith("Social: "))
        : [];

      // Run all detectors
      const keywordResults = KeywordScanner.scan();
      const structuralResults = StructuralDetector.scan();
      const phishingResults = PhishingDetector.scan();
      const socialResults = SocialEngineeringDetector.scan();
      const ecommerceResults = FakeEcommerceDetector.scan();
      const cryptoResults = CryptoScamDetector.scan();
      const techSupportResults = TechSupportScamDetector.scan();
      const romanceFeeResults = RomanceFeeDetector.scan();
      const downloadResults = MaliciousDownloadDetector.scan();

      // Aggregate scores
      const assessment = ScaimScoring.aggregate({
        keywords: keywordResults,
        structural: structuralResults,
        phishing: phishingResults,
        socialEngineering: socialResults,
        fakeEcommerce: ecommerceResults,
        cryptoScam: cryptoResults,
        techSupport: techSupportResults,
        romanceFee: romanceFeeResults,
        maliciousDownload: downloadResults
      });

      // Merge back preserved social findings (prevents race condition loss)
      if (existingSocialFindings.length > 0) {
        const existingCats = new Set(assessment.findings.map(f => f.category));
        for (const sf of existingSocialFindings) {
          if (!existingCats.has(sf.category)) {
            assessment.findings.push(sf);
          }
        }
      }

      this._results = assessment;

      // Send results to background service worker
      this._sendToBackground(assessment);

      // Show banner if threat level is caution or above
      if (assessment.level !== ScaimScoring.LEVELS.SAFE) {
        this._showBannerIfAllowed(assessment);
      }
    } catch (err) {
      console.error("[ScAIm] Analysis error:", err);
    }
  },

  /**
   * Show banner respecting the user's notification mode setting.
   */
  _showBannerIfAllowed(assessment) {
    const callId = ++this._bannerCallId;
    chrome.storage.local.get("notificationMode", (result) => {
      if (callId !== this._bannerCallId) return; // stale callback
      const mode = result.notificationMode || "full";
      if (mode === "full") {
        ScaimBanner.show(assessment);
      } else if (mode === "lite") {
        ScaimBanner.showLite(assessment);
      }
      // silent: no banner
    });
  },

  /**
   * Send assessment results to the background service worker.
   */
  _sendToBackground(assessment) {
    try {
      chrome.runtime.sendMessage({
        type: "SCAIM_RESULTS",
        data: {
          level: assessment.level,
          score: assessment.score,
          summary: assessment.summary,
          findingCount: assessment.findings.length,
          findings: assessment.findings,
          url: window.location.href,
          hostname: window.location.hostname,
          allowlisted: assessment.allowlisted || false,
          blocklisted: assessment.blocklisted || false
        }
      });
    } catch (e) {
      // Extension context may be invalidated — ignore
    }
  },

  /**
   * Re-run analysis (e.g., after SPA navigation or significant DOM changes).
   */
  rerun() {
    this._hasRun = false;
    this._results = null; // Clear stale data so popup doesn't show old page's results
    this._lastUrl = window.location.href;
    ScaimBanner.remove();
    this.run();
  },

  /**
   * Get the latest results (for popup queries).
   */
  getResults() {
    return this._results;
  },

  /**
   * Receive scam findings from the social media post scanner.
   * Merges them into the page-level results and shows the banner
   * so the user sees both inline warnings AND the page-level alert.
   */
  addSocialFindings(findings) {
    if (!findings || findings.length === 0) return;

    // Ensure we have a base result to merge into
    if (!this._results) {
      this._results = { level: "safe", score: 0, findings: [], summary: "" };
    }

    // Convert social media findings to page-level format and merge
    const newFindings = findings.map(f => ({
      severity: f.severity || "medium",
      category: "Social: " + (f.category || "Suspicious Content"),
      message: f.detail || f.category || "Suspicious content detected in post"
    }));

    // Avoid duplicates — only add findings with new categories
    const existingCategories = new Set(this._results.findings.map(f => f.category));
    for (const f of newFindings) {
      if (!existingCategories.has(f.category)) {
        this._results.findings.push(f);
        existingCategories.add(f.category);
      }
    }

    // Recalculate severity level based on merged findings
    const severityScore = { critical: 40, high: 25, medium: 15, low: 5 };
    let socialScore = 0;
    for (const f of this._results.findings) {
      socialScore += severityScore[f.severity] || 5;
    }
    socialScore = Math.min(socialScore, 100);

    if (socialScore > this._results.score) {
      this._results.score = socialScore;
    }

    // Update threat level
    if (this._results.score >= 70) {
      this._results.level = "danger";
      this._results.summary = "Scam content detected in posts/messages on this page.";
    } else if (this._results.score >= 40) {
      this._results.level = "warning";
      this._results.summary = "Suspicious content found in posts/messages on this page.";
    } else if (this._results.score >= 15) {
      this._results.level = "caution";
      this._results.summary = "Some suspicious content detected in posts/messages.";
    }

    // Show/update the banner if threat level elevated
    if (this._results.level !== "safe") {
      this._showBannerIfAllowed(this._results);
    }

    // Update background with merged results
    this._sendToBackground(this._results);
  },

  /**
   * Install SPA navigation hooks using URL polling + popstate.
   * Avoids inline script injection which violates CSP on many sites.
   */
  installNavigationHooks() {
    if (this._navigationPatched) return;
    this._navigationPatched = true;

    const self = this;

    // Listen for browser back/forward
    window.addEventListener("popstate", () => self._onUrlChange());

    // Poll for URL changes caused by pushState/replaceState.
    // Content scripts can't monkey-patch the page's history API without
    // injecting inline scripts, which CSP blocks on many sites.
    setInterval(() => {
      try { void chrome.runtime.id; } catch (e) { return; } // Context invalidated
      if (window.location.href !== self._lastUrl) {
        self._onUrlChange();
      }
    }, 1000);
  },

  /**
   * Handle URL changes from SPA navigation.
   */
  _onUrlChange() {
    const currentUrl = window.location.href;
    if (currentUrl === this._lastUrl) return;

    // URL has changed — schedule a re-analysis after content loads
    clearTimeout(this._debounceTimer);
    this._debounceTimer = setTimeout(() => {
      this.rerun();
      // Also re-scan social media posts
      if (typeof SocialMediaScanner !== "undefined" && SocialMediaScanner.isSocialMedia()) {
        SocialMediaScanner.scanAllPosts();
      }
    }, 1500);
  }
};

// Guard against duplicate injection (popup auto-inject can re-load scripts).
// Use a property keyed to our extension ID so the host page cannot set it
// to suppress ScAIm (window.__scaimLoaded was directly accessible to any page).
const _scaimGuardKey = "__scaim_" + chrome.runtime.id;
if (window[_scaimGuardKey]) {
  // Already loaded — skip re-initialization
} else {
window[_scaimGuardKey] = true;

// Listen for messages from popup/background (inside guard to prevent duplicate listeners)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAIM_GET_RESULTS") {
    if (ScaimAnalyzer._results) {
      sendResponse(ScaimAnalyzer._results);
    } else {
      // No results yet — run a synchronous scan on the spot and return results.
      try {
        const assessment = ScaimScoring.aggregate({
          keywords: KeywordScanner.scan(),
          structural: StructuralDetector.scan(),
          phishing: PhishingDetector.scan(),
          socialEngineering: SocialEngineeringDetector.scan(),
          fakeEcommerce: FakeEcommerceDetector.scan(),
          cryptoScam: CryptoScamDetector.scan(),
          techSupport: TechSupportScamDetector.scan(),
          romanceFee: RomanceFeeDetector.scan(),
          maliciousDownload: MaliciousDownloadDetector.scan()
        });
        ScaimAnalyzer._results = assessment;
        ScaimAnalyzer._hasRun = true;
        ScaimAnalyzer._sendToBackground(assessment);
        sendResponse(assessment);
      } catch (err) {
        sendResponse({ level: "safe", score: 0, findings: [], summary: "Scan pending" });
      }
    }
  } else if (message.type === "SCAIM_RERUN") {
    ScaimAnalyzer.rerun();
    sendResponse({ ok: true });
  } else if (message.type === "SCAIM_MODE_CHANGED") {
    if (message.mode === "silent") {
      ScaimBanner.remove();
    } else if (ScaimAnalyzer._results && ScaimAnalyzer._results.level !== "safe") {
      ScaimBanner.remove();
      ScaimAnalyzer._showBannerIfAllowed(ScaimAnalyzer._results);
    }
    sendResponse({ ok: true });
  } else if (message.type === "SCAIM_ALLOWLIST_ADD") {
    DomainLists.addToAllowlist(message.hostname).then(() => {
      ScaimAnalyzer.rerun();
      sendResponse({ ok: true });
    });
    return true; // Async response
  } else if (message.type === "SCAIM_BLOCKLIST_ADD") {
    DomainLists.addToBlocklist(message.hostname).then(() => {
      ScaimAnalyzer.rerun();
      sendResponse({ ok: true });
    });
    return true; // Async response
  }
});

// Run analysis on page load
ScaimAnalyzer.run();

// Install SPA navigation hooks
ScaimAnalyzer.installNavigationHooks();

// Observe DOM mutations — re-analyze on significant changes
const scaimObserver = new MutationObserver((mutations) => {
  let significantChange = false;
  let addedTextLength = 0;

  for (const mutation of mutations) {
    if (mutation.addedNodes.length > 5 || mutation.removedNodes.length > 5) {
      significantChange = true;
      break;
    }
    for (const node of mutation.addedNodes) {
      if (node.nodeType === Node.ELEMENT_NODE) {
        if (node.tagName === "FORM" || node.querySelector?.("form")) {
          significantChange = true;
          break;
        }
        // Track text content size of added elements
        addedTextLength += (node.textContent || "").length;
      }
    }
    if (significantChange) break;
  }

  // Significant if lots of text content was added (dynamic content loaded)
  if (addedTextLength > 500) significantChange = true;

  if (significantChange) {
    clearTimeout(ScaimAnalyzer._debounceTimer);
    ScaimAnalyzer._debounceTimer = setTimeout(() => {
      ScaimAnalyzer.rerun();
    }, 2000);
  }
});

if (document.body) {
  scaimObserver.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Delayed re-scans: catch content that loads after document_idle.
// Critical for SPAs like Facebook, SoundCloud, YouTube that load asynchronously.
setTimeout(() => {
  try { void chrome.runtime.id; } catch (e) { return; } // Context invalidated
  if (ScaimAnalyzer._results &&
      ScaimAnalyzer._results.score === 0 &&
      !ScaimAnalyzer._results.allowlisted) {
    ScaimAnalyzer.rerun();
  }
}, 4000);

// Second delayed scan for heavy SPAs (SoundCloud, YouTube) that take longer
setTimeout(() => {
  try { void chrome.runtime.id; } catch (e) { return; } // Context invalidated
  if (ScaimAnalyzer._results &&
      ScaimAnalyzer._results.score === 0 &&
      !ScaimAnalyzer._results.allowlisted) {
    ScaimAnalyzer.rerun();
  }
  // Also retry social media scanning if platform was detected
  if (typeof SocialMediaScanner !== "undefined" && SocialMediaScanner.isSocialMedia()) {
    SocialMediaScanner.scanAllPosts();
  }
}, 8000);

} // end _scaimGuardKey guard
