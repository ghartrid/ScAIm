/**
 * ScAIm Analyzer — Content Script Orchestrator
 * Runs all paranoid detectors, aggregates results, and triggers the banner.
 */
const ScaimAnalyzer = {
  _hasRun: false,
  _results: null,

  /**
   * Run the full paranoid analysis pipeline.
   */
  run() {
    if (this._hasRun) return;
    this._hasRun = true;

    // Check if extension is enabled before running
    chrome.storage.local.get("enabled", (result) => {
      if (result.enabled === false) return;
      this._analyze();
    });
  },

  /**
   * Internal: perform the actual analysis.
   */
  _analyze() {
    try {
      // Run all detectors
      const keywordResults = KeywordScanner.scan();
      const structuralResults = StructuralDetector.scan();
      const phishingResults = PhishingDetector.scan();
      const socialResults = SocialEngineeringDetector.scan();
      const ecommerceResults = FakeEcommerceDetector.scan();

      // Aggregate scores
      const assessment = ScaimScoring.aggregate({
        keywords: keywordResults,
        structural: structuralResults,
        phishing: phishingResults,
        socialEngineering: socialResults,
        fakeEcommerce: ecommerceResults
      });

      this._results = assessment;

      // Send results to background service worker
      this._sendToBackground(assessment);

      // Show banner if threat level is caution or above
      if (assessment.level !== ScaimScoring.LEVELS.SAFE) {
        ScaimBanner.show(assessment);
      }
    } catch (err) {
      console.error("[ScAIm] Analysis error:", err);
    }
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
          hostname: window.location.hostname
        }
      });
    } catch (e) {
      // Extension context may be invalidated — ignore
    }
  },

  /**
   * Re-run analysis (e.g., after significant DOM changes).
   */
  rerun() {
    this._hasRun = false;
    ScaimBanner.remove();
    this.run();
  },

  /**
   * Get the latest results (for popup queries).
   */
  getResults() {
    return this._results;
  }
};

// Listen for messages from popup/background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAIM_GET_RESULTS") {
    sendResponse(ScaimAnalyzer.getResults());
  }
  if (message.type === "SCAIM_RERUN") {
    ScaimAnalyzer.rerun();
    sendResponse({ ok: true });
  }
});

// Run analysis on page load
ScaimAnalyzer.run();

// Observe DOM mutations for SPAs — re-analyze on significant changes
const scaimObserver = new MutationObserver((mutations) => {
  let significantChange = false;
  for (const mutation of mutations) {
    if (mutation.addedNodes.length > 5 || mutation.removedNodes.length > 5) {
      significantChange = true;
      break;
    }
    // Check for form additions
    for (const node of mutation.addedNodes) {
      if (node.nodeType === Node.ELEMENT_NODE) {
        if (node.tagName === "FORM" || node.querySelector?.("form")) {
          significantChange = true;
          break;
        }
      }
    }
    if (significantChange) break;
  }

  if (significantChange) {
    // Debounce re-analysis
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
