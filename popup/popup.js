/**
 * ScAIm Popup Script
 * Displays threat analysis for the current page.
 * Provides Scan Page, Trust Site, and Block Site actions.
 */

const STATUS_CONFIG = {
  safe: { icon: "\u2705", text: "No threats detected" },
  caution: { icon: "\u26A0\uFE0F", text: "Some concerns detected" },
  warning: { icon: "\u{1F6A8}", text: "Multiple suspicious elements found" },
  danger: { icon: "\u{1F6D1}", text: "High risk — potential scam detected" }
};

document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("scaim-enabled");
  const statusEl = document.getElementById("scaim-status");
  const statusIcon = document.getElementById("scaim-status-icon");
  const statusText = document.getElementById("scaim-status-text");
  const scoreSection = document.getElementById("scaim-score-section");
  const scoreBar = document.getElementById("scaim-score-bar");
  const scoreValue = document.getElementById("scaim-score-value");
  const findingsSection = document.getElementById("scaim-findings-section");
  const findingsList = document.getElementById("scaim-findings-list");
  const noData = document.getElementById("scaim-no-data");
  const popup = document.querySelector(".scaim-popup");

  const scanBtn = document.getElementById("scaim-scan-btn");
  const trustBtn = document.getElementById("scaim-trust-btn");
  const blockBtn = document.getElementById("scaim-block-btn");
  const scanStatus = document.getElementById("scaim-scan-status");
  const domainNote = document.getElementById("scaim-domain-note");

  let currentHostname = null;

  // Load enabled state
  chrome.runtime.sendMessage({ type: "SCAIM_GET_STATE" }, (response) => {
    if (response) {
      toggle.checked = response.enabled;
      if (!response.enabled) popup.classList.add("disabled");
    }
  });

  // Toggle handler
  toggle.addEventListener("change", () => {
    chrome.runtime.sendMessage({ type: "SCAIM_TOGGLE" }, (response) => {
      if (response) {
        popup.classList.toggle("disabled", !response.enabled);
      }
    });
  });

  // Content script files (same order as manifest)
  const CONTENT_SCRIPTS = [
    "config/keywords.js", "config/domain-lists.js", "shared/scoring.js",
    "detectors/keyword-scanner.js", "detectors/structural.js", "detectors/phishing.js",
    "detectors/social-engineering.js", "detectors/fake-ecommerce.js",
    "detectors/crypto-scam.js", "detectors/tech-support.js",
    "detectors/romance-fee.js", "detectors/malicious-download.js",
    "content/banner.js", "content/social-media-scanner.js", "content/analyzer.js"
  ];

  function finishScan() {
    let retries = 0;
    const maxRetries = 3;

    function tryLoad() {
      chrome.runtime.sendMessage({ type: "SCAIM_GET_TAB_DATA" }, (data) => {
        if (!data && retries < maxRetries) {
          retries++;
          setTimeout(tryLoad, 1500);
          return;
        }
        // Got data (or exhausted retries) — update UI
        loadTabData();
        scanBtn.classList.remove("scanning");
        scanBtn.innerHTML = "&#x1F50D; Scan Page";
        scanStatus.style.display = "none";
      });
    }

    // First attempt after 2s, then retry up to 3 more times at 1.5s intervals
    setTimeout(tryLoad, 2000);
  }

  // Inject content scripts programmatically (fallback when scripts aren't loaded)
  function injectAndScan(tabId) {
    chrome.scripting.insertCSS({ target: { tabId }, files: ["content/banner.css"] }).catch(() => {});
    chrome.scripting.executeScript({
      target: { tabId },
      files: CONTENT_SCRIPTS
    }).then(() => {
      // Scripts injected — give them a moment to initialize, then trigger scan
      setTimeout(() => {
        chrome.tabs.sendMessage(tabId, { type: "SCAIM_RERUN" }, () => {
          if (chrome.runtime.lastError) { /* ignore */ }
          finishScan();
        });
      }, 1000);
    }).catch(() => {
      finishScan();
    });
  }

  // ---- Scan Page button ----
  scanBtn.addEventListener("click", () => {
    scanBtn.classList.add("scanning");
    scanBtn.textContent = "Scanning...";
    scanStatus.style.display = "block";

    // Hide old results during re-scan
    scoreSection.style.display = "none";
    findingsSection.style.display = "none";

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) return;
      const tabId = tabs[0].id;
      chrome.tabs.sendMessage(tabId, { type: "SCAIM_RERUN" }, () => {
        if (chrome.runtime.lastError) {
          // Content script not available — inject it programmatically
          injectAndScan(tabId);
        } else {
          finishScan();
        }
      });
    });
  });

  // ---- Trust Site button ----
  trustBtn.addEventListener("click", () => {
    if (!currentHostname) return;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) return;
      chrome.tabs.sendMessage(tabs[0].id, {
        type: "SCAIM_ALLOWLIST_ADD",
        hostname: currentHostname
      }, () => {
        trustBtn.style.display = "none";
        blockBtn.style.display = "";
        domainNote.textContent = currentHostname + " added to trusted list. It will no longer be scanned.";
        domainNote.className = "scaim-domain-note allowlisted";
        domainNote.style.display = "block";
        setTimeout(() => loadTabData(), 1500);
      });
    });
  });

  // ---- Block Site button ----
  blockBtn.addEventListener("click", () => {
    if (!currentHostname) return;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) return;
      chrome.tabs.sendMessage(tabs[0].id, {
        type: "SCAIM_BLOCKLIST_ADD",
        hostname: currentHostname
      }, () => {
        blockBtn.style.display = "none";
        trustBtn.style.display = "";
        domainNote.textContent = currentHostname + " added to blocklist. It will always be flagged as dangerous.";
        domainNote.className = "scaim-domain-note blocklisted";
        domainNote.style.display = "block";
        setTimeout(() => loadTabData(), 1500);
      });
    });
  });

  // ---- Load tab data ----
  function loadTabData() {
    chrome.runtime.sendMessage({ type: "SCAIM_GET_TAB_DATA" }, (data) => {
      if (!data) {
        statusEl.style.display = "none";
        noData.style.display = "block";
        trustBtn.style.display = "none";
        blockBtn.style.display = "none";
        return;
      }

      noData.style.display = "none";
      statusEl.style.display = "block";
      currentHostname = data.hostname;

      const config = STATUS_CONFIG[data.level] || STATUS_CONFIG.safe;

      // Update status
      statusEl.className = "scaim-status " + data.level;
      statusIcon.textContent = config.icon;
      // Show hostname in safe message so user knows the scan ran
      if (data.level === "safe" && data.hostname) {
        statusText.textContent = data.hostname + " scanned — no threats detected";
      } else {
        statusText.textContent = config.text;
      }

      // Update score bar
      scoreSection.style.display = "block";
      scoreValue.textContent = data.score;
      scoreBar.className = "scaim-score-bar " + data.level;
      setTimeout(() => {
        scoreBar.style.width = data.score + "%";
      }, 100);

      // Show/hide trust and block buttons based on current state
      if (data.allowlisted) {
        trustBtn.style.display = "none";
        blockBtn.style.display = "";
        domainNote.textContent = currentHostname + " is on your trusted list.";
        domainNote.className = "scaim-domain-note allowlisted";
        domainNote.style.display = "block";
      } else if (data.blocklisted) {
        trustBtn.style.display = "";
        blockBtn.style.display = "none";
        domainNote.textContent = currentHostname + " is on your blocklist.";
        domainNote.className = "scaim-domain-note blocklisted";
        domainNote.style.display = "block";
      } else {
        trustBtn.style.display = "";
        blockBtn.style.display = "";
        domainNote.style.display = "none";
      }

      // Render findings
      if (data.findings && data.findings.length > 0) {
        findingsSection.style.display = "block";
        findingsList.innerHTML = data.findings.map(f => `
          <div class="scaim-finding-item ${f.severity}">
            <div class="scaim-finding-item-header">
              <span class="scaim-finding-badge ${f.severity}">${f.severity}</span>
              <span class="scaim-finding-category">${escapeHtml(f.category)}</span>
            </div>
            <div class="scaim-finding-message">${escapeHtml(f.message)}</div>
          </div>
        `).join("");
      } else {
        findingsSection.style.display = "none";
        findingsList.innerHTML = "";
      }
    });
  }

  // Initial load
  loadTabData();
});

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
