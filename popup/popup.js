/**
 * ScAIm Popup Script
 * Displays threat analysis for the current page.
 */

const STATUS_CONFIG = {
  safe: { icon: "\u2705", text: "Page scanned — no major concerns" },
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

  // Load tab data
  chrome.runtime.sendMessage({ type: "SCAIM_GET_TAB_DATA" }, (data) => {
    if (!data) {
      statusEl.style.display = "none";
      noData.style.display = "block";
      return;
    }

    const config = STATUS_CONFIG[data.level] || STATUS_CONFIG.safe;

    // Update status
    statusEl.className = "scaim-status " + data.level;
    statusIcon.textContent = config.icon;
    statusText.textContent = config.text;

    // Update score bar
    scoreSection.style.display = "block";
    scoreValue.textContent = data.score;
    scoreBar.className = "scaim-score-bar " + data.level;
    setTimeout(() => {
      scoreBar.style.width = data.score + "%";
    }, 100);

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
    }
  });
});

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
