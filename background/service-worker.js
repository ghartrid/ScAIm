/**
 * ScAIm Background Service Worker
 * Manages badge state, stores per-tab results, and coordinates with popup.
 */

// Per-tab threat data
const tabData = {};

// Badge configuration for each level
const BADGE_CONFIG = {
  safe: { text: "OK", color: "#28A745" },
  caution: { text: "!", color: "#F0AD4E" },
  warning: { text: "!!", color: "#E67E22" },
  danger: { text: "!!!", color: "#DC3545" }
};

// Listen for results from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAIM_RESULTS" && sender.tab) {
    const tabId = sender.tab.id;
    tabData[tabId] = message.data;
    updateBadge(tabId, message.data.level);
    sendResponse({ ok: true });
    return;
  }

  if (message.type === "SCAIM_GET_TAB_DATA") {
    // Popup requesting data for the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        sendResponse(tabData[tabs[0].id] || null);
      } else {
        sendResponse(null);
      }
    });
    return true; // Keep channel open for async response
  }

  if (message.type === "SCAIM_TOGGLE") {
    // Toggle extension on/off
    chrome.storage.local.get("enabled", (result) => {
      const newState = !(result.enabled !== false); // default is true
      chrome.storage.local.set({ enabled: newState });
      sendResponse({ enabled: newState });

      // If re-enabled, tell the active tab to re-scan immediately
      if (newState) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) {
            chrome.tabs.sendMessage(tabs[0].id, { type: "SCAIM_RERUN" }, () => {
              chrome.runtime.lastError; // Clear any error if tab has no listener
            });
          }
        });
      }
    });
    return true;
  }

  if (message.type === "SCAIM_GET_STATE") {
    chrome.storage.local.get("enabled", (result) => {
      sendResponse({ enabled: result.enabled !== false });
    });
    return true;
  }
});

// Update toolbar badge for a tab
function updateBadge(tabId, level) {
  const config = BADGE_CONFIG[level] || BADGE_CONFIG.safe;

  chrome.action.setBadgeText({ text: config.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
}

// Clean up tab data when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
});

// Reset badge when navigating to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    delete tabData[tabId];
    chrome.action.setBadgeText({ text: "", tabId });
  }
});

// Set default state on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ enabled: true });
});
