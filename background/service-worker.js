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
  // Only accept messages from our own extension (defense in depth)
  if (sender.id !== chrome.runtime.id) return;

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
    });
    return true;
  }

  if (message.type === "SCAIM_GET_STATE") {
    chrome.storage.local.get("enabled", (result) => {
      sendResponse({ enabled: result.enabled !== false });
    });
    return true;
  }

  // Domain list management from popup
  if (message.type === "SCAIM_ALLOWLIST_ADD") {
    chrome.storage.local.get("scaim_allowlist", (result) => {
      const list = new Set(result.scaim_allowlist || []);
      list.add(message.hostname.toLowerCase());
      // Remove from blocklist if present
      chrome.storage.local.get("scaim_blocklist", (blockResult) => {
        const blockList = new Set(blockResult.scaim_blocklist || []);
        blockList.delete(message.hostname.toLowerCase());
        chrome.storage.local.set({
          scaim_allowlist: [...list],
          scaim_blocklist: [...blockList]
        }, () => {
          // Notify the active tab to re-run analysis
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
              chrome.tabs.sendMessage(tabs[0].id, { type: "SCAIM_RERUN" });
            }
          });
          sendResponse({ ok: true });
        });
      });
    });
    return true;
  }

  if (message.type === "SCAIM_ALLOWLIST_REMOVE") {
    chrome.storage.local.get("scaim_allowlist", (result) => {
      const list = new Set(result.scaim_allowlist || []);
      list.delete(message.hostname.toLowerCase());
      chrome.storage.local.set({ scaim_allowlist: [...list] }, () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) {
            chrome.tabs.sendMessage(tabs[0].id, { type: "SCAIM_RERUN" });
          }
        });
        sendResponse({ ok: true });
      });
    });
    return true;
  }

  if (message.type === "SCAIM_BLOCKLIST_ADD") {
    chrome.storage.local.get("scaim_blocklist", (result) => {
      const list = new Set(result.scaim_blocklist || []);
      list.add(message.hostname.toLowerCase());
      // Remove from allowlist if present
      chrome.storage.local.get("scaim_allowlist", (allowResult) => {
        const allowList = new Set(allowResult.scaim_allowlist || []);
        allowList.delete(message.hostname.toLowerCase());
        chrome.storage.local.set({
          scaim_blocklist: [...list],
          scaim_allowlist: [...allowList]
        }, () => {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
              chrome.tabs.sendMessage(tabs[0].id, { type: "SCAIM_RERUN" });
            }
          });
          sendResponse({ ok: true });
        });
      });
    });
    return true;
  }

  if (message.type === "SCAIM_BLOCKLIST_REMOVE") {
    chrome.storage.local.get("scaim_blocklist", (result) => {
      const list = new Set(result.scaim_blocklist || []);
      list.delete(message.hostname.toLowerCase());
      chrome.storage.local.set({ scaim_blocklist: [...list] }, () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) {
            chrome.tabs.sendMessage(tabs[0].id, { type: "SCAIM_RERUN" });
          }
        });
        sendResponse({ ok: true });
      });
    });
    return true;
  }

  if (message.type === "SCAIM_GET_LISTS") {
    chrome.storage.local.get(["scaim_allowlist", "scaim_blocklist"], (result) => {
      sendResponse({
        allowlist: (result.scaim_allowlist || []).sort(),
        blocklist: (result.scaim_blocklist || []).sort()
      });
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
