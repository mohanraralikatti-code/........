/**
 * ScamGuard AI - Chrome Extension V3 Background Service Worker
 * Enables right-click context menu scanning for job boards (LinkedIn, Indeed),
 * rental platforms (Craigslist, Zillow), and email web clients.
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scamguard-scan-text",
    title: "🛡️ Scan with ScamGuard AI",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "scamguard-scan-link",
    title: "🔍 Inspect Domain with ScamGuard AI",
    contexts: ["link"]
  });

  console.log("[ScamGuard AI] Extension installed & context menus registered.");
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scamguard-scan-text" && info.selectionText) {
    const queryPayload = encodeURIComponent(info.selectionText);
    const scannerUrl = chrome.runtime.getURL(`index.html?scan_text=${queryPayload}`);
    
    chrome.tabs.create({ url: scannerUrl });
  } else if (info.menuItemId === "scamguard-scan-link" && info.linkUrl) {
    const queryPayload = encodeURIComponent(info.linkUrl);
    const scannerUrl = chrome.runtime.getURL(`index.html?scan_url=${queryPayload}`);

    chrome.tabs.create({ url: scannerUrl });
  }
});
