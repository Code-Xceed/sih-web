// GovShield Sentinel Grid 3.0 — Background Service Worker
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    evaluateTabSecurity(tabId, tab.url);
  }
});

function evaluateTabSecurity(tabId, url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();

    const isGov = host.endsWith(".gov.in") || host.endsWith(".nic.in") || host.endsWith(".mil.in");
    const isDeceptive = host.includes("g0v") || host.includes("pmkisan-") || (host.includes("kisan") && host.endsWith(".xyz"));

    if (isGov) {
      chrome.action.setBadgeText({ tabId, text: "GOV" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#00875a" });
    } else if (isDeceptive) {
      chrome.action.setBadgeText({ tabId, text: "FAKE" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#de350b" });
      // Notify content script to inject warning
      chrome.tabs.sendMessage(tabId, {
        action: "SHOW_FRAUD_BANNER",
        domain: host
      }).catch(() => {});
    } else {
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  } catch (e) {
    // Ignore invalid URLs
  }
}