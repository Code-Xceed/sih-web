// GovShield Sentinel Grid 3.0 — Background Service Worker
const LOCAL_API = "http://localhost:8000/api/scan";
const PROD_API = "https://govshield-veje.onrender.com/api/scan";

// In-memory tab scan cache
const tabScanCache = new Map();

// Tab update listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    evaluateTabSecurity(tabId, tab.url);
  }
});

// Tab switch listener
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && tab.url.startsWith("http")) {
      if (tabScanCache.has(tab.id)) {
        const cached = tabScanCache.get(tab.id);
        applyBadge(tab.id, cached.risk_score, cached.verdict, cached.is_genuine_gov_tld);
      } else {
        evaluateTabSecurity(tab.id, tab.url);
      }
    }
  } catch (_) {}
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "UPDATE_BADGE") {
    const tabId = msg.tabId || (sender.tab ? sender.tab.id : null);
    if (tabId) {
      tabScanCache.set(tabId, {
        risk_score: msg.risk_score,
        verdict: msg.verdict,
        is_genuine_gov_tld: msg.is_genuine_gov_tld
      });
      applyBadge(tabId, msg.risk_score, msg.verdict, msg.is_genuine_gov_tld);
    }
  }
  return true;
});

async function evaluateTabSecurity(tabId, url) {
  if (!url || !url.startsWith("http")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  let hostname = "";
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname.toLowerCase();
  } catch (_) {
    return;
  }

  // Fast sovereign domain check (.gov.in / .nic.in / .mil.in)
  const isGov = hostname.endsWith(".gov.in") || hostname.endsWith(".nic.in") || hostname.endsWith(".mil.in");
  if (isGov) {
    applyBadge(tabId, 2, "LEGITIMATE", true);
    return;
  }

  // Set scanning state indicator
  chrome.action.setBadgeText({ tabId, text: "..." });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#5c3cf6" });

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    let resp = null;
    try {
      resp = await fetch(LOCAL_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });
    } catch (_) {
      resp = await fetch(PROD_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });
    }
    clearTimeout(timeoutId);

    if (resp && resp.ok) {
      const data = await resp.json();
      const score = Math.round(data.risk_score || 0);
      tabScanCache.set(tabId, {
        risk_score: score,
        verdict: data.verdict,
        is_genuine_gov_tld: data.is_genuine_gov_tld
      });
      applyBadge(tabId, score, data.verdict, data.is_genuine_gov_tld);

      if (score >= 60 || data.verdict === "PHISHING_CLONE" || data.verdict === "MALICIOUS") {
        chrome.tabs.sendMessage(tabId, {
          action: "SHOW_FRAUD_BANNER",
          domain: hostname,
          risk_score: score
        }).catch(() => {});
      }
      return;
    }
  } catch (e) {
    console.debug("Backend API unavailable for tab background scan:", e);
  }

  // Sovereign client heuristics fallback if backend is sleeping/offline
  const isScam = hostname.includes("g0v") || hostname.includes("kisan-pm") || hostname.includes("yapple") ||
                 hostname.includes("subsidy") || hostname.includes(".xyz") || hostname.includes("daflonpneus");
  const score = isScam ? 92 : 15;
  const verdict = isScam ? "PHISHING_CLONE" : "LEGITIMATE";
  applyBadge(tabId, score, verdict, false);
}

function applyBadge(tabId, score, verdict, isGov) {
  let text = "";
  let color = "#00875a";

  if (score >= 60 || verdict === "PHISHING_CLONE" || verdict === "MALICIOUS") {
    text = "RISK";
    color = "#de350b"; // Critical Red
  } else if (score >= 26 || verdict === "SUSPICIOUS") {
    text = "SUSP";
    color = "#f59e0b"; // Warning Orange
  } else if (isGov) {
    text = "GOV";
    color = "#00875a"; // Official Sovereign Green
  } else {
    text = "OK";
    color = "#00875a"; // Safe Green
  }

  try {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch (_) {}
}