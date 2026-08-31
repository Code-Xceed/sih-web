document.addEventListener('DOMContentLoaded', async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    document.getElementById('urlDisplay').innerText = tab.url;

    try {
        const res = await fetch("http://localhost:8000/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: tab.url })
        });
        const data = await res.json();
        
        const score = data.risk_score;
        let activeLight = "";
        let msg = "";

        if (score > 70) {
            activeLight = "lightRed";
            msg = "PHISHING DETECTED";
        } else if (score > 30) {
            activeLight = "lightYellow";
            msg = "SUSPICIOUS URL";
        } else {
            activeLight = "lightGreen";
            msg = "SAFE PORTAL";
        }

        document.getElementById(activeLight).classList.add("active");
        document.getElementById('statusMsg').innerText = msg;

    } catch (e) {
        document.getElementById('statusMsg').innerText = "Backend Offline";
        document.getElementById('lightYellow').classList.add("active");
    }
});
