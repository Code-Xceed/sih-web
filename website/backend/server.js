import express from 'express';
import cors from 'cors';
import { chromium } from 'playwright';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Local Screenshot Storage (bypassing MinIO for local execution)
const SCREENSHOT_DIR = path.join(__dirname, 'screenshots');
if (!fs.existsSync(SCREENSHOT_DIR)) {
    fs.mkdirSync(SCREENSHOT_DIR);
}
app.use('/screenshots', express.static(SCREENSHOT_DIR));

// Local JSON DB (bypassing Postgres to avoid native compilation issues)
const DB_FILE = path.join(__dirname, 'database.json');
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify([]));
}

app.post('/api/scan', async (req, res) => {
    let targetUrl = req.body.url;
    if (!targetUrl) return res.status(400).json({ error: "URL is required" });
    if (!targetUrl.startsWith("http")) targetUrl = "https://" + targetUrl;

    let screenshotFileName = null;
    let screenshotUrl = null;

    try {
        const browser = await chromium.launch({ headless: true });
        const page = await browser.newPage();
        await page.goto(targetUrl, { waitUntil: 'load', timeout: 15000 });
        screenshotFileName = `scan_${uuidv4()}.png`;
        await page.screenshot({ path: path.join(SCREENSHOT_DIR, screenshotFileName) });
        await browser.close();
        screenshotUrl = `http://localhost:8000/screenshots/${screenshotFileName}`;
    } catch (err) {
        console.error("Playwright error:", err);
    }

    let riskScore = 10.0;
    let verdict = "SAFE";

    const suspiciousKeywords = ["update", "kyc", "login", "verify", "refund", "claim", "free"];
    if (suspiciousKeywords.some(k => targetUrl.toLowerCase().includes(k)) && !targetUrl.toLowerCase().includes(".gov")) {
        riskScore = 88.5;
        verdict = "PHISHING";
    }

    const record = {
        id: uuidv4(),
        url: targetUrl,
        risk_score: riskScore,
        verdict: verdict,
        screenshot_url: screenshotUrl,
        timestamp: new Date().toISOString()
    };

    // Save to local JSON DB
    const db = JSON.parse(fs.readFileSync(DB_FILE));
    db.push(record);
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

    res.json({
        status: "success",
        target_url: targetUrl,
        risk_score: riskScore,
        verdict: verdict,
        screenshot_id: screenshotUrl 
    });
});

app.listen(8000, () => {
    console.log('Node.js Backend listening on port 8000');
});
