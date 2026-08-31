"""
GovShield Sentinel Grid — Backend Server Launcher
SIH 2026 Problem Statement SIH1454
"""

import sys
import os

# Add backend directory to sys.path
backend_dir = os.path.join(os.path.dirname(__file__), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    import uvicorn
    from main import app

    if __name__ == "__main__":
        print("=" * 65)
        print("🛡️  GovShield Sentinel Grid — AI/ML Phishing Detection Layer")
        print("   SIH Problem Statement: SIH1454")
        print("   API Base: http://127.0.0.1:8000")
        print("   Swagger Docs: http://127.0.0.1:8000/docs")
        print("=" * 65)
        uvicorn.run(app, host="127.0.0.1", port=8000)
except ImportError as e:
    print(f"Missing requirements: {e}")
    print("Please install requirements first using: pip install -r backend/requirements.txt")
