# ?? GovShield Production Deployment Guide

This guide walks you through deploying the **FastAPI AI Backend**, the **Web Portal**, and the **Chrome/Edge Extension** to production cloud infrastructure with zero local dev dependencies.

---

## ??? Architecture Overview

The system is architected as a **unified cloud service**:
1. **Cloud Service (FastAPI + Web Portal)**:
   - Hosted on any cloud platform (Render, Railway, Fly.io, AWS, Google Cloud Run).
   - Serves the **REST API** at /api/scan, /api/health, /api/report-certin.
   - Serves the **Web Portal UI** at /.
2. **Browser Extension**:
   - Packaged as a standard Manifest V3 .zip.
   - Automatically connects to your deployed production URL (https://your-app.onrender.com).

---

## Option 1: 1-Click Deployment on Render.com (Recommended Free/Easy)

1. Push your code to **GitHub**:
   `ash
   git init
   git add .
   git commit -m "GovShield Production Release v1.0.0"
   git remote add origin https://github.com/YOUR_USERNAME/govshield.git
   git push -u origin main
   `

2. Open [Render.com](https://render.com) and click **New + > Web Service**.
3. Connect your GitHub repository.
4. Render will automatically detect the settings:
   - **Environment**: Python 3
   - **Build Command**: pip install -r requirements.txt
   - **Start Command**: python backend/main.py
5. In **Environment Variables**, add:
   - GEMINI_API_KEY: *(Your Google AI Studio Gemini API Key)*
   - PORT: 10000
6. Click **Deploy Web Service**.
7. Once deployed, your production URL will be live at:
   https://govshield-ai.onrender.com

---

## Option 2: 1-Click Deployment on Railway.app

1. Go to [Railway.app](https://railway.app) and click **New Project > Deploy from GitHub repo**.
2. Select your repository.
3. Railway will build using the root Dockerfile.
4. In the Railway dashboard:
   - Go to **Variables** > Add GEMINI_API_KEY.
   - Go to **Settings** > **Generate Domain** (e.g., https://govshield.up.railway.app).
5. Your Web Portal and API are instantly live!

---

## Option 3: Deploy via Docker (AWS / DigitalOcean / VPS)

1. Build and run locally or on your server:
   `ash
   docker build -t govshield .
   docker run -d -p 80:8000 -e GEMINI_API_KEY="YOUR_KEY" govshield
   `
2. Your service is now live on port 80 of your server IP or domain!

---

## ?? Deploying the Chrome / Edge Extension

1. The distribution package is generated:
   - **File**: govshield-extension-v1.0.0.zip
   - (To re-generate anytime, run: powershell -File package_extension.ps1)

2. **To Publish to Chrome Web Store**:
   - Go to the [Chrome Developer Dashboard](https://chrome.google.com/webstore/devcenter).
   - Click **Add new item** and upload govshield-extension-v1.0.0.zip.
   - Fill in the store listing details, screenshots, and submit for review.

3. **To Publish to Microsoft Edge Add-ons**:
   - Go to the [Microsoft Partner Center](https://partner.microsoft.com/dashboard/microsoftedge).
   - Click **Create new extension** and upload govshield-extension-v1.0.0.zip.
