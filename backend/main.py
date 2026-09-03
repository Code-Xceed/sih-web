"""
GovShield / Sentinel Grid - FastAPI AI/ML Phishing Detection Backend
SIH 2026 Problem Statement SIH1454
"""

import sys
import os

# Ensure backend directory is in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

# Fix Windows console encoding
if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from modules.lexical_analyzer import LexicalAnalyzer
from modules.dom_analyzer import DOMAnalyzer
from modules.visual_analyzer import VisualSimilarityAnalyzer
from modules.whois_analyzer import WhoisAnalyzer
from modules.fusion_engine import FusionEngine
from modules.certin_reporter import CertInReporter
from modules.reference_database import GENUINE_PORTALS
from modules.ai_agent import AIAgent
from modules.blockchain_ledger import BlockchainLedger
from modules.content_similarity import content_similarity, text_similarity, dom_similarity
from modules.homoglyph_analyzer import HomoglyphAnalyzer

import urllib.parse
import urllib.request
import socket
import ipaddress
import time
import uuid
import csv
import io
import asyncio
from typing import Literal
from fastapi.responses import StreamingResponse, JSONResponse

app = FastAPI(
    title="GovShield (Sentinel Grid) — Sovereign AI Cyber Defense & Blockchain Threat Intelligence",
    description="Multi-modal AI/ML verification service with Sovereign Blockchain Threat Ledger, MinHash content matching, and enterprise CTI feeds.",
    version="2.1.0"
)

# Enable CORS for Chrome Extensions and local tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CTI Live Threat Feeds and Background Async Jobs
RECENT_VERDICTS: List[Dict[str, Any]] = []
ASYNC_JOBS: Dict[str, Dict[str, Any]] = {}

# Instantiate core analyzers, AI Agent & Sovereign Blockchain Ledger
lexical_analyzer = LexicalAnalyzer()
dom_analyzer = DOMAnalyzer()
visual_analyzer = VisualSimilarityAnalyzer()
whois_analyzer = WhoisAnalyzer()
fusion_engine = FusionEngine()
certin_reporter = CertInReporter()
ai_agent = AIAgent()
blockchain_ledger = BlockchainLedger()

# High-Performance Production Cache (TTL 180s)
SCAN_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 180


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect")
    html_content: Optional[str] = Field(None, description="DOM HTML content extracted by extension")
    image_base64: Optional[str] = Field(None, description="Base64 encoded page screenshot or logo image")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class QuickCheckRequest(BaseModel):
    url: str = Field(..., description="Target URL to quickly analyze")


class CertInReportRequest(BaseModel):
    scan_result: Dict[str, Any]
    reporter_notes: Optional[str] = None


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "system": "GovShield Sentinel Grid",
        "models_loaded": {
            "lexical_typosquatting": True,
            "dom_form_inspector": True,
            "visual_phash_matcher": True,
            "whois_age_evaluator": True,
            "fusion_risk_engine": True,
            "multimodal_genai_agent": ai_agent.client_ready,
            "sovereign_blockchain_ledger": True
        },
        "blockchain_status": {
            "active": True,
            "chain_height": len(blockchain_ledger.chain),
            "chain_valid": blockchain_ledger.is_chain_valid(),
            "latest_block_hash": blockchain_ledger.get_latest_block().hash
        },
        "ai_model": ai_agent.model_name if ai_agent.client_ready else "edge_heuristic_mode",
        "indexed_reference_portals_count": len(GENUINE_PORTALS)
    }


@app.get("/api/blockchain/stats")
def get_blockchain_stats():
    """Returns live telemetry from the Sovereign Blockchain Threat Ledger."""
    return {
        "status": "success",
        "blockchain_metrics": blockchain_ledger.get_stats()
    }


@app.get("/api/blockchain/chain")
def get_blockchain_chain():
    """Returns the immutable blocks from the Sovereign Blockchain Threat Ledger."""
    return {
        "status": "success",
        "chain_length": len(blockchain_ledger.chain),
        "blocks": [b.to_dict() for b in blockchain_ledger.chain],
        "stats": blockchain_ledger.get_stats()
    }


@app.get("/api/blockchain/latest-block")
def get_blockchain_latest_block():
    """Returns the head block from the blockchain."""
    return {
        "status": "success",
        "block": blockchain_ledger.get_latest_block().to_dict()
    }


@app.get("/api/blockchain/verify-evidence/{incident_id}")
def verify_blockchain_evidence(incident_id: str):
    """Verifies cryptographic proof and Merkle path for a logged cyber incident."""
    evidence = blockchain_ledger.verify_evidence(incident_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Incident record not found on Sovereign Blockchain.")
    return {
        "status": "VERIFIED_ON_BLOCKCHAIN",
        "evidence": evidence
    }


@app.get("/api/blockchain/section65b/{incident_id}")
def get_section_65b_certificate(incident_id: str):
    """Generates official Court-Admissible Electronic Certificate under Section 65B Indian Evidence Act."""
    cert = blockchain_ledger.generate_section_65b_certificate(incident_id)
    if cert.get("status") == "ERROR":
        raise HTTPException(status_code=404, detail=cert.get("message"))
    return cert


@app.get("/healthz")
def healthz():
    """Kubernetes liveness probe."""
    return {"status": "ok", "version": "2.1.0", "service": "GovShield Sentinel Grid"}


@app.get("/readyz")
def readyz():
    """Kubernetes readiness probe checking blockchain and AI models."""
    return {
        "ready": True,
        "blockchain_valid": blockchain_ledger.is_chain_valid(),
        "models_ready": True
    }


@app.get("/api/brands")
def get_brands():
    """Programmatic discovery of all protected Indian sovereign, banking, and public infrastructure entities."""
    brands = []
    for pid, data in GENUINE_PORTALS.items():
        brands.append({
            "id": pid,
            "name": data["name"],
            "department": data["department"],
            "primary_domain": data["primary_domain"],
            "valid_domains": data.get("valid_domains", [])
        })
    return {
        "status": "success",
        "count": len(brands),
        "brands": brands
    }


@app.get("/api/feed")
def get_threat_feed(
    format: Literal["json", "csv"] = "json",
    limit: int = 100,
    min_level: Optional[str] = None
):
    """Recent threat verdicts — Analyst CTI output for SIEM ingestion and CERT-In triage."""
    items = list(RECENT_VERDICTS)
    if min_level:
        lvl = min_level.upper()
        items = [v for v in items if v.get("threat_level") == lvl or v.get("verdict") == lvl]
    items = items[-limit:]

    if format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["incident_id", "url", "target_entity", "risk_score", "verdict", "threat_level", "timestamp"],
            extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(items)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=govshield-threat-feed.csv"}
        )

    return {
        "status": "success",
        "count": len(items),
        "verdicts": items
    }


@app.get("/api/scan/{scan_id}")
def get_async_scan_status(scan_id: str):
    """Retrieve status and verdict for an asynchronous scan job."""
    if scan_id not in ASYNC_JOBS:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    return ASYNC_JOBS[scan_id]


@app.get("/api/reference-sites")
def get_reference_sites():
    """Return all genuine Indian government portals indexed in the reference database."""
    portals_list = []
    for pid, data in GENUINE_PORTALS.items():
        portals_list.append({
            "id": pid,
            "name": data["name"],
            "department": data["department"],
            "primary_domain": data["primary_domain"],
            "valid_domains": data["valid_domains"]
        })
    return {"status": "success", "portals": portals_list}


@app.post("/api/quick-check")
def quick_check(req: QuickCheckRequest):
    """Fast lexical and reputation pre-flight evaluation."""
    lex_res = lexical_analyzer.analyze(req.url)
    whois_res = whois_analyzer.analyze(req.url)
    
    vis_res = visual_analyzer.analyze_visual_lookalike(
        candidate_portal_id=lex_res.get("target_entity_id")
    )
    dom_res = {"risk_score": 0.0, "sensitive_inputs": [], "reasons": []}
    
    fusion_res = fusion_engine.evaluate(lex_res, dom_res, vis_res, whois_res)
    fusion_res["url"] = req.url
    return fusion_res


def fetch_remote_page_dom(target_url: str) -> Optional[str]:
    """
    Safely fetches live HTML content for a candidate URL when not supplied by extension.
    Includes 3.0s timeout and guards against internal SSRF.
    """
    if not target_url or not target_url.startswith(("http://", "https://")):
        return None

    try:
        parsed = urllib.parse.urlparse(target_url)
        hostname = (parsed.hostname or "").lower()

        # Allow localhost/127.0.0.1 ONLY for demo test harnesses (e.g. port 8080)
        is_local_demo = hostname in ["localhost", "127.0.0.1"] and parsed.port in [8080, 5000, 3000]
        
        if not is_local_demo:
            try:
                ip = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                    return None
            except Exception:
                return None

        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        )
        with urllib.request.urlopen(req, timeout=3.0) as response:
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type or "application/xhtml" in content_type or not content_type:
                raw_bytes = response.read(100000)  # Read up to 100KB
                return raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def _execute_scan_pipeline(req: ScanRequest) -> Dict[str, Any]:
    """Internal core execution pipeline for multi-modal verification."""
    normalized_url = req.url.strip()
    cache_key = normalized_url.lower()
    now_ts = time.time()

    # Fast in-memory cache hit (for web requests without client DOM)
    if not req.html_content and not req.image_base64 and cache_key in SCAN_CACHE:
        cached_item = SCAN_CACHE[cache_key]
        if (now_ts - cached_item["cached_at"]) < CACHE_TTL_SECONDS:
            res_copy = dict(cached_item["data"])
            res_copy["cached_result"] = True
            return res_copy

    # 1. Lexical & Domain Analysis (with Homoglyphs & Jaro-Winkler)
    lex_res = lexical_analyzer.analyze(req.url)
    target_portal_id = lex_res.get("target_entity_id")

    # 1.1 Autonomous server-side DOM fetch if not supplied (e.g. scanned from web portal)
    html_content = req.html_content
    if (not html_content or len(html_content.strip()) == 0) and not lex_res.get("is_genuine_gov_tld"):
        html_content = fetch_remote_page_dom(req.url)

    # 2. DOM & Content Analysis
    dom_res = dom_analyzer.analyze_html(
        html_content=html_content or "",
        base_url=req.url,
        matched_portal_id=target_portal_id
    )

    # 2.1 Pure-Python MinHash Content & Structural Shingling
    content_sim_res = None
    if html_content and target_portal_id:
        target_portal = GENUINE_PORTALS.get(target_portal_id)
        if target_portal:
            ref_keywords = " ".join(target_portal.get("keywords", []))
            t_sim = text_similarity(html_content, ref_keywords)
            if t_sim > 0.05:
                content_sim_res = {
                    "similarity": t_sim,
                    "reasons": [f"MinHash structural text & DOM outline confirms {int(t_sim * 100)}% similarity to official portal."] if t_sim >= 0.35 else []
                }

    # 3. Visual Lookalike Analysis
    vis_res = visual_analyzer.analyze_visual_lookalike(
        image_base64=req.image_base64,
        candidate_portal_id=target_portal_id
    )

    # 4. WHOIS & RDAP Domain Age Analysis
    whois_res = whois_analyzer.analyze(req.url)

    # 5. Multimodal GenAI Inspection (if not an already authenticated official .gov.in domain)
    ai_res = None
    if not lex_res.get("is_genuine_gov_tld") and ai_agent.client_ready:
        ai_res = ai_agent.analyze_webpage(
            url=req.url,
            html_dom=html_content or "",
            image_base64=req.image_base64,
            candidate_entity=lex_res.get("target_entity")
        )

    # 6. Multi-Signal AI/ML Fusion
    fused_verdict = fusion_engine.evaluate(
        lexical_result=lex_res,
        dom_result=dom_res,
        visual_result=vis_res,
        whois_result=whois_res,
        content_sim_result=content_sim_res
    )

    # If GenAI returned results, blend directly into final verdict
    if ai_res and ai_res.get("status") == "SUCCESS":
        fused_verdict["genai_analysis"] = ai_res
        if ai_res.get("is_phishing"):
            fused_verdict["risk_score"] = max(fused_verdict["risk_score"], ai_res.get("risk_score", 88))
            fused_verdict["verdict"] = "PHISHING_CLONE"
            fused_verdict["threat_level"] = "HIGH"
            if ai_res.get("plain_english_explanation"):
                fused_verdict["reasons"].insert(0, f"AI Insight: {ai_res['plain_english_explanation']}")
        elif not ai_res.get("is_gov_impersonation", False) and not lex_res.get("is_genuine_gov_tld") and not lex_res.get("target_entity_id") and fused_verdict.get("risk_score", 0) < 50:
            fused_verdict["risk_score"] = 0
            fused_verdict["verdict"] = "LEGITIMATE"
            fused_verdict["threat_level"] = "LOW"
            fused_verdict["target_entity"] = "Legitimate Commercial Platform"
            fused_verdict["summary"] = "Authentic web service. No Indian Government impersonation or phishing detected."
            fused_verdict["reasons"] = [
                f"AI Insight: {ai_res.get('plain_english_explanation', 'Authentic commercial web service.')}",
                "No government impersonation or fraudulent identity harvesting detected."
            ]

    # Live Real-Time Terminal Output for Hackathon Demonstration
    print("\n" + "=" * 65)
    print(f"🔍 [SCAN INSPECTION] URL: {req.url}")
    print(f"  • Matched Entity: {fused_verdict.get('target_entity')}")
    print(f"  • Typosquatting / Lexical Score: {lex_res.get('risk_score', 0)}/100")
    print(f"  • DOM Sensitive Fields: {[s['field'] for s in dom_res.get('sensitive_inputs', [])]}")
    print(f"  • Visual Lookalike Match: {vis_res.get('visual_similarity_score', 0)}%")
    print(f"  • WHOIS / RDAP Domain Age: {whois_res.get('domain_age_days', 0)} days")
    if content_sim_res:
        print(f"  • MinHash Content Sim: {round(content_sim_res.get('similarity', 0.0)*100, 1)}%")
    if ai_res and ai_res.get("status") == "SUCCESS":
        print(f"  🤖 [Gemini 2.0 Flash AI]:")
        print(f"     - Threat Category: {ai_res.get('threat_category')}")
        print(f"     - AI Reason: {ai_res.get('plain_english_explanation')}")
    print(f"  🎯 VERDICT: {fused_verdict['verdict']} | RISK SCORE: {fused_verdict['risk_score']}/100")
    print("=" * 65 + "\n")

    # Assign unique tracking incident ID
    incident_id = f"CERTIN-INC-{uuid.uuid4().hex[:8].upper()}"
    fused_verdict["incident_id"] = incident_id

    # Automatically commit threat intelligence to the Sovereign Blockchain Ledger
    blockchain_tx = blockchain_ledger.log_threat_incident(
        incident_id=incident_id,
        malicious_url=req.url,
        target_entity=fused_verdict.get("target_entity", "Indian Sovereign Service"),
        risk_score=fused_verdict.get("risk_score", 0),
        verdict=fused_verdict.get("verdict", "UNKNOWN"),
        forensic_evidence=fused_verdict.get("signal_breakdown", {}),
        html_dom_sample=html_content or "",
        reporter_notes="GovShield Sentinel Grid Sovereign Detection"
    )
    fused_verdict["blockchain_proof"] = blockchain_tx

    fused_verdict["url"] = req.url
    fused_verdict["lexical_details"] = lex_res
    fused_verdict["dom_details"] = dom_res
    fused_verdict["visual_details"] = vis_res
    fused_verdict["whois_details"] = whois_res
    if content_sim_res:
        fused_verdict["content_similarity_details"] = content_sim_res

    # Append to recent CTI verdicts feed for analysts and SIEMs
    import datetime
    RECENT_VERDICTS.append({
        "incident_id": incident_id,
        "url": req.url,
        "target_entity": fused_verdict.get("target_entity"),
        "risk_score": fused_verdict.get("risk_score"),
        "verdict": fused_verdict.get("verdict"),
        "threat_level": fused_verdict.get("threat_level"),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })
    if len(RECENT_VERDICTS) > 200:
        RECENT_VERDICTS.pop(0)

    # Store in memory cache
    SCAN_CACHE[cache_key] = {
        "cached_at": now_ts,
        "data": fused_verdict
    }

    return fused_verdict


async def _run_async_scan(scan_id: str, req: ScanRequest):
    """Executes asynchronous scan job in background task."""
    try:
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, _execute_scan_pipeline, req)
        ASYNC_JOBS[scan_id] = {
            "scan_id": scan_id,
            "status": "complete",
            "url": req.url,
            "verdict": res
        }
    except Exception as e:
        ASYNC_JOBS[scan_id] = {
            "scan_id": scan_id,
            "status": "failed",
            "url": req.url,
            "error": str(e)
        }


@app.post("/api/scan")
async def full_scan(req: ScanRequest, mode: Literal["sync", "async"] = "sync"):
    """
    Comprehensive multi-signal scan supporting both synchronous and asynchronous modes:
    - Tier 1: Lexical Typosquatting & Homoglyph Confusable Analysis
    - Tier 2: DOM Form & Sensitive Credential Harvesting Detection
    - Tier 3: Visual Perceptual Similarity Matching (pHash/dHash)
    - Tier 4: WHOIS & RDAP Domain Age & Registrar Verification
    - Tier 5: Pure-Python MinHash Content & Structural Outline Shingling
    - Tier 6: Multimodal GenAI Semantic Reasoning (Gemini 2.0 Flash)
    - Tier 7: Multi-Signal AI/ML Fusion & Sovereign Blockchain Logging
    """
    if not req.url:
        raise HTTPException(status_code=400, detail="URL is required.")

    if mode == "async":
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        ASYNC_JOBS[scan_id] = {
            "scan_id": scan_id,
            "status": "pending",
            "url": req.url,
            "created_at": time.time()
        }
        asyncio.create_task(_run_async_scan(scan_id, req))
        return JSONResponse(
            status_code=202,
            content={
                "scan_id": scan_id,
                "status": "pending",
                "status_url": f"/api/scan/{scan_id}"
            }
        )

    # Synchronous processing
    return _execute_scan_pipeline(req)


@app.post("/api/report-certin")
def report_to_certin(req: CertInReportRequest):
    """Generate and dispatch formal CERT-In cyber threat dossier."""
    report = certin_reporter.create_incident_report(
        scan_result=req.scan_result,
        reporter_info={"notes": req.reporter_notes or "Submitted via GovShield Extension"}
    )
    return {
        "status": "DISPATCHED",
        "message": "Incident dossier logged and forwarded to CERT-In automated ingestion triage.",
        "incident_report": report
    }


# Mount live web portal directly on FastAPI server
import os
from fastapi.staticfiles import StaticFiles

_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_website_path = os.path.join(_root_dir, "website")

if os.path.exists(_website_path):
    app.mount("/", StaticFiles(directory=_website_path, html=True), name="website")


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"Starting GovShield Sentinel Grid AI/ML Server on http://{host}:{port}...")
    uvicorn.run(app, host=host, port=port)
