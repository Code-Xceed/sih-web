"""
GovShield / Sentinel Grid - FastAPI AI/ML Phishing Detection Backend
SIH 2026 Problem Statement SIH1454
"""

import sys
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

app = FastAPI(
    title="GovShield (Sentinel Grid) - Phishing Detection AI",
    description="Multi-modal AI/ML verification service to detect lookalike phishing domains targeting Indian Government services.",
    version="1.0.0"
)

# Enable CORS for Chrome Extensions and local tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate core analyzers & AI Agent
lexical_analyzer = LexicalAnalyzer()
dom_analyzer = DOMAnalyzer()
visual_analyzer = VisualSimilarityAnalyzer()
whois_analyzer = WhoisAnalyzer()
fusion_engine = FusionEngine()
certin_reporter = CertInReporter()
ai_agent = AIAgent()


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
            "multimodal_genai_agent": ai_agent.client_ready
        },
        "ai_model": ai_agent.model_name if ai_agent.client_ready else "edge_heuristic_mode",
        "indexed_reference_portals_count": len(GENUINE_PORTALS)
    }


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


@app.post("/api/scan")
def full_scan(req: ScanRequest):
    """
    Comprehensive multi-signal scan:
    - Tier 1: Lexical Typosquatting Analysis
    - Tier 2: DOM Form & Sensitive Credential Harvesting Detection
    - Tier 3: Visual Perceptual Similarity Matching
    - Tier 4: WHOIS Domain Age & Registrar Verification
    - Tier 5: Multimodal GenAI Semantic Reasoning (Gemini)
    - Tier 6: Multi-Signal Risk Fusion
    """
    if not req.url:
        raise HTTPException(status_code=400, detail="URL is required.")

    # 1. Lexical & Domain Analysis
    lex_res = lexical_analyzer.analyze(req.url)
    target_portal_id = lex_res.get("target_entity_id")

    # 2. DOM & Content Analysis
    dom_res = dom_analyzer.analyze_html(
        html_content=req.html_content or "",
        base_url=req.url,
        matched_portal_id=target_portal_id
    )

    # 3. Visual Lookalike Analysis
    vis_res = visual_analyzer.analyze_visual_lookalike(
        image_base64=req.image_base64,
        candidate_portal_id=target_portal_id
    )

    # 4. WHOIS & Domain Age Analysis
    whois_res = whois_analyzer.analyze(req.url)

    # 5. Multimodal GenAI Inspection (if not an already authenticated official .gov.in domain)
    ai_res = None
    if not lex_res.get("is_genuine_gov_tld") and ai_agent.client_ready:
        ai_res = ai_agent.analyze_webpage(
            url=req.url,
            html_dom=req.html_content or "",
            image_base64=req.image_base64,
            candidate_entity=lex_res.get("target_entity")
        )

    # 6. Multi-Signal AI/ML Fusion
    fused_verdict = fusion_engine.evaluate(
        lexical_result=lex_res,
        dom_result=dom_res,
        visual_result=vis_res,
        whois_result=whois_res
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
            # Confirmed legitimate commercial platform (e.g. ChatGPT, Google, GitHub, etc.)
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
    print(f"  • Matched Gov Entity: {fused_verdict.get('target_entity')}")
    print(f"  • Typosquatting / Lexical Score: {lex_res.get('risk_score', 0)}/100")
    print(f"  • DOM Sensitive Fields: {[s['field'] for s in dom_res.get('sensitive_inputs', [])]}")
    print(f"  • Visual Lookalike Match: {vis_res.get('visual_similarity_score', 0)}%")
    print(f"  • WHOIS Domain Age: {whois_res.get('domain_age_days', 0)} days")
    if ai_res and ai_res.get("status") == "SUCCESS":
        print(f"  🤖 [Gemini 2.0 Flash AI]:")
        print(f"     - Threat Category: {ai_res.get('threat_category')}")
        print(f"     - AI Reason: {ai_res.get('plain_english_explanation')}")
    print(f"  🎯 VERDICT: {fused_verdict['verdict']} | RISK SCORE: {fused_verdict['risk_score']}/100")
    print("=" * 65 + "\n")

    fused_verdict["url"] = req.url
    fused_verdict["lexical_details"] = lex_res
    fused_verdict["dom_details"] = dom_res
    fused_verdict["visual_details"] = vis_res
    fused_verdict["whois_details"] = whois_res

    return fused_verdict


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
